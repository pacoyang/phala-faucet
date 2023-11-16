#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

use pink_extension as pink;

#[ink::contract(env = pink::PinkEnvironment)]
mod phala_faucet {
    use super::pink;
    use crate::alloc::string::ToString;
    use alloc::{string::String, vec::Vec, boxed::Box};
    use scale::{Decode, Encode, Compact};
    use pink::chain_extension::{signing, SigType};
    use pink_subrpc::{
        create_transaction, send_transaction, ExtraParam,
        get_ss58addr_version, Ss58Codec,
    };
    use phat_js;
    use ink::env::hash;
    use ink::storage::Mapping;
    #[allow(unused_imports)]
    use ink::storage::traits::StorageLayout;

    #[ink(storage)]
    pub struct PhalaFaucet {
        owner: AccountId,
        private_key: [u8; 32],
        public_key: [u8; 32],

        // The chain & rpc_endpoint is used to create transaction.
        chain: String,
        rpc_endpoint: String,
        call_index: (u8, u8),

        // We don't save the proven scripts inside the contract, instead, we save the hash of those
        // scripts.
        proven_script_hash: Vec<[u8; 32]>,
        proven_script_secrets: Mapping<[u8; 32], String>,

        // Then base token amount an account can claim each time slot.
        base_token_amount: u128,
        // If the address have balance more than this threshold, it will be rejected.
        balance_threshold: u128,
        claim_peridical_seconds: u64,
        account_check_js: String,

        next_id: u64,
        proven_scores: Mapping<u64, ProvenScore>,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct ProvenScore {
        address: AccountId,
        js_code_hash: [u8; 32],
        score: u128,
    }

    #[derive(Encode, Decode, PartialEq, Eq, Clone, Debug)]
    #[cfg_attr(feature = "std", derive(Hash, scale_info::TypeInfo))]
    pub enum MultiAddress<AccountId, AccountIndex> {
        /// It's an account ID (pubkey).
        Id(AccountId),
        /// It's an account index.
        Index(#[codec(compact)] AccountIndex),
        /// It's some arbitrary raw bytes.
        Raw(Vec<u8>),
        /// It's a 32 byte representation.
        Address32([u8; 32]),
        /// Its a 20 byte representation.
        Address20([u8; 20]),
    }

    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct ProvenResult {
        pub js_code_hash: [u8; 32],
        pub result: u128,
        pub signature: Vec<u8>,
    }

    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EvmCaller {
        pub compressed_pubkey: [u8; 33],
        pub address: [u8; 20],
    }

    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct FaucetResult {
        pub tx_id: Vec<u8>,
        pub amount: u128,
    }

    #[derive(Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        JsError(String),
        BadProvenScript,
        BadProvenScore,
        NotNeedFaucet,
    }

    struct CallerInfo {
        owner_ss58_address: String,
        ss58_address: String,
        evm_address: Option<[u8; 20]>,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl PhalaFaucet {
        #[ink(constructor)]
        pub fn default(salt: Option<String>, rpc_endpoint: String, chain: Option<String>, call_index: (u8, u8), account_check_js: String) -> Self {
            let nonce = salt.unwrap_or_default();
            let private_key = pink_web3::keys::pink::KeyPair::derive_keypair(nonce.as_bytes()).private_key();
            let public_key = signing::get_public_key(&private_key, SigType::Sr25519)
                .try_into()
                .unwrap();
            Self {
                owner: Self::env().caller(),
                public_key,
                private_key,
                chain: chain.unwrap_or("phala".into()),
                rpc_endpoint,
                call_index,
                proven_script_hash: Default::default(),
                proven_script_secrets: Mapping::default(),
                next_id: 0,
                proven_scores: Mapping::default(),
                base_token_amount: 1_000_000_000_000_u128 * 5,      // 5 PHA
                balance_threshold: 1_000_000_000_000_u128 * 5_000,  // 5,000 PHA
                claim_peridical_seconds: 60 * 60 * 24,              // 24 hours
                account_check_js,
            }
        }

        ///
        /// The SS58 format address of the faucet
        ///
        /// @category core
        ///
        #[ink(message)]
        pub fn get_public_key(&self) -> AccountId {
            let account_id: AccountId = self.public_key.into();
            account_id
        }

        ///
        /// The Chain ID, it requires substrate network.
        ///
        /// @category core
        ///
        #[ink(message)]
        pub fn get_chain(&self) -> String {
            self.chain.clone()
        }

        ///
        /// The Chain ID, it requires substrate network.
        ///
        /// @category core
        ///
        #[ink(message)]
        pub fn set_chain(&mut self, chain: String) -> Result<()> {
            self.ensure_owner()?;
            self.chain = chain;
            Ok(())
        }

        ///
        /// The HTTP RPC endpoint, only owner can access that so we can use private endpoint here.
        ///
        /// @category core
        ///
        #[ink(message)]
        pub fn get_rpc_endpoint(&self) -> Result<String> {
            self.ensure_owner()?;
            Ok(self.rpc_endpoint.clone())
        }

        ///
        /// @category core
        ///
        #[ink(message)]
        pub fn set_rpc_endpoint(&mut self, rpc_endpoint: String) -> Result<()> {
            self.ensure_owner()?;
            self.rpc_endpoint = rpc_endpoint;
            Ok(())
        }

        ///
        /// @category base
        ///
        #[ink(message)]
        pub fn set_account_check_js(&mut self, js_code: String) -> Result<()> {
            self.ensure_owner()?;
            self.account_check_js = js_code;
            Ok(())
        }

        ///
        /// @category base
        ///
        #[ink(message)]
        pub fn get_account_check_js(&self) -> Result<String> {
            self.ensure_owner()?;
            Ok(self.account_check_js.clone())
        }

        ///
        /// @category base
        ///
        #[ink(message)]
        pub fn account_check(&self) -> Result<bool> {
            let caller_info = self.get_caller_info(self.env().caller(), Option::None);
            let evm_address = if caller_info.evm_address.is_some() {
                alloc::format!("0x{}", hex::encode(caller_info.evm_address.unwrap()))
            } else {
                "".into()
            };

            let js_result = self.run_js_code(&self.account_check_js, alloc::vec![
                caller_info.owner_ss58_address,
                caller_info.ss58_address,
                evm_address,
                self.balance_threshold.to_string(),
                self.claim_peridical_seconds.to_string(),
            ])?;
            let result = js_result.parse::<bool>().unwrap();
            Ok(result)
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn add_proven_script(&mut self, hash: [u8; 32]) -> Result<()> {
            self.ensure_owner()?;
            self.proven_script_hash.push(hash);
            Ok(())
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn get_proven_scripts(&self) -> Vec<[u8; 32]> {
            self.proven_script_hash.clone()
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn set_proven_script_secret(&mut self, hash: [u8; 32], secret: String) -> Result<()> {
            self.ensure_owner()?;
            self.proven_script_secrets.insert(hash, &secret);
            Ok(())
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn get_proven_script_secret(&self, hash: [u8; 32]) -> Result<String> {
            self.ensure_owner()?;
            Ok(self.proven_script_secrets.get(&hash).unwrap_or_default())
        }

        ///
        ///
        /// @category proven
        ///
        /// @ui js_code widget codemirror
        /// @ui js_code options.lang javascript
        ///
        #[ink(message)]
        pub fn test_proven_script(&self, js_code: String, evm_caller: Option<EvmCaller>, secret: Option<String>) -> Result<ProvenResult> {
            let context = self.get_caller_context_json(self.env().caller(), evm_caller);
            let result = self.run_js_code(&js_code, alloc::vec![
                context,
                secret.unwrap_or("".into()),
            ])?;

            let hashed = self
                .env()
                .hash_bytes::<ink::env::hash::Blake2x256>(js_code.as_bytes());
            let message = alloc::format!("{}{}{}", hex::encode(self.env().caller()), hex::encode(hashed), result);
            let signature = signing::sign(message.as_bytes(), &self.private_key, SigType::Sr25519);
            let js_code_hash: [u8; 32] = hashed.into();

            Ok(ProvenResult {
                js_code_hash,
                result: result.parse::<u128>().unwrap(),
                signature,
            })
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn run_proven_script(&self, js_code: String, evm_caller: Option<EvmCaller>) -> Result<ProvenResult> {
            // check is it in the proven list
            let hashed = self
                .env()
                .hash_bytes::<ink::env::hash::Blake2x256>(js_code.as_bytes());
            if self.proven_script_hash.iter().find(|&x| x == &hashed).is_none() {
                return Err(Error::BadProvenScript);
            }

            let context = self.get_caller_context_json(self.env().caller(), evm_caller);
            let secret = self.proven_script_secrets.get(hashed).unwrap_or("".into()).clone();
            let result = self.run_js_code(&js_code, alloc::vec![
                context,
                secret,
            ])?;

            let message = alloc::format!("{}{}{}", hex::encode(self.env().caller()), hex::encode(hashed), result);
            let signature = signing::sign(message.as_bytes(), &self.private_key, SigType::Sr25519);
            let js_code_hash: [u8; 32] = hashed.into();

            Ok(ProvenResult {
                js_code_hash,
                result: result.parse::<u128>().unwrap(),
                signature,
            })
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn save_proven_score(&mut self, result:ProvenResult) -> Result<()> {
            let caller = self.env().caller();

            if self.proven_script_hash.iter().find(|&x| x == &result.js_code_hash).is_none() {
                return Err(Error::BadProvenScript);
            }

            // verify signature first.
            let message = alloc::format!("{}{}{}", hex::encode(self.env().caller()), hex::encode(result.js_code_hash), result.result);
            let pass = signing::verify(message.as_bytes(), &self.public_key, &result.signature, SigType::Sr25519);
            if !pass {
                return Err(Error::BadProvenScore)
            }

            let mut counts = 0;
            let mut rec: Option<ProvenScore> = Option::None;
            for id in 0..self.next_id {
                if let Some(record) = self.proven_scores.get(id) {
                    if record.address == caller && record.js_code_hash == result.js_code_hash {
                        rec = Some(record);
                        break;
                    }
                    counts += 1;
                }
            }
            if rec.is_some() {
                let mut record = rec.unwrap();
                record.score = result.result;
                self.proven_scores.insert(counts, &record);
            } else {
                let record = ProvenScore {
                    address: caller,
                    js_code_hash: result.js_code_hash,
                    score: result.result,
                };
                self.proven_scores.insert(self.next_id, &record);
                self.next_id += 1;
            }

            Ok(())
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn get_proven_score(&self) -> Result<u128> {
            let caller = self.env().caller();
            let mut scores = 0;
            for id in 0..self.next_id {
                if let Some(record) = self.proven_scores.get(id) {
                    if record.address == caller {
                        scores += record.score;
                    }
                }
            }
            Ok(scores)
        }

        ///
        /// @category proven
        ///
        #[ink(message)]
        pub fn get_all_proven_scores(&self) -> Result<Vec<ProvenScore>> {
            let mut scores = Vec::new();
            for id in 0..self.next_id {
                if let Some(record) = self.proven_scores.get(id) {
                    scores.push(record);
                }
            }
            Ok(scores)
        }

        ///
        /// The faucet will transfer test-PHA to the caller.
        ///
        /// @category faucet
        ///
        #[ink(message)]
        pub fn claim(&self, evm_caller: Option<EvmCaller>) -> Result<FaucetResult> {
            let caller = self.env().caller();
            let caller_info = self.get_caller_info(caller, evm_caller);
            let evm_address = if caller_info.evm_address.is_some() {
                alloc::format!("0x{}", hex::encode(caller_info.evm_address.unwrap()))
            } else {
                "".into()
            };
            let js_result = self.run_js_code(&self.account_check_js, alloc::vec![
                caller_info.owner_ss58_address,
                caller_info.ss58_address,
                evm_address,
                self.balance_threshold.to_string(),
                self.claim_peridical_seconds.to_string(),
            ])?;
            let result = js_result.parse::<bool>().unwrap();
            if !result {
                return Err(Error::NotNeedFaucet)
            }

            let mut amount = self.base_token_amount;
            for id in 0..self.next_id {
                if let Some(record) = self.proven_scores.get(id) {
                    if record.address == caller {
                        amount += record.score * 1_000_000_000_000_u128;
                    }
                }
            }
            pink::info!("{}", alloc::format!("Claim amount: {}", amount));

            pink::info!("{}", self.chain);
            pink::info!("{}", self.rpc_endpoint);

            let recipient: MultiAddress<AccountId, u32>  = MultiAddress::Id(Self::env().caller());
            let signed_tx = create_transaction(
                &self.private_key,
                &self.chain,
                &self.rpc_endpoint,
                0x07u8,
                0x00u8,
                (recipient, Compact(amount)),
                ExtraParam::default(),
            )
            .unwrap();
            let tx_id = send_transaction(&self.rpc_endpoint, &signed_tx).unwrap();
            Ok(FaucetResult {
                tx_id,
                amount,
            })
        }

        ///
        /// Helpers
        ///

        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(Error::BadOrigin)
            }
        }

        pub fn run_js_code(&self, js_code: &String, args: Vec<String>) -> Result<String> {
            let output = match phat_js::eval(&js_code, &args) {
                Ok(output) => output,
                Err(e) => {
                    return Err(Error::JsError(e));
                }
            };
            let output_as_bytes = match output {
                phat_js::Output::String(s) => s.into_bytes(),
                phat_js::Output::Bytes(b) => b,
                phat_js::Output::Undefined => panic!("Undefined"),

            };
            Ok(String::from_utf8(output_as_bytes).unwrap())
        }

        fn get_caller_info(&self, account_id: AccountId, evm_caller: Option<EvmCaller>) -> CallerInfo {
            let chain_id = Box::leak(self.chain.clone().into_boxed_str());
            let version_prefix = get_ss58addr_version(chain_id).unwrap().prefix();
            let account: [u8; 32] = *Self::env().caller().as_ref();
            let ss58_address = account.to_ss58check_with_version(version_prefix);
            let owner: [u8; 32] = *self.owner.as_ref();
            let owner_addr = owner.to_ss58check_with_version(version_prefix);

            // When we get the compressed public key and address, we assume that signed by EVM
            // wallet client.
            if evm_caller.is_some() {
                let caller = evm_caller.unwrap();
                let mut output = <hash::Blake2x256 as hash::HashOutput>::Type::default();
                ink::env::hash_bytes::<hash::Blake2x256>(&caller.compressed_pubkey, &mut output);
                let account_id_from_compressed_key = AccountId::decode(&mut &output[..]).unwrap();
                if account_id_from_compressed_key == account_id {
                    let mut calc_addr = [0; 20];
                    let _ = ink::env::ecdsa_to_eth_address(&caller.compressed_pubkey, &mut calc_addr);
                    return CallerInfo {
                        owner_ss58_address: owner_addr,
                        ss58_address,
                        evm_address: Some(calc_addr),
                    };
                }
            }

            return CallerInfo {
                owner_ss58_address: owner_addr,
                ss58_address,
                evm_address: Option::None,
            };

        }

        fn get_caller_context_json(&self, account_id: AccountId, evm_caller: Option<EvmCaller>) -> String {
            let caller_info = self.get_caller_info(account_id, evm_caller);
            let ss58_address = caller_info.ss58_address.to_string();
            let evm_address = if caller_info.evm_address.is_some() {
                alloc::format!("0x{}", hex::encode(caller_info.evm_address.unwrap()))
            } else {
                "".into()
            };
            alloc::format!(
                r#"
                    {{"ss58_address": "{ss58_address}", "evm_address": "{evm_address}"}}
                "#
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex::FromHex;

        #[ink::test]
        fn it_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use super::*;

        use ink_e2e::build_message;

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test]
        async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            Ok(())
        }
    }
}
