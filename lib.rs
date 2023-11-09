#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

use pink_extension as pink;

#[ink::contract(env = pink::PinkEnvironment)]
mod phala_faucet {
    use super::pink;
    use alloc::string::String;
    use alloc::vec::Vec;
    use scale::{Decode, Encode, Compact};
    use pink::chain_extension::{signing, SigType};
    use pink_subrpc::{
        create_transaction, send_transaction, ExtraParam,
    };
    use phat_js;

    #[ink(storage)]
    pub struct PhalaFaucet {
        admin: AccountId,
        private_key: [u8; 32],
        public_key: [u8; 32],
        chain: String,
        rpc_endpoint: String,
        js_code: String,
        after_js_code: Option<String>
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
    pub enum Error {
        BadOrigin,
        JsError(String),
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl PhalaFaucet {
        #[ink(constructor)]
        pub fn default(salt: String, chain: String, rpc_endpoint: String, js_code: String, after_js_code: Option<String>) -> Self {
            let private_key =
                pink_web3::keys::pink::KeyPair::derive_keypair(salt.as_bytes()).private_key();
            let public_key = signing::get_public_key(&private_key, SigType::Sr25519)
                .try_into()
                .unwrap();
            Self {
                admin: Self::env().caller(),
                public_key,
                private_key,
                chain,
                rpc_endpoint,
                js_code,
                after_js_code,
            }
        }

        #[ink(message)]
        pub fn get_public_key(&self) -> AccountId {
            let account_id: AccountId = self.public_key.into();
            account_id
        }

        #[ink(message)]
        pub fn get_chain(&self) -> String {
            self.chain.clone()
        }

        #[ink(message)]
        pub fn set_chain(&mut self, chain: String) -> Result<()> {
            self.ensure_admin()?;
            self.chain = chain;
            Ok(())
        }

        #[ink(message)]
        pub fn get_rpc_endpoint(&self) -> String {
            self.rpc_endpoint.clone()
        }

        #[ink(message)]
        pub fn set_rpc_endpoint(&mut self, rpc_endpoint: String) -> Result<()> {
            self.ensure_admin()?;
            self.rpc_endpoint = rpc_endpoint;
            Ok(())
        }

        #[ink(message)]
        pub fn get_js_code(&self) -> String {
            self.js_code.clone()
        }

        #[ink(message)]
        pub fn set_js_code(&mut self, js_code: String) -> Result<()> {
            self.ensure_admin()?;
            self.js_code = js_code;
            Ok(())
        }

        #[ink(message)]
        pub fn set_after_js_code(&mut self, js_code: String) -> Result<()> {
            self.ensure_admin()?;
            self.after_js_code = Some(js_code);
            Ok(())
        }

        fn ensure_admin(&self) -> Result<()> {
            if self.env().caller() == self.admin {
                Ok(())
            } else {
                Err(Error::BadOrigin)
            }
        }

        #[ink(message)]
        pub fn system_remark(&self, remark: String) -> Result<Vec<u8>> {
            let signed_tx = create_transaction(
                &self.private_key,
                &self.chain,
                &self.rpc_endpoint,
                1u8,
                0u8,
                remark,
                ExtraParam::default(),
            )
            .unwrap();
            let tx_id = send_transaction(&self.rpc_endpoint, &signed_tx).unwrap();
            Ok(tx_id)
        }

        #[ink(message)]
        pub fn balances_transfer(&self) -> Result<Vec<u8>> {
            let js_result = self.run_js_code(self.js_code.clone(), alloc::vec![hex::encode(Self::env().caller())])?;
            let pha = js_result.parse::<u128>().unwrap();
            let recipient: MultiAddress<AccountId, u32>  = MultiAddress::Id(Self::env().caller());
            let signed_tx = create_transaction(
                &self.private_key,
                &self.chain,
                &self.rpc_endpoint,
                0x07u8,
                0x07u8,
                (recipient, Compact(pha * 1_000_000_000_000_u128)),
                ExtraParam::default(),
            )
            .unwrap();
            let tx_id = send_transaction(&self.rpc_endpoint, &signed_tx).unwrap();
            if let Some(after_js_code) = self.after_js_code.clone() {
                let _ = self.run_js_code(after_js_code.clone(), alloc::vec![hex::encode(Self::env().caller())])?;
            }
            Ok(tx_id)
        }

        #[ink(message)]
        pub fn run_js_code(&self, js_code: String, args: Vec<String>) -> Result<String> {
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
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex::FromHex;

        #[ink::test]
        fn it_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let private_key =
                pink_web3::keys::pink::KeyPair::derive_keypair(b"salt").private_key();
            let public_key = signing::get_public_key(&private_key, SigType::Sr25519);
            println!("private_key: {}", hex::encode(&private_key));
            println!("public_key: {}", hex::encode(&public_key));
            let bytes = <[u8; 32]>::from_hex("0413729913658156b940c8c33227500d264070a31f52fb98494bc2272c142e35").unwrap();
            let recipient: MultiAddress<AccountId, u32> = MultiAddress::Id(AccountId::from(bytes));
            let amount = Compact(10 * 1_000_000_000_000_u128);
            let chain = "khala";
            let rpc_endpoint = "https://poc6.phala.network/ws";
            let signed_tx = create_transaction(
                &private_key,
                &chain,
                &rpc_endpoint,
                0x07u8,
                0x07u8,
                (recipient, amount),
                ExtraParam::default(),
            )
            .unwrap();
            let tx_id = send_transaction(&rpc_endpoint, &signed_tx).unwrap();
            println!("signed_tx: {}", hex::encode(&signed_tx));
            println!("tx_id: {}", hex::encode(&tx_id));
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
