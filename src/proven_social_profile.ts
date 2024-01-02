import '@phala/pink-env'

interface CallerInfo {
  ss58_address: String
  evm_address: String
}

interface Env {
  AIRSTACK_API_KEY: string
}

function stringToHex(str: string): string {
  var hex = "";
  for (var i = 0; i < str.length; i++) {
      hex += str.charCodeAt(i).toString(16);
  }
  return "0x" + hex;
}

export default function main(caller_info: string, secret: string) {
  const caller: CallerInfo = JSON.parse(caller_info)
  const env: Env = JSON.parse(secret)

  if (!caller.evm_address) {
    return 0
  }
  const body = JSON.stringify({
    query: `
      query MyQuery {
        Socials(
          input: {filter: {identity: {_eq: "${caller.evm_address}"}}, blockchain: ethereum}
        ) {
          Social {
            dappName
            profileName
            profileDisplayName
            userAddress
            userAssociatedAddresses
          }
        }
      }
    `
  })
  const response = pink.httpRequest({
    url: 'https://api.airstack.xyz/gql',
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "phat-contract",
      "Authorization": env.AIRSTACK_API_KEY,
    },
    body: stringToHex(body),
    returnTextBody: true,
  })

  if (response.statusCode !== 200) {
    console.log('Bad Request:', response.statusCode)
    throw new Error('Bad Request')
  }

  const data = JSON.parse(response.body as string)
  const profiles = data?.data?.Socials?.Social || []
  return profiles.length > 0 ? 1000 : 0
}
