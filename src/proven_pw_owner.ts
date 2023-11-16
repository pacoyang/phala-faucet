import '@phala/pink-env'

interface CallerInfo {
  ss58_address: String
  evm_address: String
}

interface Env {
  PW_API_URL: string
}

export default function main(caller_info: string, secret: string) {
  const caller: CallerInfo = JSON.parse(caller_info)
  const env: Env = JSON.parse(secret)

  const search = JSON.stringify({
    "json":{"owner": caller.ss58_address, "collectionIds":[2]}
  })
  const pwNftQuery = pink.httpRequest({
    url: `${env.PW_API_URL}/rpc/nfts.list?input=${encodeURIComponent(search)}`,
    method: 'GET',
    headers: {
      'User-Agent': 'phat-contract',
    },
    returnTextBody: true,
  })

  if (pwNftQuery.statusCode !== 200) {
    console.log('Bad Request:', pwNftQuery.body)
    throw new Error('Bad Request')
  }

  const nftData = JSON.parse(pwNftQuery.body as string)
  const nftCounts = nftData?.result?.data?.json?.items?.length || 0

  return nftCounts > 0 ? 100 : 0
}
