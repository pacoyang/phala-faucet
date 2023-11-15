import '@phala/pink-env'

export default function main(callerAddress: string) {
  const search = JSON.stringify({
    "json":{"owner": callerAddress, "collectionIds":[2]}
  })
  const pwNftQuery = pink.httpRequest({
    url: `https://api.phala.world/rpc/nfts.list?input=${encodeURIComponent(search)}`,
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

  // console.log(nftData?.result?.data?.json?.items)

  return nftCounts > 0 ? 100 : 0
}
