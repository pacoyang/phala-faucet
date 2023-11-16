import '@phala/pink-env'

export default function main(faucetAddr: string, userAddr: string, evmAddress: string, claimBarrier: string, coldDownSecs: string) {
  const upper = Number(claimBarrier)
  const coldDown = Number(coldDownSecs)
  const options = {
    method: 'GET',
    headers: {
      'User-Agent': 'phat-contract',
    },
    returnTextBody: true,
  }
  const historyQuery = pink.httpRequest({
    url: `https://poc6-statescan-api.phala.network/accounts/${userAddr}/transfers?from=${faucetAddr}&limit=1`,
    ...options,
  })
  const balanceQuery = pink.httpRequest({
    url: `https://poc6-statescan-api.phala.network/accounts/${userAddr}`,
    ...options,
  })

  const historyData = JSON.parse(historyQuery.body as string)
  const timestamp = historyData?.items?.[0]?.indexer?.blockTime
  const now = (new Date()).getTime()
  const diff = now - timestamp
  const needColdDown = diff < coldDown * 1000

  const balanceData = JSON.parse(balanceQuery.body as string)
  const balance = (balanceData?.data?.free || 0) / 1e12
  const isRich = balance > upper

  return !isRich && !needColdDown
}
