import '@phala/pink-env'

enum Error {
  FailedToFetchData = 'FailedToFetchData'
}

export default function main(address: string) {
  const response = pink.httpRequest({
    url: `https://website-git-work-2023w44-phala.vercel.app/api/faucet?address=${address}`,
    method: 'GET',
    headers: {
      'User-Agent': 'phat-contract',
    },
    returnTextBody: true,
  })

  if (response.statusCode !== 200) {
    throw Error.FailedToFetchData
  }

  const data = JSON.parse(response.body as string)

  if (!data.succeed) {
    throw data.error
  }

  return 100
}

