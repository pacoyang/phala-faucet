import '@phala/pink-env'

function stringToHex(str: string): string {
  var hex = ''
  for (var i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16)
  }
  return '0x' + hex
}

export default function main(address: string) {
  const response = pink.httpRequest({
    url: 'https://website-git-work-2023w44-phala.vercel.app/api/faucet',
    method: 'POST',
    headers: {
      'User-Agent': 'phat-contract',
      'Content-Type': 'application/json',
    },
    body: stringToHex(JSON.stringify({
      address,
    })),
    returnTextBody: true,
  })

  return response.statusCode
}

