export type CheckResultOK = {
  input: string
  result: 'ok'
}

export type CheckResultVulnerable = {
  input: string
  result: 'vulnerable'
  kleene: string
  prefix: string
  pumpable: string
  suffix: string
}

type CheckResultError = {
  input: string
  result: 'error'
  error: string
}

export type CheckResult = CheckResultOK | CheckResultVulnerable

export async function check (regex: string): Promise<CheckResult> {
  let response = await fetch('https://go.regex.rip/check', {
    method: 'POST',
    body: JSON.stringify({
      regexes: [regex]
    })
  })

  if (!response.ok) {
    throw new Error('not ok')
  }

  let json = await response.json() as {results: (CheckResult | CheckResultError)[]}
  if (json.results[0].result === 'error') {
    throw new Error(json.results[0].error)
  }
  return json.results[0]
}
