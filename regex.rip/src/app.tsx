import * as React from 'react'
import { CheckResult, CheckResultVulnerable, check } from './check.tsx'
import 'style/index.scss'
import TextareaAutosize from 'react-textarea-autosize'
import classNames from 'classNames'

export default function App () {
  let [input, setInput] = React.useState('')
  let [regex, setRegex] = React.useState('')
  let [loading, setLoading] = React.useState(false)
  let [error, setError] = React.useState<Error | null>(null)
  let [result, setResult] = React.useState<CheckResult | null>(null)

  React.useEffect(() => {
    (async () => {
      let regexWas = regex
      try {
        console.log(regex)
        if ((regex === '' || regex === '//') && result == null) {
          setLoading(false)
          setError(null)
          setResult(null)
          setRegex('')
          return
        }
        setLoading(true)
        let newResult = await check(regex)
        if (regex !== regexWas) {
          return
        }
        setLoading(false)
        setError(null)
        setResult(newResult)
      } catch (e) {
        if (regex !== regexWas) {
          return
        }
        setLoading(false)
        setError(e)
        setResult(null)
      }

    })()
  }, [regex])

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Enter') {
      return
    }
    if (input.startsWith('/') && !/^\/.*\/[a-z]*$/.test(input)) {
      setInput(input + '/')
      setRegex(input + '/')
    } else {
      setRegex(input)
    }
    e.preventDefault()
  }

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value)
  }

  const className = classNames('input', {
    'empty': regex === '' || input !== regex,
    'loading': loading,
    'vulnerable': !loading && regex === input && result && result.result === 'vulnerable',
    'ok': !loading && regex === input && result && result.result === 'ok',
    'error': !loading && regex === input && error
  })

  return <>
    <h1>TODO HEADER</h1>
    <p>Enter a regular expression to test whether it is vulnerable to <a href='https://medium.com/p/f8983bb76afc/edit'>ReDOS</a>.</p>
    <div className={className}>
      <TextareaAutosize value={input} onChange={handleChange} placeholder='/(a|b|ab)*c/' onKeyDown={handleKeyDown} />
      <div className='progress'/>
      { error ? (
        <>
         <h3>ERROR</h3>
         <code>{error.message}</code>
         <p>Sorry, something went wrong. Please check your regex and try again.</p>
        </>
      ) : null}
      { result && result.result === 'ok' ? (
        <>
          <h3>GREAT</h3>
          <code>{result.input.startsWith('/') ? result.input : '/' + result.input + '/'}</code>
          <p>This regular expression is not vulnerable to exponential backtracking.</p>
        </>
      ) : null}
      { result && result.result === 'vulnerable' ? (
        renderVulnerable(result)
      ) : null}
      <hr/>
      <p><small><a href='/'>regex.rip</a> is a project from <a href='https://superhuman.com/jobs'>Superhuman Labs</a>. If you're interested in helping us solve the problems required to build the fastest email client in the world, ping <a href='mailto:conrad.irwin@superhuman.com?subject=re:+regex.rip'>conrad.irwin@superhuman.com</a>.</small></p>
      <p><small>N.B. This service is provided as-is. Please join in on <a href='https://github.com/superhuman/rxxr2'>GitHub</a> to help make improvements.</small></p>
    </div>
  </>
}

function renderVulnerable (result: CheckResultVulnerable) {
  let kleeneIndex = result.input.indexOf(result.kleene)
  let kleeneLength = result.kleene.length
  let regex = result.input
  if (!result.input.startsWith('/')) {
    regex = '/' + regex + '/'
  }
  // do this unconditionally to work around an rxxr2 bug
  kleeneIndex += 1

  return <>
    <h3>VULNERABLE</h3>
    <code>
      {regex.slice(0, kleeneIndex)}
      <span className='vulnerable'>{regex.slice(kleeneIndex, kleeneIndex + kleeneLength)}</span>
      {regex.slice(kleeneIndex + kleeneLength)}
    </code>
    <p>This regular expression is vulnerable to exponential backtracking.<p>
    <p>
    When matching strings of the form <code>^{result.prefix}({result.pumpable})*{result.suffix}$</code>, the time taken for matching to fail will double with each additional <code>{result.pumpable}</code>.
    </p>

    <p>For example: copy and paste this into a javascript console:</p>
    <code>({regex}).test({JSON.stringify(result.prefix)} + {JSON.stringify(result.pumpable)}.repeat(25) + {JSON.stringify(result.suffix)})</code>
  </>
}
