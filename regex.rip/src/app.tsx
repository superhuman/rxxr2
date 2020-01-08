import * as React from 'react'
import { CheckResult, CheckResultVulnerable, check } from './check.tsx'
import RegexLogo from './components/regex_logo'
import SuperhumanLogo from './components/superhuman_logo'
import RegexInput from './components/regex_input'
import 'style/index.scss'
import TextareaAutosize from 'react-textarea-autosize'
import classNames from 'classnames'

export default function App () {
  let [input, setInput] = React.useState('')
  let [regex, setRegex] = React.useState('')
  let [loading, setLoading] = React.useState(false)
  let [error, setError] = React.useState<Error | null>(null)
  let [result, setResult] = React.useState<CheckResult | null>(null)
  let [isFocused, setFocus] = React.useState(false)

  React.useEffect(() => {
    (async () => {
      let regexWas = regex
      try {
        setError(null)
        setResult(null)

        if ((regex === '' || regex === '//') && result == null) {
          setLoading(false)
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

  let inputStatus

  if (isFocused) {
    if (regex === input && error) {
      inputStatus = 'error'
    } else if (regex === input && result && result.result === 'vulnerable') {
      inputStatus = 'vulnerable'
    } else if (regex === input && result && result.input && result.result === 'ok') {
      inputStatus = 'ok'
    } else {
      inputStatus = 'focused'
    }
  }

  return <>
    <div className="body">
      <div className="text-block">
        <RegexLogo />
        <p className="instruction-text">Enter a regular expression to test whether it is vulnerable to <a href='https://medium.com/p/f8983bb76afc'>ReDOS</a>.</p>
      </div>
      <div className='input-block'>
        <RegexInput
          value={input}
          placeholder='/(a|b|ab)*c/'
          onChange={handleChange}
          loading={loading}
          status={inputStatus}
          onFocus={() => setFocus(true)}
          onBlur={() => setFocus(false)}
          onKeyDown={handleKeyDown}
        />
      </div>
      <div className="text-block result-container">
        { error ? (
            <>
              <p><code>{error.message}</code></p>
              <p>Sorry, something went wrong. Please check your regex and try again.</p>
            </>
        ) : null}
        { result && result.input && result.result === 'ok' ? (
            <>
              <p><code>{result.input.startsWith('/') ? result.input : '/' + result.input + '/'}</code></p>
              <p>This regular expression is not vulnerable to exponential backtracking.</p>
            </>
        ) : null}
        { result && result.result === 'vulnerable' ? (
            renderVulnerable(result)
        ) : null}
      </div>
    </div>
    <div className="footer">
      <div className="input-block"><hr/></div>
      <div className="text-block flex flex-wrap justify-between">
        <SuperhumanLogo/>
        <div className="footer-text">
          <p className="mt0">
            <small>
              <a href='/'>regex.rip</a> is a project from <a href='https://superhuman.com/jobs'>Superhuman Labs</a>.
              If you&#39;re interested in helping us solve the problems required to build the fastest email client in the world,
              ping <a href='mailto:conrad.irwin@superhuman.com?subject=re:+regex.rip'>conrad.irwin@superhuman.com</a>.
            </small>
          </p>
          <p className="small-line-break">
            <small>
              N.B. This service is provided as-is.
              Please join in on <a href='https://github.com/superhuman/rxxr2'>GitHub</a> to help make improvements.
            </small>
          </p>
        </div>
      </div>
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

  return (<>
    <p>
      <code className="vulnerable-regex">
        {regex.slice(0, kleeneIndex)}
        <span className='vulnerable'>{regex.slice(kleeneIndex, kleeneIndex + kleeneLength)}</span>
        {regex.slice(kleeneIndex + kleeneLength)}
      </code>
    </p>
    <p>
      This regular expression is vulnerable to exponential backtracking.
      When matching strings of the form <code>^{result.prefix}({result.pumpable})*{result.suffix}$</code>,
          the time taken for matching to fail will double with each additional <code>{result.pumpable}</code>.
    </p>
    <p className="line-break">For example: copy and paste this into a javascript console:</p>
    <code>
      ({regex}).test({JSON.stringify(result.prefix)} + {JSON.stringify(result.pumpable)}.repeat(25) + {JSON.stringify(result.suffix)})
    </code>
  </>)
}
