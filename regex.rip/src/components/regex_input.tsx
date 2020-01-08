import * as React from 'react'
import classNames from 'classnames'
import TextareaAutosize from 'react-textarea-autosize'
import 'style/regex_input'

type RegexInputProps = {
  value: string,
  placeholder: string,
  onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void,
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void,
  onFocus: (e: React.FocusEvent<HTMLTextAreaElement>) => void,
  onBlur: (e: React.FocusEvent<HTMLTextAreaElement>) => void,
  loading: boolean,
  status: string | undefined
}

let timeoutId: undefined | number

function RegexInput ({
  value, placeholder, onChange,
  onKeyDown, loading, status,
  onFocus, onBlur
}: RegexInputProps) {
  let [displayLoader, setLoaderDisplay] = React.useState(false)

  React.useEffect(() => {
    if (loading) {
      timeoutId = setTimeout(() => {
        setLoaderDisplay(true)
      }, 250)
    } else {
      clearInterval(timeoutId)
      setLoaderDisplay(false)
    }
  }, [loading])

  return (
    <div className="RegexInput">
      <div className={classNames('status', { loading: displayLoader }, status)} />
      <TextareaAutosize
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        onKeyDown={onKeyDown}
        onFocus={onFocus}
        onBlur={onBlur}
        autoFocus
      />
    </div>
  )
}

export default RegexInput
