type token =
  | Regex of ((int * int) * ParsingData.regex)
  | Mod of (int)
  | Eos

val parse :
  (Lexing.lexbuf  -> token) -> Lexing.lexbuf -> ParsingData.pattern
