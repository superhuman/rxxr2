type token =
  | Literal of ((int * int) * char)
  | Anchor of ((int * int) * ParsingData.pred)
  | GrpOpen of (int * ParsingData.gkind)
  | BeginQuote of ((int * int))
  | EndQuote of ((int * int))
  | TkDot of (int)
  | ModsGrpOpen of (int)
  | Mod of (int)
  | GrpClose of (int)
  | ClsClose of (int)
  | TkBackref of ((int * int) * int)
  | ClsOpen of (int * bool)
  | ClsRange of (char * char)
  | ClsNamed of ((int * int) * ((char * char) list))
  | Repetition of (int * (int * int * ParsingData.qfier))
  | VBar
  | NegMods
  | EndMods
  | Eos

val parse :
  (Lexing.lexbuf  -> token) -> Lexing.lexbuf -> ParsingData.regex
