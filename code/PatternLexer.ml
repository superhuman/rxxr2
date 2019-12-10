# 3 "PatternLexer.mll"
 
open PatternParser

(* different states of the regex lexer *)
type rlstate = {mutable rl_phase : rlphase}
and rlphase = REGEX_BODY | CLS_HEAD | CLS_BODY | MODS_LIST | QUOTE;;

(* switch between different lexing functions based on the current state / token *)
let create_regex_lexer_decorator () =
  let state = { rl_phase = REGEX_BODY } in
  let lex_regex_stateful lbuf = match state.rl_phase with
    REGEX_BODY ->
      begin
        let tk = RegexLexer.tk_normal lbuf in
        let _ = match tk with
          RegexParser.ClsOpen(_) -> state.rl_phase <- CLS_HEAD
          |RegexParser.ModsGrpOpen(_) -> state.rl_phase <- MODS_LIST
          |RegexParser.BeginQuote(_) -> state.rl_phase <- QUOTE
          |_ -> () in tk
      end
    |CLS_HEAD ->
      let _ = state.rl_phase <- CLS_BODY in
      RegexLexer.tk_class_header lbuf
    |CLS_BODY ->
      begin
        let tk = RegexLexer.tk_class_body lbuf in
        let _ = match tk with
          RegexParser.ClsClose(_) -> state.rl_phase <- REGEX_BODY
          |_ -> () in tk
      end
    |MODS_LIST ->
      begin
        let tk = RegexLexer.tk_mods_head lbuf in
        let _ = match tk with
          RegexParser.GrpClose(_) -> state.rl_phase <- REGEX_BODY
          |RegexParser.EndMods -> state.rl_phase <- REGEX_BODY
          |_ -> () in tk
      end
    |QUOTE ->
      begin
        let tk = RegexLexer.tk_quote lbuf in
        let _ = match tk with
          RegexParser.EndQuote(_) -> state.rl_phase <- REGEX_BODY
          |_ -> () in tk
      end in
  lex_regex_stateful;;

(* method for parsing the inner regex of /REGEX/MODS *)
let parse_regex r_str =
  let lexbuf = Lexing.from_string (Printf.sprintf "%s\n" r_str) in
  RegexParser.parse (create_regex_lexer_decorator ()) lexbuf;;

(* map of possible global modifers *)
let flg_map = Hashtbl.create 8;;
Hashtbl.add flg_map 'd' ParsingData.flg_unix_lines;;
Hashtbl.add flg_map 'i' ParsingData.flg_no_case;;
Hashtbl.add flg_map 'm' ParsingData.flg_multiline;;
Hashtbl.add flg_map 's' ParsingData.flg_dotall;;
(* greedy / reluctant quantifiers don't matter for ReDoS *)
Hashtbl.add flg_map 'G' 0;;
(* snort specific modifiers that we don't care about *)
Hashtbl.add flg_map 'g' 0;;
Hashtbl.add flg_map 'y' 0;;
Hashtbl.add flg_map 'R' 0;;
Hashtbl.add flg_map 'U' 0;;
Hashtbl.add flg_map 'P' 0;;
Hashtbl.add flg_map 'H' 0;;
Hashtbl.add flg_map 'D' 0;;
Hashtbl.add flg_map 'M' 0;;
Hashtbl.add flg_map 'C' 0;;
Hashtbl.add flg_map 'K' 0;;
Hashtbl.add flg_map 'S' 0;;
Hashtbl.add flg_map 'B' 0;;
Hashtbl.add flg_map 'O' 0;;

(* resolve global modifier *)
let get_flag c cpos =
  try
    Hashtbl.find flg_map c
  with Not_found ->
    raise (ParsingData.UnsupportedGlobalModifier(cpos, c));;

(* functions for querying token position *)
let get_pos lbuf = (Lexing.lexeme_start lbuf, Lexing.lexeme_end lbuf - 1);;
let get_spos lbuf = Lexing.lexeme_start lbuf;;
let get_epos lbuf = Lexing.lexeme_end lbuf - 1;;

# 88 "PatternLexer.ml"
let __ocaml_lex_tables = {
  Lexing.lex_base =
   "\000\000\251\255\001\000\002\000\003\000\004\000\005\000\006\000\
    \253\255\254\255\255\255";
  Lexing.lex_backtrk =
   "\255\255\255\255\002\000\003\000\000\000\255\255\001\000\255\255\
    \255\255\255\255\255\255";
  Lexing.lex_default =
   "\002\000\000\000\002\000\005\000\002\000\005\000\005\000\009\000\
    \000\000\000\000\000\000";
  Lexing.lex_trans =
   "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\004\000\255\255\255\255\255\255\255\255\255\255\
    \010\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\003\000\
    \000\000\006\000\000\000\006\000\006\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
    \001\000\255\255\255\255\255\255\255\255\255\255\008\000";
  Lexing.lex_check =
   "\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\000\000\002\000\003\000\004\000\005\000\006\000\
    \007\000\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\000\000\
    \255\255\003\000\255\255\005\000\006\000\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\255\
    \000\000\002\000\003\000\004\000\005\000\006\000\007\000";
  Lexing.lex_base_code =
   "";
  Lexing.lex_backtrk_code =
   "";
  Lexing.lex_default_code =
   "";
  Lexing.lex_trans_code =
   "";
  Lexing.lex_check_code =
   "";
  Lexing.lex_code =
   "";
}

let rec tk_normal lexbuf =
   __ocaml_lex_tk_normal_rec lexbuf 0
and __ocaml_lex_tk_normal_rec lexbuf __ocaml_lex_state =
  match Lexing.engine __ocaml_lex_tables __ocaml_lex_state lexbuf with
      | 0 ->
# 90 "PatternLexer.mll"
             ( Eos )
# 188 "PatternLexer.ml"

  | 1 ->
let
# 91 "PatternLexer.mll"
                      r_str
# 194 "PatternLexer.ml"
= Lexing.sub_lexeme lexbuf (lexbuf.Lexing.lex_start_pos + 1) (lexbuf.Lexing.lex_curr_pos + -1) in
# 91 "PatternLexer.mll"
                                 ( Regex(get_pos lexbuf, parse_regex r_str) )
# 198 "PatternLexer.ml"

  | 2 ->
let
# 92 "PatternLexer.mll"
                       r_str
# 204 "PatternLexer.ml"
= Lexing.sub_lexeme lexbuf lexbuf.Lexing.lex_start_pos lexbuf.Lexing.lex_curr_pos in
# 92 "PatternLexer.mll"
                             ( Regex(get_pos lexbuf, parse_regex r_str) )
# 208 "PatternLexer.ml"

  | 3 ->
# 93 "PatternLexer.mll"
         ( raise (ParsingData.UnbalancedPatternMarker(get_spos lexbuf)) )
# 213 "PatternLexer.ml"

  | 4 ->
# 94 "PatternLexer.mll"
         ( raise ParsingData.UnexpectedEndOfInput )
# 218 "PatternLexer.ml"

  | __ocaml_lex_state -> lexbuf.Lexing.refill_buff lexbuf;
      __ocaml_lex_tk_normal_rec lexbuf __ocaml_lex_state

and tk_mods lexbuf =
   __ocaml_lex_tk_mods_rec lexbuf 7
and __ocaml_lex_tk_mods_rec lexbuf __ocaml_lex_state =
  match Lexing.engine __ocaml_lex_tables __ocaml_lex_state lexbuf with
      | 0 ->
# 96 "PatternLexer.mll"
             ( Eos )
# 230 "PatternLexer.ml"

  | 1 ->
let
# 97 "PatternLexer.mll"
          c
# 236 "PatternLexer.ml"
= Lexing.sub_lexeme_char lexbuf lexbuf.Lexing.lex_start_pos in
# 97 "PatternLexer.mll"
            ( Mod(get_flag c (get_spos lexbuf)) )
# 240 "PatternLexer.ml"

  | 2 ->
# 98 "PatternLexer.mll"
         ( raise ParsingData.UnexpectedEndOfInput )
# 245 "PatternLexer.ml"

  | __ocaml_lex_state -> lexbuf.Lexing.refill_buff lexbuf;
      __ocaml_lex_tk_mods_rec lexbuf __ocaml_lex_state

;;

