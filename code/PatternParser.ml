type token =
  | Regex of ((int * int) * ParsingData.regex)
  | Mod of (int)
  | Eos

open Parsing;;
let _ = parse_error;;
# 2 "PatternParser.mly"
(* © Copyright University of Birmingham, UK *)

open ParsingData

(* validate backreference *)
let re_evaluate_backref (i, pos) gcount =
  let rec rebuild r clist npos = match clist with
    [] -> r
    |c :: t -> rebuild (make_r (Conc (r, make_r (Atom (Char c)) (npos, npos))) (r_spos r, npos)) t (npos + 1) in
  let rec unparse j epos clist = match j with
    |_ when j <= gcount -> rebuild (make_r (Backref j) (fst pos, epos)) clist (epos + 1)
    |_ when j < 10 -> raise (ParsingData.InvalidBackreference (fst pos))
    |_ -> unparse (j / 10) (epos - 1) ((Char.chr (48 + (j mod 10))) :: clist) in
  unparse i (snd pos) [];;

(* assign capturing group identifiers and validate backreferences *)
let rec fix_captures r go gc = match (fst r) with
  Zero | One | Dot | Pred _ | Atom _ -> (r, gc)
  |Group (CAP _, m_on, m_off, r1) ->
    let (_r1, gc2) = fix_captures r1 (go + 1) gc in
    ((Group (CAP (go + 1), m_on, m_off, _r1), snd r), gc2 + 1)
  |Group (gkind, m_on, m_off, r1) ->
    let (_r1, gc2) = fix_captures r1 go gc in
    ((Group (gkind, m_on, m_off, _r1), snd r), gc2)
  |Backref i ->
    (re_evaluate_backref (i, r_pos r) gc, gc)
  |Conc (r1, r2) ->
    let (_r1, gc2) = fix_captures r1 go gc in
    let (_r2, gc3) = fix_captures r2 go gc2 in
    ((Conc (_r1, _r2), snd r), gc3) 
  |Alt (r1, r2) ->
    let (_r1, gc2) = fix_captures r1 go gc in
    let (_r2, gc3) = fix_captures r2 go gc in
    ((Alt (_r1, _r2), snd r), gc2 + (gc3 - gc))
  |Kleene (qf, r1) ->
    let (_r1, gc2) = fix_captures r1 go gc in
    ((Kleene (qf, _r1), snd r), gc2);;
  
# 48 "PatternParser.ml"
let yytransl_const = [|
  259 (* Eos *);
    0|]

let yytransl_block = [|
  257 (* Regex *);
  258 (* Mod *);
    0|]

let yylhs = "\255\255\
\001\000\001\000\002\000\002\000\000\000"

let yylen = "\002\000\
\001\000\003\000\000\000\002\000\002\000"

let yydefred = "\000\000\
\000\000\000\000\000\000\001\000\005\000\000\000\000\000\004\000\
\002\000"

let yydgoto = "\002\000\
\005\000\007\000"

let yysindex = "\002\000\
\255\254\000\000\002\255\000\000\000\000\002\255\254\254\000\000\
\000\000"

let yyrindex = "\000\000\
\000\000\000\000\003\255\000\000\000\000\003\255\000\000\000\000\
\000\000"

let yygindex = "\000\000\
\000\000\255\255"

let yytablesize = 6
let yytable = "\003\000\
\009\000\004\000\001\000\006\000\008\000\003\000"

let yycheck = "\001\001\
\003\001\003\001\001\000\002\001\006\000\003\001"

let yynames_const = "\
  Eos\000\
  "

let yynames_block = "\
  Regex\000\
  Mod\000\
  "

let yyact = [|
  (fun _ -> failwith "parser")
; (fun __caml_parser_env ->
    Obj.repr(
# 50 "PatternParser.mly"
           ( (make_r One (0, 0), 0) )
# 104 "PatternParser.ml"
               : ParsingData.pattern))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : (int * int) * ParsingData.regex) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'mods) in
    Obj.repr(
# 51 "PatternParser.mly"
                  ( (fst (fix_captures (make_r (fst (snd _1)) (fst _1)) 0 0), _2) )
# 112 "PatternParser.ml"
               : ParsingData.pattern))
; (fun __caml_parser_env ->
    Obj.repr(
# 53 "PatternParser.mly"
      ( ParsingData.flg_dotall )
# 118 "PatternParser.ml"
               : 'mods))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : int) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'mods) in
    Obj.repr(
# 54 "PatternParser.mly"
            ( _1 lor _2 )
# 126 "PatternParser.ml"
               : 'mods))
(* Entry parse *)
; (fun __caml_parser_env -> raise (Parsing.YYexit (Parsing.peek_val __caml_parser_env 0)))
|]
let yytables =
  { Parsing.actions=yyact;
    Parsing.transl_const=yytransl_const;
    Parsing.transl_block=yytransl_block;
    Parsing.lhs=yylhs;
    Parsing.len=yylen;
    Parsing.defred=yydefred;
    Parsing.dgoto=yydgoto;
    Parsing.sindex=yysindex;
    Parsing.rindex=yyrindex;
    Parsing.gindex=yygindex;
    Parsing.tablesize=yytablesize;
    Parsing.table=yytable;
    Parsing.check=yycheck;
    Parsing.error_function=parse_error;
    Parsing.names_const=yynames_const;
    Parsing.names_block=yynames_block }
let parse (lexfun : Lexing.lexbuf -> token) (lexbuf : Lexing.lexbuf) =
   (Parsing.yyparse yytables 1 lexfun lexbuf : ParsingData.pattern)
