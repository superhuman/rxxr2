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

open Parsing;;
let _ = parse_error;;
# 2 "RegexParser.mly"
(* © Copyright University of Birmingham, UK *)

open ParsingData

(* insert entire character class into a ctr tree *)
let ctr_add_cls tr cls = List.fold_left (fun tr (u, v) -> ctr_add tr u v) tr cls;;

(* make a sequence of n copies of a given regex *)
let rec make_seq r n cpos = match n with
  1 -> r
  |n2 when n2 > 1 -> make_r (Conc (r, make_seq r (n - 1) cpos)) cpos
  |_-> raise ParsingData.InternalParsingError;;

(* make e{0, n} greedy *)
let rec make_greedy_zton r n cpos = match n with
  -1 -> make_r (Kleene (Gq, r)) cpos 
  |1 -> make_r (Alt (r, make_r One cpos)) cpos
  |n2 when n2 > 1 -> make_r (Alt (make_seq r n cpos, make_greedy_zton r (n - 1) cpos)) cpos
  |_-> raise ParsingData.InternalParsingError;;

(* make e{0, n} reluctant *)
let rec make_reluctant_zton r n cpos = match n with
  -1 -> make_r (Kleene (Rq, r)) cpos 
  |1 -> make_r (Alt (make_r One cpos, r)) cpos
  |n2 when n2 > 1 -> make_r (Alt (make_reluctant_zton r (n - 1) cpos, make_seq r n cpos)) cpos
  |_-> raise ParsingData.InternalParsingError;;

(* make e{m, n} *)
let rec make_range r rng cpos = match rng with
  (0, 0, _) -> make_r One cpos
  |(0, -1, qf) -> make_r (Kleene (qf, r)) cpos
  |(m, -1, qf) -> make_r (Conc (make_seq r m cpos, make_range r (0, -1, qf) cpos)) cpos
  |(0, n, Gq) -> make_greedy_zton r n cpos
  |(0, n, Rq) -> make_reluctant_zton r n cpos
  |(m, n, _) when m = n -> make_seq r m cpos
  |(m, n, qf) when m < n -> make_r (Conc (make_seq r m cpos, make_range r (0, (n - m), qf) cpos)) cpos
  |_ -> raise (ParsingData.InvalidRangeDefinition(snd cpos, rng))

# 64 "RegexParser.ml"
let yytransl_const = [|
  272 (* VBar *);
  273 (* NegMods *);
  274 (* EndMods *);
  275 (* Eos *);
    0|]

let yytransl_block = [|
  257 (* Literal *);
  258 (* Anchor *);
  259 (* GrpOpen *);
  260 (* BeginQuote *);
  261 (* EndQuote *);
  262 (* TkDot *);
  263 (* ModsGrpOpen *);
  264 (* Mod *);
  265 (* GrpClose *);
  266 (* ClsClose *);
  267 (* TkBackref *);
  268 (* ClsOpen *);
  269 (* ClsRange *);
  270 (* ClsNamed *);
  271 (* Repetition *);
    0|]

let yylhs = "\255\255\
\001\000\001\000\002\000\002\000\003\000\003\000\004\000\004\000\
\005\000\005\000\005\000\005\000\005\000\005\000\005\000\005\000\
\005\000\005\000\005\000\005\000\005\000\007\000\007\000\006\000\
\008\000\008\000\010\000\010\000\009\000\009\000\011\000\011\000\
\011\000\000\000"

let yylen = "\002\000\
\001\000\002\000\001\000\003\000\001\000\002\000\001\000\002\000\
\001\000\001\000\001\000\002\000\003\000\002\000\003\000\001\000\
\003\000\004\000\005\000\003\000\001\000\001\000\002\000\001\000\
\001\000\003\000\000\000\002\000\001\000\002\000\001\000\001\000\
\001\000\002\000"

let yydefred = "\000\000\
\000\000\000\000\024\000\010\000\000\000\000\000\011\000\000\000\
\016\000\000\000\021\000\001\000\034\000\000\000\000\000\000\000\
\007\000\009\000\014\000\000\000\012\000\000\000\000\000\000\000\
\000\000\000\000\031\000\032\000\033\000\000\000\000\000\002\000\
\000\000\008\000\006\000\015\000\023\000\013\000\028\000\017\000\
\000\000\000\000\020\000\030\000\004\000\018\000\000\000\026\000\
\019\000"

let yydgoto = "\002\000\
\013\000\014\000\015\000\016\000\017\000\018\000\023\000\025\000\
\030\000\026\000\031\000"

let yysindex = "\012\000\
\000\255\000\000\000\000\000\000\043\255\032\255\000\000\030\255\
\000\000\008\255\000\000\000\000\000\000\253\254\025\255\028\255\
\000\000\000\000\000\000\039\255\000\000\050\255\065\255\030\255\
\044\255\062\255\000\000\000\000\000\000\070\255\008\255\000\000\
\071\255\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\057\255\030\255\000\000\000\000\000\000\000\000\072\255\000\000\
\000\000"

let yyrindex = "\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\009\255\
\000\000\000\000\000\000\000\000\000\000\000\000\006\255\001\255\
\000\000\000\000\000\000\000\000\000\000\079\255\000\000\009\255\
\000\000\047\255\000\000\000\000\000\000\000\000\076\255\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\058\255\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000"

let yygindex = "\000\000\
\000\000\251\255\071\000\000\000\000\000\002\000\066\000\000\000\
\058\000\237\255\000\000"

let yytablesize = 89
let yytable = "\020\000\
\003\000\004\000\005\000\006\000\039\000\007\000\008\000\022\000\
\027\000\005\000\009\000\010\000\001\000\011\000\003\000\032\000\
\005\000\027\000\012\000\005\000\028\000\029\000\048\000\022\000\
\003\000\027\000\027\000\045\000\003\000\004\000\005\000\006\000\
\003\000\007\000\008\000\047\000\021\000\024\000\009\000\010\000\
\033\000\011\000\034\000\003\000\004\000\005\000\006\000\036\000\
\007\000\008\000\003\000\019\000\040\000\009\000\010\000\025\000\
\011\000\003\000\004\000\005\000\006\000\041\000\007\000\008\000\
\025\000\046\000\027\000\009\000\010\000\038\000\011\000\003\000\
\004\000\005\000\006\000\027\000\007\000\008\000\042\000\043\000\
\049\000\009\000\010\000\022\000\011\000\029\000\035\000\037\000\
\044\000"

let yycheck = "\005\000\
\001\001\002\001\003\001\004\001\024\000\006\001\007\001\006\000\
\001\001\009\001\011\001\012\001\001\000\014\001\009\001\019\001\
\016\001\009\001\019\001\019\001\013\001\014\001\042\000\022\000\
\019\001\017\001\018\001\033\000\001\001\002\001\003\001\004\001\
\001\001\006\001\007\001\041\000\005\001\008\001\011\001\012\001\
\016\001\014\001\015\001\001\001\002\001\003\001\004\001\009\001\
\006\001\007\001\001\001\009\001\009\001\011\001\012\001\009\001\
\014\001\001\001\002\001\003\001\004\001\018\001\006\001\007\001\
\018\001\009\001\009\001\011\001\012\001\005\001\014\001\001\001\
\002\001\003\001\004\001\018\001\006\001\007\001\017\001\010\001\
\009\001\011\001\012\001\005\001\014\001\010\001\016\000\022\000\
\031\000"

let yynames_const = "\
  VBar\000\
  NegMods\000\
  EndMods\000\
  Eos\000\
  "

let yynames_block = "\
  Literal\000\
  Anchor\000\
  GrpOpen\000\
  BeginQuote\000\
  EndQuote\000\
  TkDot\000\
  ModsGrpOpen\000\
  Mod\000\
  GrpClose\000\
  ClsClose\000\
  TkBackref\000\
  ClsOpen\000\
  ClsRange\000\
  ClsNamed\000\
  Repetition\000\
  "

let yyact = [|
  (fun _ -> failwith "parser")
; (fun __caml_parser_env ->
    Obj.repr(
# 58 "RegexParser.mly"
           ( make_r One (0, 0) )
# 199 "RegexParser.ml"
               : ParsingData.regex))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'expr) in
    Obj.repr(
# 59 "RegexParser.mly"
            ( _1 )
# 206 "RegexParser.ml"
               : ParsingData.regex))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'conc) in
    Obj.repr(
# 61 "RegexParser.mly"
           ( _1 )
# 213 "RegexParser.ml"
               : 'expr))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'conc) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'expr) in
    Obj.repr(
# 62 "RegexParser.mly"
                  ( make_r (Alt (_1, _3)) (r_spos _1, r_epos _3) )
# 221 "RegexParser.ml"
               : 'expr))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'factor) in
    Obj.repr(
# 64 "RegexParser.mly"
             ( _1 )
# 228 "RegexParser.ml"
               : 'conc))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'factor) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'conc) in
    Obj.repr(
# 65 "RegexParser.mly"
               ( make_r (Conc (_1, _2)) (r_spos _1, r_epos _2) )
# 236 "RegexParser.ml"
               : 'conc))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'atom) in
    Obj.repr(
# 67 "RegexParser.mly"
             ( _1 )
# 243 "RegexParser.ml"
               : 'factor))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'factor) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : int * (int * int * ParsingData.qfier)) in
    Obj.repr(
# 68 "RegexParser.mly"
                     ( make_range _1 (snd _2) (r_spos _1, fst _2) )
# 251 "RegexParser.ml"
               : 'factor))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'literal) in
    Obj.repr(
# 70 "RegexParser.mly"
              ( _1 )
# 258 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * ParsingData.pred) in
    Obj.repr(
# 71 "RegexParser.mly"
          ( make_r (Pred (snd _1)) (fst _1) )
# 265 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 72 "RegexParser.mly"
         ( make_r Dot (_1, _1) )
# 272 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : (int * int)) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : (int * int)) in
    Obj.repr(
# 73 "RegexParser.mly"
                       ( make_r One (fst _1, snd _2) )
# 280 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : (int * int)) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'quote_body) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : (int * int)) in
    Obj.repr(
# 74 "RegexParser.mly"
                                  ( _2 )
# 289 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : int * ParsingData.gkind) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 75 "RegexParser.mly"
                    ( make_r (Group (snd _1, 0, 0, make_r One (fst _1, _2))) (fst _1, _2) )
# 297 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : int * ParsingData.gkind) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'expr) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 76 "RegexParser.mly"
                         ( make_r (Group (snd _1, 0, 0, _2)) (fst _1, _3) )
# 306 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * int) in
    Obj.repr(
# 77 "RegexParser.mly"
             ( make_r (Backref (snd _1)) (fst _1) )
# 313 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : int) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'mods) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 78 "RegexParser.mly"
                             ( make_r (Group (MODS, fst _2, snd _2, make_r One (_1, _3))) (_1, _3) )
# 322 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 3 : int) in
    let _2 = (Parsing.peek_val __caml_parser_env 2 : 'mods) in
    let _4 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 79 "RegexParser.mly"
                                     ( make_r One (_1, _4) )
# 331 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 4 : int) in
    let _2 = (Parsing.peek_val __caml_parser_env 3 : 'mods) in
    let _4 = (Parsing.peek_val __caml_parser_env 1 : 'expr) in
    let _5 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 80 "RegexParser.mly"
                                          ( make_r (Group (NOCAP, fst _2, snd _2, _4)) (_1, _5) )
# 341 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : int * bool) in
    let _2 = (Parsing.peek_val __caml_parser_env 1 : 'ch_range_list) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : int) in
    Obj.repr(
# 81 "RegexParser.mly"
                                  (
    let p = (fst _1, _3) in 
      if snd _1 then
        make_r (Atom (Cls (ctr_negative _2))) p 
      else 
        make_r (Atom (Cls (ctr_positive _2))) p
  )
# 356 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * ((char * char) list)) in
    Obj.repr(
# 88 "RegexParser.mly"
            ( make_r (Atom (Cls (snd _1))) (fst _1) )
# 363 "RegexParser.ml"
               : 'atom))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'literal) in
    Obj.repr(
# 90 "RegexParser.mly"
                    ( _1 )
# 370 "RegexParser.ml"
               : 'quote_body))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'literal) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'quote_body) in
    Obj.repr(
# 91 "RegexParser.mly"
                       ( make_r (Conc (_1, _2)) (r_spos _1, r_epos _2)  )
# 378 "RegexParser.ml"
               : 'quote_body))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * char) in
    Obj.repr(
# 93 "RegexParser.mly"
                 ( make_r (Atom (Char (snd _1))) (fst _1) )
# 385 "RegexParser.ml"
               : 'literal))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'mod_list) in
    Obj.repr(
# 95 "RegexParser.mly"
               ( (_1, 0) )
# 392 "RegexParser.ml"
               : 'mods))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 2 : 'mod_list) in
    let _3 = (Parsing.peek_val __caml_parser_env 0 : 'mod_list) in
    Obj.repr(
# 96 "RegexParser.mly"
                             ((_1, _3) )
# 400 "RegexParser.ml"
               : 'mods))
; (fun __caml_parser_env ->
    Obj.repr(
# 98 "RegexParser.mly"
          ( 0 )
# 406 "RegexParser.ml"
               : 'mod_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : int) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'mod_list) in
    Obj.repr(
# 99 "RegexParser.mly"
                ( _1 lor _2 )
# 414 "RegexParser.ml"
               : 'mod_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : 'ch_range) in
    Obj.repr(
# 101 "RegexParser.mly"
                        ( ctr_add_cls CTNull _1 )
# 421 "RegexParser.ml"
               : 'ch_range_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'ch_range) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'ch_range_list) in
    Obj.repr(
# 102 "RegexParser.mly"
                          ( ctr_add_cls _2 _1 )
# 429 "RegexParser.ml"
               : 'ch_range_list))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * char) in
    Obj.repr(
# 104 "RegexParser.mly"
                  ( [(snd _1, snd _1)] )
# 436 "RegexParser.ml"
               : 'ch_range))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : char * char) in
    Obj.repr(
# 105 "RegexParser.mly"
            ( [_1] )
# 443 "RegexParser.ml"
               : 'ch_range))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : (int * int) * ((char * char) list)) in
    Obj.repr(
# 106 "RegexParser.mly"
            ( snd _1 )
# 450 "RegexParser.ml"
               : 'ch_range))
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
   (Parsing.yyparse yytables 1 lexfun lexbuf : ParsingData.regex)
