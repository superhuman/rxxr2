(* server_example.ml *)
open Lwt
open Cohttp_lwt_unix
open Cohttp
open Yojson

let cors_headers =
  Header.add (
    Header.add (Header.init ()) "Access-Control-Allow-Origin" "*"
  ) "Access-Control-Allow-Method" "POST"

let check_regex r =
  print_endline(Basic.to_string(`String r)) ;
  let lexbuf =  Lexing.from_string (r ^ "\n") in
  try
    let p = ParsingMain.parse_pattern lexbuf in
    let nfa = Nfa.make p in
    match AnalyserMain.search_optimized nfa 100 with
      |(_f, _, None) ->
          `Assoc [
            ("input", `String r);
            ("result", `String "ok")
          ]
      |(_f, _, Some (ik, x, y, z)) ->
          `Assoc [
            ("input", `String r);
            ("result", `String "vulnerable");
            ("kleene", `String (let (i, j) = Nfa.get_subexp_location nfa ik in String.sub r i (j - i + 1)));
            ("prefix", `String (Word.print_select x [('\x21', '\x7e')]));
            ("pumpable", `String (Word.print_select y [('\x21', '\x7e')]));
            ("suffix", `String (Word.print_select z [('\x21', '\x7e')]))
          ]
  with
  | ParsingData.InvalidBackreference e ->
    `Assoc [
      ("input", `String r);
      ("result", `String "error2");
      ("error", `String (Printf.sprintf "invalid backreference \\%i" e))
    ]

  | e ->
    `Assoc [
      ("input", `String r);
      ("result", `String "error");
      ("error", `String (Printexc.to_string e))
    ]


let check_regexes ( rs : string list) : Basic.t =
  `Assoc [ ("results", `List (List.map check_regex rs)) ]

let check_handler body =
  try
    let json = Basic.from_string(body) in
    let regexes = (json |> Basic.Util.member "regexes" |> Basic.Util.convert_each Basic.Util.to_string) in
    let results = check_regexes(regexes) in
      (`OK, Basic.to_string(results))
  with
  | Json_error a ->
    (`Bad_request, ("Invalid JSON\n" ^ a))
  | Basic.Util.Type_error (a, _) ->
    (`Bad_request, ("Invalid JSON\n" ^ a))

let callback _conn req body =
  if (req |> Request.meth) <> `POST then
    Server.respond_string ~status:`Method_not_allowed ~body:"405 Method not allowed\n" ()
  else if (req |> Request.resource) <> "/check" then
    Server.respond_string ~status:`Not_found ~body:("404 Not Found\n"^ (req |> Request.resource)) ()
  else
    body |> Cohttp_lwt.Body.to_string
    >|= check_handler
    >>= (fun (status, body) ->
      let headers = cors_headers in
       Server.respond_string ~headers ~status ~body ())

let port = try Sys.getenv "PORT" |> int_of_string
           with Not_found -> 8181
let server =
  Server.create ~mode:(`TCP (`Port port)) (Server.make ~callback ())

let () = 
  (print_endline "Running!") ;;
  ignore (Lwt_main.run server)
