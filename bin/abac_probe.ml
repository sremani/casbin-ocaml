(* Verification transport only; the public typed API takes Value.t directly. *)
module E = Casbin.Enforcer
module V = Casbin.Value

let fail message = prerr_endline message; exit 2
let result = function Ok value -> value | Error message -> fail message

let decode text =
  let digit = function
    | '0' .. '9' as char -> Char.code char - Char.code '0'
    | 'a' .. 'f' as char -> Char.code char - Char.code 'a' + 10
    | 'A' .. 'F' as char -> Char.code char - Char.code 'A' + 10
    | _ -> invalid_arg "invalid hex field"
  in
  if String.length text mod 2 <> 0 then invalid_arg "odd hex field";
  String.init (String.length text / 2) (fun i ->
      Char.chr (16 * digit text.[2 * i] + digit text.[2 * i + 1]))

let take = function
  | value :: rest -> value, rest
  | [] -> invalid_arg "truncated typed input"

let count tokens =
  let value, rest = take tokens in
  if value = "" || not (String.for_all (function '0' .. '9' -> true | _ -> false) value)
  then invalid_arg "invalid field count";
  let count = int_of_string value in
  if count > 100000 then invalid_arg "probe field count exceeds 100000";
  count, rest

let rec named parser depth remaining tokens acc =
  if remaining = 0 then List.rev acc, tokens
  else
    let name, tokens = take tokens in
    let value, tokens = parser depth tokens in
    named parser depth (remaining - 1) tokens ((decode name, value) :: acc)

let rec schema depth tokens =
  if depth > 256 then invalid_arg "probe nesting exceeds 256";
  let tag, tokens = take tokens in
  match tag with
  | "s" -> V.TString, tokens
  | "n" -> V.TNumber, tokens
  | "b" -> V.TBool, tokens
  | "o" ->
      let size, tokens = count tokens in
      let fields, tokens = named schema (depth + 1) size tokens [] in
      V.TObject fields, tokens
  | _ -> invalid_arg "unsupported schema tag"

let rec value depth tokens =
  if depth > 256 then invalid_arg "probe nesting exceeds 256";
  let tag, tokens = take tokens in
  match tag with
  | "s" -> let text, rest = take tokens in V.String (decode text), rest
  | "n" -> let text, rest = take tokens in V.Number (float_of_string text), rest
  | "b" ->
      let text, rest = take tokens in
      let boolean = match text with "true" -> true | "false" -> false | _ -> invalid_arg "invalid Boolean" in
      V.Bool boolean, rest
  | "o" ->
      let size, tokens = count tokens in
      let fields, tokens = named value (depth + 1) size tokens [] in
      V.Object fields, tokens
  | _ -> invalid_arg "unsupported value tag (arrays and null are outside typed ABAC)"

let complete (value, rest) =
  if rest <> [] then invalid_arg "trailing typed input tokens";
  value

let schemas tokens =
  let size, tokens = count tokens in
  complete (named schema 0 size tokens [])

let values tokens =
  let size, tokens = count tokens in
  let rec loop remaining tokens acc =
    if remaining = 0 then List.rev acc, tokens
    else let item, tokens = value 0 tokens in loop (remaining - 1) tokens (item :: acc)
  in
  complete (loop size tokens [])

let () =
  if Array.length Sys.argv <> 3 then fail "usage: abac_probe MODEL POLICY";
  try
    let request_schema = schemas (String.split_on_char '\t' (read_line ())) in
    let request = values (String.split_on_char '\t' (read_line ())) in
    (try ignore (input_char stdin); invalid_arg "extra input after request" with End_of_file -> ());
    let enforcer = result (E.of_files_abac ~request_schema ~model:Sys.argv.(1) ~policy:Sys.argv.(2)) in
    print_endline (string_of_bool (result (E.enforce_values enforcer request)))
  with
  | Invalid_argument message | Failure message -> fail message
  | End_of_file -> fail "typed probe needs schema and request lines"
