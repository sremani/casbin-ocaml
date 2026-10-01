type string_expr = Literal of string | Field of string

type t =
  | Boolean of bool
  | Equal of string_expr * string_expr
  | Not_equal of string_expr * string_expr
  | And of t * t
  | Or of t * t
  | Not of t
  | Role of string_expr * string_expr

type value = String of string_expr | Bool of t

type token_kind =
  | Identifier of string
  | Quoted of string
  | True | False
  | Eq | Ne | Conjunction | Disjunction | Bang
  | Left | Right | Comma | End

type token = { kind : token_kind; offset : int }
exception Invalid_matcher of string

let invalid offset message =
  raise (Invalid_matcher (Printf.sprintf "matcher at byte %d: %s" offset message))

let is_initial = function
  | 'a' .. 'z' | 'A' .. 'Z' | '_' -> true
  | _ -> false

let is_identifier_char = function
  | '0' .. '9' -> true
  | c -> is_initial c

let valid_field name =
  String.length name > 0 && is_initial name.[0]
  && String.for_all is_identifier_char name

let lex source =
  let length = String.length source in
  let rec scan offset acc =
    if offset = length then
      List.rev ({ kind = End; offset } :: acc)
    else
      match source.[offset] with
      | ' ' | '\t' | '\r' | '\n' -> scan (offset + 1) acc
      | '(' -> add Left offset (offset + 1) acc
      | ')' -> add Right offset (offset + 1) acc
      | ',' -> add Comma offset (offset + 1) acc
      | '=' when followed_by offset '=' -> add Eq offset (offset + 2) acc
      | '!' when followed_by offset '=' -> add Ne offset (offset + 2) acc
      | '!' -> add Bang offset (offset + 1) acc
      | '&' when followed_by offset '&' -> add Conjunction offset (offset + 2) acc
      | '|' when followed_by offset '|' -> add Disjunction offset (offset + 2) acc
      | ('\'' | '"') as quote ->
          let rec finish pos =
            if pos = length then invalid offset "unterminated string literal"
            else if source.[pos] = '\\' && pos + 1 < length
                    && source.[pos + 1] = quote then
              invalid pos "escaping a quote delimiter is unsupported"
            else if source.[pos] = quote then pos
            else finish (pos + 1)
          in
          let closing = finish (offset + 1) in
          let literal = String.sub source (offset + 1) (closing - offset - 1) in
          let rec contains_assertion pos =
            pos + 1 < String.length literal
            && ((let rec after_digits index =
                   if index < String.length literal then
                     match literal.[index] with
                     | '0' .. '9' -> after_digits (index + 1)
                     | _ -> index
                   else index
                 in
                 let dot = after_digits (pos + 1) in
                 (literal.[pos] = 'r' || literal.[pos] = 'p')
                 && dot < String.length literal && literal.[dot] = '.')
                || contains_assertion (pos + 1))
          in
          let digit = function '0' .. '9' -> true | _ -> false in
          let rec contains_date pos =
            pos + 9 < String.length literal
            && ((digit literal.[pos] && digit literal.[pos + 1]
                 && digit literal.[pos + 2] && digit literal.[pos + 3]
                 && literal.[pos + 4] = '-'
                 && digit literal.[pos + 5] && digit literal.[pos + 6]
                 && literal.[pos + 7] = '-'
                 && digit literal.[pos + 8] && digit literal.[pos + 9])
                || contains_date (pos + 1))
          in
          if String.exists (function '#' | '\'' | '"' | '[' | ']' | ':' -> true | _ -> false) literal
             || contains_assertion 0 || contains_date 0 then
            invalid offset "unsupported literal: quotes, brackets, '#', ':', assertion-like r/p names, and date-shaped substrings have special upstream meaning";
          add (Quoted literal) offset (closing + 1) acc
      | c when is_initial c ->
          let rec finish pos =
            if pos < length && (is_identifier_char source.[pos] || source.[pos] = '.')
            then finish (pos + 1)
            else pos
          in
          let ending = finish (offset + 1) in
          let name = String.sub source offset (ending - offset) in
          let kind = match name with
            | "true" -> True
            | "false" -> False
            | _ -> Identifier name
          in
          add kind offset ending acc
      | c -> invalid offset (Printf.sprintf "unsupported character %C" c)
  and followed_by offset c = offset + 1 < length && source.[offset + 1] = c
  and add kind offset ending acc = scan ending ({ kind; offset } :: acc)
  in
  Array.of_list (scan 0 [])

let compile ~request_fields ~policy_fields ~roles_enabled source =
  try
    let validate label fields =
      let rec loop seen = function
        | [] -> ()
        | field :: rest ->
            if not (valid_field field) then
              invalid 0 (Printf.sprintf "invalid %s field name %S" label field);
            if List.mem field seen then
              invalid 0 (Printf.sprintf "duplicate %s field name %S" label field);
            loop (field :: seen) rest
      in
      loop [] fields
    in
    validate "request" request_fields;
    validate "policy" policy_fields;
    let tokens = lex source in
    let cursor = ref 0 in
    let depth = ref 0 in
    let current () = tokens.(!cursor) in
    let advance () = incr cursor in
    let boolean offset = function
      | Bool expression -> expression
      | String _ -> invalid offset "expected a Boolean expression, got a string"
    in
    let string offset = function
      | String expression -> expression
      | Bool _ -> invalid offset "expected a string operand, got a Boolean"
    in
    let expect kind description =
      let token = current () in
      if token.kind <> kind then invalid token.offset ("expected " ^ description);
      advance ()
    in
    let nested offset f =
      incr depth;
      if !depth > 256 then invalid offset "expression nesting exceeds 256 levels";
      let result = f () in
      decr depth;
      result
    in
    let field offset name =
      match String.split_on_char '.' name with
      | ["r"; name] when valid_field name && List.mem name request_fields ->
          String (Field ("r." ^ name))
      | ["p"; name] when valid_field name && List.mem name policy_fields ->
          String (Field ("p." ^ name))
      | _ -> invalid offset (Printf.sprintf "unknown or unsupported field %S" name)
    in
    let rec disjunction () =
      let first = conjunction () in
      let rec rest left =
        let token = current () in
        match token.kind with
        | Disjunction ->
            advance ();
            let right = conjunction () in
            rest (Bool (Or (boolean token.offset left, boolean token.offset right)))
        | _ -> left
      in
      rest first
    and conjunction () =
      let first = comparison () in
      let rec rest left =
        let token = current () in
        match token.kind with
        | Conjunction ->
            advance ();
            let right = comparison () in
            rest (Bool (And (boolean token.offset left, boolean token.offset right)))
        | _ -> left
      in
      rest first
    and comparison () =
      let left = unary () in
      let token = current () in
      match token.kind with
      | Eq | Ne ->
          advance ();
          let right = unary () in
          let a = string token.offset left in
          let b = string token.offset right in
          Bool (if token.kind = Eq then Equal (a, b) else Not_equal (a, b))
      | _ -> left
    and unary () =
      let token = current () in
      match token.kind with
      | Bang ->
          advance ();
          nested token.offset (fun () -> Bool (Not (boolean token.offset (unary ()))))
      | _ -> primary ()
    and primary () =
      let token = current () in
      match token.kind with
      | True -> advance (); Bool (Boolean true)
      | False -> advance (); Bool (Boolean false)
      | Quoted literal -> advance (); String (Literal literal)
      | Identifier "g" ->
          if not roles_enabled then invalid token.offset "g requires a role definition";
          advance ();
          nested token.offset (fun () ->
            expect Left "'(' after g";
            let left = string (current ()).offset (disjunction ()) in
            expect Comma "',' between g arguments";
            let right = string (current ()).offset (disjunction ()) in
            expect Right "')' after two g arguments";
            Bool (Role (left, right)))
      | Identifier name -> advance (); field token.offset name
      | Left ->
          advance ();
          nested token.offset (fun () ->
            let expression = disjunction () in
            expect Right "')'";
            expression)
      | _ -> invalid token.offset "expected a field, quoted string, Boolean, g call, or '('"
    in
    let expression = disjunction () in
    let final = current () in
    if final.kind <> End then invalid final.offset "unexpected trailing input";
    Ok (boolean final.offset expression)
  with Invalid_matcher message -> Error message

let rec uses_policy = function
  | Boolean _ -> false
  | Equal (left, right) | Not_equal (left, right) | Role (left, right) ->
      let policy = function
        | Literal _ -> false
        | Field name -> String.length name > 2 && String.sub name 0 2 = "p."
      in
      policy left || policy right
  | And (left, right) | Or (left, right) -> uses_policy left || uses_policy right
  | Not expression -> uses_policy expression

let eval ~resolve ~has_role expression =
  let operand = function
    | Literal value -> Ok value
    | Field name -> resolve name
  in
  let pair f left right =
    match operand left with
    | Error message -> Error message
    | Ok a ->
        match operand right with
        | Error message -> Error message
        | Ok b -> Ok (f a b)
  in
  let rec boolean = function
    | Boolean value -> Ok value
    | Equal (left, right) -> pair String.equal left right
    | Not_equal (left, right) -> pair (fun a b -> not (String.equal a b)) left right
    | Role (left, right) -> pair has_role left right
    | Not value -> Result.map not (boolean value)
    | And (left, right) ->
        (match boolean left with
         | Error message -> Error message
         | Ok false -> Ok false
         | Ok true -> boolean right)
    | Or (left, right) ->
        (match boolean left with
         | Error message -> Error message
         | Ok true -> Ok true
         | Ok false -> boolean right)
  in
  boolean expression
