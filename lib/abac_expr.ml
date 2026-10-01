type comparison = Eq | Ne | Lt | Le | Gt | Ge

type t = { schema : Value.schema; node : node }
and node =
  | Literal of Value.t
  | Field of string * string list
  | Compare of comparison * t * t
  | And of t * t
  | Or of t * t
  | Not of t
  | Key_match of t * t
  | Role of t * t
  | Role_in_domain of t * t * t

type token_kind =
  | Identifier of string | Quoted of string | Numeric of float
  | True | False
  | Comparison of comparison | Conjunction | Disjunction | Bang
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

let digit = function '0' .. '9' -> true | _ -> false

let valid_field name =
  String.length name > 0 && is_initial name.[0]
  && String.for_all is_identifier_char name

(* These restrictions mirror Expr's boundary around Go's preprocessing and
   automatic conversion of quoted dates, rather than decoding escape syntax. *)
let safe_literal literal =
  let length = String.length literal in
  let rec contains_assertion pos =
    pos + 1 < length
    && ((let rec after_digits index =
           if index < length && digit literal.[index] then after_digits (index + 1)
           else index
         in
         let dot = after_digits (pos + 1) in
         (literal.[pos] = 'r' || literal.[pos] = 'p')
         && dot < length && literal.[dot] = '.')
        || contains_assertion (pos + 1))
  in
  let rec contains_date pos =
    pos + 9 < length
    && ((digit literal.[pos] && digit literal.[pos + 1]
         && digit literal.[pos + 2] && digit literal.[pos + 3]
         && literal.[pos + 4] = '-'
         && digit literal.[pos + 5] && digit literal.[pos + 6]
         && literal.[pos + 7] = '-'
         && digit literal.[pos + 8] && digit literal.[pos + 9])
        || contains_date (pos + 1))
  in
  not (String.exists (function '#' | '\'' | '"' | '[' | ']' | ':' -> true | _ -> false) literal
       || contains_assertion 0 || contains_date 0)

let lex source =
  let length = String.length source in
  let rec scan offset acc =
    if offset = length then List.rev ({ kind = End; offset } :: acc)
    else match source.[offset] with
    | ' ' | '\t' | '\r' | '\n' -> scan (offset + 1) acc
    | '(' -> add Left offset (offset + 1) acc
    | ')' -> add Right offset (offset + 1) acc
    | ',' -> add Comma offset (offset + 1) acc
    | '=' when followed_by offset '=' -> add (Comparison Eq) offset (offset + 2) acc
    | '!' when followed_by offset '=' -> add (Comparison Ne) offset (offset + 2) acc
    | '!' -> add Bang offset (offset + 1) acc
    | '<' when followed_by offset '=' -> add (Comparison Le) offset (offset + 2) acc
    | '>' when followed_by offset '=' -> add (Comparison Ge) offset (offset + 2) acc
    | '<' -> add (Comparison Lt) offset (offset + 1) acc
    | '>' -> add (Comparison Gt) offset (offset + 1) acc
    | '&' when followed_by offset '&' -> add Conjunction offset (offset + 2) acc
    | '|' when followed_by offset '|' -> add Disjunction offset (offset + 2) acc
    | ('\'' | '"') as quote ->
        let rec finish pos =
          if pos = length then invalid offset "unterminated string literal"
          else if source.[pos] = '\\' && pos + 1 < length && source.[pos + 1] = quote then
            invalid pos "escaping a quote delimiter is unsupported"
          else if source.[pos] = quote then pos
          else finish (pos + 1)
        in
        let closing = finish (offset + 1) in
        let literal = String.sub source (offset + 1) (closing - offset - 1) in
        if not (safe_literal literal) then
          invalid offset "unsupported literal: quotes, brackets, '#', ':', assertion-like r/p names, and date-shaped substrings have special upstream meaning";
        add (Quoted literal) offset (closing + 1) acc
    | c when digit c || c = '.' || c = '-' ->
        let rec after_space pos =
          if pos < length then match source.[pos] with
            | ' ' | '\t' | '\r' | '\n' -> after_space (pos + 1)
            | _ -> pos
          else pos
        in
        let beginning = if c = '-' then after_space (offset + 1) else offset in
        let rec digits pos =
          if pos < length && digit source.[pos] then digits (pos + 1) else pos
        in
        let integer_end = digits beginning in
        let ending =
          if integer_end < length && source.[integer_end] = '.' then
            digits (integer_end + 1)
          else integer_end
        in
        let has_digit = integer_end > beginning
                        || (ending > integer_end + 1) in
        if not has_digit then invalid offset "expected a decimal number after '-' or '.'";
        let literal = (if c = '-' then "-" else "")
                      ^ String.sub source beginning (ending - beginning) in
        let number = match float_of_string_opt literal with
          | Some number when Float.is_finite number -> number
          | _ -> invalid offset "number literal must be a finite decimal float64"
        in
        add (Numeric number) offset ending acc
    | c when is_initial c ->
        let rec finish pos =
          if pos < length && (is_identifier_char source.[pos] || source.[pos] = '.')
          then finish (pos + 1) else pos
        in
        let ending = finish (offset + 1) in
        let name = String.sub source offset (ending - offset) in
        let kind = match name with "true" -> True | "false" -> False | _ -> Identifier name in
        add kind offset ending acc
    | c -> invalid offset (Printf.sprintf "unsupported character %C" c)
  and followed_by offset c = offset + 1 < length && source.[offset + 1] = c
  and add kind offset ending acc = scan ending ({ kind; offset } :: acc)
  in
  Array.of_list (scan 0 [])

let compile ~request_schema ~policy_fields ~role_arity source =
  try
    if role_arity <> 0 && role_arity <> 2 && role_arity <> 3 then
      invalid 0 "role arity must be 0, 2, or 3";
    let validate_names label names =
      let rec loop seen = function
        | [] -> ()
        | name :: rest ->
            if not (valid_field name) then
              invalid 0 (Printf.sprintf "invalid %s field name %S" label name);
            if List.mem name seen then
              invalid 0 (Printf.sprintf "duplicate %s field name %S" label name);
            loop (name :: seen) rest
      in
      loop [] names
    in
    validate_names "request" (List.map fst request_schema);
    validate_names "policy" policy_fields;
    List.iter (fun (name, schema) ->
      match Value.validate_schema schema with
      | Ok () -> ()
      | Error message -> invalid 0 (Printf.sprintf "request field %S: %s" name message)) request_schema;
    let tokens = lex source in
    let cursor = ref 0 and depth = ref 0 in
    let current () = tokens.(!cursor) in
    let advance () = incr cursor in
    let expect kind description =
      let token = current () in
      if token.kind <> kind then invalid token.offset ("expected " ^ description);
      advance ()
    in
    let require schema offset expression =
      if expression.schema <> schema then
        invalid offset (if schema = Value.TBool then "expected a Boolean expression"
                        else "expected a string operand");
      expression
    in
    let boolean = require Value.TBool and string = require Value.TString in
    let bool node = { schema = Value.TBool; node } in
    let nested offset f =
      incr depth;
      if !depth > 256 then invalid offset "expression nesting exceeds 256 levels";
      let expression = f () in
      decr depth;
      expression
    in
    let field offset name =
      match String.split_on_char '.' name with
      | "r" :: root :: properties when valid_field root
                                      && List.for_all valid_field properties ->
          let schema = match List.assoc_opt root request_schema with
            | Some schema -> schema
            | None -> invalid offset (Printf.sprintf "unknown request field %S" root)
          in
          let rec descend schema = function
            | [] -> schema
            | property :: rest ->
                match schema with
                | Value.TObject fields ->
                    (match List.assoc_opt property fields with
                     | Some schema -> descend schema rest
                     | None -> invalid offset (Printf.sprintf "unknown property %S in %S" property name))
                | _ -> invalid offset (Printf.sprintf "property traversal through a scalar in %S" name)
          in
          { schema = descend schema properties; node = Field ("r." ^ root, properties) }
      | ["p"; root] when valid_field root && List.mem root policy_fields ->
          { schema = Value.TString; node = Field ("p." ^ root, []) }
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
            rest (bool (Or (boolean token.offset left, boolean token.offset right)))
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
            rest (bool (And (boolean token.offset left, boolean token.offset right)))
        | _ -> left
      in
      rest first
    and comparison () =
      (* Govaluate gives all comparators one precedence and left associativity.
         Each intermediate result is Boolean and participates in static checks. *)
      let rec rest left =
        let token = current () in
        match token.kind with
        | Comparison operator ->
            advance ();
            let right = unary () in
            if left.schema <> right.schema then invalid token.offset "comparison operands must have the same primitive type";
            (match left.schema, operator with
             | (Value.TString | Value.TNumber), _ -> ()
             | Value.TBool, (Eq | Ne) -> ()
             | Value.TBool, _ -> invalid token.offset "ordering Boolean operands is unsupported"
             | Value.TObject _, _ -> invalid token.offset "object comparisons are unsupported");
            rest (bool (Compare (operator, left, right)))
        | _ -> left
      in
      rest (unary ())
    and unary () =
      let token = current () in
      match token.kind with
      | Bang ->
          advance ();
          nested token.offset (fun () -> bool (Not (boolean token.offset (unary ()))))
      | _ -> primary ()
    and primary () =
      let token = current () in
      match token.kind with
      | True -> advance (); bool (Literal (Value.Bool true))
      | False -> advance (); bool (Literal (Value.Bool false))
      | Quoted literal -> advance (); { schema = Value.TString; node = Literal (Value.String literal) }
      | Numeric number -> advance (); { schema = Value.TNumber; node = Literal (Value.Number number) }
      | Identifier "keyMatch" ->
          advance ();
          nested token.offset (fun () ->
            expect Left "'(' after keyMatch";
            let left = string (current ()).offset (disjunction ()) in
            expect Comma "',' between keyMatch arguments";
            let right = string (current ()).offset (disjunction ()) in
            expect Right "')' after two keyMatch arguments";
            bool (Key_match (left, right)))
      | Identifier "g" ->
          if role_arity = 0 then invalid token.offset "g requires a role definition";
          advance ();
          nested token.offset (fun () ->
            expect Left "'(' after g";
            let left = string (current ()).offset (disjunction ()) in
            expect Comma "',' between g arguments";
            let right = string (current ()).offset (disjunction ()) in
            if role_arity = 2 then begin
              expect Right "')' after two g arguments";
              bool (Role (left, right))
            end else begin
              expect Comma "',' before g domain argument";
              let domain = string (current ()).offset (disjunction ()) in
              expect Right "')' after three g arguments";
              bool (Role_in_domain (left, right, domain))
            end)
      | Identifier name -> advance (); field token.offset name
      | Left ->
          advance ();
          nested token.offset (fun () ->
            let expression = disjunction () in
            expect Right "')'";
            expression)
      | _ -> invalid token.offset "expected a field, scalar literal, g/keyMatch call, or '('"
    in
    let expression = disjunction () in
    let final = current () in
    if final.kind <> End then invalid final.offset "unexpected trailing input";
    Ok (boolean final.offset expression)
  with Invalid_matcher message -> Error message

let rec uses_policy expression =
  match expression.node with
  | Literal _ -> false
  | Field (root, _) -> String.length root > 2 && String.sub root 0 2 = "p."
  | Compare (_, left, right) | And (left, right) | Or (left, right)
  | Key_match (left, right) | Role (left, right) -> uses_policy left || uses_policy right
  | Not expression -> uses_policy expression
  | Role_in_domain (left, right, domain) ->
      uses_policy left || uses_policy right || uses_policy domain

let key_match key pattern =
  match String.index_opt pattern '*' with
  | None -> String.equal key pattern
  | Some length ->
      let rec prefix index =
        index = length || (key.[index] = pattern.[index] && prefix (index + 1))
      in
      String.length key >= length && prefix 0

let eval ~resolve ~has_role ~has_role_in_domain expression =
  let ( let* ) = Result.bind in
  let checked expression value =
    let* () = Value.validate ~schema:expression.schema value in
    Ok value
  in
  let as_bool = function
    | Value.Bool value -> Ok value
    | _ -> Error "expected a Boolean runtime value"
  in
  let as_string = function
    | Value.String value -> Ok value
    | _ -> Error "expected a string runtime value"
  in
  let compare operator left right =
    let from_order order =
      match operator with
      | Eq -> order = 0 | Ne -> order <> 0
      | Lt -> order < 0 | Le -> order <= 0 | Gt -> order > 0 | Ge -> order >= 0
    in
    match left, right with
    | Value.String a, Value.String b -> Ok (from_order (String.compare a b))
    | Value.Number a, Value.Number b -> Ok (from_order (Float.compare a b))
    | Value.Bool a, Value.Bool b when operator = Eq || operator = Ne ->
        Ok (if operator = Eq then a = b else a <> b)
    | _ -> Error "comparison requires matching primitive runtime values"
  in
  let rec value expression =
    match expression.node with
    | Literal literal -> Ok literal
    | Field (root, properties) ->
        let* root = resolve root in
        let* leaf = Value.lookup root properties in
        checked expression leaf
    | Compare (operator, left, right) ->
        let* left = value left in
        let* right = value right in
        let* result = compare operator left right in
        Ok (Value.Bool result)
    | Not expression ->
        let* result = boolean expression in
        Ok (Value.Bool (not result))
    | And (left, right) ->
        let* result = boolean left in
        if result then let* result = boolean right in Ok (Value.Bool result)
        else Ok (Value.Bool false)
    | Or (left, right) ->
        let* result = boolean left in
        if result then Ok (Value.Bool true)
        else let* result = boolean right in Ok (Value.Bool result)
    | Key_match (left, right) -> string_pair key_match left right
    | Role (left, right) -> string_pair has_role left right
    | Role_in_domain (left, right, domain) ->
        let* subject = string left in
        let* role = string right in
        let* domain = string domain in
        Ok (Value.Bool (has_role_in_domain subject role domain))
  and boolean expression = let* value = value expression in as_bool value
  and string expression = let* value = value expression in as_string value
  and string_pair f left right =
    let* left = string left in
    let* right = string right in
    Ok (Value.Bool (f left right))
  in
  boolean expression
