type t = String of string | Number of float | Bool of bool | Object of (string * t) list
type schema = TString | TNumber | TBool | TObject of (string * schema) list

let ( let* ) = Result.bind

let identifier name =
  let first = function 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false in
  let later = function '0' .. '9' -> true | character -> first character in
  String.length name > 0 && first name.[0] && String.for_all later name

let names ~path fields =
  let rec check seen = function
    | [] -> Ok ()
    | (name, _) :: rest ->
        if not (identifier name) then
          Error (Printf.sprintf "%s: invalid property identifier %S" path name)
        else if List.mem name seen then
          Error (Printf.sprintf "%s: duplicate property %S" path name)
        else check (name :: seen) rest
  in
  check [] fields

let child path name = path ^ "." ^ name

let rec schema_at depth path schema =
  if depth > 256 then Error (path ^ ": schema nesting exceeds 256 levels")
  else match schema with
  | TString | TNumber | TBool -> Ok ()
  | TObject fields ->
      let* () = names ~path fields in
      let rec check = function
        | [] -> Ok ()
        | (name, schema) :: rest ->
            let* () = schema_at (depth + 1) (child path name) schema in
            check rest
      in
      check fields

let validate_schema schema = schema_at 0 "schema" schema

let finite value = match classify_float value with
  | FP_normal | FP_subnormal | FP_zero -> true
  | FP_infinite | FP_nan -> false

let schema_name = function
  | TString -> "string" | TNumber -> "number" | TBool -> "Boolean" | TObject _ -> "object"

let value_name = function
  | String _ -> "string" | Number _ -> "number" | Bool _ -> "Boolean" | Object _ -> "object"

let validate ~schema value =
  let* () = validate_schema schema in
  let rec at path schema value =
    match schema, value with
    | TString, String _ | TBool, Bool _ -> Ok ()
    | TNumber, Number number ->
        if finite number then Ok () else Error (path ^ ": number must be finite")
    | TObject expected, Object actual ->
        let* () = names ~path actual in
        let rec reject_extra = function
          | [] -> Ok ()
          | (name, _) :: rest ->
              if List.mem_assoc name expected then reject_extra rest
              else Error (Printf.sprintf "%s: unexpected property %S" path name)
        in
        let* () = reject_extra actual in
        let rec check = function
          | [] -> Ok ()
          | (name, schema) :: rest ->
              match List.assoc_opt name actual with
              | None -> Error (Printf.sprintf "%s: missing property %S" path name)
              | Some value ->
                  let* () = at (child path name) schema value in
                  check rest
        in
        check expected
    | schema, value ->
        Error (Printf.sprintf "%s: expected %s, got %s" path (schema_name schema) (value_name value))
  in
  at "value" schema value

let lookup value path =
  let rec find location value = function
    | [] -> Ok value
    | name :: rest ->
        match value with
        | Object fields ->
            let* () = names ~path:location fields in
            (match List.assoc_opt name fields with
             | None -> Error (Printf.sprintf "%s: missing property %S" location name)
             | Some value -> find (child location name) value rest)
        | _ -> Error (Printf.sprintf "%s: cannot access property %S of %s"
                        location name (value_name value))
  in
  let rec bounded remaining = function
    | [] -> true
    | _ :: rest -> remaining > 0 && bounded (remaining - 1) rest
  in
  if not (bounded 256 path) then Error "value: lookup path exceeds 256 levels"
  else find "value" value path
