type t = {
  rules : string list list;
  roles : (string * string) list;
  domain_roles : (string * string * string) list;
}

exception Parse_error of string

let fail line message =
  raise (Parse_error (Printf.sprintf "policy line %d: %s" line message))

(* The reference file adapter parses each physical line separately with Go's
   encoding/csv reader and TrimLeadingSpace. In particular, trailing spaces in
   interior unquoted fields are data, and multiline quoted fields are invalid. *)
let parse_record line value =
  let length = String.length value in
  let space = function ' ' | '\t' | '\r' | '\011' | '\012' -> true | _ -> false in
  let rec skip position =
    if position < length && space value.[position] then skip (position + 1) else position
  in
  let rec fields position acc =
    let start = skip position in
    if start < length && value.[start] = '"' then quoted (start + 1) (Buffer.create 16) acc
    else unquoted start start acc
  and unquoted start position acc =
    if position = length then List.rev (String.sub value start (position - start) :: acc)
    else match value.[position] with
      | ',' -> fields (position + 1) (String.sub value start (position - start) :: acc)
      | '"' -> fail line "bare quote in unquoted CSV field"
      | _ -> unquoted start (position + 1) acc
  and quoted position buffer acc =
    if position = length then fail line "unterminated quoted CSV field (multiline fields are unsupported)"
    else if value.[position] <> '"' then begin
      Buffer.add_char buffer value.[position];
      quoted (position + 1) buffer acc
    end else if position + 1 < length && value.[position + 1] = '"' then begin
      Buffer.add_char buffer '"';
      quoted (position + 2) buffer acc
    end else if position + 1 = length then List.rev (Buffer.contents buffer :: acc)
    else if value.[position + 1] = ',' then fields (position + 2) (Buffer.contents buffer :: acc)
    else fail line "unexpected character after closing CSV quote"
  in
  fields 0 []

let of_string ~(model : Model.t) text =
  try
    let rules = ref [] in
    let roles = ref [] in
    let domain_roles = ref [] in
    let seen_rules = Hashtbl.create 16 in
    let seen_roles = Hashtbl.create 16 in
    String.split_on_char '\n' text |> List.iteri (fun index physical ->
      let line = index + 1 in
      let value = String.trim physical in
      if value <> "" && value.[0] <> '#' then begin
        match parse_record line value with
        | "p" :: values ->
            let expected = List.length model.policy_fields in
            if List.length values <> expected then fail line
              (Printf.sprintf "p row has %d fields; expected %d" (List.length values) expected);
            (* Casbin's PolicyMap joins fields with an unescaped comma. Even
               distinct CSV tuples can therefore collide; retain the first. *)
            let key = String.concat "," values in
            if not (Hashtbl.mem seen_rules key) then begin
              Hashtbl.add seen_rules key ();
              rules := values :: !rules
            end
        | "g" :: values ->
            if not model.roles_enabled then fail line "g row requires a role_definition model";
            if List.length values <> model.role_arity then fail line
              (Printf.sprintf "g row has %d fields; expected %d" (List.length values) model.role_arity);
            let key = String.concat "," values in
            if not (Hashtbl.mem seen_roles key) then begin
              begin match model.role_arity, values with
              | 2, [child; parent] -> roles := (child, parent) :: !roles
              | 3, [child; parent; domain] -> domain_roles := (child, parent, domain) :: !domain_roles
              | _ -> fail line "invalid model role arity; expected 2 or 3"
              end;
              Hashtbl.add seen_roles key ()
            end
        | kind :: _ -> fail line (Printf.sprintf "unsupported policy record type %S; expected p or g" kind)
        | [] -> fail line "missing policy record type"
      end);
    Ok { rules = List.rev !rules; roles = List.rev !roles; domain_roles = List.rev !domain_roles }
  with Parse_error message -> Error message

let of_file ~model path =
  try
    let channel = open_in_bin path in
    let contents = Fun.protect ~finally:(fun () -> close_in_noerr channel)
      (fun () -> really_input_string channel (in_channel_length channel)) in
    of_string ~model contents
  with Sys_error message -> Error (Printf.sprintf "policy file %S: %s" path message)
     | End_of_file -> Error (Printf.sprintf "policy file %S: file changed while reading" path)
