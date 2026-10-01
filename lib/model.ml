type t = {
  request_fields : string list;
  policy_fields : string list;
  policy_effect : Effector.policy_effect;
  matcher : string;
  roles_enabled : bool;
  role_arity : int;
}

exception Parse_error of string

let fail line message =
  raise (Parse_error (Printf.sprintf "model line %d: %s" line message))

let is_space = function ' ' | '\t' | '\r' | '\n' | '\011' | '\012' -> true | _ -> false

let strip_comment value =
  match String.index_opt value '#' , String.index_opt value ';' with
  | None, None -> value
  | Some index, None | None, Some index -> String.sub value 0 index
  | Some left, Some right -> String.sub value 0 (min left right)

let identifier value =
  let first = function 'a' .. 'z' | 'A' .. 'Z' | '_' -> true | _ -> false in
  let later = function '0' .. '9' -> true | char -> first char in
  String.length value > 0 && first value.[0]
  && String.for_all later value

let fields line value =
  let values = List.map String.trim (String.split_on_char ',' value) in
  let seen = Hashtbl.create 8 in
  List.iter (fun field ->
    if not (identifier field) then fail line (Printf.sprintf "invalid field identifier %S" field);
    if Hashtbl.mem seen field then fail line (Printf.sprintf "duplicate field %S" field);
    Hashtbl.add seen field ()) values;
  values

let matches_effect value tokens =
  let length = String.length value in
  let rec skip position =
    if position < length && is_space value.[position] then skip (position + 1) else position
  in
  let rec consume position = function
    | [] -> skip position = length
    | token :: rest ->
        let position = skip position in
        let count = String.length token in
        position + count <= length && String.sub value position count = token
        && consume (position + count) rest
  in
  consume 0 tokens

let parse_effect line value =
  let some row_value =
    ["some"; "("; "where"; "("; "p"; "."; "eft"; "=="; row_value; ")"; ")"]
  in
  let allow = some "allow" in
  let deny = "!" :: some "deny" in
  if matches_effect value allow then Effector.Allow_override
  else if matches_effect value deny then Effector.Deny_override
  else if matches_effect value (allow @ ["&&"] @ deny) then Effector.Allow_and_deny
  else fail line
    "unsupported policy effect; expected allow override, deny override, or allow-and-deny"

let contains_substring source target =
  let count = String.length target in
  let rec search index =
    index + count <= String.length source
    && (String.sub source index count = target || search (index + 1))
  in
  search 0

let activates_domain_matching matcher request_fields policy_fields =
  match request_fields, policy_fields with
  | _ :: request_domain :: _, _ :: policy_domain :: _ ->
      (* Upstream's registration checks this exact, comma-and-space substring
         after replacing assertion dots with underscores. Keep its whitespace
         sensitivity, including matches appearing inside literal text. *)
      List.exists (contains_substring matcher) [
        Printf.sprintf "keyMatch(r.%s, p.%s)" request_domain policy_domain;
        Printf.sprintf "keyMatch(r_%s, p_%s)" request_domain policy_domain;
      ]
  | _ -> false

let of_string text =
  try
    let section = ref None in
    let sections = Hashtbl.create 5 in
    let definitions = Hashtbl.create 5 in
    let pending = Buffer.create 128 in
    let pending_line = ref 1 in
    let awaiting_continuation = ref false in
    let expected_key = function
      | "request_definition" -> "r"
      | "policy_definition" -> "p"
      | "role_definition" -> "g"
      | "policy_effect" -> "e"
      | "matchers" -> "m"
      | name -> fail !pending_line (Printf.sprintf "unsupported section [%s]" name)
    in
    let flush () =
      if Buffer.length pending > 0 then begin
        let value = String.trim (Buffer.contents pending) in
        Buffer.clear pending;
        if value <> "" then begin
          let current = match !section with
            | Some current -> current
            | None -> fail !pending_line "definition appears before a section"
          in
          let separator = match String.index_opt value '=' with
            | Some index -> index
            | None -> fail !pending_line "expected definition of the form key = value"
          in
          let key = String.trim (String.sub value 0 separator) in
          let body = String.trim (String.sub value (separator + 1) (String.length value - separator - 1)) in
          let expected = expected_key current in
          if key <> expected then fail !pending_line
            (Printf.sprintf "unsupported definition %S in [%s]; expected %s" key current expected);
          if Hashtbl.mem definitions key then fail !pending_line (Printf.sprintf "duplicate definition %s" key);
          if body = "" then fail !pending_line (Printf.sprintf "empty definition %s" key);
          Hashtbl.add definitions key (body, !pending_line)
        end
      end
    in
    String.split_on_char '\n' text |> List.iteri (fun index physical ->
      let line = index + 1 in
      let value = String.trim physical in
      if value = "" || value.[0] = '#' || value.[0] = ';' then begin
        if !awaiting_continuation then fail line
          (Printf.sprintf "blank/comment line interrupts continuation from line %d" !pending_line);
        flush ()
      end
      else if value.[0] = '[' then begin
        if !awaiting_continuation then fail line
          (Printf.sprintf "section header interrupts continuation from line %d" !pending_line);
        flush ();
        pending_line := line;
        if value.[String.length value - 1] <> ']' then fail line "malformed section header";
        let name = String.sub value 1 (String.length value - 2) in
        ignore (expected_key name);
        if Hashtbl.mem sections name then fail line (Printf.sprintf "duplicate section [%s]" name);
        Hashtbl.add sections name ();
        section := Some name
      end else begin
        if Buffer.length pending = 0 then pending_line := line;
        let continuation = value.[String.length value - 1] = '\\' in
        awaiting_continuation := continuation;
        let content = if continuation then
            String.trim (String.sub value 0 (String.length value - 1)) ^ " "
          else value
        in
        Buffer.add_string pending (strip_comment content);
        if not continuation then flush ()
      end);
    if !awaiting_continuation then fail !pending_line "dangling continuation at end of model";
    flush ();
    let get key section_name =
      match Hashtbl.find_opt definitions key with
      | Some value -> value
      | None -> raise (Parse_error (Printf.sprintf "model: missing %s definition in [%s]" key section_name))
    in
    let request, request_line = get "r" "request_definition" in
    let policy, policy_line = get "p" "policy_definition" in
    let policy_effect, effect_line = get "e" "policy_effect" in
    let matcher, matcher_line = get "m" "matchers" in
    let request_fields = fields request_line request in
    let policy_fields = fields policy_line policy in
    let policy_effect = parse_effect effect_line policy_effect in
    let role_arity = match Hashtbl.find_opt definitions "g" with
      | None ->
          if Hashtbl.mem sections "role_definition" then
            raise (Parse_error "model: missing g definition in [role_definition]");
          0
      | Some (value, line) ->
          begin match List.map String.trim (String.split_on_char ',' value) with
          | ["_"; "_"] -> 2
          | ["_"; "_"; "_"] -> 3
          | _ -> fail line "unsupported role definition; expected g = _, _ or g = _, _, _"
          end
    in
    if role_arity = 3 && activates_domain_matching matcher request_fields policy_fields then
      fail matcher_line "automatic domain keyMatch registration is unsupported; domains must match exactly";
    let roles_enabled = role_arity <> 0 in
    Ok { request_fields; policy_fields; policy_effect; matcher; roles_enabled; role_arity }
  with Parse_error message -> Error message

let of_file path =
  try
    let channel = open_in_bin path in
    let contents = Fun.protect ~finally:(fun () -> close_in_noerr channel)
      (fun () -> really_input_string channel (in_channel_length channel)) in
    of_string contents
  with Sys_error message -> Error (Printf.sprintf "model file %S: %s" path message)
     | End_of_file -> Error (Printf.sprintf "model file %S: file changed while reading" path)
