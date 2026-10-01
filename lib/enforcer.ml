type matcher = Plain of Expr.t | Typed of Abac_expr.t * (string * Value.schema) list

type t = {
  model : Model.t;
  policy : Policy.t;
  matcher : matcher;
  roles : Role_manager.t;
  domain_roles : Role_manager.domains;
}

let ( let* ) = Result.bind

let normalize_schema model schema =
  let names = List.map fst schema in
  if List.length names <> List.length model.Model.request_fields
     || List.sort String.compare names <> List.sort String.compare model.Model.request_fields then
    Error "request schema must name every declared request field exactly once"
  else Ok (List.map (fun field -> field, List.assoc field schema) model.Model.request_fields)

let prepare ?request_schema model policy =
  let* matcher = match request_schema with
    | None ->
        let* expression = Expr.compile ~request_fields:model.Model.request_fields
            ~policy_fields:model.Model.policy_fields ~roles_enabled:model.Model.roles_enabled
            ~role_arity:model.Model.role_arity model.Model.matcher in
        Ok (Plain expression)
    | Some schema ->
        let* schema = normalize_schema model schema in
        let* expression = Abac_expr.compile ~request_schema:schema
            ~policy_fields:model.Model.policy_fields ~role_arity:model.Model.role_arity model.Model.matcher in
        Ok (Typed (expression, schema))
  in
  let* roles = Role_manager.of_links policy.Policy.roles in
  let* domain_roles = Role_manager.of_domain_links policy.Policy.domain_roles in
  Ok { model; policy; matcher; roles; domain_roles }

let of_strings ~model ~policy =
  let* model = Model.of_string model in
  let* policy = Policy.of_string ~model policy in
  prepare model policy

let of_files ~model ~policy =
  let* model = Model.of_file model in
  let* policy = Policy.of_file ~model policy in
  prepare model policy

let of_strings_abac ~request_schema ~model ~policy =
  let* model = Model.of_string model in
  let* policy = Policy.of_string ~model policy in
  prepare ~request_schema model policy

let of_files_abac ~request_schema ~model ~policy =
  let* model = Model.of_file model in
  let* policy = Policy.of_file ~model policy in
  prepare ~request_schema model policy

let validate_request matcher values =
  match matcher with
  | Plain _ ->
      if List.for_all (function Value.String _ -> true | _ -> false) values then Ok ()
      else Error "typed request values require an ABAC snapshot"
  | Typed (_, schema) ->
      let rec validate = function
        | [] -> Ok ()
        | ((field, schema), value) :: rest ->
            match Value.validate ~schema value with
            | Error message -> Error (Printf.sprintf "request field %s: %s" field message)
            | Ok () -> validate rest
      in
      validate (List.combine schema values)

let uses_policy = function
  | Plain expression -> Expr.uses_policy expression
  | Typed (expression, _) -> Abac_expr.uses_policy expression

let upstream_uses_policy t =
  (* Go selects real rows using a textual p_ search after preprocessing. This
     includes literals and request property names, alongside actual p fields. *)
  let source = t.model.Model.matcher in
  let rec contains index =
    index + 1 < String.length source
    && ((source.[index] = 'p' && source.[index + 1] = '_') || contains (index + 1))
  in
  uses_policy t.matcher || contains 0

let enforce_values t request =
  let fields = t.model.Model.request_fields in
  if List.length request <> List.length fields then
    Error (Printf.sprintf "invalid request size: expected %d, got %d"
             (List.length fields) (List.length request))
  else
    let* () = validate_request t.matcher request in
    let rbindings = List.map2 (fun field value -> ("r." ^ field, value)) fields request in
    let evaluate rule =
      let pbindings = List.map2 (fun field value -> ("p." ^ field, Value.String value))
          t.model.Model.policy_fields rule in
      let bindings = rbindings @ pbindings in
      let resolve name = match List.assoc_opt name bindings with
        | Some value -> Ok value
        | None -> Error ("unknown matcher field: " ^ name)
      in
      let has_role = Role_manager.has_link t.roles in
      let has_role_in_domain = Role_manager.has_domain_link t.domain_roles in
      match t.matcher with
      | Plain expression ->
          let resolve name =
            let* value = resolve name in
            match value with Value.String value -> Ok value | _ -> Error "string matcher resolved a typed value"
          in
          Expr.eval ~resolve ~has_role ~has_role_in_domain expression
      | Typed (expression, _) -> Abac_expr.eval ~resolve ~has_role ~has_role_in_domain expression
    in
    let decide rows = Ok (Effector.decide t.model.Model.policy_effect rows) in
    (* The same synthetic row and policy-effect path applies to typed matchers. *)
    if t.policy.Policy.rules = [] || not (upstream_uses_policy t) then
      let* matched = evaluate (List.map (fun _ -> "") t.model.Model.policy_fields) in
      decide [matched, Effector.Allow]
    else
      let row_effect rule =
        let bindings = List.combine t.model.Model.policy_fields rule in
        Effector.row_effect (List.assoc_opt "eft" bindings)
      in
      let rec collect acc = function
        | [] -> decide (List.rev acc)
        | rule :: rest ->
            let* matched = evaluate rule in
            let row = row_effect rule in
            match t.model.Model.policy_effect, matched, row with
            | Effector.Allow_override, true, Effector.Allow -> Ok true
            | (Effector.Deny_override | Effector.Allow_and_deny), true, Effector.Deny -> Ok false
            | Effector.Priority_override, true, Effector.Allow -> Ok true
            | Effector.Priority_override, true, Effector.Deny -> Ok false
            | _ -> collect ((matched, row) :: acc) rest
      in
      collect [] t.policy.Policy.rules

let enforce t request = enforce_values t (List.map (fun value -> Value.String value) request)

(* Management preserves Casbin's comma-joined identities, including collisions
   across different field tuples. Snapshot records and their lists are immutable. *)
let policy_key = String.concat ","

let grouping_key (subject, role) = policy_key [subject; role]
let domain_grouping_key (subject, role, domain) = policy_key [subject; role; domain]

let validate_policy_rule t rule =
  let expected = List.length t.model.Model.policy_fields in
  let actual = List.length rule in
  if actual = expected then Ok ()
  else Error (Printf.sprintf "invalid policy size: expected %d, got %d" expected actual)

let require_grouping t =
  if t.model.Model.roles_enabled then Ok ()
  else Error "grouping operations require a role definition"

let require_role_arity t arity =
  let* () = require_grouping t in
  if t.model.Model.role_arity = arity then Ok ()
  else Error (Printf.sprintf "grouping operation requires a %d-field role definition" arity)

let get_policy t = t.policy.Policy.rules

let has_policy t rule =
  let* () = validate_policy_rule t rule in
  let key = policy_key rule in
  Ok (List.exists (fun existing -> policy_key existing = key) t.policy.Policy.rules)

let add_policy t rule =
  let* present = has_policy t rule in
  if present then Ok (t, false)
  else
    let* rules = Priority.insert ~policy_fields:t.model.Model.policy_fields
        ~rule t.policy.Policy.rules in
    let policy = { t.policy with Policy.rules = rules } in
    Ok ({ t with policy }, true)

let remove_policy t rule =
  let* present = has_policy t rule in
  if not present then Ok (t, false)
  else
    let key = policy_key rule in
    let rules = List.filter (fun existing -> policy_key existing <> key) t.policy.Policy.rules in
    let policy = { t.policy with Policy.rules = rules } in
    Ok ({ t with policy }, true)

let get_grouping_policy t =
  let* () = require_grouping t in
  if t.model.Model.role_arity = 3 then
    Ok (List.map (fun (subject, role, domain) -> [subject; role; domain]) t.policy.Policy.domain_roles)
  else Ok (List.map (fun (subject, role) -> [subject; role]) t.policy.Policy.roles)

let has_grouping_policy t pair =
  let* () = require_role_arity t 2 in
  let key = grouping_key pair in
  Ok (List.exists (fun existing -> grouping_key existing = key) t.policy.Policy.roles)

let with_grouping t links =
  let* roles = Role_manager.of_links links in
  let policy = { t.policy with Policy.roles = links } in
  Ok ({ t with policy; roles }, true)

let add_grouping_policy t pair =
  let* present = has_grouping_policy t pair in
  if present then Ok (t, false)
  else with_grouping t (t.policy.Policy.roles @ [pair])

let remove_grouping_policy t pair =
  let* present = has_grouping_policy t pair in
  if not present then Ok (t, false)
  else
    let key = grouping_key pair in
    let links = List.filter (fun existing -> grouping_key existing <> key) t.policy.Policy.roles in
    with_grouping t links

let has_grouping_policy_in_domain t triple =
  let* () = require_role_arity t 3 in
  let key = domain_grouping_key triple in
  Ok (List.exists (fun existing -> domain_grouping_key existing = key) t.policy.Policy.domain_roles)

let with_domain_grouping t links =
  let* domain_roles = Role_manager.of_domain_links links in
  let policy = { t.policy with Policy.domain_roles = links } in
  Ok ({ t with policy; domain_roles }, true)

let add_grouping_policy_in_domain t triple =
  let* present = has_grouping_policy_in_domain t triple in
  if present then Ok (t, false)
  else with_domain_grouping t (t.policy.Policy.domain_roles @ [triple])

let remove_grouping_policy_in_domain t triple =
  let* present = has_grouping_policy_in_domain t triple in
  if not present then Ok (t, false)
  else
    let key = domain_grouping_key triple in
    let links = List.filter (fun existing -> domain_grouping_key existing <> key)
        t.policy.Policy.domain_roles in
    with_domain_grouping t links

let direct_roles t domain subject =
  t.policy.Policy.domain_roles
  |> List.filter_map (fun (user, role, stored_domain) ->
      if user = subject && stored_domain = domain then Some role else None)
  |> List.sort_uniq String.compare

let direct_users t domain role =
  t.policy.Policy.domain_roles
  |> List.filter_map (fun (user, parent, stored_domain) ->
      if parent = role && stored_domain = domain then Some user else None)
  |> List.sort_uniq String.compare

let get_roles_for_user_in_domain t ~domain subject =
  let* () = require_role_arity t 3 in
  Ok (direct_roles t domain subject)

let get_users_for_role_in_domain t ~domain role =
  let* () = require_role_arity t 3 in
  Ok (direct_users t domain role)

let get_roles_for_user t subject =
  let* () = require_grouping t in
  if t.model.Model.role_arity = 3 then Ok (direct_roles t "" subject)
  else Ok (t.policy.Policy.roles
      |> List.filter_map (fun (user, role) -> if user = subject then Some role else None)
      |> List.sort_uniq String.compare)

let get_users_for_role t role =
  let* () = require_grouping t in
  if t.model.Model.role_arity = 3 then Ok (direct_users t "" role)
  else Ok (t.policy.Policy.roles
      |> List.filter_map (fun (user, parent) -> if parent = role then Some user else None)
      |> List.sort_uniq String.compare)
