type t = {
  model : Model.t;
  policy : Policy.t;
  matcher : Expr.t;
  roles : Role_manager.t;
}

let ( let* ) = Result.bind

let prepare model policy =
  let* matcher = Expr.compile
      ~request_fields:model.Model.request_fields
      ~policy_fields:model.Model.policy_fields
      ~roles_enabled:model.Model.roles_enabled model.Model.matcher in
  let* roles = Role_manager.of_links policy.Policy.roles in
  Ok { model; policy; matcher; roles }

let of_strings ~model ~policy =
  let* model = Model.of_string model in
  let* policy = Policy.of_string ~model policy in
  prepare model policy

let of_files ~model ~policy =
  let* model = Model.of_file model in
  let* policy = Policy.of_file ~model policy in
  prepare model policy

let enforce t request =
  let fields = t.model.Model.request_fields in
  if List.length request <> List.length fields then
    Error (Printf.sprintf "invalid request size: expected %d, got %d"
             (List.length fields) (List.length request))
  else
    let rbindings = List.map2 (fun field value -> ("r." ^ field, value)) fields request in
    let evaluate rule =
      let pbindings = List.map2 (fun field value -> ("p." ^ field, value))
          t.model.Model.policy_fields rule in
      let bindings = rbindings @ pbindings in
      let resolve name = match List.assoc_opt name bindings with
        | Some value -> Ok value
        | None -> Error ("unknown matcher field: " ^ name)
      in
      Expr.eval ~resolve ~has_role:(Role_manager.has_link t.roles) t.matcher
    in
    let decide rows = Ok (Effector.decide t.model.Model.policy_effect rows) in
    (* Go Casbin evaluates one empty policy row if none exist, or when the
       matcher is independent of policy fields. This can intentionally allow. *)
    if t.policy.Policy.rules = [] || not (Expr.uses_policy t.matcher) then
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
            | _ -> collect ((matched, row) :: acc) rest
      in
      collect [] t.policy.Policy.rules

(* Management preserves Casbin's comma-joined identities, including collisions
   across different field tuples. Snapshot records and their lists are immutable. *)
let policy_key = String.concat ","

let grouping_key (subject, role) = policy_key [subject; role]

let validate_policy_rule t rule =
  let expected = List.length t.model.Model.policy_fields in
  let actual = List.length rule in
  if actual = expected then Ok ()
  else Error (Printf.sprintf "invalid policy size: expected %d, got %d" expected actual)

let require_grouping t =
  if t.model.Model.roles_enabled then Ok ()
  else Error "grouping operations require a role definition"

let get_policy t = t.policy.Policy.rules

let has_policy t rule =
  let* () = validate_policy_rule t rule in
  let key = policy_key rule in
  Ok (List.exists (fun existing -> policy_key existing = key) t.policy.Policy.rules)

let add_policy t rule =
  let* present = has_policy t rule in
  if present then Ok (t, false)
  else
    let policy = { t.policy with Policy.rules = t.policy.Policy.rules @ [rule] } in
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
  Ok (List.map (fun (subject, role) -> [subject; role]) t.policy.Policy.roles)

let has_grouping_policy t pair =
  let* () = require_grouping t in
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

let get_roles_for_user t subject =
  let* () = require_grouping t in
  Ok (t.policy.Policy.roles
      |> List.filter_map (fun (user, role) -> if user = subject then Some role else None)
      |> List.sort_uniq String.compare)

let get_users_for_role t role =
  let* () = require_grouping t in
  Ok (t.policy.Policy.roles
      |> List.filter_map (fun (user, parent) -> if parent = role then Some user else None)
      |> List.sort_uniq String.compare)
