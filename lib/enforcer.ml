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
