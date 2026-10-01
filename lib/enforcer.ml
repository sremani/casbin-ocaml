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
    (* Go Casbin evaluates one empty policy row if none exist, or when the
       matcher is independent of policy fields. This can intentionally allow. *)
    if t.policy.Policy.rules = [] || not (Expr.uses_policy t.matcher) then
      evaluate (List.map (fun _ -> "") t.model.Model.policy_fields)
    else
      let rec any = function
        | [] -> Ok false
        | rule :: rest ->
            let* matched = evaluate rule in
            if matched then Ok true else any rest
      in
      any t.policy.Policy.rules
