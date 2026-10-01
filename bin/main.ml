let fail message =
  prerr_endline ("casbin-ocaml: " ^ message);
  exit 2

let () =
  match Array.to_list Sys.argv with
  | _ :: model :: policy :: request ->
      (match Casbin.Enforcer.of_files ~model ~policy with
       | Error message -> fail message
       | Ok enforcer ->
           match Casbin.Enforcer.enforce enforcer request with
           | Error message -> fail message
           | Ok decision -> print_endline (string_of_bool decision))
  | _ -> fail "usage: casbin-ocaml MODEL.conf POLICY.csv REQUEST_FIELD..."
