module E = Casbin.Enforcer
module V = Casbin.Value
external monotonic_seconds : unit -> float = "casbin_benchmark_monotonic"
let result = function Ok value -> value | Error error -> failwith error
let integer_bool value = if value then 1 else 0
let () =
  try
    if Array.length Sys.argv <> 5 then failwith "usage: benchmark SCENARIO MODEL POLICY ITERATIONS";
    let scenario, model, policy = Sys.argv.(1), Sys.argv.(2), Sys.argv.(3) in
    let iterations = int_of_string Sys.argv.(4) in
    if iterations <= 0 then failwith "iterations must be positive";
    let enforcer =
      if scenario = "abac" then result (E.of_files_abac ~model ~policy
        ~request_schema:["sub", V.TString; "obj", V.TObject ["Owner", V.TString; "Age", V.TNumber]; "act", V.TString])
      else result (E.of_files ~model ~policy)
    in
    let final_snapshot = ref enforcer in
    let step = match scenario with
      | "load" -> (fun () -> List.length (E.get_policy (result (E.of_files ~model ~policy))))
      | "management" -> (fun () ->
          let added, yes = result (E.add_policy enforcer ["temporary"; "data"; "read"]) in
          let removed, gone = result (E.remove_policy added ["temporary"; "data"; "read"]) in
          final_snapshot := removed;
          integer_bool yes + integer_bool gone)
      | "abac" ->
          let request = [V.String "alice"; V.Object ["Owner", V.String "alice"; "Age", V.Number 42.]; V.String "read"] in
          (fun () -> integer_bool (result (E.enforce_values enforcer request)))
      | _ ->
          let request = match scenario with
            | "acl-first" -> ["u0"; "data"; "read"]
            | "acl-last" | "priority" -> ["u99"; "data"; "read"]
            | "acl-miss" -> ["absent"; "data"; "read"]
            | "rbac" -> ["u0"; "data"; "read"]
            | "domain" -> ["u0"; "tenant"; "data"; "read"]
            | _ -> failwith "unknown benchmark scenario"
          in (fun () -> integer_bool (result (E.enforce enforcer request)))
    in
    for _ = 1 to 100 do ignore (step ()) done;
    Gc.full_major ();
    let allocated_before = Gc.allocated_bytes () in
    let started = monotonic_seconds () in
    let checksum = ref 0 in
    for _ = 1 to iterations do checksum := !checksum + step () done;
    let elapsed = monotonic_seconds () -. started in
    let allocated_bytes = Gc.allocated_bytes () -. allocated_before in
    if scenario = "management" && E.get_policy !final_snapshot <> E.get_policy enforcer then failwith "management state drift";
    Printf.printf "%s\t%d\t%.9f\t%d\t%.0f\n" scenario iterations elapsed !checksum allocated_bytes
  with Failure error | Invalid_argument error -> prerr_endline error; exit 2
