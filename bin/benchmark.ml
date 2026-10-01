module E = Casbin.Enforcer
module V = Casbin.Value
external monotonic_seconds : unit -> float = "casbin_benchmark_monotonic"
let result = function Ok value -> value | Error error -> failwith error
let integer_bool value = if value then 1 else 0
let runtime_info () =
  let config = Gc.get () in
  Printf.printf "{\"minor_heap_words\":%d,\"space_overhead\":%d,\"stack_limit_words\":%d,\"verbose\":%d}\n"
    config.minor_heap_size config.space_overhead config.stack_limit config.verbose
let () =
  try
    if Array.length Sys.argv = 2 && Sys.argv.(1) = "--runtime-info" then begin
      runtime_info (); exit 0
    end;
    if Array.length Sys.argv <> 5 && Array.length Sys.argv <> 6 then
      failwith "usage: benchmark SCENARIO MODEL POLICY ITERATIONS [ROWS]";
    let scenario, model, policy = Sys.argv.(1), Sys.argv.(2), Sys.argv.(3) in
    let iterations = int_of_string Sys.argv.(4) in
    if iterations <= 0 then failwith "iterations must be positive";
    let rows = if Array.length Sys.argv = 6 then int_of_string Sys.argv.(5) else 100 in
    if rows <= 0 then failwith "rows must be positive";
    if scenario = "rbac-cold" && iterations > rows then
      failwith "cold role requests require iterations <= rows";
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
      | "rbac-cold" ->
          let index = ref 0 in
          (fun () ->
            let request = ["u" ^ string_of_int !index; "data"; "read"] in
            incr index;
            integer_bool (result (E.enforce enforcer request)))
      | _ ->
          let request = match scenario with
            | "acl-first" -> ["u0"; "data"; "read"]
            | "acl-last" | "priority" -> ["u" ^ string_of_int (rows - 1); "data"; "read"]
            | "acl-miss" -> ["absent"; "data"; "read"]
            | "rbac" -> ["u0"; "data"; "read"]
            | "domain" -> ["u0"; "tenant"; "data"; "read"]
            | "keymatch" -> ["u" ^ string_of_int (rows - 1); "/segment" ^ string_of_int (rows - 1) ^ "/item"; "read"]
            | "deny-override" | "allow-and-deny" | "priority-first" -> ["alice"; "data"; "read"]
            | _ -> failwith "unknown benchmark scenario"
          in (fun () -> integer_bool (result (E.enforce enforcer request)))
    in
    (* Compile Go's lazy expression using a tuple distinct from every measured
       request; all measured role tuples remain unseen. *)
    if scenario = "rbac-cold" then
      ignore (result (E.enforce enforcer ["warmup-unlinked"; "data"; "read"]));
    let warmup = if scenario = "rbac-cold" then 0 else min 100 (max 1 (500000 / rows)) in
    for _ = 1 to warmup do ignore (step ()) done;
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
