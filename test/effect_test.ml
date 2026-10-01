open Casbin.Effector

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label

let policies = [Allow_override; Deny_override; Allow_and_deny]
let rows = [false, Allow; false, Deny; false, Indeterminate;
            true, Allow; true, Deny; true, Indeterminate]

(* Classify the evidence into four rows of the aggregation truth table.
   This oracle states the externally observable policy semantics, independent
   of the implementation's individual aggregation branches. *)
let expected policy input =
  let evidence = List.fold_left (fun mask -> function
    | true, Allow -> mask lor 1
    | true, Deny -> mask lor 2
    | _ -> mask) 0 input in
  let allow, deny, combined = match evidence with
    | 0 -> false, true, false
    | 1 -> true, true, true
    | 2 -> false, false, false
    | 3 -> true, false, false
    | _ -> assert false
  in
  match policy with
  | Allow_override -> allow
  | Deny_override -> deny
  | Allow_and_deny -> combined

let rec sequences length =
  if length = 0 then [[]]
  else List.concat_map (fun rest -> List.map (fun row -> row :: rest) rows)
      (sequences (length - 1))

let rec insert item = function
  | [] -> [[item]]
  | first :: rest as items ->
      (item :: items) :: List.map (fun tail -> first :: tail) (insert item rest)

let rec permutations = function
  | [] -> [[]]
  | first :: rest -> List.concat_map (insert first) (permutations rest)

let () =
  List.iter (fun (input, expected_row) ->
    check "row-effect classification" expected_row (row_effect input))
    [None, Allow; Some "allow", Allow; Some "deny", Deny;
     Some "", Indeterminate; Some "Allow", Indeterminate;
     Some "DENY", Indeterminate; Some " allow", Indeterminate;
     Some "allow ", Indeterminate; Some "deny\n", Indeterminate;
     Some "unknown", Indeterminate; Some "允许", Indeterminate;
     Some "allow\000", Indeterminate];
  check "allow override empty defaults to deny" false (decide Allow_override []);
  check "deny override empty defaults to allow" true (decide Deny_override []);
  check "combined empty defaults to deny" false (decide Allow_and_deny []);
  let cases = ref 0 in
  for length = 0 to 4 do
    List.iter (fun input ->
      incr cases;
      List.iter (fun policy ->
        let verdict = expected policy input in
        check "exhaustive aggregation truth table" verdict (decide policy input);
        (* All permutations exercise early, late, and duplicated witnesses.
           Unmatched and indeterminate rows must remain irrelevant. *)
        List.iter (fun reordered ->
          check "aggregation is independent of row order" verdict (decide policy reordered))
          (permutations input);
        check "unmatched rows do not change a decision" verdict
          (decide policy ((false, Allow) :: (false, Deny) :: input));
        check "matched indeterminate rows do not change a decision" verdict
          (decide policy ((true, Indeterminate) :: input))) policies)
      (sequences length)
  done;
  Printf.printf "effector: %d exhaustive row lists, %d checks passed\n" !cases !checks
