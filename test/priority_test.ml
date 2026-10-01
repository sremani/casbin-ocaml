open Casbin

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let rejects label result =
  incr checks;
  match result with Error message when message <> "" -> () | _ -> failwith label
let changed label result =
  let snapshot, flag = ok result in check label true flag; snapshot
let unchanged label snapshot result =
  let next, flag = ok result in
  check (label ^ " flag") false flag;
  check (label ^ " identity") true (next == snapshot)

let priority_effect = "priority(p.eft) || deny"
let model ?(request = "sub") ?(fields = "sub, eft")
    ?(policy_effect = priority_effect) ?roles matcher =
  "[request_definition]\nr = " ^ request
  ^ "\n[policy_definition]\np = " ^ fields
  ^ (match roles with None -> "" | Some definition -> "\n[role_definition]\ng = " ^ definition)
  ^ "\n[policy_effect]\ne = " ^ policy_effect ^ "\n[matchers]\nm = " ^ matcher ^ "\n"
let enforcer ?request ?fields ?policy_effect ?roles matcher policy =
  ok (Enforcer.of_strings ~model:(model ?request ?fields ?policy_effect ?roles matcher) ~policy)
let decide snapshot = ok (Enforcer.enforce snapshot ["alice"])
let csv rows = String.concat "" (List.map (fun row -> "p, " ^ String.concat ", " row ^ "\n") rows)

let numeric_grammar () =
  List.iter (fun (text, number) -> check ("signed64 " ^ text) (Ok number) (Priority.parse text))
    ["0", 0L; "+0", 0L; "-0", 0L; "0000", 0L; "+0001", 1L; "-0001", -1L;
     "9223372036854775807", Int64.max_int; "-9223372036854775808", Int64.min_int;
     "+9223372036854775807", Int64.max_int;
     "0009223372036854775807", Int64.max_int;
     "-0009223372036854775808", Int64.min_int;
     "4611686018427387904", 4611686018427387904L;
     "-4611686018427387905", -4611686018427387905L];
  List.iter (fun text -> rejects ("invalid priority " ^ String.escaped text) (Priority.parse text))
    [""; "+"; "-"; " 1"; "1 "; "\t1"; "1\n"; "1.0"; "1e2"; "0x10";
     "1_000"; "--1"; "+-1"; "++1"; "١"; "1\000";
     "9223372036854775808"; "+9223372036854775808"; "-9223372036854775809";
     "18446744073709551615"; String.make 100 '9'];
  check "many leading zeroes do not overflow" (Ok 1L)
    (Priority.parse (String.make 100 '0' ^ "1"));
  check "many negative zeroes accepted" (Ok 0L) (Priority.parse ("-" ^ String.make 100 '0'));
  let rows = [["two"; "2"]; ["one-a"; "+1"]; ["one-b"; "01"]; ["negative"; "-1"]; ["one-c"; "1"]] in
  let sorted = [["negative"; "-1"]; ["one-a"; "+1"]; ["one-b"; "01"]; ["one-c"; "1"]; ["two"; "2"]] in
  check "stable numeric order keeps raw equal strings" (Ok sorted)
    (Priority.order ~policy_fields:["sub"; "priority"] rows);
  check "insert after all numeric ties" (Ok (List.filter (fun row -> row <> ["two"; "2"]) sorted
      @ [["one-d"; "0001"]; ["two"; "2"]]))
    (Priority.insert ~policy_fields:["sub"; "priority"] ~rule:["one-d"; "0001"] sorted);
  check "without field order is unchanged" (Ok rows) (Priority.order ~policy_fields:["sub"; "rank"] rows);
  check "without field new row appends" (Ok (rows @ [["new"; "bogus"]]))
    (Priority.insert ~policy_fields:["sub"; "rank"] ~rule:["new"; "bogus"] rows);
  rejects "missing retained priority cell" (Priority.order ~policy_fields:["sub"; "priority"] [["alice"]]);
  rejects "missing inserted priority cell"
    (Priority.insert ~policy_fields:["sub"; "priority"] ~rule:["alice"] []);
  rejects "missing existing cell on insertion"
    (Priority.insert ~policy_fields:["sub"; "priority"] ~rule:["alice"; "1"] [["bad"]])

let ordered_effects () =
  let open Effector in
  let options = [false, Allow; false, Deny; false, Indeterminate;
                 true, Allow; true, Deny; true, Indeterminate] in
  let rec sequences size = if size = 0 then [[]]
    else List.concat_map (fun tail -> List.map (fun row -> row :: tail) options) (sequences (size - 1)) in
  (* The index of the earliest relevant row, rather than an unordered evidence
     mask, defines the independently stated expected decision. *)
  let expected input =
    let indexed = List.mapi (fun index row -> index, row) input in
    let relevant = List.filter (function _, (true, (Allow | Deny)) -> true | _ -> false) indexed in
    match relevant with (_, (_, Allow)) :: _ -> true | _ -> false in
  for size = 0 to 4 do
    List.iter (fun input -> check "first matched determinate effect" (expected input)
        (decide Priority_override input)) (sequences size)
  done;
  check "allow then deny" true (decide Priority_override [true, Allow; true, Deny]);
  check "deny then allow" false (decide Priority_override [true, Deny; true, Allow]);
  let rec unneeded = (true, Indeterminate) :: unneeded in
  check "allow terminates before unreachable rows" true (decide Priority_override ((true, Allow) :: unneeded));
  check "deny terminates before unreachable rows" false (decide Priority_override ((true, Deny) :: unneeded))

let load_and_order () =
  let effects = ["some(where (p.eft == allow))"; "!some(where (p.eft == deny))";
    "some(where (p.eft == allow)) && !some(where (p.eft == deny))"; priority_effect] in
  List.iter (fun policy_effect ->
    List.iter (fun (fields, rows, sorted) ->
      let snapshot = enforcer ~fields ~policy_effect "r.sub == p.sub" (csv rows) in
      check "priority sorting at any field position and under every effect" sorted (Enforcer.get_policy snapshot))
      ["priority, sub, eft", [["2"; "alice"; "deny"]; ["-1"; "alice"; "allow"]],
         [["-1"; "alice"; "allow"]; ["2"; "alice"; "deny"]];
       "sub, priority, eft", [["alice"; "2"; "deny"]; ["alice"; "-1"; "allow"]],
         [["alice"; "-1"; "allow"]; ["alice"; "2"; "deny"]];
       "sub, eft, priority", [["alice"; "deny"; "2"]; ["alice"; "allow"; "-1"]],
         [["alice"; "allow"; "-1"]; ["alice"; "deny"; "2"]]]) effects;
  let fields = "priority, sub, eft" in
  let rows = [["1"; "alice"; "deny"]; ["+1"; "alice"; "allow"]; ["01"; "alice"; "UNKNOWN"]] in
  let tied = enforcer ~fields "r.sub == p.sub" (csv (rows @ [List.hd rows])) in
  check "raw duplicate dedup leaves numeric-equal spellings" rows (Enforcer.get_policy tied);
  check "first loaded numeric tie wins" false (decide tied);
  let added = changed "equal insertion" (Enforcer.add_policy tied ["0001"; "alice"; "allow"]) in
  check "inserted equal priority is last tie" (rows @ [["0001"; "alice"; "allow"]]) (Enforcer.get_policy added);
  check "equal insertion preserves first decision" false (decide added);
  let removed = changed "first tie removed" (Enforcer.remove_policy added (List.hd rows)) in
  check "remaining tie order preserved" (List.tl rows @ [["0001"; "alice"; "allow"]]) (Enforcer.get_policy removed);
  check "next equal allow now decides" true (decide removed);
  check "old tie snapshot unchanged" false (decide tied);
  let earlier = changed "earlier insertion" (Enforcer.add_policy tied ["-2"; "alice"; "allow"]) in
  check "smaller priority immediately wins" true (decide earlier);
  let absent = enforcer "r.sub == p.sub" "p, alice, deny\np, alice, allow\n" in
  check "no priority field preserves file order" [["alice"; "deny"]; ["alice"; "allow"]] (Enforcer.get_policy absent);
  check "file-order deny wins" false (decide absent);
  let appended = changed "no priority appends" (Enforcer.add_policy absent ["bob"; "allow"]) in
  check "no priority insertion append order" [["alice"; "deny"]; ["alice"; "allow"]; ["bob"; "allow"]] (Enforcer.get_policy appended);
  let remaining = changed "no priority removal" (Enforcer.remove_policy appended ["alice"; "deny"]) in
  check "no priority removal preserves order" [["alice"; "allow"]; ["bob"; "allow"]] (Enforcer.get_policy remaining);
  check "no priority next matching allow wins" true (decide remaining);
  check "old no-priority snapshot unchanged" false (decide absent);
  let wide = enforcer ~fields "r.sub == p.sub"
      "p, 9223372036854775807, alice, deny\np, -9223372036854775808, alice, allow\n" in
  check "signed64 extrema order numerically" true (decide wide)

let numeric_atomicity_and_raw_keys () =
  let fields = "sub, priority, eft" in
  let source = model ~fields "r.sub == p.sub" in
  List.iter (fun priority -> rejects "invalid retained load priority"
      (Enforcer.of_strings ~model:source ~policy:(csv [["alice"; priority; "allow"]])))
    ["bad"; ""; "1 "; "9223372036854775808"; "-9223372036854775809"];
  let snapshot = enforcer ~fields "r.sub == p.sub" "p, alice, 1, allow\n" in
  List.iter (fun priority ->
    rejects "invalid newly stored priority" (Enforcer.add_policy snapshot ["bob"; priority; "deny"]);
    check "failed addition leaves policy" [["alice"; "1"; "allow"]] (Enforcer.get_policy snapshot);
    check "failed addition leaves verdict" true (decide snapshot)) ["bad"; ""; "1 "; "9223372036854775808"];
  rejects "wrong arity insertion" (Enforcer.add_policy snapshot ["alice"; "bad"]);
  let colliding = enforcer ~fields "r.sub == p.sub" "p, \"a,b\", 1, allow\np, a, \"b,1\", allow\n" in
  check "load validates retained rows after raw-key dedup" [["a,b"; "1"; "allow"]] (Enforcer.get_policy colliding);
  let invalid = ["a"; "b,1"; "allow"] in
  check "has uses colliding raw key before numeric validation" (Ok true) (Enforcer.has_policy colliding invalid);
  unchanged "invalid raw collision addition is noop" colliding (Enforcer.add_policy colliding invalid);
  let removed = changed "invalid raw collision removal" (Enforcer.remove_policy colliding invalid) in
  check "collision removal uses raw key" [] (Enforcer.get_policy removed);
  check "old collision snapshot intact" [["a,b"; "1"; "allow"]] (Enforcer.get_policy colliding);
  check "has nonexistent invalid numeric row" (Ok false) (Enforcer.has_policy snapshot ["bob"; "bad"; "allow"]);
  unchanged "remove nonexistent invalid numeric row" snapshot (Enforcer.remove_policy snapshot ["bob"; "bad"; "allow"]);
  rejects "first retained colliding invalid row rejected"
    (Enforcer.of_strings ~model:source ~policy:"p, a, \"b,1\", allow\np, \"a,b\", 1, allow\n")

let effect_and_synthetic () =
  let fields = "priority, sub, eft" in
  let snapshot = enforcer ~fields "r.sub == p.sub"
      "p, -2, bob, deny\np, -1, alice, UNKNOWN\np, 0, alice, \np, 1, alice, allow\np, 2, alice, deny\n" in
  check "unmatched and indeterminate effects skipped" true (decide snapshot);
  let unknown = enforcer "r.sub == p.sub" "p, alice, unknown\np, alice, \n" in
  check "no determinate match denies" false (decide unknown);
  check "no matched rows denies" false (ok (Enforcer.enforce snapshot ["nobody"]));
  let implicit = enforcer ~fields:"priority, sub" "r.sub == p.sub" "p, 1, alice\n" in
  check "missing eft is implicit allow" true (decide implicit);
  let empty = enforcer ~fields "r.sub == r.sub" "" in
  check "empty policy synthetic row implicit allow" true (decide empty);
  let empty_false = enforcer ~fields "false && r.sub == p.sub" "" in
  check "nonmatching empty synthetic row denies" false (decide empty_false);
  let request_only = enforcer ~fields "r.sub == 'alice'" "p, 0, alice, deny\n" in
  check "request-only matcher selects synthetic allow" true (decide request_only);
  let textual = enforcer ~fields "r.sub == 'p_sub'" "p, 0, any, deny\np, 1, any, allow\n" in
  check "textual p_ chooses priority real rows" (Ok false) (Enforcer.enforce textual ["p_sub"])

let typed_domain_management () =
  let open Value in
  let request_schema = ["sub", TObject ["Name", TString; "Tenant", TString; "Score", TNumber]; "obj", TString] in
  let source = model ~request:"sub, obj" ~fields:"priority, sub, dom, obj, eft" ~roles:"_, _, _"
      "g(r.sub.Name, p.sub, r.sub.Tenant) && r.sub.Tenant == p.dom && keyMatch(r.obj, p.obj) && r.sub.Score >= 1" in
  let original = ok (Enforcer.of_strings_abac ~request_schema ~model:source
      ~policy:"p, -1, admin, other, /data/*, deny\np, 1, admin, one, /data/*, allow\np, 2, admin, one, /data/*, deny\ng, alice, admin, one\ng, alice, admin, other\n") in
  let values ?(name = "alice") ?(tenant = "one") ?(score = 1.5) () =
    [Object ["Name", String name; "Tenant", String tenant; "Score", Number score]; String "/data/item"] in
  let run snapshot values = ok (Enforcer.enforce_values snapshot values) in
  check "typed domain/keyMatch priority composition" true (run original (values ()));
  check "separate domain selects earlier deny" false (run original (values ~tenant:"other" ()));
  check "typed predicate filters every row" false (run original (values ~score:0.5 ()));
  let earlier = changed "typed earlier priority insertion"
      (Enforcer.add_policy original ["0"; "admin"; "one"; "/data/*"; "deny"]) in
  check "typed newly earlier deny wins" false (run earlier (values ()));
  check "old typed priority snapshot unchanged" true (run original (values ()));
  let removed = changed "typed priority removal"
      (Enforcer.remove_policy earlier ["0"; "admin"; "one"; "/data/*"; "deny"]) in
  check "typed removal restores next decision" true (run removed (values ()));
  check "typed requester initially has no domain role" false (run removed (values ~name:"bob" ()));
  let linked = changed "typed domain grouping addition"
      (Enforcer.add_grouping_policy_in_domain removed ("bob", "admin", "one")) in
  check "role update preserves priority and schema" true (run linked (values ~name:"bob" ()));
  check "old typed role snapshot unchanged" false (run removed (values ~name:"bob" ()));
  rejects "typed priority invalid insertion is atomic"
    (Enforcer.add_policy linked ["bad"; "admin"; "one"; "/data/*"; "deny"]);
  check "typed invalid addition leaves authorization" true (run linked (values ~name:"bob" ()))

let () =
  numeric_grammar ();
  ordered_effects ();
  load_and_order ();
  numeric_atomicity_and_raw_keys ();
  effect_and_synthetic ();
  typed_domain_management ();
  Printf.printf "priority: %d signed64, ordering, effect, and snapshot checks passed\n" !checks
