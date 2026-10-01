open Casbin

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let error label result = check label true (Result.is_error result)
let changed label expected result =
  let snapshot, actual = ok result in
  check label expected actual;
  snapshot
let unchanged label original result =
  let snapshot = changed label false result in
  check (label ^ " keeps the original snapshot") true (snapshot == original)
let decision snapshot request = ok (Enforcer.enforce snapshot request)

let model ?(roles = false) ?(eft = false)
    ?(policy_effect = "some(where (p.eft == allow))") () =
  "[request_definition]\nr = sub, obj, act\n" ^
  "[policy_definition]\np = sub, obj, act" ^ (if eft then ", eft\n" else "\n") ^
  (if roles then "[role_definition]\ng = _, _\n" else "") ^
  "[policy_effect]\ne = " ^ policy_effect ^ "\n" ^
  "[matchers]\nm = " ^ (if roles then "g(r.sub, p.sub)" else "r.sub == p.sub") ^
  " && r.obj == p.obj && r.act == p.act\n"

let create ?roles ?eft ?policy_effect policy =
  ok (Enforcer.of_strings ~model:(model ?roles ?eft ?policy_effect ()) ~policy)

let policy_management () =
  let alice = ["alice"; "data1"; "read"] in
  let bob = ["bob"; "data2"; "write"] in
  let carol = ["carol"; "data3"; "read"] in
  let base = create "p, alice, data1, read\np, bob, data2, write\n" in
  check "initial policy order" [alice; bob] (Enforcer.get_policy base);
  check "has existing policy" true (ok (Enforcer.has_policy base alice));
  check "has missing policy" false (ok (Enforcer.has_policy base carol));
  unchanged "duplicate policy is a no-op" base (Enforcer.add_policy base alice);
  unchanged "missing policy removal is a no-op" base (Enforcer.remove_policy base carol);
  let added = changed "new policy appended" true (Enforcer.add_policy base carol) in
  check "append preserves old row order" [alice; bob; carol] (Enforcer.get_policy added);
  check "new snapshot permits added policy" true (decision added carol);
  check "input snapshot still denies added policy" false (decision base carol);
  check "input snapshot rows unchanged" [alice; bob] (Enforcer.get_policy base);
  let removed = changed "existing policy removed" true (Enforcer.remove_policy added bob) in
  check "remove preserves remaining row order" [alice; carol] (Enforcer.get_policy removed);
  check "removed policy no longer permits" false (decision removed bob);
  check "prior snapshot still permits removed policy" true (decision added bob);
  let readded = changed "removed policy can be readded" true (Enforcer.add_policy removed bob) in
  check "readded row goes at the end" [alice; carol; bob] (Enforcer.get_policy readded);
  List.iter (fun bad ->
    error "wrong-arity has is rejected" (Enforcer.has_policy readded bad);
    error "wrong-arity add is rejected" (Enforcer.add_policy readded bad);
    error "wrong-arity removal is rejected" (Enforcer.remove_policy readded bad);
    check "arity errors leave rows unchanged" [alice; carol; bob] (Enforcer.get_policy readded);
    check "arity errors leave decisions unchanged" true (decision readded bob))
    [[]; ["alice"]; ["alice"; "data1"]; ["alice"; "data1"; "read"; "deny"]];
  let unusual = ["香港"; "file,\"quotes\"\n[]:2026-10-01"; ""] in
  let special = changed "arbitrary byte strings can be added" true (Enforcer.add_policy base unusual) in
  check "Unicode, comma, quote, newline, and empty data are preserved" true
    (ok (Enforcer.has_policy special unusual));
  check "arbitrary values enforce as strings" true (decision special unusual);
  check "arbitrary values are not parser syntax" false
    (decision special ["香港"; "file,\"quotes\"\n[]:2026-10-01"; "read"]);
  let empty = [""; ""; ""] in
  let special = changed "empty fields can be added" true (Enforcer.add_policy special empty) in
  check "empty fields preserved in queries" true (ok (Enforcer.has_policy special empty));
  check "empty fields match exactly" true (decision special empty);
  let spaced = [" alice"; "data1 "; "read"] in
  let special = changed "library fields are not trimmed" true (Enforcer.add_policy special spaced) in
  check "spaces retained by management" true (List.mem spaced (Enforcer.get_policy special));
  check "spaces retained during enforcement" true (decision special spaced);
  let cleared = changed "arbitrary values removable" true (Enforcer.remove_policy special unusual) in
  check "removed arbitrary values absent" false (ok (Enforcer.has_policy cleared unusual));
  check "original arbitrary-value snapshot intact" true (ok (Enforcer.has_policy special unusual));
  let first = ["a,b"; "c"; "read"] and collision = ["a"; "b,c"; "read"] in
  let colliding = changed "first comma-key tuple added" true (Enforcer.add_policy base first) in
  check "has uses upstream comma-key identity" true (ok (Enforcer.has_policy colliding collision));
  unchanged "colliding distinct tuple is duplicate" colliding (Enforcer.add_policy colliding collision);
  check "colliding add keeps original stored tuple" [alice; bob; first] (Enforcer.get_policy colliding);
  check "stored tuple still authorizes" true (decision colliding first);
  check "colliding identity does not replace tuple values" false (decision colliding collision);
  let without = changed "remove by colliding key removes stored tuple" true
      (Enforcer.remove_policy colliding collision) in
  check "collision removal preserves unrelated row order" [alice; bob] (Enforcer.get_policy without);
  check "both identities absent after collision removal" false (ok (Enforcer.has_policy without first));
  check "old collision snapshot unchanged" [alice; bob; first] (Enforcer.get_policy colliding)

let grouping_management () =
  let request = ["alice"; "data"; "read"] in
  let base = create ~roles:true "p, admin, data, read\n" in
  check "initial groupings empty" [] (ok (Enforcer.get_grouping_policy base));
  check "self membership does not create direct roles" [] (ok (Enforcer.get_roles_for_user base "admin"));
  check "self membership does not create direct users" [] (ok (Enforcer.get_users_for_role base "admin"));
  check "role self still authorizes" true (decision base ["admin"; "data"; "read"]);
  check "missing role initially denies" false (decision base request);
  check "missing grouping absent" false (ok (Enforcer.has_grouping_policy base ("alice", "member")));
  unchanged "missing grouping removal is a no-op" base
    (Enforcer.remove_grouping_policy base ("alice", "member"));
  let direct = changed "first grouping added" true
    (Enforcer.add_grouping_policy base ("alice", "member")) in
  check "direct link exists" true (ok (Enforcer.has_grouping_policy direct ("alice", "member")));
  check "incomplete inheritance still denies" false (decision direct request);
  let chain = changed "transitive grouping added" true
    (Enforcer.add_grouping_policy direct ("member", "admin")) in
  check "role updates rebuild transitive enforcement" true (decision chain request);
  check "old graph still denies" false (decision direct request);
  check "initial graph still empty" [] (ok (Enforcer.get_grouping_policy base));
  check "grouping insertion order" [["alice"; "member"]; ["member"; "admin"]]
    (ok (Enforcer.get_grouping_policy chain));
  unchanged "duplicate grouping is a no-op" chain
    (Enforcer.add_grouping_policy chain ("alice", "member"));
  error "cycle mutation is rejected" (Enforcer.add_grouping_policy chain ("admin", "alice"));
  error "self edge on existing name is rejected" (Enforcer.add_grouping_policy chain ("member", "member"));
  error "self edge on unknown name is rejected" (Enforcer.add_grouping_policy chain ("new", "new"));
  check "failed grouping additions preserve rows" [["alice"; "member"]; ["member"; "admin"]]
    (ok (Enforcer.get_grouping_policy chain));
  check "failed grouping additions preserve enforcement" true (decision chain request);
  check "failed cycle not observable via has" false
    (ok (Enforcer.has_grouping_policy chain ("admin", "alice")));
  let other = ["admin"; "other"; "write"] in
  let with_permission = changed "policy added to RBAC snapshot" true
    (Enforcer.add_policy chain other) in
  check "policy addition retains inherited graph" true
    (decision with_permission ["alice"; "other"; "write"]);
  check "old RBAC snapshot lacks new permission" false
    (decision chain ["alice"; "other"; "write"]);
  let with_permission = changed "policy removed from RBAC snapshot" true
    (Enforcer.remove_policy with_permission ["admin"; "data"; "read"]) in
  check "policy removal keeps other inherited permission" true
    (decision with_permission ["alice"; "other"; "write"]);
  check "removed RBAC permission no longer authorizes" false (decision with_permission request);
  check "policy mutations preserve grouping rows"
    [["alice"; "member"]; ["member"; "admin"]]
    (ok (Enforcer.get_grouping_policy with_permission));
  check "old graph and policy snapshot still authorize" true (decision chain request);
  let sorted = changed "zeta link added" true (Enforcer.add_grouping_policy chain ("alice", "zeta")) in
  let sorted = changed "charlie link added" true (Enforcer.add_grouping_policy sorted ("charlie", "admin")) in
  let sorted = changed "bob link added" true (Enforcer.add_grouping_policy sorted ("bob", "admin")) in
  check "roles query returns sorted direct links" ["member"; "zeta"]
    (ok (Enforcer.get_roles_for_user sorted "alice"));
  check "users query returns sorted direct links" ["bob"; "charlie"; "member"]
    (ok (Enforcer.get_users_for_role sorted "admin"));
  check "transitive role excluded from direct role query" false
    (List.mem "admin" (ok (Enforcer.get_roles_for_user sorted "alice")));
  check "transitive user excluded from direct users query" false
    (List.mem "alice" (ok (Enforcer.get_users_for_role sorted "admin")));
  check "unknown role query is empty" [] (ok (Enforcer.get_roles_for_user sorted "unknown"));
  check "unknown user query is empty" [] (ok (Enforcer.get_users_for_role sorted "unknown"));
  let severed = changed "inheritance edge removed" true
    (Enforcer.remove_grouping_policy sorted ("member", "admin")) in
  check "edge removal rebuilds authorization graph" false (decision severed request);
  check "unrelated direct link remains authorized" true (decision severed ["bob"; "data"; "read"]);
  check "old graph remains authorized" true (decision sorted request);
  check "remove preserves grouping row order"
    [["alice"; "member"]; ["alice"; "zeta"]; ["charlie"; "admin"]; ["bob"; "admin"]]
    (ok (Enforcer.get_grouping_policy severed));
  let first = "a,b", "c" and collision = "a", "b,c" in
  let colliding = changed "comma-key grouping added" true (Enforcer.add_grouping_policy chain first) in
  let colliding = changed "permission for collision target added" true
    (Enforcer.add_policy colliding ["c"; "data"; "read"]) in
  check "grouping has uses comma-key identity" true (ok (Enforcer.has_grouping_policy colliding collision));
  unchanged "colliding grouping is a no-op" colliding (Enforcer.add_grouping_policy colliding collision);
  check "graph uses stored tuple, not collision query" ["c"]
    (ok (Enforcer.get_roles_for_user colliding "a,b"));
  check "collision does not create a second graph edge" []
    (ok (Enforcer.get_roles_for_user colliding "a"));
  check "stored collision edge authorizes" true (decision colliding ["a,b"; "data"; "read"]);
  let without = changed "grouping removable by colliding key" true
    (Enforcer.remove_grouping_policy colliding collision) in
  check "collision grouping removed from graph" [] (ok (Enforcer.get_roles_for_user without "a,b"));
  check "collision removal rebuilds actual enforcement graph" false
    (decision without ["a,b"; "data"; "read"]);
  check "old snapshot keeps collision enforcement graph" true
    (decision colliding ["a,b"; "data"; "read"]);
  check "collision removal leaves prior grouping order"
    [["alice"; "member"]; ["member"; "admin"]] (ok (Enforcer.get_grouping_policy without));
  let identity = changed "acyclic self-edge-key witness added" true
    (Enforcer.add_grouping_policy chain ("a", "a,a,a")) in
  unchanged "colliding self edge is a duplicate, not a stored candidate" identity
    (Enforcer.add_grouping_policy identity ("a,a", "a,a"));
  check "colliding self edge is found by joined identity" true
    (ok (Enforcer.has_grouping_policy identity ("a,a", "a,a")));
  check "duplicate collision did not insert a self edge" []
    (ok (Enforcer.get_roles_for_user identity "a,a"));
  let cycle_key = changed "cycle-key first witness added" true
    (Enforcer.add_grouping_policy chain ("x", "a,b")) in
  let cycle_key = changed "cycle-key second witness added" true
    (Enforcer.add_grouping_policy cycle_key ("a", "b,x")) in
  unchanged "colliding cycle edge is a duplicate, not a stored candidate" cycle_key
    (Enforcer.add_grouping_policy cycle_key ("a,b", "x"));
  check "duplicate collision did not insert a cycle edge" []
    (ok (Enforcer.get_roles_for_user cycle_key "a,b"));
  let special = changed "arbitrary grouping names added" true
    (Enforcer.add_grouping_policy chain ("", "角色\"[,]:\n")) in
  check "arbitrary grouping names preserved" ["角色\"[,]:\n"] (ok (Enforcer.get_roles_for_user special ""));
  check "empty child can be queried" [""] (ok (Enforcer.get_users_for_role special "角色\"[,]:\n"));
  check "arbitrary grouping pair found" true
    (ok (Enforcer.has_grouping_policy special ("", "角色\"[,]:\n")));
  let cleared = changed "arbitrary grouping removable" true
    (Enforcer.remove_grouping_policy special ("", "角色\"[,]:\n")) in
  check "arbitrary grouping removed" [] (ok (Enforcer.get_roles_for_user cleared ""));
  check "arbitrary grouping old snapshot preserved" ["角色\"[,]:\n"]
    (ok (Enforcer.get_roles_for_user special ""))

let disabled_grouping () =
  let base = create "p, alice, data, read\n" in
  error "get_grouping requires role model" (Enforcer.get_grouping_policy base);
  error "has_grouping requires role model" (Enforcer.has_grouping_policy base ("alice", "admin"));
  error "add_grouping requires role model" (Enforcer.add_grouping_policy base ("alice", "admin"));
  error "remove_grouping requires role model" (Enforcer.remove_grouping_policy base ("alice", "admin"));
  error "roles query requires role model" (Enforcer.get_roles_for_user base "alice");
  error "users query requires role model" (Enforcer.get_users_for_role base "admin");
  check "disabled grouping errors preserve policy" [["alice"; "data"; "read"]] (Enforcer.get_policy base);
  check "disabled grouping errors preserve decision" true (decision base ["alice"; "data"; "read"])

let effects_management () =
  let request = ["alice"; "data"; "read"] in
  let allow = request @ ["allow"] and deny = request @ ["deny"] in
  let unknown = request @ ["ALLOW"] in
  List.iter (fun (policy_effect, allow_expected, deny_expected) ->
    let base = create ~eft:true ~policy_effect "" in
    error "explicit effect is included in mutation arity" (Enforcer.add_policy base request);
    check "failed effect mutation leaves no rows" [] (Enforcer.get_policy base);
    let allowed = changed "allow row added" true (Enforcer.add_policy base allow) in
    check "allow addition changes effect verdict" true (decision allowed request);
    let vetoed = changed "deny row added" true (Enforcer.add_policy allowed deny) in
    check "deny addition follows selected effect" allow_expected (decision vetoed request);
    check "older allow snapshot unaffected" true (decision allowed request);
    let only_deny = changed "allow row removed" true (Enforcer.remove_policy vetoed allow) in
    check "allow removal follows selected effect" deny_expected (decision only_deny request);
    let restored = changed "deny row removed" true (Enforcer.remove_policy vetoed deny) in
    check "deny removal restores allow verdict" true (decision restored request);
    let indeterminate = changed "unknown effect added" true (Enforcer.add_policy restored unknown) in
    check "unknown effect does not override allow" true (decision indeterminate request);
    check "effect rows retain all field values" [allow; unknown] (Enforcer.get_policy indeterminate);
    check "older mixed-effect snapshot unchanged" [allow; deny] (Enforcer.get_policy vetoed))
    ["some(where (p.eft == allow))", true, false;
     "!some(where (p.eft == deny))", false, false;
     "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false, false]

let () =
  policy_management ();
  grouping_management ();
  disabled_grouping ();
  effects_management ();
  Printf.printf "management: %d stateful checks passed\n" !checks
