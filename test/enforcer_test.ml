open Casbin

let ok = function Ok value -> value | Error message -> failwith message
let model ?(roles=false) matcher =
  "[request_definition]\nr = sub, obj, act\n" ^
  "[policy_definition]\np = sub, obj, act\n" ^
  (if roles then "[role_definition]\ng = _, _\n" else "") ^
  "[policy_effect]\ne = some(where (p.eft == allow))\n" ^
  "[matchers]\nm = " ^ matcher ^ "\n"
let check label expected actual =
  if actual <> expected then failwith label
let decision enforcer request = ok (Enforcer.enforce enforcer request)

let () =
  let acl = ok (Enforcer.of_strings
      ~model:(model "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
      ~policy:"p, alice, data1, read\np, bob, data2, write\n") in
  check "ACL allow" true (decision acl ["alice"; "data1"; "read"]);
  check "ACL deny" false (decision acl ["alice"; "data1"; "write"]);
  check "missing request argument" true
    (match Enforcer.enforce acl ["alice"] with Error _ -> true | Ok _ -> false);
  let rbac = ok (Enforcer.of_strings
      ~model:(model ~roles:true "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
      ~policy:"p, admin, data, read\ng, alice, member\ng, member, admin\n") in
  check "transitive role" true (decision rbac ["alice"; "data"; "read"]);
  check "role self" true (decision rbac ["admin"; "data"; "read"]);
  check "unknown role denies" false (decision rbac ["missing"; "data"; "read"]);
  check "cyclic role policy is rejected at load" true
    (match Enforcer.of_strings ~model:(model ~roles:true "g(r.sub, p.sub)")
       ~policy:"g, admin, member\ng, member, admin\n" with Error _ -> true | Ok _ -> false);
  check "self edge rejected at load" true
    (match Role_manager.of_links ["admin", "admin"] with Error _ -> true | Ok _ -> false);
  let links = List.init 11 (fun i -> (string_of_int i, string_of_int (i+1))) in
  let graph = ok (Role_manager.of_links links) in
  check "ten edges" true (Role_manager.has_link graph "0" "10");
  check "eleven edges" false (Role_manager.has_link graph "0" "11");
  check "unknown self" true (Role_manager.has_link graph "unknown" "unknown");
  let empty = ok (Enforcer.of_strings
      ~model:(model "r.sub == p.sub && r.obj == p.obj && r.act == p.act") ~policy:"") in
  check "ordinary empty policy denies" false (decision empty ["alice"; "data"; "read"]);
  check "upstream empty-row behavior" true (decision empty [""; ""; ""]);
  let constant = ok (Enforcer.of_strings ~model:(model "true") ~policy:"") in
  check "constant without policy" true (decision constant ["alice"; "data"; "read"]);
  let direct = ok (Enforcer.of_strings ~model:(model "r.sub == 'alice'")
      ~policy:"p, bob, other, write\n") in
  check "request-only matcher" true (decision direct ["alice"; "data"; "read"]);
  check "reject unknown matcher field before requests" true
    (match Enforcer.of_strings ~model:(model "r.missing == 'alice'") ~policy:"" with
     | Error _ -> true | Ok _ -> false);
  check "missing files are errors" true
    (match Enforcer.of_files ~model:"/does/not/exist" ~policy:"/does/not/exist" with
     | Error _ -> true | Ok _ -> false);
  let effect_model policy_effect =
    "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act, eft\n" ^
    "[policy_effect]\ne = " ^ policy_effect ^ "\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n" in
  let contradictory = "p, alice, data, read, allow\np, alice, data, read, deny\n" in
  List.iter (fun (label, policy_effect, expected) ->
      let e = ok (Enforcer.of_strings ~model:(effect_model policy_effect) ~policy:contradictory) in
      check label expected (decision e ["alice"; "data"; "read"]))
    ["allow overrides deny", "some(where (p.eft == allow))", true;
     "deny overrides allow", "!some(where (p.eft == deny))", false;
     "allow-and-deny veto", "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false];
  let deny_only = ok (Enforcer.of_strings
      ~model:(effect_model "!some(where (p.eft == deny))") ~policy:contradictory) in
  check "no matching deny defaults allow" true (decision deny_only ["bob"; "data"; "read"]);
  let unknown = ok (Enforcer.of_strings ~model:(effect_model "some(where (p.eft == allow))")
      ~policy:"p, alice, data, read, ALLOW\n") in
  check "unknown explicit effect is indeterminate" false (decision unknown ["alice"; "data"; "read"]);
  let empty_explicit = ok (Enforcer.of_strings
      ~model:(effect_model "some(where (p.eft == allow))") ~policy:"") in
  check "synthetic empty row has implicit allow" true (decision empty_explicit [""; ""; ""]);
  print_endline "enforcer, effect and role boundary tests passed"
