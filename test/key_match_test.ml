open Casbin

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let compile ?(roles_enabled = false) source =
  Expr.compile ~request_fields:["sub"; "obj"; "act"]
    ~policy_fields:["sub"; "obj"; "act"; "eft"] ~roles_enabled source
let compiled ?roles_enabled source = ok (compile ?roles_enabled source)
let evaluate ?(bindings = []) source =
  Expr.eval ~resolve:(fun name ->
      match List.assoc_opt name bindings with Some value -> Ok value | None -> Error ("missing " ^ name))
    ~has_role:(fun _ _ -> failwith "keyMatch must not call the role resolver")
    (compiled source)
let matches key pattern =
  evaluate ~bindings:["r.obj", key; "p.obj", pattern] "keyMatch(r.obj, p.obj)"

let byte_semantics () =
  List.iter (fun (key, pattern, expected) ->
    check (Printf.sprintf "keyMatch(%S, %S)" key pattern) (Ok expected) (matches key pattern))
    ["", "", true; "", "*", true; "", "*ignored", true;
     "anything", "*ignored", true; "anything", "**suffix", true;
     "nonempty", "", false; "", "prefix*", false;
     "/foo", "/foo", true; "/foo/", "/foo", false;
     "/Foo", "/foo", false; "/FOO", "/foo*", false;
     "/foo", "/foo*", true; "/foobar", "/foo*", true;
     "/foo", "/foo/*", false; "/foobar", "/foo/*", false;
     "/foo/", "/foo/*", true; "/foo/bar", "/foo/*", true;
     "/foo/bar", "/foo/*ignored", true;
     "/foo/bar", "/foo/**ignored", true;
     "/foo/one/two", "/foo/*/must-not-be-required", true;
     "/fo", "/foo*", false; "/fox", "/foo*", false;
     "/foo%2fbar", "/foo/*", false;
     "/foo/../bar", "/foo/*", true;
     "/foo//bar", "/foo/*", true;
     "foo\\suffix", "foo\\*ignored", true;
     "foo\\", "foo\\*ignored", true;
     "foo*", "foo\\*", false;
     "foo\\bar", "foo\\bar", true;
     "foo/bar", "foo\\bar", false;
     "a\000b", "a\000b", true;
     "a\000b", "a\000*ignored", true;
     "a\000", "a\000*ignored", true;
     "a", "a\000*ignored", false;
     "a\n\tb", "a\n*ignored", true;
     "香港/资料", "香港/*", true;
     "香港", "香港/*", false;
     "é/data", "é/*", true;
     "e\204\129/data", "é/*", false;
     "é/data", "e\204\129/*", false;
     "\195\169", "\195*", true;
     "\255\000suffix", "\255\000*", true;
     "\255", "\254*", false];
  (* Prefix fixtures exclude '*'. For every suffix, changing only ignored
     pattern text must retain the decision, while a key shorter than the prefix
     must fail. This also exercises partial UTF-8 and control-byte prefixes. *)
  List.iter (fun prefix ->
    List.iter (fun suffix ->
      check "asterisk matches arbitrary trailing bytes" (Ok true)
        (matches (prefix ^ suffix) (prefix ^ "*"));
      check "all pattern suffix bytes are ignored" (Ok true)
        (matches (prefix ^ suffix) (prefix ^ "*different/*\000suffix")))
      [""; "/"; "tail"; "*"; "\000"; "香港"; "\255\000"];
    if prefix <> "" then
      check "key shorter than the prefix cannot match" (Ok false)
        (matches (String.sub prefix 0 (String.length prefix - 1)) (prefix ^ "*")))
    [""; "a"; "/a/"; "é"; "\195"; "\000"; "\\"; "香港/"]

let grammar_and_evaluation () =
  List.iter (fun (source, expected) -> check source (Ok expected) (evaluate source))
    ["keyMatch('/foo', '/foo*')", true;
     "keyMatch(('/foo'), (\"/foo*\"))", true;
     "!keyMatch('/foo', '/foo/*')", true;
     "false || keyMatch('/foo/x', '/foo/*') && true", true;
     "keyMatch('', '*ignored') && !false", true;
     {|keyMatch('\path', '\p*ignored')|}, true];
  List.iter (fun source ->
    check ("compile rejects " ^ source) true (Result.is_error (compile ~roles_enabled:true source)))
    ["keyMatch()"; "keyMatch('/foo')"; "keyMatch('/foo', '*', 'extra')";
     "keyMatch('/foo',)"; "keyMatch(, '*')";
     "keyMatch(true, '*')"; "keyMatch('/foo', false)";
     "keyMatch(r.obj == p.obj, '*')"; "keyMatch('/foo', true && false)";
     "keyMatch(keyMatch('/foo', '*'), '*')";
     "keyMatch('/foo', g(r.sub, p.sub))";
     "g(keyMatch('/foo', '*'), p.sub)";
     "g(r.sub, keyMatch('/foo', '*'))";
     "keyMatch('/foo', '*') == true";
     "keyMatch('/foo', '*') != 'string'";
     "keyMatch('/foo', '*') == keyMatch('/bar', '*')";
     "keyMatch r.obj, p.obj"; "keyMatch('/foo' '*')";
     "keyMatch2(r.obj, p.obj)"; "KeyMatch(r.obj, p.obj)";
     "keyMatch(r.unknown, '*')";
     "false && keyMatch(true, '*')"; "true || keyMatch('/foo')";
     "true || keyMatch2(r.obj, p.obj)";
     {|keyMatch('/foo', '[x]*')|}; {|keyMatch('/foo', 'x:*')|};
     {|keyMatch('/foo', 'r.*')|}; {|keyMatch('/foo', '2026-10-01*')|}];
  check "left resolver error is preserved" (Error "missing r.obj")
    (evaluate "keyMatch(r.obj, '*')");
  check "right resolver error is preserved" (Error "missing p.obj")
    (evaluate "keyMatch('/foo', p.obj)");
  check "false conjunction skips field resolution" (Ok false)
    (evaluate "false && keyMatch(r.obj, p.obj)");
  check "true disjunction skips field resolution" (Ok true)
    (evaluate "true || keyMatch(r.obj, p.obj)");
  check "true conjunction propagates resolver error" (Error "missing r.obj")
    (evaluate "true && keyMatch(r.obj, p.obj)");
  check "false disjunction propagates resolver error" (Error "missing r.obj")
    (evaluate "false || keyMatch(r.obj, p.obj)");
  let resolved = ref [] in
  let expression = compiled "keyMatch(r.obj, p.obj)" in
  let result = Expr.eval ~resolve:(fun field -> resolved := field :: !resolved; Error "first failure")
      ~has_role:(fun _ _ -> false) expression in
  check "first operand failure returned unchanged" (Error "first failure") result;
  check "right operand not resolved after left error" ["r.obj"] !resolved;
  List.iter (fun (source, expected) ->
    check ("uses_policy " ^ source) expected (Expr.uses_policy (compiled source)))
    ["keyMatch(r.obj, '*')", false;
     "keyMatch('/foo', '*')", false;
     "keyMatch(p.obj, '*')", true;
     "keyMatch(r.obj, p.obj)", true;
     "true || !keyMatch(p.obj, r.obj)", true]

let configuration ?(roles = false) ?(eft = false)
    ?(policy_effect = "some(where (p.eft == allow))") matcher =
  "[request_definition]\nr = sub, obj, act\n" ^
  "[policy_definition]\np = sub, obj, act" ^ (if eft then ", eft\n" else "\n") ^
  (if roles then "[role_definition]\ng = _, _\n" else "") ^
  "[policy_effect]\ne = " ^ policy_effect ^ "\n[matchers]\nm = " ^ matcher ^ "\n"
let enforcer ?roles ?eft ?policy_effect matcher policy =
  ok (Enforcer.of_strings ~model:(configuration ?roles ?eft ?policy_effect matcher) ~policy)
let decision snapshot obj = ok (Enforcer.enforce snapshot ["alice"; obj; "read"])
let acl = "r.sub == p.sub && keyMatch(r.obj, p.obj) && r.act == p.act"

let enforcer_semantics () =
  let empty = enforcer "keyMatch(r.obj, p.obj)" "" in
  check "empty policy supplies empty pattern" true (decision empty "");
  check "empty policy empty pattern rejects nonempty key" false (decision empty "/foo");
  let first_argument = enforcer "keyMatch(p.obj, r.obj)" "p, alice, /foo/x, read\n" in
  check "policy dependence in first operand uses stored key" true (decision first_argument "/foo*");
  check "stored key fails a different first-operand prefix" false (decision first_argument "/bar*");
  let request_only = enforcer ~eft:true "keyMatch(r.obj, '/pub*')"
      "p, alice, ignored, read, deny\n" in
  check "request-only keyMatch ignores explicit row effects" true (decision request_only "/public");
  check "request-only matcher still rejects wrong prefix" false (decision request_only "/private");
  let synthetic = enforcer "keyMatch(p.obj, '*')" "" in
  check "star accepts synthetic empty policy value" true (decision synthetic "/anything");
  let rbac = enforcer ~roles:true
      "g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act"
      "p, admin, /data/*, read\ng, alice, member\ng, member, admin\n" in
  check "keyMatch composes with transitive roles" true (decision rbac "/data/item");
  check "role matcher retains required slash prefix" false (decision rbac "/data");
  List.iter (fun (policy_effect, secret, unmatched) ->
    let snapshot = enforcer ~eft:true ~policy_effect acl
      "p, alice, /data/*, read, allow\np, alice, /data/secret*, read, deny\n" in
    check "matching allow pattern grants access" true (decision snapshot "/data/public");
    check "overlapping patterns honor selected effect" secret (decision snapshot "/data/secret-file");
    check "nonmatching patterns honor selected effect default" unmatched (decision snapshot "/elsewhere"))
    ["some(where (p.eft == allow))", true, false;
     "!some(where (p.eft == deny))", false, true;
     "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false, false];
  let base = enforcer acl "p, alice, /old/*, read\n" in
  let row = ["alice"; "/new/*ignored"; "read"] in
  let added, changed = ok (Enforcer.add_policy base row) in
  check "pattern management reports addition" true changed;
  check "new pattern grants access" true (decision added "/new/item");
  check "old snapshot still lacks new pattern" false (decision base "/new/item");
  let duplicate, changed = ok (Enforcer.add_policy added row) in
  check "duplicate pattern is a no-op" false changed;
  check "duplicate retains snapshot identity" true (duplicate == added);
  let removed, changed = ok (Enforcer.remove_policy added row) in
  check "pattern management reports removal" true changed;
  check "removed pattern no longer grants access" false (decision removed "/new/item");
  check "removal preserves old pattern" true (decision removed "/old/item");
  check "prior snapshot keeps removed pattern" true (decision added "/new/item");
  let raw, changed = ok (Enforcer.add_policy base ["alice"; "\255\000*"; "read"]) in
  check "arbitrary byte pattern can be managed" true changed;
  check "enforcer resolves NUL and invalid UTF-8 pattern bytes" true
    (decision raw "\255\000suffix");
  check "arbitrary byte prefix still distinguishes mismatches" false
    (decision raw "\254\000suffix");
  let role_row = ["admin"; "/other/*"; "read"] in
  let role_added, changed = ok (Enforcer.add_policy rbac role_row) in
  check "role pattern addition reports change" true changed;
  check "pattern addition retains role graph" true (decision role_added "/other/item");
  check "old role snapshot keeps prior pattern set" false (decision rbac "/other/item");
  let role_removed, _ = ok (Enforcer.remove_policy role_added role_row) in
  check "role pattern removal revokes new access" false (decision role_removed "/other/item");
  check "role pattern removal retains original access" true (decision role_removed "/data/item")

let () =
  byte_semantics ();
  grammar_and_evaluation ();
  enforcer_semantics ();
  Printf.printf "keyMatch: %d byte, matcher, and snapshot checks passed\n" !checks
