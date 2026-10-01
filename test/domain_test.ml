open Casbin

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let rejects label result = check label true (Result.is_error result)
let changed label expected result =
  let snapshot, actual = ok result in
  check label expected actual;
  snapshot
let unchanged label original result =
  let snapshot = changed label false result in
  check (label ^ " retains snapshot identity") true (snapshot == original)

let matcher = "g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && r.act == p.act"
let model ?(eft = false) ?(policy_effect = "some(where (p.eft == allow))")
    ?(request_fields = "sub, dom, obj, act") ?(policy_fields = "sub, dom, obj, act")
    ?(role_definition = "_, _, _") expression =
  "[request_definition]\nr = " ^ request_fields ^ "\n" ^
  "[policy_definition]\np = " ^ policy_fields ^ (if eft then ", eft\n" else "\n") ^
  "[role_definition]\ng = " ^ role_definition ^ "\n" ^
  "[policy_effect]\ne = " ^ policy_effect ^ "\n[matchers]\nm = " ^ expression ^ "\n"
let enforcer ?eft ?policy_effect expression policy =
  ok (Enforcer.of_strings ~model:(model ?eft ?policy_effect expression) ~policy)
let decision snapshot subject domain obj = ok (Enforcer.enforce snapshot [subject; domain; obj; "read"])

let graph_boundaries () =
  let graph = ok (Role_manager.of_domain_links
      ["alice", "member", "D1"; "member", "admin", "D1"; "member", "admin", "D2";
       "nul", "nul-admin", "\000"; "literal-star", "star-admin", "*"]) in
  check "transitive membership within one domain" true (Role_manager.has_domain_link graph "alice" "admin" "D1");
  check "other-domain edge cannot complete a path" false (Role_manager.has_domain_link graph "alice" "admin" "D2");
  check "domains compare case-sensitively" false (Role_manager.has_domain_link graph "alice" "admin" "d1");
  check "empty domain does not inherit named-domain graph" false (Role_manager.has_domain_link graph "alice" "admin" "");
  check "unknown self membership in absent domain" true (Role_manager.has_domain_link graph "unknown" "unknown" "absent");
  check "unknown nonself membership in absent domain" false (Role_manager.has_domain_link graph "unknown" "other" "absent");
  check "NUL domain is distinct from empty domain" false (Role_manager.has_domain_link graph "nul" "nul-admin" "");
  check "NUL domain retains its links" true (Role_manager.has_domain_link graph "nul" "nul-admin" "\000");
  check "literal star domain is exact" true (Role_manager.has_domain_link graph "literal-star" "star-admin" "*");
  check "literal star domain is not a wildcard" false (Role_manager.has_domain_link graph "literal-star" "star-admin" "anything");
  let links = List.init 11 (fun i -> string_of_int i, string_of_int (i + 1), "depth") in
  let deep = ok (Role_manager.of_domain_links links) in
  check "domain role depth includes ten edges" true (Role_manager.has_domain_link deep "0" "10" "depth");
  check "domain role depth excludes eleven edges" false (Role_manager.has_domain_link deep "0" "11" "depth");
  check "deep graph absent in other domain" false (Role_manager.has_domain_link deep "0" "10" "other");
  let split = ok (Role_manager.of_domain_links (List.mapi
      (fun i (a, b, _) -> a, b, if i < 5 then "first" else "second") links)) in
  check "split-domain prefix exists" true (Role_manager.has_domain_link split "0" "5" "first");
  check "split-domain chain never joins" false (Role_manager.has_domain_link split "0" "10" "first");
  let opposite = ok (Role_manager.of_domain_links ["a", "b", "one"; "b", "a", "two"]) in
  check "cross-domain opposite edges are valid" true (Role_manager.has_domain_link opposite "a" "b" "one");
  check "opposite-domain edge does not leak" false (Role_manager.has_domain_link opposite "b" "a" "one");
  rejects "same-domain cycle is rejected"
    (Role_manager.of_domain_links ["a", "b", "one"; "b", "a", "one"]);
  rejects "same-domain self edge is rejected" (Role_manager.of_domain_links ["a", "a", "one"]);
  rejects "cycle in one partition invalidates whole candidate"
    (Role_manager.of_domain_links ["ok", "role", "clean"; "a", "b", "bad"; "b", "a", "bad"]);
  let identities = ok (Role_manager.of_domain_links ["b:c", "x", "a"; "c", "y", "a:b"]) in
  check "graph domains and names are separate byte keys" false (Role_manager.has_domain_link identities "b:c" "y" "a");
  check "second partition with separator-looking bytes intact" true (Role_manager.has_domain_link identities "c" "y" "a:b")

let parser_boundaries () =
  let parsed = ok (Model.of_string (model matcher)) in
  check "domain model has arity three" 3 parsed.role_arity;
  check "domain role definition enables roles" true parsed.roles_enabled;
  let policy = ok (Policy.of_string ~model:parsed
      "p, admin, one, /data/*, read\ng, alice, admin, one\n") in
  check "domain policy uses separate triple storage" ["alice", "admin", "one"] policy.domain_roles;
  check "domain policy leaves two-field role storage empty" [] policy.roles;
  List.iter (fun row -> rejects "domain CSV g arity is strict" (Policy.of_string ~model:parsed row))
    ["g, alice, admin"; "g, alice, admin, one, extra"; "g, alice"; "g"];
  let plain = ok (Model.of_string (model ~role_definition:"_, _" "g(r.sub, p.sub)")) in
  check "two-field model arity preserved" 2 plain.role_arity;
  rejects "two-field g CSV cannot contain domain" (Policy.of_string ~model:plain "g, alice, admin, one");
  List.iter (fun definition -> rejects "unsupported role arity" (Model.of_string (model ~role_definition:definition matcher)))
    ["_"; "_, _, _, _"; "_, domain, _"];
  rejects "automatic domain keyMatch registration model is rejected"
    (Model.of_string (model "g(r.sub, p.sub, r.dom) && keyMatch(r.dom, p.dom)"));
  rejects "automatic domain matching uses arbitrary second token names"
    (Model.of_string (model ~request_fields:"sub, tenant, obj, act" ~policy_fields:"sub, scope, obj, act"
       "g(r.sub, p.sub, r.tenant) && keyMatch(r.tenant, p.scope)"));
  check "non-activating comma formatting keeps exact-domain model legal" 3
    (ok (Model.of_string (model "g(r.sub, p.sub, r.dom) && keyMatch(r.dom,p.dom)"))).role_arity;
  check "space after opening parenthesis does not activate domain matching" 3
    (ok (Model.of_string (model "g(r.sub, p.sub, r.dom) && keyMatch( r.dom, p.dom)"))).role_arity;
  rejects "automatic domain registration also detects underscore text in literal"
    (Model.of_string (model "g(r.sub, p.sub, r.dom) || 'keyMatch(r_dom, p_dom)' == 'unused'"));
  rejects "initial domain cycle deliberately stricter than pinned Go"
    (Enforcer.of_strings ~model:(model matcher)
       ~policy:"g, a, b, one\ng, b, a, one\n");
  rejects "initial domain self edge deliberately stricter than pinned Go"
    (Enforcer.of_strings ~model:(model matcher) ~policy:"g, a, a, one\n");
  let cross = enforcer matcher "g, a, b, one\ng, b, a, two\n" in
  check "cross-domain opposite CSV links accepted" [["a"; "b"; "one"]; ["b"; "a"; "two"]]
    (ok (Enforcer.get_grouping_policy cross))

let expr_boundaries () =
  let compile ?(role_arity = 3) source = Expr.compile ~role_arity
      ~request_fields:["sub"; "dom"; "obj"; "act"]
      ~policy_fields:["sub"; "dom"; "obj"; "act"] ~roles_enabled:true source in
  let domain_expr = ok (compile "g(r.sub, p.sub, r.dom)") in
  let calls = ref [] in
  let resolve name = match name with
    | "r.sub" -> Ok "alice" | "p.sub" -> Ok "admin" | "r.dom" -> Ok "one"
    | _ -> Error ("missing " ^ name) in
  let in_domain subject role domain = calls := (subject, role, domain) :: !calls; domain = "one" in
  let eval ?has_role_in_domain ?(resolve = resolve) expression =
    Expr.eval ?has_role_in_domain ~resolve ~has_role:(fun _ _ -> failwith "g3 must not call g2 callback") expression in
  check "g3 resolver receives all exact string arguments" (Ok true)
    (eval ~has_role_in_domain:in_domain domain_expr);
  check "g3 callback receives domain in third position" ["alice", "admin", "one"] !calls;
  let resolved = ref [] in
  check "domain operands resolve left to right" (Ok true)
    (eval ~has_role_in_domain:in_domain ~resolve:(fun name -> resolved := name :: !resolved; resolve name) domain_expr);
  check "domain resolver order includes third operand last" ["r.sub"; "p.sub"; "r.dom"]
    (List.rev !resolved);
  rejects "g3 without domain callback returns error" (eval domain_expr);
  calls := [];
  check "third argument resolver error propagates" (Error "missing r.dom")
    (eval ~has_role_in_domain:in_domain ~resolve:(fun name -> if name = "r.dom" then Error "missing r.dom" else resolve name) domain_expr);
  check "callback not invoked after resolver failure" [] !calls;
  List.iter (fun failing ->
    calls := [];
    check "earlier domain-call operand errors propagate" (Error ("missing " ^ failing))
      (eval ~has_role_in_domain:in_domain ~resolve:(fun name ->
           if name = failing then Error ("missing " ^ failing) else resolve name) domain_expr);
    check "earlier operand failure does not call domain resolver" [] !calls)
    ["r.sub"; "p.sub"];
  List.iter (fun (source, expected) ->
    check "domain call Boolean short-circuit" (Ok expected)
      (eval ~resolve:(fun _ -> Error "not evaluated") (ok (compile source))))
    ["false && g(r.sub, p.sub, r.dom)", false; "true || g(r.sub, p.sub, r.dom)", true];
  check "domain call literals and parenthesized strings" (Ok true)
    (eval ~has_role_in_domain:in_domain (ok (compile "g(('alice'), 'admin', ('one'))")));
  check "third operand alone establishes policy dependency" true
    (Expr.uses_policy (ok (compile "g('alice', 'admin', p.dom)")));
  check "unreachable third-operand policy dependency retained" true
    (Expr.uses_policy (ok (compile "true || g('alice', 'admin', p.dom)")));
  check "request-only domain call has no policy dependency" false
    (Expr.uses_policy (ok (compile "g(r.sub, 'admin', r.dom)")));
  List.iter (fun source -> rejects ("g3 compile rejects " ^ source) (compile source))
    ["g(r.sub, p.sub)"; "g(r.sub, p.sub, r.dom, p.dom)";
     "g(true, p.sub, r.dom)"; "g(r.sub, false, r.dom)"; "g(r.sub, p.sub, true)";
     "g(r.sub, p.sub, keyMatch(r.dom, p.dom))"; "g(r.sub, p.sub, r.unknown)";
     "true || g(r.sub, p.sub)"; "false && g(r.sub, p.sub, true)";
     "g(r.sub, p.sub, r.dom) == true"];
  rejects "g2 declaration rejects g3 call" (compile ~role_arity:2 "g(r.sub, p.sub, r.dom)");
  List.iter (fun role_arity -> rejects "enabled role arity metadata is validated"
    (compile ~role_arity "true")) [0; 1; 4];
  rejects "disabled g cannot claim domain arity"
    (Expr.compile ~role_arity:3 ~request_fields:[] ~policy_fields:[] ~roles_enabled:false "true");
  let old = ok (Expr.compile ~request_fields:["sub"] ~policy_fields:["sub"] ~roles_enabled:true "g(r.sub, p.sub)") in
  check "legacy Expr.compile and eval labels remain usable" (Ok true)
    (Expr.eval ~resolve ~has_role:(fun a b -> a = "alice" && b = "admin") old)

let enforcement_and_management () =
  let base = enforcer matcher
      "p, admin, one, /data/*, read\np, admin, two, /data/*, read\ng, alice, member, one\ng, member, admin, one\n" in
  check "domain RBAC and keyMatch allow" true (decision base "alice" "one" "/data/item");
  check "same permission in different domain does not grant a role" false (decision base "alice" "two" "/data/item");
  check "role self works in domain without grouping links" true (decision base "admin" "two" "/data/item");
  check "case of domain matters" false (decision base "alice" "ONE" "/data/item");
  check "domain keyMatch retains prefix boundary" false (decision base "alice" "one" "/data");
  let synthetic = enforcer "g(r.sub, p.sub, r.dom)" "" in
  check "synthetic empty policy preserves domain self membership" true
    (decision synthetic "" "absent" "/anything");
  check "synthetic empty policy does not create domain role links" false
    (decision synthetic "alice" "absent" "/anything");
  let request_only = enforcer ~eft:true "g(r.sub, 'admin', r.dom)"
      "p, admin, one, /data/*, read, deny\ng, alice, admin, one\n" in
  check "request-only domain matcher retains synthetic implicit allow" true
    (decision request_only "alice" "one" "/anything");
  check "request-only domain matcher remains isolated" false
    (decision request_only "alice" "two" "/anything");
  let reordered = ok (Enforcer.of_strings
      ~model:(model ~request_fields:"obj, act, sub, tenant" ~policy_fields:"act, obj, scope, sub"
        "g(r.sub, p.sub, r.tenant) && r.tenant == p.scope && keyMatch(r.obj, p.obj) && r.act == p.act")
      ~policy:"p, read, /data/*, one, admin\ng, alice, admin, one\n") in
  check "domain matcher uses declared fields at arbitrary positions" (Ok true)
    (Enforcer.enforce reordered ["/data/item"; "read"; "alice"; "one"]);
  check "reordered domain field still isolates role graphs" (Ok false)
    (Enforcer.enforce reordered ["/data/item"; "read"; "alice"; "two"]);
  let added = changed "domain grouping link appended" true
    (Enforcer.add_grouping_policy_in_domain base ("alice", "admin", "two")) in
  check "new domain graph grants access" true (decision added "alice" "two" "/data/item");
  check "old snapshot domain graph unchanged" false (decision base "alice" "two" "/data/item");
  unchanged "duplicate domain link is no-op" added
    (Enforcer.add_grouping_policy_in_domain added ("alice", "admin", "two"));
  unchanged "missing domain link removal is no-op" added
    (Enforcer.remove_grouping_policy_in_domain added ("missing", "admin", "two"));
  check "domain grouping has exact triple" true
    (ok (Enforcer.has_grouping_policy_in_domain added ("alice", "admin", "two")));
  check "same pair in other domain absent" false
    (ok (Enforcer.has_grouping_policy_in_domain added ("alice", "admin", "absent")));
  rejects "same-domain cycle mutation is atomic"
    (Enforcer.add_grouping_policy_in_domain added ("admin", "alice", "one"));
  rejects "domain self-edge mutation is atomic"
    (Enforcer.add_grouping_policy_in_domain added ("alice", "alice", "two"));
  check "rejected mutations preserve decision" true (decision added "alice" "one" "/data/item");
  check "rejected cycle absent from stored triples" false
    (ok (Enforcer.has_grouping_policy_in_domain added ("admin", "alice", "one")));
  let removed = changed "domain link removed" true
    (Enforcer.remove_grouping_policy_in_domain added ("alice", "admin", "two")) in
  check "domain removal rebuilds graph" false (decision removed "alice" "two" "/data/item");
  check "domain removal does not affect other graph" true (decision removed "alice" "one" "/data/item");
  check "prior domain graph still authorizes" true (decision added "alice" "two" "/data/item");
  rejects "pair has requires two-field model" (Enforcer.has_grouping_policy base ("alice", "admin"));
  rejects "pair add requires two-field model" (Enforcer.add_grouping_policy base ("alice", "admin"));
  rejects "pair remove requires two-field model" (Enforcer.remove_grouping_policy base ("alice", "admin"));
  let queried = changed "empty-domain link added" true
    (Enforcer.add_grouping_policy_in_domain base ("alice", "zeta", "")) in
  let queried = changed "empty-domain second link added" true
    (Enforcer.add_grouping_policy_in_domain queried ("alice", "alpha", "")) in
  let queried = changed "empty-domain other user added" true
    (Enforcer.add_grouping_policy_in_domain queried ("bob", "alpha", "")) in
  check "unscoped roles query uses empty domain" ["alpha"; "zeta"] (ok (Enforcer.get_roles_for_user queried "alice"));
  check "unscoped users query uses empty domain" ["alice"; "bob"] (ok (Enforcer.get_users_for_role queried "alpha"));
  check "domain role query is direct and sorted" ["member"]
    (ok (Enforcer.get_roles_for_user_in_domain queried ~domain:"one" "alice"));
  check "domain users query excludes transitive users" ["member"]
    (ok (Enforcer.get_users_for_role_in_domain queried ~domain:"one" "admin"));
  let sorted = changed "second named-domain direct role added" true
    (Enforcer.add_grouping_policy_in_domain queried ("alice", "alpha", "one")) in
  let sorted = changed "named-domain direct user added" true
    (Enforcer.add_grouping_policy_in_domain sorted ("aaron", "admin", "one")) in
  check "explicit named-domain roles sorted lexicographically" ["alpha"; "member"]
    (ok (Enforcer.get_roles_for_user_in_domain sorted ~domain:"one" "alice"));
  check "explicit named-domain users sorted lexicographically" ["aaron"; "member"]
    (ok (Enforcer.get_users_for_role_in_domain sorted ~domain:"one" "admin"));
  check "domain query excludes unknown implicit self" []
    (ok (Enforcer.get_roles_for_user_in_domain queried ~domain:"missing" "unknown"));
  let unicode = changed "Unicode control-byte domain link added" true
    (Enforcer.add_grouping_policy_in_domain queried ("alice", "admin", "租户\000")) in
  let unicode = changed "Unicode-domain permission added" true
    (Enforcer.add_policy unicode ["admin"; "租户\000"; "/data/*"; "read"]) in
  check "Unicode NUL domains preserve exact strings" true (decision unicode "alice" "租户\000" "/data/item");
  check "similar Unicode domain does not inherit" false (decision unicode "alice" "租户" "/data/item");
  let collision = changed "domain comma-key stored tuple added" true
    (Enforcer.add_grouping_policy_in_domain base ("a,b", "admin", "one")) in
  check "has uses all three comma-joined fields" true
    (ok (Enforcer.has_grouping_policy_in_domain collision ("a", "b,admin", "one")));
  unchanged "colliding domain tuple is no-op" collision
    (Enforcer.add_grouping_policy_in_domain collision ("a", "b,admin", "one"));
  check "stored comma tuple actually authorizes" true (decision collision "a,b" "one" "/data/item");
  let collision_removed = changed "domain collision removal removes stored tuple" true
    (Enforcer.remove_grouping_policy_in_domain collision ("a", "b,admin", "one")) in
  check "domain collision removal rebuilds actual graph" false (decision collision_removed "a,b" "one" "/data/item");
  check "old domain collision snapshot graph retained" true (decision collision "a,b" "one" "/data/item");
  let domain_collision = changed "key collision spanning domain boundary added" true
    (Enforcer.add_grouping_policy_in_domain base ("c", "admin,west", "one")) in
  check "joined identity may span role and domain separators" true
    (ok (Enforcer.has_grouping_policy_in_domain domain_collision ("c", "admin", "west,one")));
  unchanged "cross-domain joined-key collision remains no-op" domain_collision
    (Enforcer.add_grouping_policy_in_domain domain_collision ("c", "admin", "west,one"));
  check "collision does not migrate edge to another domain" []
    (ok (Enforcer.get_roles_for_user_in_domain domain_collision ~domain:"west,one" "c"));
  check "stored domain tuple remains in original graph" ["admin,west"]
    (ok (Enforcer.get_roles_for_user_in_domain domain_collision ~domain:"one" "c"));
  let self_collision = changed "acyclic domain self-key witness added" true
    (Enforcer.add_grouping_policy_in_domain base ("a", "a,a,a", "one")) in
  unchanged "colliding domain self edge is duplicate before graph validation" self_collision
    (Enforcer.add_grouping_policy_in_domain self_collision ("a,a", "a,a", "one"));
  check "colliding domain self edge not inserted into graph" []
    (ok (Enforcer.get_roles_for_user_in_domain self_collision ~domain:"one" "a,a"));
  List.iter (fun (policy_effect, expected, unmatched) ->
    let effects = enforcer ~eft:true ~policy_effect matcher
        "p, admin, one, /data/*, read, allow\np, admin, one, /data/secret*, read, deny\ng, alice, admin, one\n" in
    check "domain effects honor deny/allow aggregation" expected (decision effects "alice" "one" "/data/secret-file");
    check "different domain has no matching effect rows" unmatched (decision effects "alice" "two" "/data/secret-file"))
    ["some(where (p.eft == allow))", true, false;
     "!some(where (p.eft == deny))", false, true;
     "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false, false];
  let plain = ok (Enforcer.of_strings
      ~model:(model ~request_fields:"sub, obj, act" ~policy_fields:"sub, obj, act" ~role_definition:"_, _"
          "g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act")
      ~policy:"p, admin, /data/*, read\ng, alice, admin\n") in
  check "legacy two-field enforcer and groupings remain usable" true (ok (Enforcer.enforce plain ["alice"; "/data/item"; "read"]));
  rejects "domain has requires three-field model" (Enforcer.has_grouping_policy_in_domain plain ("alice", "admin", "one"));
  rejects "domain add requires three-field model" (Enforcer.add_grouping_policy_in_domain plain ("alice", "admin", "one"));
  rejects "domain remove requires three-field model" (Enforcer.remove_grouping_policy_in_domain plain ("alice", "admin", "one"));
  rejects "explicit domain roles query requires three-field model" (Enforcer.get_roles_for_user_in_domain plain ~domain:"one" "alice");
  rejects "explicit domain users query requires three-field model" (Enforcer.get_users_for_role_in_domain plain ~domain:"one" "admin")

let nul_cache_identity_boundary () =
  (* Pinned Go joins g-cache arguments with NUL delimiters, so these distinct
     tuples share a memoization key. The OCaml graph uses independent exact
     string keys and must not reuse the first tuple's true membership result. *)
  let configuration = model ~request_fields:"dummy" ~policy_fields:"child, parent, dom, eft"
      "g(p.child, p.parent, p.dom)" in
  let empty = ok (Enforcer.of_strings ~model:configuration ~policy:"") in
  let first = ["a\000b"; "c"; "d"; "UNKNOWN"] in
  let second = ["a"; "b\000c"; "d"; "allow"] in
  let linked = changed "NUL cache-boundary first edge added" true
      (Enforcer.add_grouping_policy_in_domain empty ("a\000b", "c", "d")) in
  let initial = changed "NUL cache-boundary indeterminate policy added" true
      (Enforcer.add_policy linked first) in
  check "matched UNKNOWN row is indeterminate" Effector.Indeterminate
    (Effector.row_effect (Some "UNKNOWN"));
  check "true first membership with unknown effect does not authorize" (Ok false)
    (Enforcer.enforce initial ["ignored"]);
  let both = changed "NUL cache-boundary distinct allow row added" true
      (Enforcer.add_policy initial second) in
  check "NUL-delimited cache collision cannot grant unrelated membership" (Ok false)
    (Enforcer.enforce both ["ignored"]);
  check "distinct NUL tuples retain separate policy rows" [first; second] (Enforcer.get_policy both);
  check "first NUL tuple retains its exact graph edge" ["c"]
    (ok (Enforcer.get_roles_for_user_in_domain both ~domain:"d" "a\000b"));
  check "second NUL tuple has no graph edge" []
    (ok (Enforcer.get_roles_for_user_in_domain both ~domain:"d" "a"));
  check "second NUL grouping tuple does not exist" false
    (ok (Enforcer.has_grouping_policy_in_domain both ("a", "b\000c", "d")));
  check "NUL policy addition preserves prior snapshot rows" [first] (Enforcer.get_policy initial);
  check "prior indeterminate-only snapshot still denies" (Ok false)
    (Enforcer.enforce initial ["ignored"]);
  check "old grouping-only snapshot still has no policy rows" [] (Enforcer.get_policy linked)

let () =
  graph_boundaries ();
  parser_boundaries ();
  expr_boundaries ();
  enforcement_and_management ();
  nul_cache_identity_boundary ();
  Printf.printf "domains: %d isolated-graph, typed-matcher, and snapshot checks passed\n" !checks
