open Casbin
open Value

let checks = ref 0
let check label expected actual =
  incr checks;
  if expected <> actual then failwith label
let ok = function Ok value -> value | Error message -> failwith message
let rejects label result = check label true (Result.is_error result)
let changed label result =
  let snapshot, flag = ok result in check label true flag; snapshot

let object_schema = TObject ["Owner", TString; "Path", TString;
    "Meta", TObject ["Quota", TNumber; "Enabled", TBool]]
let attributes ?(owner = "alice") ?(path = "/data/item") ?(quota = 1.25) ?(enabled = true) () =
  Object ["Meta", Object ["Enabled", Bool enabled; "Quota", Number quota];
          "Path", String path; "Owner", String owner]

let values_and_schemas () =
  check "valid nested schema" (Ok ()) (validate_schema object_schema);
  check "object property order immaterial" (Ok ()) (validate ~schema:object_schema (attributes ()));
  check "case-sensitive independent schema properties" (Ok ())
    (validate ~schema:(TObject ["Owner", TString; "owner", TBool])
       (Object ["owner", Bool false; "Owner", String "alice"]));
  List.iter (fun bad -> rejects "invalid schema property identifier"
      (validate_schema (TObject [bad, TString]))) [""; "0x"; "x.y"; "x-y"; "香港"; "x\000"];
  check "ASCII identifier accepts underscore and digits" (Ok ())
    (validate_schema (TObject ["_0", TString; "Owner2", TBool]));
  rejects "duplicate schema property" (validate_schema (TObject ["x", TString; "x", TBool]));
  rejects "duplicate nested schema property" (validate_schema (TObject ["Unused", TObject ["x", TString; "x", TString]]));
  rejects "invalid nested schema property" (validate_schema (TObject ["Unused", TObject ["bad.key", TBool]]));
  let rec cyclic_schema = TObject ["self", cyclic_schema] in
  rejects "cyclic public schema terminates with an error" (validate_schema cyclic_schema);
  let nested count = List.fold_left (fun schema _ -> TObject ["self", schema]) TString (List.init count Fun.id) in
  check "schema allows 256 nested property levels" (Ok ()) (validate_schema (nested 256));
  rejects "schema rejects nesting beyond 256 levels" (validate_schema (nested 257));
  List.iter (fun (schema, valid) ->
    List.iter (fun value -> check "all primitive types validate without coercion"
      (value = valid) (Result.is_ok (validate ~schema value)))
      [String "1"; Number 1.; Bool true; Object []])
    [TString, String "1"; TNumber, Number 1.; TBool, Bool true; TObject [], Object []];
  List.iter (fun value -> check "finite IEEE float64 accepted" (Ok ())
      (validate ~schema:TNumber (Number value)))
    [0.; -0.; 1.25; -1.25; max_float; min_float; Int64.float_of_bits 1L];
  List.iter (fun value -> rejects "nonfinite numbers rejected" (validate ~schema:TNumber (Number value)))
    [infinity; neg_infinity; nan];
  List.iter (fun value -> rejects "full nested object shape validated" (validate ~schema:object_schema value))
    [Object []; Object ["Owner", String "alice"; "Path", String "/data/item"];
     Object ["Owner", String "alice"; "Path", String "/data/item"; "Meta", Object []];
     Object ["Owner", String "alice"; "Path", String "/data/item"; "Meta", Object ["Quota", Number infinity; "Enabled", Bool true]];
     Object ["Owner", String "alice"; "Owner", String "bob"; "Path", String "/data/item"; "Meta", Object ["Quota", Number 1.; "Enabled", Bool true]];
     Object ["Owner", String "alice"; "Path", String "/data/item"; "Meta", Object ["Quota", String "1"; "Enabled", Bool true]];
     Object ["Owner", String "alice"; "Path", String "/data/item"; "Meta", Object ["Quota", Number 1.; "Enabled", Bool true; "Extra", Bool false]];
     Object ["Owner", String "alice"; "Path", String "/data/item"; "Meta", Object ["Quota", Number 1.; "Enabled", Bool true]; "Extra", String "x"];
     Object ["bad.name", String "x"]];
  rejects "validate rejects malformed schema before inspecting primitive value"
    (validate ~schema:(TObject ["unused", TObject ["duplicate", TBool; "duplicate", TNumber]]) (String "wrong"));
  check "nested lookup" (Ok (Number 1.25)) (lookup (attributes ()) ["Meta"; "Quota"]);
  check "lookup empty path returns original value" (Ok (attributes ())) (lookup (attributes ()) []);
  rejects "lookup unknown property" (lookup (attributes ()) ["Missing"]);
  rejects "lookup unknown nested property" (lookup (attributes ()) ["Meta"; "Missing"]);
  rejects "lookup cannot reflect through primitive" (lookup (attributes ()) ["Owner"; "Name"]);
  rejects "lookup ambiguous property is an error" (lookup (Object ["x", String "a"; "x", String "b"]) ["x"]);
  let rec cyclic_value = Object ["self", cyclic_value] in
  rejects "lookup rejects paths longer than 256 levels"
    (lookup cyclic_value (List.init 257 (fun _ -> "self")));
  let rec cyclic_path = "self" :: cyclic_path in
  rejects "lookup cyclic path terminates with a depth error" (lookup cyclic_value cyclic_path)

let request_schema = ["sub", TString; "obj", object_schema; "act", TString;
    "score", TNumber; "enabled", TBool;
    "subject", TObject ["Name", TString; "Tenant", TString]]
let bindings = ["sub", String "alice"; "obj", attributes (); "act", String "read";
    "score", Number 1.25; "enabled", Bool true;
    "subject", Object ["Name", String "alice"; "Tenant", String "one"]]
let compile ?(role_arity = 0) source = Abac_expr.compile ~request_schema
    ~policy_fields:["sub"; "obj"; "act"; "dom"; "eft"] ~role_arity source
let resolve name = match String.split_on_char '.' name with
  | "r" :: path -> lookup (Object bindings) path
  | ["p"; "sub"] -> Ok (String "admin")
  | ["p"; "dom"] -> Ok (String "one")
  | ["p"; "obj"] -> Ok (String "/data/*")
  | _ -> Error ("missing " ^ name)
let eval ?(role_arity = 0) ?(resolve = resolve)
    ?(has_role = fun _ _ -> false) ?(has_role_in_domain = fun _ _ _ -> false) source =
  Abac_expr.eval ~resolve ~has_role ~has_role_in_domain (ok (compile ~role_arity source))

let typed_expressions () =
  List.iter (fun (source, expected) -> check source (Ok expected) (eval source))
    ["r.sub == r.obj.Owner", true;
     "r.obj.Meta.Quota >= 1.2 && r.obj.Meta.Enabled", true;
     "r.score > -1.5 && r.score <= 1.25", true;
     "r.score != 1.5", true;
     "r.enabled == true && !false", true;
     "r.enabled != false", true;
     "'10' < '2'", true; "'same' <= 'same'", true;
     "'z' > 'a'", true; "'z' >= 'z'", true;
     ".5 == 0.5", true; "1. == 1", true; "-.5 == -0.5", true;
     "- .5 == -.5", true; "- 1 == -1", true; "-\t1 == -1", true;
     "-1.25 > -1.3", true;
     "-0.0 == 0", true;
     "9007199254740992 == 9007199254740993", true;
     "keyMatch(r.obj.Path, p.obj)", true;
     "1 < 2 == true", true; "1 < 2 != false", true;
     "2 > 1 == false", false; "'a' < 'b' == true", true;
     "1 == 2 == false", true; "true == false == false", true;
     "r.score > 1 == r.enabled", true;
     "r.obj.Owner == 'alice' == true", true;
     "r.obj.Owner == 'bob' || r.obj.Meta.Enabled && r.score > 1", true];
  check "fractional numeric request compared without integer truncation" (Ok false)
    (eval "r.score == 1");
  check "float64 request/literal rounding is explicit" (Ok true)
    (eval ~resolve:(fun name -> if name = "r.score" then Ok (Number 9007199254740992.) else resolve name)
      "r.score == 9007199254740993");
  List.iter (fun source -> rejects ("typed compile rejects " ^ source) (compile source))
    ["r.obj == r.obj"; "r.obj != r.obj"; "r.score == '1.25'";
     "r.score == p.obj"; "r.enabled < true"; "r.score > true";
     "r.obj.Owner == 1"; "r.obj.Meta.Unknown == true";
     "r.obj.Owner.Name == 'alice'"; "r.unknown == 'alice'";
     "r.obj"; "r.score"; "r.obj.Meta.Quota && true";
     "keyMatch(r.score, '*')"; "keyMatch(r.obj.Path, true)";
     "keyMatch(r.obj.Path)"; "keyMatch(r.obj.Path, p.obj, 'extra')";
     "g(r.sub, p.sub)"; "true || r.obj.Unknown == 'x'";
     "false && r.score == '1.25'"; "eval('true')";
     "r.score + 1 > 2"; "r.obj['Owner'] == 'alice'";
     "1e999 == 1e999"; "keyMatch2(r.obj.Path, p.obj)";
     "1e-2 == 0.01"; "+1 == 1"; "0x10 == 16"; "1.2.3 == 1";
     "1 < 2 < 3"; "1 < 2 == 1"; "1 == 2 < 3";
     "r.score < 2 > true"; "-r.score > 0"; "-(1) == -1";
     "r.obj.Owner == '2026-10-01'"; "r.obj.Owner == 'x:y'"];
  List.iter (fun source -> rejects "typed role call validates all string operands"
      (compile ~role_arity:3 source))
    ["g(r.sub, p.sub)"; "g(r.sub, p.sub, p.dom, 'extra')";
     "g(r.score, p.sub, p.dom)"; "g(r.sub, r.enabled, p.dom)";
     "g(r.sub, p.sub, r.score)"; "false && g(r.sub, p.sub, r.enabled)"];
  let role_calls = ref [] in
  check "two-string g can use nested subject attribute" (Ok true)
    (eval ~role_arity:2 ~has_role:(fun child parent -> role_calls := [child; parent]; true)
      "g(r.subject.Name, p.sub)");
  check "two-string callback gets exact attribute values" ["alice"; "admin"] !role_calls;
  let domain_calls = ref [] in
  check "three-string g can use nested domain attribute" (Ok true)
    (eval ~role_arity:3 ~has_role_in_domain:(fun child parent domain -> domain_calls := [child; parent; domain]; true)
      "g(r.subject.Name, p.sub, r.subject.Tenant)");
  check "all three domain callback values preserved" ["alice"; "admin"; "one"] !domain_calls;
  check "third g operand establishes policy dependency" true
    (Abac_expr.uses_policy (ok (compile ~role_arity:3 "g(r.subject.Name, 'admin', p.dom)")));
  check "nested request attribute does not establish policy dependency" false
    (Abac_expr.uses_policy (ok (compile "r.sub == r.obj.Owner")));
  check "unreachable policy field still establishes dependency" true
    (Abac_expr.uses_policy (ok (compile "true || keyMatch(r.obj.Path, p.obj)")));
  check "ABAC resolver errors preserved" (Error "exact resolver failure")
    (eval ~resolve:(fun _ -> Error "exact resolver failure") "r.score > 0");
  List.iter (fun value -> rejects "ABAC runtime resolver value type and finite number checked"
      (eval ~resolve:(fun _ -> Ok value) "r.score != 1"))
    [String "1"; Bool true; Object []; Number nan; Number infinity; Number neg_infinity];
  rejects "ABAC runtime nested missing property diagnosed"
    (eval ~resolve:(fun _ -> Ok (Object [])) "r.obj.Owner == 'alice'");
  rejects "ABAC runtime nested ambiguous property diagnosed"
    (eval ~resolve:(fun _ -> Ok (Object ["Owner", String "alice"; "Owner", String "bob"]))
      "r.obj.Owner == 'alice'");
  rejects "ABAC compile validates unused schema properties"
    (Abac_expr.compile ~request_schema:["Unused", TObject ["x", TString; "x", TBool]]
       ~policy_fields:[] ~role_arity:0 "true");
  rejects "ABAC compile rejects unsupported role arity"
       (Abac_expr.compile ~request_schema:[] ~policy_fields:[] ~role_arity:4 "true");
  rejects "legacy string Expr still rejects numeric comparator chains"
    (Expr.compile ~request_fields:[] ~policy_fields:[] ~roles_enabled:false "1 < 2 == true");
  check "ABAC Boolean short circuit skips resolver errors" (Ok true)
    (eval ~resolve:(fun _ -> Error "not evaluated") "true || r.score > 0");
  check "ABAC conjunction short circuit skips resolver errors" (Ok false)
    (eval ~resolve:(fun _ -> Error "not evaluated") "false && r.score > 0");
  let order = ref [] in
  check "ABAC operand evaluation succeeds" (Ok true)
    (eval ~resolve:(fun name -> order := name :: !order; resolve name) "r.sub == r.obj.Owner");
  check "ABAC root operand resolution is left to right" ["r.sub"; "r.obj"] (List.rev !order)

let configuration ?(request_fields = "sub, obj, act") ?(policy_fields = "sub, obj, act")
    ?(role_definition = "") ?(policy_effect = "some(where (p.eft == allow))") source =
  "[request_definition]\nr = " ^ request_fields ^ "\n[policy_definition]\np = " ^ policy_fields ^ "\n" ^
  (if role_definition = "" then "" else "[role_definition]\ng = " ^ role_definition ^ "\n") ^
  "[policy_effect]\ne = " ^ policy_effect ^ "\n[matchers]\nm = " ^ source ^ "\n"
let standard_schema = ["act", TString; "obj", object_schema; "sub", TString]
let typed ?(request_schema = standard_schema) model policy =
  ok (Enforcer.of_strings_abac ~request_schema ~model ~policy)
let request ?owner ?path ?quota ?enabled () =
  [String "alice"; attributes ?owner ?path ?quota ?enabled (); String "read"]
let decide snapshot values = ok (Enforcer.enforce_values snapshot values)

let typed_enforcement () =
  let ownership_model = configuration "r.sub == r.obj.Owner && r.obj.Meta.Quota >= 1 && r.obj.Meta.Enabled" in
  let ownership = typed ownership_model "" in
  check "typed owner and nested attributes permit owner" true (decide ownership (request ()));
  check "typed owner predicate rejects other owner" false (decide ownership (request ~owner:"bob" ()));
  check "typed nested number threshold rejects fraction" false (decide ownership (request ~quota:0.5 ()));
  check "typed nested Boolean condition rejects false" false (decide ownership (request ~enabled:false ()));
  rejects "legacy string constructor retains nested-attribute rejection"
    (Enforcer.of_strings ~model:ownership_model ~policy:"");
  rejects "string enforce wraps values and applies typed schema"
    (Enforcer.enforce ownership ["alice"; "opaque object text"; "read"]);
  let dead = typed (configuration "true || r.obj.Owner == 'alice'") "" in
  List.iter (fun value -> rejects "whole request validated even when matcher branch skipped"
      (Enforcer.enforce_values dead [String "alice"; value; String "read"]))
    [Object []; String "wrong"; attributes ~quota:infinity (); attributes ~quota:nan ();
     Object ["Owner", String "alice"; "Owner", String "bob"; "Path", String "x"; "Meta", Object ["Quota", Number 1.; "Enabled", Bool true]];
     Object ["Owner", String "alice"; "Path", String "x"; "Meta", Object ["Quota", Number 1.; "Enabled", Bool true]; "Extra", Bool true]];
  rejects "typed request arity too short" (Enforcer.enforce_values dead [String "alice"]);
  rejects "typed request arity too long" (Enforcer.enforce_values dead (request () @ [Bool true]));
  List.iter (fun request_schema -> rejects "constructor rejects complete invalid request schema"
      (Enforcer.of_strings_abac ~request_schema ~model:ownership_model ~policy:""))
    [["sub", TString; "obj", object_schema];
     ["sub", TString; "obj", object_schema; "act", TString; "extra", TString];
     ["sub", TString; "obj", object_schema; "act", TString; "act", TString];
     ["sub", TString; "obj", TObject ["Owner", TString; "Unused", TObject ["duplicate", TBool; "duplicate", TNumber]]; "act", TString]];
  rejects "dead branch unknown attribute still rejected at construction"
    (Enforcer.of_strings_abac ~request_schema:standard_schema
       ~model:(configuration "true || r.obj.Unknown == 'x'") ~policy:"");
  let legacy = ok (Enforcer.of_strings ~model:(configuration "true") ~policy:"") in
  rejects "typed object cannot bypass legacy string request validation"
    (Enforcer.enforce_values legacy (request ()));
  check "typed string values remain accepted on legacy snapshot" (Ok true)
    (Enforcer.enforce_values legacy [String "alice"; String "data"; String "read"]);
  let all_strings = typed ~request_schema:["sub", TString; "obj", TString; "act", TString]
      (configuration "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
      "p, alice, data, read\n" in
  check "legacy enforce works on a typed all-string snapshot" (Ok true)
    (Enforcer.enforce all_strings ["alice"; "data"; "read"]);
  let pattern_model = configuration "r.sub == p.sub && keyMatch(r.obj.Path, p.obj) && r.act == p.act && r.obj.Meta.Enabled" in
  let base = typed pattern_model "p, alice, /old/*, read\n" in
  let added = changed "typed pattern policy added" (Enforcer.add_policy base ["alice"; "/new/*"; "read"]) in
  check "management preserves typed matcher" true (decide added (request ~path:"/new/item" ()));
  check "old typed policy snapshot remains unchanged" false (decide base (request ~path:"/new/item" ()));
  rejects "management preserves full request schema on new snapshot"
    (Enforcer.enforce_values added [String "alice"; Object []; String "read"]);
  let removed = changed "typed pattern policy removed" (Enforcer.remove_policy added ["alice"; "/new/*"; "read"]) in
  check "typed removal revokes added permission" false (decide removed (request ~path:"/new/item" ()));
  check "prior typed snapshot retains removed permission" true (decide added (request ~path:"/new/item" ()))

let roles_domains_and_effects () =
  let subject_schema = TObject ["Name", TString; "Tenant", TString] in
  let schema = ["sub", subject_schema; "obj", object_schema; "act", TString] in
  let values ?(tenant = "one") () = [Object ["Name", String "alice"; "Tenant", String tenant]; attributes (); String "read"] in
  let g2_model = configuration ~role_definition:"_, _"
      "g(r.sub.Name, p.sub) && keyMatch(r.obj.Path, p.obj) && r.act == p.act" in
  let g2 = typed ~request_schema:schema g2_model "p, admin, /data/*, read\n" in
  check "typed role snapshot initially denies" false (decide g2 (values ()));
  let g2_added = changed "typed two-field grouping added" (Enforcer.add_grouping_policy g2 ("alice", "admin")) in
  check "typed two-field graph callback authorizes" true (decide g2_added (values ()));
  check "old typed two-field grouping snapshot unchanged" false (decide g2 (values ()));
  let domain_model policy_effect = configuration ~policy_fields:"sub, dom, obj, act, eft" ~role_definition:"_, _, _" ~policy_effect
      "g(r.sub.Name, p.sub, r.sub.Tenant) && r.sub.Tenant == p.dom && keyMatch(r.obj.Path, p.obj) && r.act == p.act" in
  List.iter (fun (policy_effect, expected) ->
    let snapshot = typed ~request_schema:schema (domain_model policy_effect)
        "p, admin, one, /data/*, read, allow\np, admin, one, /data/*, read, deny\ng, alice, member, one\ng, member, admin, one\n" in
    check "typed domain callbacks compose with effects" expected (decide snapshot (values ())))
    ["some(where (p.eft == allow))", true;
     "!some(where (p.eft == deny))", false;
     "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false];
  let domain = typed ~request_schema:schema (domain_model "some(where (p.eft == allow))")
      "p, admin, one, /data/*, read, allow\np, admin, two, /data/*, read, allow\ng, alice, admin, one\n" in
  check "typed domain attribute isolates graphs" false (decide domain (values ~tenant:"two" ()));
  let domain_added = changed "typed domain grouping added"
      (Enforcer.add_grouping_policy_in_domain domain ("alice", "admin", "two")) in
  check "typed domain mutation preserves matcher and schema" true (decide domain_added (values ~tenant:"two" ()));
  check "old typed domain snapshot stays isolated" false (decide domain (values ~tenant:"two" ()));
  let synthetic = typed ~request_schema:schema
      (configuration ~role_definition:"_, _, _" "g(r.sub.Name, p.sub, r.sub.Tenant)") "" in
  check "typed synthetic policy row preserves domain self membership" true
    (decide synthetic [Object ["Name", String ""; "Tenant", String "absent"]; attributes (); String "read"]);
  let direct = typed ~request_schema:schema
      (configuration ~policy_fields:"sub, obj, act, eft" ~role_definition:"_, _, _"
        "g(r.sub.Name, 'admin', r.sub.Tenant) && r.obj.Meta.Enabled")
      "p, admin, /data/*, read, deny\ng, alice, admin, one\n" in
  check "typed request-only matcher keeps synthetic implicit allow" true (decide direct (values ()))

let textual_policy_dependency () =
  (* Go's policy loop uses a textual p_ check after assertion rewriting. These
     valid request-only expressions therefore evaluate real policy effects,
     although their compiled ASTs contain no actual policy field references. *)
  let deny = "p, alice, data, read, deny\n" in
  let literal_source = "r.obj.Owner == 'p_sub'" in
  let literal = typed (configuration ~policy_fields:"sub, obj, act, eft" literal_source) deny in
  check "literal p_ text selects real policy effects" false
    (decide literal (request ~owner:"p_sub" ()));
  check "literal p_ text does not change actual-reference AST analysis" false
    (Abac_expr.uses_policy (ok (compile literal_source)));
  let property_schema = ["sub", TString; "obj", TObject ["p_sub", TString]; "act", TString] in
  let property_source = "r.obj.p_sub == 'yes'" in
  let property = typed ~request_schema:property_schema
      (configuration ~policy_fields:"sub, obj, act, eft" property_source) deny in
  check "request property p_ text selects real policy effects" false
    (decide property [String "alice"; Object ["p_sub", String "yes"]; String "read"]);
  check "request property p_ text does not change actual-reference AST analysis" false
    (Abac_expr.uses_policy (ok (Abac_expr.compile ~request_schema:property_schema
       ~policy_fields:["sub"; "obj"; "act"; "eft"] ~role_arity:0 property_source)));
  let ordinary = typed (configuration ~policy_fields:"sub, obj, act, eft"
      "r.obj.Owner == 'plain'") deny in
  check "ordinary typed request-only matcher retains synthetic effects" true
    (decide ordinary (request ~owner:"plain" ()));
  let legacy = ok (Enforcer.of_strings
      ~model:(configuration ~policy_fields:"sub, obj, act, eft" "r.obj == 'p_sub'") ~policy:deny) in
  check "legacy literal p_ text also selects real policy effects" (Ok false)
    (Enforcer.enforce legacy ["alice"; "p_sub"; "read"]);
  let legacy_plain = ok (Enforcer.of_strings
      ~model:(configuration ~policy_fields:"sub, obj, act, eft" "r.obj == 'plain'") ~policy:deny) in
  check "ordinary legacy request-only matcher retains synthetic effects" (Ok true)
    (Enforcer.enforce legacy_plain ["alice"; "plain"; "read"])

let () =
  values_and_schemas ();
  typed_expressions ();
  typed_enforcement ();
  roles_domains_and_effects ();
  textual_policy_dependency ();
  Printf.printf "ABAC: %d schema, value, matcher, and typed snapshot checks passed\n" !checks
