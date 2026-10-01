open Casbin

let expect_ok label = function
  | Ok value -> value
  | Error message -> failwith (label ^ ": " ^ message)

let expect_error label = function
  | Error message when message <> "" -> ()
  | Error _ -> failwith (label ^ ": empty diagnostic")
  | Ok _ -> failwith (label ^ ": unexpectedly accepted")

let check label condition = if not condition then failwith label

let acl = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"

let replace source before after =
  let rec find position =
    if position + String.length before > String.length source then failwith "replacement absent"
    else if String.sub source position (String.length before) = before then position
    else find (position + 1)
  in
  let position = find 0 in
  String.sub source 0 position ^ after
  ^ String.sub source (position + String.length before)
      (String.length source - position - String.length before)

let () =
  let model = expect_ok "ACL" (Model.of_string acl) in
  check "fields parsed" (model.request_fields = ["sub"; "obj"; "act"]);
  check "ACL roles disabled" (not model.roles_enabled);
  check "implicit allow override" (model.policy_effect = Effector.Allow_override);
  let effect_models = [
    "allow override", "some(where (p.eft == allow))", Effector.Allow_override;
    "deny override", "!some(where (p.eft == deny))", Effector.Deny_override;
    "allow and deny", "some(where (p.eft == allow)) && !some(where (p.eft == deny))", Effector.Allow_and_deny;
    "compact deny override", "!some(where(p.eft==deny))", Effector.Deny_override;
    "spaced deny override", "! some ( where ( p . eft == deny ) )", Effector.Deny_override;
    "compact allow and deny", "some(where(p.eft==allow))&&!some(where(p.eft==deny))", Effector.Allow_and_deny;
    "spaced allow and deny", "some ( where ( p . eft == allow ) ) && ! some ( where ( p . eft == deny ) )", Effector.Allow_and_deny;
    "priority", "priority(p.eft) || deny", Effector.Priority_override;
    "compact priority", "priority(p.eft)||deny", Effector.Priority_override;
    "spaced priority", "priority ( p . eft ) || deny", Effector.Priority_override;
  ] in
  List.iter (fun (label, expression, expected) ->
    let parsed = expect_ok label (Model.of_string
      (replace acl "some(where (p.eft == allow))" expression)) in
    check (label ^ " parsed enum") (parsed.policy_effect = expected);
    check (label ^ " eft remains optional") (parsed.policy_fields = ["sub"; "obj"; "act"])) effect_models;
  List.iter (fun (label, definition, expected) ->
    let parsed = expect_ok label (Model.of_string
      (replace acl "p = sub, obj, act" definition)) in
    check (label ^ " fields preserved") (parsed.policy_fields = expected)) [
      "eft last", "p = sub, obj, act, eft", ["sub"; "obj"; "act"; "eft"];
      "eft first", "p = eft, sub, obj, act", ["eft"; "sub"; "obj"; "act"];
      "eft middle", "p = sub, eft, obj, act", ["sub"; "eft"; "obj"; "act"];
      "eft alone", "p = eft", ["eft"];
    ];
  let explicit_model = expect_ok "explicit eft model" (Model.of_string
    (replace acl "p = sub, obj, act" "p = sub, eft, obj, act")) in
  let explicit_rows = expect_ok "explicit eft rows" (Policy.of_string ~model:explicit_model
    "p, alice, allow, data1, read\np, alice, deny, data1, write\np, alice, unknown, data1, admin\n") in
  check "effect values remain strings until enforcement"
    (explicit_rows.rules = [["alice"; "allow"; "data1"; "read"];
       ["alice"; "deny"; "data1"; "write"]; ["alice"; "unknown"; "data1"; "admin"]]);
  expect_error "explicit eft participates in row arity"
    (Policy.of_string ~model:explicit_model "p, alice, data1, read");
  let continued_effect = expect_ok "continued allow-and-deny effect" (Model.of_string
    (replace acl "some(where (p.eft == allow))"
      ("some(where (p.eft == allow)) && " ^ "\\" ^ "\n!some(where (p.eft == deny))"))) in
  check "effect continuation parsed enum" (continued_effect.policy_effect = Effector.Allow_and_deny);
  let multiline = replace acl "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = r.sub == p.sub && " ^ "\\" ^ "\n    r.obj == p.obj && " ^ "\\" ^ "\n    r.act == p.act") in
  let continued = expect_ok "continuation" (Model.of_string multiline) in
  check "continuation joined" (continued.matcher = model.matcher);
  ignore (expect_ok "comments" (Model.of_string
    ("# heading\n; alternative comment\n" ^ replace acl "r = sub, obj, act" "r = sub, obj, act # fields")));
  ignore (expect_ok "CRLF" (Model.of_string (String.concat "\r\n" (String.split_on_char '\n' acl))));
  ignore (expect_ok "effect spaces" (Model.of_string
    (replace acl "some(where (p.eft == allow))" "some ( where ( p.eft == allow ) )")));
  let rbac = expect_ok "RBAC" (Model.of_string (acl ^ "[role_definition]\ng = _, _\n")) in
  check "RBAC enabled" rbac.roles_enabled;
  List.iter (fun (label, value) -> expect_error label (Model.of_string value)) [
    "unknown section", acl ^ "[anything]\nx = value\n";
    "multiple requests", replace acl "r = sub, obj, act" "r = sub, obj, act\nr2 = sub, obj, act";
    "duplicate section", acl ^ "[matchers]\nm = true\n";
    "duplicate definition", replace acl "r = sub, obj, act" "r = sub, obj, act\nr = foo";
    "duplicate fields", replace acl "r = sub, obj, act" "r = sub, sub";
    "empty field", replace acl "r = sub, obj, act" "r = sub,,act";
    "invalid field", replace acl "r = sub, obj, act" "r = sub, 1obj, act";
    "subject priority effect", replace acl "some(where (p.eft == allow))" "subjectPriority(p.eft) || deny";
    "custom effect", replace acl "some(where (p.eft == allow))" "custom(p.eft)";
    "positive deny aggregation", replace acl "some(where (p.eft == allow))" "some(where (p.eft == deny))";
    "negated allow aggregation", replace acl "some(where (p.eft == allow))" "!some(where (p.eft == allow))";
    "effect disjunction", replace acl "some(where (p.eft == allow))"
      "some(where (p.eft == allow)) || !some(where (p.eft == deny))";
    "reversed effect conjunction", replace acl "some(where (p.eft == allow))"
      "!some(where (p.eft == deny)) && some(where (p.eft == allow))";
    "trailing effect token", replace acl "some(where (p.eft == allow))" "some(where (p.eft == allow)) false";
    "parenthesized effect", replace acl "some(where (p.eft == allow))" "(some(where (p.eft == allow)))";
    "duplicate effect field", replace acl "p = sub, obj, act" "p = sub, eft, eft";
    "split effect conjunction", replace acl "some(where (p.eft == allow))"
      "some(where (p.eft == allow)) & & !some(where (p.eft == deny))";
    "broken effect keyword", replace acl "some(where (p.eft == allow))" "s o m e(where (p.eft == allow))";
    "broken effect operator", replace acl "some(where (p.eft == allow))" "some(where (p.eft = = allow))";
    "empty matcher", replace acl "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act" "m = ";
    "missing matcher", replace acl "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act" "# absent";
    "unsupported role arity", acl ^ "[role_definition]\ng = _, _, _, _\n";
    "empty role section", acl ^ "[role_definition]\n";
    "unsectioned definition", "x = value\n" ^ acl;
    "bad section", replace acl "[matchers]" "[matchers";
    "dangling EOF continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
      ("m = true " ^ "\\");
    "dangling newline continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = true " ^ "\\");
    "blank interrupts continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = true " ^ "\\" ^ "\n\n&& false");
    "comment interrupts continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = true " ^ "\\" ^ "\n# ignored\n&& false");
    "semicolon comment interrupts continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = true " ^ "\\" ^ "\n; ignored\n&& false");
    "section interrupts continuation", replace acl
      "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"
      ("m = true " ^ "\\" ^ "\n[role_definition]\ng = _, _");
  ];
  let policy = expect_ok "policy" (Policy.of_string ~model:rbac
    "# heading\n p, alice, data1, read \np, alice, data1, read\ng, alice, readers\ng, alice, readers\n") in
  check "policy deduplicated" (policy.rules = [["alice"; "data1"; "read"]]);
  check "roles deduplicated" (policy.roles = ["alice", "readers"]);
  let quoted = expect_ok "quoted CSV" (Policy.of_string ~model
    "p, \"alice, jr\", \"a\"\"b\", read\n") in
  check "quoted values" (quoted.rules = [["alice, jr"; "a\"b"; "read"]]);
  let collisions = expect_ok "upstream comma-joined duplicate keys" (Policy.of_string ~model:rbac
    "p, \"a,b\", c, read\np, a, \"b,c\", read\ng, \"a,b\", c\ng, a, \"b,c\"\n") in
  check "policy key collision retains first tuple" (collisions.rules = [["a,b"; "c"; "read"]]);
  check "role key collision retains first tuple" (collisions.roles = ["a,b", "c"]);
  let spaces = expect_ok "CSV significant spaces" (Policy.of_string ~model
    "p, alice , data1 , read\n") in
  check "interior trailing spaces preserved" (spaces.rules = [["alice "; "data1 "; "read"]]);
  let empties = expect_ok "empty CSV fields" (Policy.of_string ~model "p,,,\n") in
  check "empty values preserved" (empties.rules = [[""; ""; ""]]);
  ignore (expect_ok "empty policy" (Policy.of_string ~model "# none\n \n"));
  List.iter (fun (label, value) -> expect_error label (Policy.of_string ~model value)) [
    "short policy", "p, alice, data1";
    "long policy", "p, alice, data1, read, allow";
    "unknown record", "p2, alice, data1, read";
    "empty record", ", alice, data1, read";
    "roles absent", "g, alice, readers";
    "bare quote", "p, al\"ice, data1, read";
    "unclosed quote", "p, \"alice, data1, read";
    "quote suffix", "p, \"alice\" , data1, read";
    "multiline quote", "p, \"alice\njr\", data1, read";
    "semicolon not comment", "; comment";
  ];
  expect_error "role arity" (Policy.of_string ~model:rbac "g, alice, readers, domain");
  expect_error "missing model file" (Model.of_file "/no/such/casbin/model.conf");
  expect_error "missing policy file" (Policy.of_file ~model "/no/such/casbin/policy.csv");
  print_endline "parser semantic tests passed"
