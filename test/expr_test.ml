open Casbin

let checks = ref 0
let check label condition =
  incr checks;
  if not condition then failwith label

let compile ?(roles_enabled = false) source =
  Expr.compile ~request_fields:["sub"; "obj"; "act"]
    ~policy_fields:["sub"; "obj"; "act"] ~roles_enabled source

let compiled ?roles_enabled source =
  match compile ?roles_enabled source with
  | Ok value -> value
  | Error message -> failwith (source ^ ": " ^ message)

let evaluate ?(roles_enabled = false) ?(bindings = [])
    ?(has_role = fun _ _ -> false) source =
  Expr.eval
    ~resolve:(fun name -> match List.assoc_opt name bindings with
      | Some value -> Ok value
      | None -> Error ("missing " ^ name))
    ~has_role (compiled ~roles_enabled source)

let rejects source =
  check ("must reject: " ^ source) (Result.is_error (compile ~roles_enabled:true source))

let () =
  List.iter (fun (source, expected) ->
    check source (evaluate source = Ok expected))
    ["true", true;
     "false", false;
     "!false", true;
     "!!true", true;
     "true || false && false", true;
     "(true || false) && false", false;
     "false && true || true", true;
     "!(true || false) && true", false;
     "'alice' == \"alice\"", true;
     "'alice' != 'bob'", true;
     "'alice' != 'alice'", false;
     "('alice') == ('alice')", true;
     "'true' == 'true'", true;
     "'' == ''", true;
     "'香港' == \"香港\"", true;
     {|'\n\t' == "\n\t"|}, true;
     {|'\\path' != '\path'|}, true];
  check "fields and string equality"
    (evaluate ~bindings:["r.sub", "alice"; "p.sub", "alice"]
       "r.sub == p.sub" = Ok true);
  check "literal backslashes preserved"
    (evaluate ~bindings:["r.sub", "\\n\\t"] {|r.sub == '\n\t'|} = Ok true);
  check "backslash n is not a newline"
    (evaluate ~bindings:["r.sub", "\n"] {|r.sub == '\n'|} = Ok false);
  check "resolver failure is preserved"
    (evaluate "r.sub == 'alice'" = Error "missing r.sub");
  check "right operand resolver failure is preserved"
    (evaluate "'alice' == p.sub" = Error "missing p.sub");
  check "and short-circuits"
    (evaluate "false && r.sub == 'alice'" = Ok false);
  check "or short-circuits"
    (evaluate "true || r.sub == 'alice'" = Ok true);
  check "and evaluated branch propagates errors"
    (evaluate "true && r.sub == 'alice'" = Error "missing r.sub");
  check "or evaluated branch propagates errors"
    (evaluate "false || r.sub == 'alice'" = Error "missing r.sub");
  check "disabled role function"
    (Result.is_error (compile "g(r.sub, p.sub)"));
  let role_calls = ref [] in
  let has_role a b = role_calls := (a, b) :: !role_calls; a = "alice" && b = "admin" in
  check "role with fields"
    (evaluate ~roles_enabled:true ~has_role
       ~bindings:["r.sub", "alice"; "p.sub", "admin"]
       "g(r.sub, p.sub)" = Ok true);
  check "role receives strings" (!role_calls = ["alice", "admin"]);
  check "role literals and parentheses"
    (evaluate ~roles_enabled:true ~has_role "g(('alice'), 'admin')" = Ok true);
  role_calls := [];
  check "role short-circuit"
    (evaluate ~roles_enabled:true ~has_role "true || g('alice', 'admin')" = Ok true
     && !role_calls = []);
  check "role resolver error before role invocation"
    (evaluate ~roles_enabled:true ~has_role "g(r.sub, 'admin')" = Error "missing r.sub"
     && !role_calls = []);
  check "no policy use" (not (Expr.uses_policy (compiled "r.sub == 'alice'")));
  check "policy use in unreachable branch"
    (Expr.uses_policy (compiled "true || p.sub == 'alice'"));
  check "policy use in negation"
    (Expr.uses_policy (compiled "!(r.sub == p.sub)"));
  check "policy use in role call"
    (Expr.uses_policy (compiled ~roles_enabled:true "g(r.sub, p.sub)"));
  List.iter rejects
    [""; " "; "r.unknown == 'alice'"; "p.unknown == 'alice'";
     "r1.sub == 'alice'"; "r.sub.name == 'alice'"; "r..sub == 'alice'";
     "r. == 'alice'"; "sub == 'alice'"; "True"; "FALSE";
     "r.sub"; "'alice'"; "true == false"; "true != false";
     "r.sub == true"; "true == r.sub"; "!r.sub == 'alice'";
     "r.sub && true"; "true || 'alice'";
     "'a' == 'a' == 'a'"; "'a' =="; "== 'a'"; "true false";
     "(true"; "true)"; "()"; "true &&"; "|| false"; "!";
     "true & false"; "true | false"; "r.sub = 'alice'";
     "1 == 1"; "r.sub + p.sub == 'alice'"; "r.sub =~ 'alice'";
     "eval('true')"; "keyMatch2(r.obj, p.obj)"; "g2(r.sub, p.sub)";
     "g()"; "g('alice')"; "g('alice', 'admin', 'domain')";
     "g(true, 'admin')"; "g('alice', false)"; "g('alice', 'admin') == true";
     "g 'alice', 'admin'"; "g('alice' 'admin')";
     "'unterminated"; "\"unterminated";
     {|'a\'b' == 'a'|}; {|"a\"b" == "a"|};
     {|'x r.sub' == 'x r_sub'|}; {|'p.obj' == 'p.obj'|}; {|'x#y' == 'x#y'|};
     {|'x r1.sub' == 'x r1_sub'|}; {|'p123.obj' == 'p123.obj'|};
     {|'r.' == 'r.'|}; {|'p.' == 'p.'|}; {|'r2.' == 'r2.'|};
     {|'x r.' == 'x r.'|}; {|'p12.' == 'p12.'|};
     {|"a'b" == "a'b"|}; {|'a"b' == 'a"b'|};
     {|'[x]' == '[x]'|}; {|'x]' == 'x]'|}; {|'12:00AM' == '12:00AM'|};
     {|'2026-10-01' == '2026-10-01'|};
     {|'x2026-10-01suffix' == 'x2026-10-01suffix'|};
     {|'2026-10-01T15Z0700' == '2026-10-01T15Z0700'|};
     "false && unknown == 'alice'"; "true || eval('true')"];
  check "invalid declared field name"
    (Result.is_error
       (Expr.compile ~request_fields:["x.y"] ~policy_fields:[] ~roles_enabled:false "true"));
  check "duplicate declared field name"
    (Result.is_error
       (Expr.compile ~request_fields:["sub"; "sub"] ~policy_fields:[] ~roles_enabled:false "true"));
  rejects (String.make 257 '!' ^ "true");
  rejects (String.make 257 '(' ^ "true" ^ String.make 257 ')');
  Printf.printf "expr: %d checks passed\n" !checks
