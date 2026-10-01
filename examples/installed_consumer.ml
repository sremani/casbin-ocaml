module E = Casbin.Enforcer
module V = Casbin.Value
let result = function Ok value -> value | Error message -> failwith message
let model = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = priority, sub, obj, act, eft\n[policy_effect]\ne = priority(p.eft) || deny\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
let () =
  let original = result (E.of_strings ~model ~policy:"p, 2, alice, data, read, allow\n") in
  assert (result (E.enforce original ["alice";"data";"read"]));
  let updated, changed = result (E.add_policy original ["1";"alice";"data";"read";"deny"]) in
  assert changed;
  assert (not (result (E.enforce updated ["alice";"data";"read"])));
  assert (result (E.enforce original ["alice";"data";"read"]));
  let abac = "[request_definition]\nr = sub, obj\n[policy_definition]\np = sub, obj\n[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == r.obj.Owner\n" in
  let typed = result (E.of_strings_abac ~request_schema:["sub",V.TString;"obj",V.TObject ["Owner",V.TString]] ~model:abac ~policy:"") in
  assert (result (E.enforce_values typed [V.String "alice";V.Object ["Owner",V.String "alice"]]));
  (match E.enforce_values typed [V.String "alice";V.Object []] with Error _ -> () | Ok _ -> failwith "invalid request authorized");
  print_endline "installed package: ACL, priority, immutable update, typed ABAC and error checks passed"
