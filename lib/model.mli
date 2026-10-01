(** Validated, single-model ACL/basic RBAC configuration with allow override,
    deny override, or combined allow-and-deny policy effects. Policy fields may
    include an explicit [eft] field at any position; absence implies allow. *)
type t = {
  request_fields : string list;
  policy_fields : string list;
  policy_effect : Effector.policy_effect;
  matcher : string;
  roles_enabled : bool;
}
val of_string : string -> (t, string) result
val of_file : string -> (t, string) result
