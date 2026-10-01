(** Validated, single-model ACL/RBAC/typed ABAC configuration with allow override,
    deny override, combined allow-and-deny, or priority policy effects. Policy fields may
    include an explicit [eft] field at any position; absence implies allow. *)
type t = {
  request_fields : string list;
  policy_fields : string list;
  policy_effect : Effector.policy_effect;
  matcher : string;
  roles_enabled : bool;
  role_arity : int; (** 0 without g; otherwise 2 or 3. *)
}
val of_string : string -> (t, string) result
val of_file : string -> (t, string) result
