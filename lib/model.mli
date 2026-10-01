(** Validated, single-model ACL/basic or exact-domain RBAC configuration with allow override,
    deny override, or combined allow-and-deny policy effects. Policy fields may
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
