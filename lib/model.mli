(** Validated, single-model ACL/basic RBAC configuration. *)
type t = {
  request_fields : string list;
  policy_fields : string list;
  matcher : string;
  roles_enabled : bool;
}
val of_string : string -> (t, string) result
val of_file : string -> (t, string) result
