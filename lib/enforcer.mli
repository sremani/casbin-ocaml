(** An immutable, validated model and policy snapshot. *)
type t
val of_strings : model:string -> policy:string -> (t, string) result
val of_files : model:string -> policy:string -> (t, string) result
val enforce : t -> string list -> (bool, string) result

(** Management returns a new snapshot and a changed flag. The input snapshot
    remains usable. Policy arities are validated; role cycles are rejected. *)
val get_policy : t -> string list list
val has_policy : t -> string list -> (bool, string) result
val add_policy : t -> string list -> (t * bool, string) result
val remove_policy : t -> string list -> (t * bool, string) result
val get_grouping_policy : t -> (string list list, string) result
val has_grouping_policy : t -> string * string -> (bool, string) result
val add_grouping_policy : t -> string * string -> (t * bool, string) result
val remove_grouping_policy : t -> string * string -> (t * bool, string) result
val get_roles_for_user : t -> string -> (string list, string) result
val get_users_for_role : t -> string -> (string list, string) result

(** Domain grouping mutations require a three-field g definition. Queries use
    exact domains; old snapshots remain valid after updates. *)
val has_grouping_policy_in_domain : t -> string * string * string -> (bool, string) result
val add_grouping_policy_in_domain : t -> string * string * string -> (t * bool, string) result
val remove_grouping_policy_in_domain : t -> string * string * string -> (t * bool, string) result
val get_roles_for_user_in_domain : t -> domain:string -> string -> (string list, string) result
val get_users_for_role_in_domain : t -> domain:string -> string -> (string list, string) result

(** Explicit typed ABAC construction. The schema names every request field,
    including its recursively declared object properties. *)
val of_strings_abac : request_schema:(string * Value.schema) list ->
  model:string -> policy:string -> (t, string) result
val of_files_abac : request_schema:(string * Value.schema) list ->
  model:string -> policy:string -> (t, string) result
val enforce_values : t -> Value.t list -> (bool, string) result
