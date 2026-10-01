(** Schema-checked ABAC expressions; legacy Expr string typing is unchanged. *)
type t
val compile : request_schema:(string * Value.schema) list -> policy_fields:string list ->
  role_arity:int -> string -> (t, string) result
val uses_policy : t -> bool

(** The resolver supplies root bindings such as r.obj; nested properties are
    accessed through Value.lookup and scalar leaves are runtime-validated. *)
val eval : resolve:(string -> (Value.t, string) result) ->
  has_role:(string -> string -> bool) ->
  has_role_in_domain:(string -> string -> string -> bool) -> t -> (bool, string) result
