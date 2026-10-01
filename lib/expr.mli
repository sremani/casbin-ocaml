(** Compiled, validated Boolean matcher over string fields. *)
type t

(** Supports string equality/inequality, Boolean logic, parentheses, and enabled
    two- or three-string [g] calls selected by [role_arity], plus two-string [keyMatch] byte-prefix matching.
    [keyMatch] requires no role definition and ignores pattern text from the first
    asterisk onward. Quoted literals preserve backslashes. Literal values
    containing quotes, brackets, [#], [:], assertion-like [r]/[p] names followed
    by optional digits and a dot, or a [YYYY-MM-DD] shaped substring are rejected
    to avoid upstream preprocessing and implicit date conversion. This does not
    constrain request or policy values supplied to the resolver. *)
val compile :
  ?role_arity:int ->
  request_fields:string list -> policy_fields:string list ->
  roles_enabled:bool -> string -> (t, string) result

(** Whether any branch references a policy field, including unreachable branches. *)
val uses_policy : t -> bool

(** Domain g calls require [has_role_in_domain]; its absence is an error. *)
val eval :
  ?has_role_in_domain:(string -> string -> string -> bool) ->
  resolve:(string -> (string, string) result) ->
  has_role:(string -> string -> bool) -> t -> (bool, string) result
