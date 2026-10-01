(** Supported Casbin policy-effect aggregations. *)
type policy_effect = Allow_override | Deny_override | Allow_and_deny
type row_effect = Allow | Deny | Indeterminate
val row_effect : string option -> row_effect
val decide : policy_effect -> (bool * row_effect) list -> bool
