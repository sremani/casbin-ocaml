(** Immutable role graph. The Go default checks paths of at most ten edges. *)
type t
val of_links : (string * string) list -> (t, string) result
val has_link : t -> string -> string -> bool
