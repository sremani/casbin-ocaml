(** Immutable role graph. The Go default checks paths of at most ten edges. *)
type t
val of_links : (string * string) list -> (t, string) result
val has_link : t -> string -> string -> bool

(** Exact-domain graphs, validated independently with the same depth bound. *)
type domains
val of_domain_links : (string * string * string) list -> (domains, string) result
val has_domain_link : domains -> string -> string -> string -> bool
