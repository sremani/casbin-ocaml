(** An immutable, validated model and policy snapshot. *)
type t
val of_strings : model:string -> policy:string -> (t, string) result
val of_files : model:string -> policy:string -> (t, string) result
val enforce : t -> string list -> (bool, string) result
