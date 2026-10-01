(** Explicit immutable ABAC values. Numbers use finite IEEE float64 values. *)
type t = String of string | Number of float | Bool of bool | Object of (string * t) list
type schema = TString | TNumber | TBool | TObject of (string * schema) list
val validate_schema : schema -> (unit, string) result
val validate : schema:schema -> t -> (unit, string) result
val lookup : t -> string list -> (t, string) result
