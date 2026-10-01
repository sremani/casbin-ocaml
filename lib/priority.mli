(** Signed 64-bit decimal priorities and stable policy ordering. *)
val parse : string -> (int64, string) result

(** Validate retained rows and sort by a field exactly named priority. Without
    that field, preserve the input order. Missing cells return an error. *)
val order : policy_fields:string list -> string list list -> (string list list, string) result

(** Validate a newly stored row and insert after equal priorities, or append
    when no priority field is declared. Existing rows must already be ordered
    by [order]. Duplicate detection belongs to callers. *)
val insert : policy_fields:string list -> rule:string list -> string list list ->
  (string list list, string) result
