type t = {
  rules : string list list;
  roles : (string * string) list;
  domain_roles : (string * string * string) list;
}
val of_string : model:Model.t -> string -> (t, string) result
val of_file : model:Model.t -> string -> (t, string) result
