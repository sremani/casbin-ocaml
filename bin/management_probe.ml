(* A verification-only operation trace driver. Applications use Enforcer's
   typed API and keep error diagnostics from its result values. *)
module E = Casbin.Enforcer

let encode value =
  let buffer = Buffer.create (2 * String.length value) in
  String.iter (fun char -> Buffer.add_string buffer (Printf.sprintf "%02x" (Char.code char))) value;
  Buffer.contents buffer

let decode value =
  let digit = function
    | '0' .. '9' as char -> Char.code char - Char.code '0'
    | 'a' .. 'f' as char -> Char.code char - Char.code 'a' + 10
    | 'A' .. 'F' as char -> Char.code char - Char.code 'A' + 10
    | _ -> invalid_arg "non-hex argument"
  in
  if String.length value mod 2 <> 0 then invalid_arg "odd hex argument";
  String.init (String.length value / 2) (fun i ->
      Char.chr (16 * digit value.[2 * i] + digit value.[2 * i + 1]))

let print_bool value = print_endline (string_of_bool value)
let print_rows rows =
  print_endline ("rows\t" ^ String.concat ";"
      (List.map (fun row -> String.concat "," (List.map encode row)) rows))
let print_values values =
  print_endline ("values\t" ^ String.concat "," (List.map encode (List.sort String.compare values)))
let report render = function
  | Ok value -> render value
  | Error _ -> print_endline "error"

let operate current line =
  let adopt = function
    | Ok (snapshot, changed) -> current := snapshot; print_bool changed
    | Error _ -> print_endline "error"
  in
  try
    match String.split_on_char '\t' line with
    | command :: encoded ->
        let args = List.map decode encoded in
        let snapshot = !current in
        begin match command, args with
        | "enforce", args -> report print_bool (E.enforce snapshot args)
        | "get_policy", [] -> print_rows (E.get_policy snapshot)
        | "has_policy", args -> report print_bool (E.has_policy snapshot args)
        | "add_policy", args -> adopt (E.add_policy snapshot args)
        | "remove_policy", args -> adopt (E.remove_policy snapshot args)
        | "get_grouping_policy", [] -> report print_rows (E.get_grouping_policy snapshot)
        | "has_grouping_policy", [child; parent] ->
            report print_bool (E.has_grouping_policy snapshot (child, parent))
        | "add_grouping_policy", [child; parent] ->
            adopt (E.add_grouping_policy snapshot (child, parent))
        | "remove_grouping_policy", [child; parent] ->
            adopt (E.remove_grouping_policy snapshot (child, parent))
        | "get_roles_for_user", [user] -> report print_values (E.get_roles_for_user snapshot user)
        | "get_users_for_role", [role] -> report print_values (E.get_users_for_role snapshot role)
        | _ -> print_endline "error"
        end
    | [] -> print_endline "error"
  with Invalid_argument _ -> print_endline "error"

let () =
  if Array.length Sys.argv <> 3 then begin
    prerr_endline "usage: management_probe MODEL POLICY";
    exit 2
  end;
  match E.of_files ~model:Sys.argv.(1) ~policy:Sys.argv.(2) with
  | Error message -> prerr_endline message; exit 2
  | Ok snapshot ->
      let current = ref snapshot in
      try while true do operate current (read_line ()) done with End_of_file -> ()
