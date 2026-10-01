let ( let* ) = Result.bind

let parse value =
  let length = String.length value in
  let beginning =
    if length > 0 && (value.[0] = '+' || value.[0] = '-') then 1 else 0
  in
  let rec decimal index =
    index = length
    || (value.[index] >= '0' && value.[index] <= '9' && decimal (index + 1))
  in
  if beginning = length || not (decimal beginning) then
    Error (Printf.sprintf "invalid priority %S: expected optional ASCII sign and decimal digits" value)
  else match Int64.of_string_opt value with
    | Some priority -> Ok priority
    | None -> Error (Printf.sprintf "invalid priority %S: outside signed 64-bit range" value)

let priority_index fields =
  let rec find index = function
    | [] -> None
    | "priority" :: _ -> Some index
    | _ :: rest -> find (index + 1) rest
  in
  find 0 fields

let row_priority index row =
  match List.nth_opt row index with
  | Some value -> parse value
  | None -> Error (Printf.sprintf "policy row is missing priority cell at field %d" (index + 1))

let annotate index rows =
  let rec loop position acc = function
    | [] -> Ok (List.rev acc)
    | row :: rest ->
        (match row_priority index row with
         | Error message -> Error (Printf.sprintf "policy row %d: %s" position message)
         | Ok priority -> loop (position + 1) ((priority, row) :: acc) rest)
  in
  loop 1 [] rows

let order ~policy_fields rows =
  match priority_index policy_fields with
  | None -> Ok rows
  | Some index ->
      let* rows = annotate index rows in
      Ok (List.map snd (List.stable_sort (fun (left, _) (right, _) -> Int64.compare left right) rows))

let insert ~policy_fields ~rule rows =
  match priority_index policy_fields with
  | None -> Ok (rows @ [rule])
  | Some index ->
      let* priority = row_priority index rule in
      let* ordered = annotate index rows in
      let rec position prefix = function
        | [] -> List.rev_append prefix [rule]
        | (stored, row) :: rest as remaining ->
            if Int64.compare stored priority > 0 then
              List.rev_append prefix (rule :: List.map snd remaining)
            else position (row :: prefix) rest
      in
      Ok (position [] ordered)
