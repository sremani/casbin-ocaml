type policy_effect = Allow_override | Deny_override | Allow_and_deny | Priority_override
type row_effect = Allow | Deny | Indeterminate

let row_effect = function
  | None | Some "allow" -> Allow
  | Some "deny" -> Deny
  | Some _ -> Indeterminate

let decide policy rows =
  let has selected = List.exists (fun (matched, row) -> matched && row = selected) rows in
  match policy with
  | Allow_override -> has Allow
  | Deny_override -> not (has Deny)
  | Allow_and_deny -> not (has Deny) && has Allow
  | Priority_override ->
      let rec first = function
        | [] -> false
        | (true, Allow) :: _ -> true
        | (true, Deny) :: _ -> false
        | _ :: rest -> first rest
      in
      first rows
