module Names = Set.Make (String)
module Graph = Map.Make (String)
type t = Names.t Graph.t

let of_links links =
  let graph = List.fold_left
    (fun graph (subject, role) ->
      let roles = match Graph.find_opt subject graph with
        | None -> Names.empty | Some roles -> roles
      in
      let graph = if Graph.mem role graph then graph else Graph.add role Names.empty graph in
      Graph.add subject (Names.add role roles) graph)
    Graph.empty links
  in
  (* The pinned Go enforcer enables cycle detection while loading role links.
     Kahn's algorithm detects cycles without recursion proportional to graph size. *)
  let degrees = Hashtbl.create (Graph.cardinal graph) in
  Graph.iter (fun name _ -> Hashtbl.add degrees name 0) graph;
  Graph.iter (fun _ roles -> Names.iter
      (fun role -> Hashtbl.replace degrees role (Hashtbl.find degrees role + 1)) roles) graph;
  let ready = Queue.create () in
  Hashtbl.iter (fun name degree -> if degree = 0 then Queue.add name ready) degrees;
  let removed = ref 0 in
  while not (Queue.is_empty ready) do
    let name = Queue.take ready in
    incr removed;
    Names.iter (fun role ->
        let degree = Hashtbl.find degrees role - 1 in
        Hashtbl.replace degrees role degree;
        if degree = 0 then Queue.add role ready) (Graph.find name graph)
  done;
  if !removed <> Graph.cardinal graph then Error "cycle detected in role inheritance"
  else Ok graph

let has_link graph subject target =
  let rec search remaining visited frontier =
    if remaining < 0 || Names.is_empty frontier then false
    else if Names.mem target frontier then true
    else
      let visited = Names.union visited frontier in
      let next = Names.fold
        (fun name acc -> match Graph.find_opt name graph with
          | None -> acc | Some roles -> Names.union roles acc)
        frontier Names.empty
      in
      search (remaining - 1) visited (Names.diff next visited)
  in
  search 10 Names.empty (Names.singleton subject)
