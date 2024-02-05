(**************************************************************************)
(*  This file is part of BINSEC.                                          *)
(*                                                                        *)
(*  Copyright (C) 2016-2019                                               *)
(*    CEA (Commissariat à l'énergie atomique et aux énergies              *)
(*         alternatives)                                                  *)
(*                                                                        *)
(*  you can redistribute it and/or modify it under the terms of the GNU   *)
(*  Lesser General Public License as published by the Free Software       *)
(*  Foundation, version 2.1.                                              *)
(*                                                                        *)
(*  It is distributed in the hope that it will be useful,                 *)
(*  but WITHOUT ANY WARRANTY; without even the implied warranty of        *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *)
(*  GNU Lesser General Public License for more details.                   *)
(*                                                                        *)
(*  See the GNU Lesser General Public License version 2.1                 *)
(*  for more details (enclosed in the file licenses/LGPLv2.1).            *)
(*                                                                        *)
(**************************************************************************)

let byte_size = Natural.to_int Basic_types.Constants.bytesize

let id_ref = ref 0

let get_id () = incr id_ref; !id_ref

module Bv = Bitvector
module BiMap = Basic_types.BigInt.Map

module rec Expr : sig
  include Term.S with type a := bool and type b := Memory.t

  val is_secret_var : t -> bool

end = struct
  include Term.Make
    (struct
      type t = bool

      let compare = Bool.compare

      let equal = Bool.equal

      let hash = Bool.to_int
    end)
    (Memory)
  
  let is_secret_var = function
      | Expr.Var {label;_} -> label
      | _ -> assert false
end

and Memory : sig
  type t =
    | Unknown
    | Source of {
        id : int;
        over : t;
        addr : Bv.t;
        orig : Loader_buf.t;
        len : int;
      }
    | Layer of {
        id : int;
        over : t;
        addr : Expr.t;
        bytes : Expr.t BiMap.t;
        pop : int;
      }

  val compare : t -> t -> int

  val equal : t -> t -> bool

  val hash : t -> int

  val source : addr:Bv.t -> len:int -> Loader_buf.t -> t -> t

  val layer : addr:Expr.t -> ?pop:int -> Expr.t BiMap.t -> t -> t

  val write : addr:Expr.t -> Expr.t -> Expr.endianness -> t -> t

  val read : addr:Expr.t -> int -> Expr.endianness -> t -> Expr.t

  val pp : Format.formatter -> t -> unit
end = struct
  type t =
    | Unknown
    | Source of {
        id : int;
        over : t;
        addr : Bv.t;
        orig : Loader_buf.t;
        len : int;
      }
    | Layer of {
        id : int;
        over : t;
        addr : Expr.t;
        bytes : Expr.t BiMap.t;
        pop : int;
      }

  let hash = function Unknown -> 0 | Source { id; _ } | Layer { id; _ } -> id

  let compare t t' = hash t - hash t'

  let equal t t' = hash t = hash t'

  let source ~addr ~len orig over =
    Source { id = get_id (); orig; addr; len; over }

  let layer ~addr ?pop bytes over =
    let pop = match pop with
    | None -> BiMap.cardinal bytes
    | Some pop -> pop in
    Layer { id = get_id (); over; addr; bytes; pop}

  let byte n value =
    Expr.restrict ~lo:(byte_size * n) ~hi:((byte_size * (n + 1)) - 1) value

  let split dir value offset =
    let len = Expr.sizeof value / byte_size in
    match dir with
    | Expr.LittleEndian ->
        let rec fold n value offset map =
          if n = 0 then map
          else
            let n = n - 1 in
            fold n value offset
              (BiMap.add (Z.add offset (Z.of_int n)) (byte n value) map)
        in
        (fold len value offset BiMap.empty, len)
    | Expr.BigEndian ->
        let rec fold i n value offset map =
          if i = n then map
          else
            fold (i + 1) n value offset
              (BiMap.add
                 (Z.add offset (Z.of_int i))
                 (byte (n - i - 1) value)
                 map)
        in
        (fold 0 len value offset BiMap.empty, len)

  let layer_split addr value dir over =
    let bytes, pop = split dir value Z.zero in
    Layer { id = get_id (); over; addr; bytes; pop }

  let write ~addr value dir over =
    match over with
    | Unknown | Source _ -> layer_split addr value dir over
    | Layer {addr = addr'; bytes = bytes'; pop = pop'; over = over'; _ } -> (
        match Expr.sub addr addr' with
        | Expr.Cst bv ->
            let offset = Bv.signed_of bv in
            let bytes, pop = split dir value offset in
            let cnt = ref (pop' + pop) in
            let bytes =
              BiMap.union
                (fun _ _ b ->
                  decr cnt;
                  Some b)
                bytes' bytes
            in
            Layer { id = get_id (); over = over'; addr = addr'; bytes; pop = !cnt }
        | _ -> layer_split addr value dir over)

  let read =
    let concat dir buf =
      match dir with
      | Expr.LittleEndian ->
          let value = ref Array.(get buf (length buf - 1)) in
          for i = Array.length buf - 2 downto 0 do
            value := Expr.append !value (Array.get buf i)
          done;
          !value
      | Expr.BigEndian ->
          let value = ref Array.(get buf 0) in
          for i = 1 to Array.length buf - 1 do
            value := Expr.append !value (Array.get buf i)
          done;
          !value
    in
    let fill dir addr map buf memory =
      let map = ref map in
      let load = Expr.load (Array.length buf) dir addr memory in
      while !map <> Z.zero do
        let x = Z.trailing_zeros !map in
        Array.set buf x (byte x load);
        map := Z.(!map lxor (one lsl x))
      done
    in
    let rec lookup dir addr map buf memory =
      match memory with
      | Memory.Unknown -> fill dir addr map buf memory
      | Memory.Source { addr = base; len; orig; over; _ } -> (
          match addr with
          | Expr.Cst bv ->
              let offset = Bv.sub bv base in
              let map = ref map and map' = ref Z.zero in
              while !map <> Z.zero do
                let x = Z.trailing_zeros !map in
                (try
                   let y = Z.to_int (Bv.value_of (Bv.add_int offset x)) in
                   if y < len then
                     let v =
                       if y < Bigarray.Array1.dim orig then
                         Bigarray.Array1.unsafe_get orig y
                       else 0
                     in
                     Array.set buf x
                       (Expr.constant (Bv.of_int ~size:byte_size v))
                   else map' := Z.(!map' lor (one lsl x))
                 with Z.Overflow -> map' := Z.(!map' lor (one lsl x)));
                map := Z.(!map lxor (one lsl x))
              done;
              if !map' <> Z.zero then lookup dir addr !map' buf over
          | _ -> fill dir addr map buf memory)
      | Layer { addr = addr'; bytes; over; _ } -> (
          match Expr.sub addr addr' with
          | Expr.Cst bv ->
              let offset = Bv.signed_of bv in
              let map = ref map and map' = ref Z.zero in
              while !map <> Z.zero do
                let x = Z.trailing_zeros !map in
                let y = Z.add offset (Z.of_int x) in
                (match BiMap.find y bytes with
                | byte -> Array.set buf x byte
                | exception Not_found -> map' := Z.(!map' lor (one lsl x)));
                map := Z.(!map lxor (one lsl x))
              done;
              if !map' <> Z.zero then lookup dir addr !map' buf over
          | _ -> fill dir addr map buf memory)
    in
    fun ~addr bytes dir memory ->
      let buf = Array.make bytes Expr.zero (* no value *) in
      lookup dir addr (Z.pred (Z.shift_left Z.one bytes)) buf memory;
      concat dir buf

  let pp_bytes ppf bytes =
    BiMap.pp ppf Z.pp_print Term.pp bytes

  let pp ppf memory =
    let rec pp_node mem =
      match mem with
      | Unknown -> assert false
      | Layer {id; over = Unknown; addr; pop; bytes} -> 
          Format.fprintf ppf "Layer node %d : addr = %a , pop = %d, bytes = %a, over = Unknown" id Term.pp addr pop pp_bytes bytes
      | Layer {id; over = Layer {id = id'; _} as over; addr; pop; bytes} | Layer {id; over = Source {id = id'; _} as over; addr; pop; bytes} ->
        Format.fprintf ppf "Layer node %d : addr = %a , pop = %d, bytes = %a, over = Node %d\n" id Term.pp addr pop pp_bytes bytes id';
        pp_node over
      | Source {id; over = Unknown; addr; len; _} -> 
        Format.fprintf ppf "Source node %d : addr = %a , len = %d, over = Unknown" id Bv.pp addr len
      | Source {id; over = Layer {id = id'; _} as over; addr; len; _} | Source {id; over = Source {id = id'; _} as over; addr; len; _} ->
        Format.fprintf ppf "Source node %d : addr = %a , len = %d, over = Node %d\n" id Bv.pp addr len id';
        pp_node over
    in
    match memory with
    | Unknown -> Format.pp_print_string ppf "Unknown"
    | _ -> pp_node memory
end

module BvTbl = Hashtbl.Make (struct
  include Expr

  let equal = is_equal
end)

module AxTbl = Hashtbl.Make (Memory)
