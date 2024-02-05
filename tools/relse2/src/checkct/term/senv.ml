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

open Checkct_options

let solvers =
  let open Formula_options in
  [ Bitwuzla; Boolector; Z3; CVC4; Yices ]

let map =
  let open Formula_options in
  let open Smt_options in
  function
  | Best | Bitwuzla_native -> assert false
  | Bitwuzla_smtlib -> Bitwuzla
  | Boolector_smtlib -> Boolector
  | Z3_smtlib -> Z3
  | CVC4_smtlib -> CVC4
  | Yices_smtlib -> Yices

let get_solver_factory () =
  let open Formula_options in
  let open Smt_options in
  match Smt_options.SMTSolver.get () with
  | (Smt_options.Best | Smt_options.Bitwuzla_native) when Smt_bitwuzla.available
    ->
      (module Native_solver.Solver : Solver_sig.FACTORY)
  | Best -> (
      try
        let solver = List.find Prover.ping solvers in
        Logger.info "Found %a in the path." Prover.pp solver;
        Solver.set solver;
        (module Smt2_solver.Solver : Solver_sig.FACTORY)
      with Not_found -> Logger.fatal "No SMT solver found.")
  | Bitwuzla_native ->
      Logger.fatal "Native bitwuzla binding is required but not available."
  | solver when Prover.ping (map solver) ->
      Solver.set (map solver);
      (module Smt2_solver.Solver : Solver_sig.FACTORY)
  | solver ->
      Logger.fatal "%a is required but not available in path." Prover.pp
        (map solver)

exception Unknown = Checkct_types.Unknown

type 'a test = 'a Checkct_types.test =
  | True of 'a
  | False of 'a
  | Both of { t : 'a; f : 'a }

module Query_stats = struct
  module Preprocess = struct
    let sat = ref 0

    let unsat = ref 0

    let const = ref 0

    let total () = !sat + !unsat + !const

    let reset () =
      sat := 0;
      unsat := 0;
      const := 0

    let pp ppf () =
      let open Format in
      fprintf ppf
        "@[<v 2>@[<h>Preprocessing simplifications@]@,\
         @[<h>total          %d@]@,\
         @[<h>sat            %d@]@,\
         @[<h>unsat          %d@]@,\
         @[<h>constant enum  %d@]@]" (total ()) !sat !unsat !const

    let toml () =
      let open Toml in
      Min.of_key_values
        [
          (Min.key "total", Types.TInt (total ()));
          (Min.key "sat", Types.TInt !sat);
          (Min.key "unsat", Types.TInt !unsat);
          (Min.key "constant enum", Types.TInt !const);
        ]
  end

  module SMT = struct
    let sat = ref 0

    let unsat = ref 0

    let err = ref 0

    let time = ref 0.0

    let add_time t = time := !time +. t

    let total () = !sat + !unsat + !err

    let avg_time () = !time /. float (total ())

    let reset () =
      sat := 0;
      unsat := 0;
      err := 0;
      time := 0.0

    let pp ppf () =
      let open Format in
      fprintf ppf
        "@[<v 2>@[<h>Satisfiability queries@]@,\
         @[<h>total          %d@]@,\
         @[<h>sat            %d@]@,\
         @[<h>unsat          %d@]@,\
         @[<h>unknown        %d@]@,\
         @[<h>time           %.2f@]@,\
         @[<h>average        %.2f@]@]" (total ()) !sat !unsat !err !time
        (avg_time ())

    let toml () =
      let open Toml in
      Min.of_key_values
        [
          (Min.key "total", Types.TInt (total ()));
          (Min.key "sat", Types.TInt !sat);
          (Min.key "unsat", Types.TInt !unsat);
          (Min.key "unknown", Types.TInt !err);
          (Min.key "time", Types.TFloat !time);
          (Min.key "average", Types.TFloat (avg_time ()));
        ]
  end

  let _reset () =
    Preprocess.reset ();
    SMT.reset ()

  let pp ppf () =
    let open Format in
    fprintf ppf "@[<v 0>%a@,@,%a@,@]" Preprocess.pp () SMT.pp ()

  let toml () =
    let open Toml in
    Min.of_key_values
      [
        ( Min.key "Preprocessing simplifications",
          Types.TTable (Preprocess.toml ()) );
        (Min.key "Satisfiability queries", Types.TTable (SMT.toml ()));
      ]
end

module Ct_stats = struct
  type t = {
    cf_taint_secure : int;
    cf_cv_insecure : int;
    cf_secure : int;
    cf_insecure : int;
    cf_unknown : int;
    mem_taint_secure : int;
    mem_cv_insecure : int;
    mem_secure : int;
    mem_insecure : int;
    mem_unknown : int;
    solver_time : float;
  }

  let empty =
    {
      cf_taint_secure = 0;
      cf_cv_insecure = 0;
      cf_secure = 0;
      cf_insecure = 0;
      cf_unknown = 0;
      mem_taint_secure = 0;
      mem_cv_insecure = 0;
      mem_secure = 0;
      mem_insecure = 0;
      mem_unknown = 0;
      solver_time = 0.0;
    }

  let add_taint_secure is_cf s =
    if is_cf then { s with cf_taint_secure = s.cf_taint_secure + 1 }
    else { s with mem_taint_secure = s.mem_taint_secure + 1 }

  let add_cv_insecure is_cf s =
    if is_cf then { s with cf_cv_insecure = s.cf_cv_insecure + 1 }
    else { s with mem_cv_insecure = s.mem_cv_insecure + 1 }

  let add_secure is_cf s =
    if is_cf then { s with cf_secure = s.cf_secure + 1 }
    else { s with mem_secure = s.mem_secure + 1 }

  let add_insecure is_cf s =
    if is_cf then { s with cf_insecure = s.cf_insecure + 1 }
    else { s with mem_insecure = s.mem_insecure + 1 }

  let add_unknown is_cf s =
    if is_cf then { s with cf_unknown = s.cf_unknown + 1 }
    else { s with mem_unknown = s.mem_unknown + 1 }

  let add_solver_time t s = { s with solver_time = s.solver_time +. t }

  let pp ppf s =
    let cf =
      s.cf_taint_secure + s.cf_cv_insecure + s.cf_secure + s.cf_insecure
      + s.cf_unknown
    in
    let mem =
      s.mem_taint_secure + s.mem_cv_insecure + s.mem_secure + s.mem_insecure
      + s.mem_unknown
    in
    let avg_time =
      s.solver_time
      /. float
           (s.cf_unknown + s.cf_secure + s.cf_insecure + s.mem_unknown
          + s.mem_secure + s.mem_insecure)
    in
    Format.fprintf ppf
      "@[<v 0>@[<h 1>Control flow checks      %d@]@,\
       @[<h>  secure (taint)         %d@]@,\
       @[<h>  insecure (CV)          %d@]@,\
       @[<h>  secure (RelSE)         %d@]@,\
       @[<h>  insecure (RelSE)       %d@]@,\
       @[<h>  unknown                %d@]@,\
       @[<h>Memory access checks     %d@]@,\
       @[<h>  secure (taint)         %d@]@,\
       @[<h>  insecure (CV)          %d@]@,\
       @[<h>  secure (RelSE)         %d@]@,\
       @[<h>  insecure (RelSE)       %d@]@,\
       @[<h>  unknown                %d@]@,\
       @[<h>TOTAL                    %d@]@,\
       @[<h>Total solver time        %.2f@]@,\
       @[<h>Average solver time      %.2f@]@,\
       @]"
      cf s.cf_taint_secure s.cf_cv_insecure s.cf_secure s.cf_insecure
      s.cf_unknown mem s.mem_taint_secure s.mem_cv_insecure s.mem_secure
      s.mem_insecure s.mem_unknown (cf + mem) s.solver_time avg_time

  let toml s =
    let open Toml in
    let cf_toml =
      Min.of_key_values
        [
          (Min.key "secure (taint)", Types.TInt s.cf_taint_secure);
          (Min.key "insecure (CV)", Types.TInt s.cf_cv_insecure);
          (Min.key "secure (RelSE)", Types.TInt s.cf_secure);
          (Min.key "insecure (RelSE)", Types.TInt s.cf_insecure);
          (Min.key "unknown", Types.TInt s.cf_unknown);
        ]
    in
    let mem_toml =
      Min.of_key_values
        [
          (Min.key "secure (taint)", Types.TInt s.mem_taint_secure);
          (Min.key "insecure (CV)", Types.TInt s.mem_cv_insecure);
          (Min.key "secure (RelSE)", Types.TInt s.mem_secure);
          (Min.key "insecure (RelSE)", Types.TInt s.mem_insecure);
          (Min.key "unknown", Types.TInt s.mem_unknown);
        ]
    in
    Min.of_key_values
      [
        (Min.key "Control flow checks", Types.TTable cf_toml);
        (Min.key "Memory access checks", Types.TTable mem_toml);
        (Min.key "Solver time", Types.TFloat s.solver_time);
      ]

  module R = struct
    let value = ref empty

    let add_taint_secure is_cf = value := add_taint_secure is_cf !value

    let add_cv_insecure is_cf = value := add_cv_insecure is_cf !value

    let add_secure is_cf = value := add_secure is_cf !value

    let add_insecure is_cf = value := add_insecure is_cf !value

    let add_unknown is_cf = value := add_unknown is_cf !value

    let add_solver_time t = value := add_solver_time t !value

    let pp ppf () = pp ppf !value

    let toml () = toml !value
  end

  include R
end

(* utils *)
let pp_int_as_bv ppf x = function
  | 1 -> Format.fprintf ppf "#b%d" x
  | 4 -> Format.fprintf ppf "#x%01x" x
  | 8 -> Format.fprintf ppf "#x%02x" x
  | 12 -> Format.fprintf ppf "#x%03x" x
  | 16 -> Format.fprintf ppf "#x%04x" x
  | 20 -> Format.fprintf ppf "#x%05x" x
  | 24 -> Format.fprintf ppf "#x%06x" x
  | 28 -> Format.fprintf ppf "#x%07x" x
  | 32 -> Format.fprintf ppf "#x%08x" x
  | 64 when x >= 0 -> Format.fprintf ppf "#x%016x" x
  | sz -> Format.fprintf ppf "(_ bv%d %d)" x sz

let pp_bv ppf value size =
  try pp_int_as_bv ppf (Z.to_int value) size
  with Z.Overflow -> Format.fprintf ppf "(_ bv%a %d)" Z.pp_print value size

let byte_size = Natural.to_int Basic_types.Constants.bytesize

module BiTbl = Basic_types.BigInt.Htbl
module BiMap = Basic_types.BigInt.Map
module NiTbl = Basic_types.Int.Htbl
module Sname = Suid
open Sexpr
module BiItM = Imap
module BvSet = Set.Make (Expr)
module BvMap = Map.Make (Expr)
module MemMap = Map.Make (Memory)
module BitvectorSet = Set.Make (Bitvector)
module S = Basic_types.String.Map

module I = Map.Make (struct
  type t = Z.t

  let compare x y = -Z.compare x y
end)

module Model = struct
  type t = Bv.t BvTbl.t * char BiTbl.t

  let empty () : t = (BvTbl.create 0, BiTbl.create 0)

  let maybe_pp_char ppf c =
    if String_utils.is_char_printable c then Format.fprintf ppf " (%c)" c

  let concrete_values vars filter ((values, _) : t) =
    let values =
      S.map
        (fun list ->
          let rlist = List.rev list in
          List.filter_map
            (fun var ->
              if filter var then
                match BvTbl.find values var with
                | exception Not_found ->
                    None (* Any value can satsify the model *)
                | bv -> Some bv
              else None)
            rlist)
        vars
    in
    S.filter (fun _ l -> l <> []) values

  let pp_variables ppf vars values =
    if S.is_empty vars = false then (
      Format.pp_print_string ppf "# Variables";
      Format.pp_print_cut ppf ();
      S.iter
        (fun name list ->
          let list = List.rev list in
          Format.fprintf ppf "%s : @[<hov>%a@]@ " name
            (Format.pp_print_list ~pp_sep:Format.pp_print_space (fun ppf var ->
                 match BvTbl.find values var with
                 | exception Not_found -> Format.pp_print_string ppf "--"
                 | bv -> Bitvector.pp_hex_or_bin ppf bv))
            list;
          match list with
          | var :: _ :: _ when Expr.sizeof var = 8 ->
              Format.pp_print_string ppf "  [as ascii] ";
              List.iter
                (fun var ->
                  match BvTbl.find values var with
                  | exception Not_found -> Format.pp_print_string ppf "."
                  | bv -> Format.pp_print_char ppf (Bitvector.to_char bv))
                list;
              Format.pp_print_space ppf ()
          | _ -> ())
        vars)

  let pp_memory ppf memory addr_space =
    if BiTbl.length memory = 0 then
      Format.pp_print_string ppf "-- empty memory --"
    else (
      Format.pp_print_string ppf "# Memory";
      Format.pp_print_cut ppf ();
      let img = Kernel_functions.get_img () in
      let noname = "" in
      let section_name addr =
        let address = Virtual_address.to_int (Virtual_address.of_bigint addr) in
        match Loader_utils.find_section_by_address ~address img with
        | None -> noname
        | Some section -> Loader.Section.name section
      in
      let pp_section ppf name =
        if name == noname then Format.pp_print_string ppf "unamed section"
        else Format.fprintf ppf "section %s" name
      in
      let last_section = ref "--" in
      I.iter (fun addr byte ->
          let name = section_name addr in
          if name <> !last_section then (
            Format.fprintf ppf "; %a@ " pp_section name;
            last_section := name);
          pp_bv ppf addr addr_space;
          Format.fprintf ppf " : %02x %a@ " (Char.code byte) maybe_pp_char byte)
      @@ BiTbl.fold I.add memory I.empty)

  let pp ppf vars addr_space ((values, memory) : t) =
    if S.is_empty vars && BiTbl.length memory = 0 then
      Format.fprintf ppf "@[<h>--- Empty model ---@]"
    else (
      Format.fprintf ppf "@[<v 0>--- Model ---@ ";
      pp_variables ppf vars values;
      Format.pp_print_space ppf ();
      pp_memory ppf memory addr_space;
      Format.pp_close_box ppf ())

  let rec eval ((vars, _) as m : t) = function
    | Expr.Cst bv -> bv
    | e -> (
        try BvTbl.find vars e
        with Not_found ->
          let size = Expr.sizeof e in
          let value =
            match e with
            | Expr.Cst _ -> assert false
            | Expr.Var _ -> Bitvector.create (Z.of_int (Expr.hash e)) size
            | Expr.Load { addr; len; dir; label; _ } ->
                eval_load m (eval m addr) len dir label
            | Expr.Unary { f; x; _ } -> Term.Bv.unary f (eval m x)
            | Expr.Binary { f; x; y; _ } ->
                Term.Bv.binary f (eval m x) (eval m y)
            | Expr.Ite { c; t; e; _ } ->
                if Bv.zero = eval m c then eval m e else eval m t
          in
          BvTbl.add vars e value;
          value)

  and eval_load =
    let concat dir buf =
      let size = Bytes.length buf in
      let size' = size - 1 in
      if dir = Term.BigEndian then
        for i = 0 to (size / 2) - 1 do
          let j = size' - i in
          let x = Bytes.get buf i and y = Bytes.get buf j in
          Bytes.set buf i y;
          Bytes.set buf j x
        done;
      Bitvector.create
        (Z.of_bits (Bytes.unsafe_to_string buf))
        (byte_size * size)
    in
    let fill memory ptr map buf =
      let map = ref map in
      while !map <> Z.zero do
        let x = Z.trailing_zeros !map in
        let ptr = Bitvector.value_of (Bitvector.add_int ptr x) in
        let byte =
          match BiTbl.find memory ptr with
          | exception Not_found ->
              let byte =
                Char.unsafe_chr (Z.to_int (Z.logand ptr (Z.of_int 0xff)))
              in
              BiTbl.add memory ptr byte;
              byte
          | c -> c
        in
        Bytes.set buf x byte;
        map := Z.(!map lxor (one lsl x))
      done
    in
    let rec lookup ((_, memory) as m) ptr map buf = function
      | Memory.Unknown -> fill memory ptr map buf
      | Memory.Source { addr; len; orig; over; _ } ->
          let offset = Bv.sub ptr addr in
          let map = ref map and map' = ref Z.zero in
          while !map <> Z.zero do
            let x = Z.trailing_zeros !map in
            (try
               let y = Z.to_int (Bv.value_of (Bv.add_int offset x)) in
               if y < len then
                 if y < Bigarray.Array1.dim orig then
                   Bytes.set buf x
                     (Char.unsafe_chr (Bigarray.Array1.unsafe_get orig y))
                 else Bytes.set buf x '\x00'
               else map' := Z.(!map' lor (one lsl x))
             with Z.Overflow -> map' := Z.(!map' lor (one lsl x)));
            map := Z.(!map lxor (one lsl x))
          done;
          if !map' <> Z.zero then lookup m ptr !map' buf over
      | Layer { addr; bytes; over; _ } ->
          let addr = eval m addr in
          let offset = Bv.signed_of (Bv.sub ptr addr) in
          let map = ref map and map' = ref Z.zero in
          while !map <> Z.zero do
            let x = Z.trailing_zeros !map in
            let y = Z.add offset (Z.of_int x) in
            (match BiMap.find y bytes with
            | byte -> Bytes.set buf x (Bitvector.to_char (eval m byte))
            | exception Not_found -> map' := Z.(!map' lor (one lsl x)));
            map := Z.(!map lxor (one lsl x))
          done;
          if !map' <> Z.zero then lookup m ptr !map' buf over
    in
    fun (m : t) ptr len dir memory ->
      let buf = Bytes.make len '\x00' (* no value *) in
      lookup m ptr (Z.pred (Z.shift_left Z.one len)) buf memory;
      concat dir buf

  let manual_var_set ((variables, _) : t) var value =
    BvTbl.add variables var value
end

module State (F : Solver_sig.FACTORY) = struct
  type t = {
    constraints : Expr.t list;
    (* reversed sequence of assertions *)
    constset : BvSet.t;
    vsymbols : Expr.t S.t;
    (* collection of visible symbols *)
    emirror : Expr.t BvMap.t;
    (* collection of mirrors of expressions *)
    mmirror : Memory.t MemMap.t;
    (* collection of mirrors of memory *)
    vmemory : Memory.t;
    (* visible memory *)
    fid : Sname.t;
    (* unique indice counter *)
    fvariables : Expr.t list S.t;
    (* collection of free variables *)
    ilocs : (Z.t * Loader_buf.t) BiItM.t;
    (* set of initialized memory locations *)
    model : Model.t; (* a model that satisfy constraints *)
  }

  let pp ppf state =
    Model.pp ppf state.fvariables
      (Kernel_options.Machine.word_size ())
      state.model

  let empty () =
    {
      constraints = [];
      constset = BvSet.empty;
      vsymbols = S.empty;
      emirror = BvMap.empty;
      mmirror = MemMap.empty;
      vmemory = Memory.Unknown;
      fid = Sname.(incr zero);
      (* zero is reserved for initial memory *)
      fvariables = S.empty;
      ilocs = BiItM.empty;
      model = Model.empty ();
    }

  let fresh name size ?(secret = false) state =
    let fid = Sname.incr state.fid in
    let v = Expr.var (Sname.to_string state.fid) size secret in
    let h =
      match S.find name state.fvariables with
      | exception Not_found -> [ v ]
      | h -> v :: h
    in
    let fvariables = S.add name h state.fvariables in
    let vsymbols = S.add name v state.vsymbols in
    if secret then
      let mirror_v = Expr.var (Sname.to_string fid) size false in
      let fid = Sname.incr fid in
      let emirror = BvMap.add v mirror_v state.emirror in
      { state with vsymbols; fid; fvariables; emirror }
    else { state with vsymbols; fid; fvariables }

  let assign name value state =
    { state with vsymbols = S.add name value state.vsymbols }

  let write ~addr value dir state =
    { state with vmemory = Memory.write ~addr value dir state.vmemory }

  let rec lookup name size state =
    match S.find name state.vsymbols with
    | exception Not_found -> lookup name size (fresh name size state)
    | bv -> (bv, state)

  let read ~addr bytes dir state = Memory.read ~addr bytes dir state.vmemory

  let memcpy ~addr len orig state =
    let base = Bv.value_of addr in
    let ilocs = BiItM.add ~base len (Bv.value_of addr, orig) state.ilocs in
    let vmemory = Memory.source ~addr ~len orig state.vmemory in
    { state with ilocs; vmemory }

  module Engine (Solver : Solver_sig.S) = struct
    type result = Unsat | Sat of t

    let extract_memory state =
      match Solver.get_memory () with
      | exception Not_found -> (BiTbl.create 0, state.constraints)
      | array, history ->
          let dirty = BiTbl.create 32 and memory = BiTbl.create 32 in
          let addr_space = Kernel_options.Machine.word_size () in
          let constraints =
            Queue.fold
              (fun constraints (access : Solver.access) ->
                match access with
                | Select (index, len) ->
                    let index = Solver.get_value index in
                    let z = Solver.assignment index in
                    let rec fold z index len memory constraints =
                      if len = 0 then constraints
                      else if BiTbl.mem dirty z then
                        fold
                          Z.(z + one)
                          (Solver.succ index) (len - 1) memory constraints
                      else
                        let k = Solver.get_at array index in
                        let v = Z.to_int k in
                        let constraints =
                          match BiItM.find z state.ilocs with
                          | exception Not_found ->
                              BiTbl.add memory z (Char.unsafe_chr v);
                              constraints
                          | base, img ->
                              let y = Z.to_int (Z.sub z base) in
                              let v' =
                                if y < Bigarray.Array1.dim img then
                                  Bigarray.Array1.get img y
                                else 0
                              in
                              if v <> v' then
                                Expr.(
                                  equal
                                    (load 1 LittleEndian
                                       (constant (Bv.create z addr_space))
                                       Memory.Unknown)
                                    (constant (Bv.of_int ~size:byte_size v')))
                                :: constraints
                              else constraints
                        in
                        fold
                          Z.(z + one)
                          (Solver.succ index) (len - 1) memory constraints
                    in
                    fold z index len memory constraints
                | Store index ->
                    let z = Solver.(assignment (get_value index)) in
                    BiTbl.replace dirty z ();
                    constraints)
              state.constraints history
          in
          (memory, constraints)

    let extract_vars state =
      let vars = BvTbl.create 32 in
      S.iter
        (fun _ ->
          List.iter (fun bv ->
              match Solver.get bv with
              | exception Not_found -> ()
              | x ->
                  BvTbl.add vars bv
                    (Bitvector.create
                       Solver.(assignment (get_value x))
                       (Expr.sizeof bv))))
        state.fvariables;
      vars

    let rec force_lazy_init constraints state =
      if constraints == state.constraints = false then
        match constraints with
        | [] -> ()
        | eq :: constraints ->
            let addr, value =
              match eq with
              | Binary
                  { f = Eq; x = Load { addr = Cst addr; _ }; y = Cst value; _ }
                ->
                  (Bitvector.value_of addr, Bitvector.value_of value)
              | _ -> assert false
            in
            Solver.set_memory ~addr value;
            force_lazy_init constraints state

    let enumerate =
      let rec iter state e expr size n enum =
        if n = 0 then enum
        else
          match Solver.check_sat () with
          | Unknown ->
              incr Query_stats.SMT.err;
              raise Unknown
          | Unsat ->
              incr Query_stats.SMT.unsat;
              enum
          | Sat ->
              incr Query_stats.SMT.sat;
              let memory, constraints = extract_memory state in
              if constraints == state.constraints = false then (
                force_lazy_init constraints state;
                iter { state with constraints } e expr size n enum)
              else
                let x = Solver.(assignment (get_value expr)) in
                let b = Bv.create x size in
                let cond = Expr.equal e (Expr.constant b) in
                let state' =
                  {
                    state with
                    constraints = cond :: constraints;
                    constset = BvSet.add cond state.constset;
                    model = (extract_vars state, memory);
                  }
                in
                Solver.neq expr x;
                iter state e expr size (n - 1) ((b, state') :: enum)
      in
      fun e ?(n = (1 lsl Expr.sizeof e) - 1) ?(except = []) state ->
        let size = Expr.sizeof e in
        let expr = Solver.bind state.fid e state.constraints in
        let init =
          let bv = Model.eval state.model e in
          if List.mem bv except then []
          else (
            incr Query_stats.Preprocess.const;
            Solver.neq expr (Bitvector.value_of bv);
            let cond = Expr.equal e (Expr.constant bv) in
            [
              ( bv,
                {
                  state with
                  constraints = cond :: state.constraints;
                  constset = BvSet.add cond state.constset;
                } );
            ])
        in
        List.iter (fun bv -> Solver.neq expr (Bitvector.value_of bv)) except;
        iter state e expr size (n - 1) init

    let check_sat =
      let rec check_sat_true state =
        match Solver.check_sat () with
        | Unknown -> raise Unknown
        | Unsat -> Unsat
        | Sat ->
            let memory, constraints = extract_memory state in
            if constraints == state.constraints = false then (
              force_lazy_init constraints state;
              check_sat_true { state with constraints })
            else Sat { state with model = (extract_vars state, memory) }
      in
      fun state ->
        Solver.put state.fid state.constraints;
        check_sat_true state

    let close () = Solver.close ()
  end

  let rec is_tainted (exp : Expr.t) =
    (* Logger.debug ~level:6 "Checking if expression %a is tainted" Term.pp exp; *)
    match exp with
    | Expr.Cst _ -> false
    | Expr.Var { label; _ } -> label
    | Expr.Load { label; _ } -> is_tainted_memory label
    | Expr.Unary { x; _ } -> is_tainted x
    | Expr.Binary { x; y; _ } -> is_tainted x || is_tainted y
    | Expr.Ite { c; t; e; _ } -> is_tainted c || is_tainted t || is_tainted e

  and is_tainted_memory m =
    match m with
    | Unknown -> false
    | Layer _ -> true
    | Source { over; _ } -> is_tainted_memory over

  let taint_analysis exp (state : t) =
    let open Checkct_types in
    if is_tainted exp then (Ct_status.CT_Unknown, state)
    else (Ct_status.CT_Secure, state)

  let rec make_mirror exp state =
    (* Logger.debug ~level:6 "Building mirror of expression %a" Term.pp e; *)
    if BvMap.mem exp state.emirror then (BvMap.find exp state.emirror, state)
    else
      let mirror_exp, state =
        match exp with
        | Expr.Var { label; _ } when label ->
            assert false (* secrets should already be in the mirror *)
        | Expr.Var _ | Expr.Cst _ -> (exp, state)
        | Expr.Load { label; len; dir; addr; _ } ->
            let mirror_label, state = mirror_memory label state in
            let mirror_addr, state = make_mirror addr state in
            let mirror_exp =
              if mirror_label != label || mirror_addr != addr then
                Expr.load len dir mirror_addr mirror_label
              else exp
            in
            (mirror_exp, state)
        | Expr.Unary { x; f; _ } ->
            let mirror_x, state = make_mirror x state in
            let mirror_exp =
              if mirror_x != x then Expr.unary f mirror_x else exp
            in
            (mirror_exp, state)
        | Expr.Binary { x; y; f; _ } ->
            let mirror_x, state = make_mirror x state in
            let mirror_y, state = make_mirror y state in
            let mirror_exp =
              if mirror_x != x || mirror_y != y then
                Expr.binary f mirror_x mirror_y
              else exp
            in
            (mirror_exp, state)
        | Expr.Ite { c; t; e; _ } ->
            let mirror_c, state = make_mirror c state in
            let mirror_t, state = make_mirror t state in
            let mirror_e, state = make_mirror e state in
            let mirror_exp =
              if mirror_c != c || mirror_t != t || mirror_e != e then
                Expr.ite mirror_c mirror_t mirror_e
              else exp
            in
            (mirror_exp, state)
      in
      let emirror = BvMap.add exp mirror_exp state.emirror in
      (mirror_exp, { state with emirror })

  and mirror_memory m state =
    if MemMap.mem m state.mmirror then (MemMap.find m state.mmirror, state)
    else
      let mirror_m, state =
        match m with
        | Unknown -> (m, state)
        | Source { over; addr; len; orig; _ } ->
            let mirror_over, state = mirror_memory over state in
            let mirror_m =
              if mirror_over != over then
                Memory.source ~addr ~len orig mirror_over
              else m
            in
            (mirror_m, state)
        | Layer { addr; bytes; over; pop; _ } ->
            let fold_bytes k b (mirror_bytes, state, rebuilt_bytes) =
              let mirror_b, state = make_mirror b state in
              let mirror_bytes = BiMap.add k mirror_b mirror_bytes in
              let rebuilt_bytes = rebuilt_bytes || b != mirror_b in
              (mirror_bytes, state, rebuilt_bytes)
            in
            let mirror_bytes, state, rebuilt_bytes =
              BiMap.fold fold_bytes bytes (BiMap.empty, state, false)
            in
            let mirror_over, state = mirror_memory over state in
            let mirror_m =
              if rebuilt_bytes || mirror_over != over then
                Memory.layer ~addr ~pop mirror_bytes mirror_over
              else m
            in
            (mirror_m, state)
      in
      let mmirror = MemMap.add m mirror_m state.mmirror in
      (mirror_m, { state with mmirror })

  let cv_analysis (e : Expr.t) state =
    (* Initialize low variables through the ancient model*)
    let vars = BvTbl.create 32 in
    let secrets = ref BvSet.empty in
    S.iter
      (fun _ ->
        List.iter (fun bv ->
            if Expr.is_secret_var bv then secrets := BvSet.add bv !secrets
            else BvTbl.add vars bv (Model.eval state.model bv)))
      state.fvariables;
    let memory = snd state.model in
    let init_funs =
      [
        Bitvector.zeros;
        (* 0 *)
        Bitvector.ones;
        (* 1 *)
        Bitvector.fill;
        (* 111...11 *)
        (* Bitvector.max_sbv; *)
        (* (fun size -> Bitvector.fill ~lo:(size/2) size); *)
        (* (fun size -> Bitvector.fill ~hi:(size/2 - 1) size); *)
      ]
    in
    let n = List.length init_funs in
    let models = List.init n (fun _ -> (BvTbl.copy vars, memory)) in
    let init_secrets model init_fun =
      BvSet.iter
        (fun bv ->
          match bv with
          | Expr.Var { size; _ } ->
              Model.manual_var_set model bv (init_fun size)
          | _ -> assert false)
        !secrets
    in
    List.iter2 init_secrets models init_funs;
    let refmod = List.hd models in
    let refval = Model.eval refmod e in
    let rec find_violating_model l =
      match l with
      | [] -> None
      | hd :: tl ->
          let newval = Model.eval hd e in
          if newval = refval then find_violating_model tl else Some hd
    in
    let violating_model = find_violating_model (List.tl models) in
    let open Checkct_types in
    match violating_model with
    | None -> (Ct_status.CT_Unknown, state)
    | Some othermod ->
        let public =
          Model.concrete_values state.fvariables
            (fun x -> not (Expr.is_secret_var x))
            state.model
        in
        let secret1 =
          Model.concrete_values state.fvariables Expr.is_secret_var refmod
        in
        let secret2 =
          Model.concrete_values state.fvariables Expr.is_secret_var othermod
        in
        (CT_Insecure { public; secret1; secret2 }, state)

  let relse_analysis expr state =
    let open Checkct_types in
    (* mirror the expression *)
    let mirror_expr, state = make_mirror expr state in
    if (not (Checkct_options.RelseIsDumb.get ())) && expr = mirror_expr then
      (Ct_status.CT_Secure, state) (* if not tainted, no need to do relse *)
    else
      (* mirror the constraints *)
      let all_constraints = ref state.constraints in
      let all_constset = ref state.constset in
      let state =
        List.fold_left
          (fun state bv ->
            let mirror_bv, state = make_mirror bv state in
            if bv != mirror_bv then (
              all_constraints := mirror_bv :: !all_constraints;
              all_constset := BvSet.add mirror_bv !all_constset);
            state)
          state state.constraints
      in

      (* add the final condition *)
      let final_constraint = Expr.binary Term.Diff expr mirror_expr in
      all_constraints := final_constraint :: !all_constraints;
      all_constset := BvSet.add final_constraint !all_constset;

      (* Extract the secrets' mirrors *)
      let secret_mirrors =
        S.fold
          (fun name l secret_mirrors ->
            let new_l =
              List.fold_left
                (fun new_l bv ->
                  if Expr.is_secret_var bv then
                    let mirror_bv = BvMap.find bv state.emirror in
                    mirror_bv :: new_l
                  else new_l)
                [] l
            in
            if List.length new_l > 0 then S.add name new_l secret_mirrors
            else secret_mirrors)
          state.fvariables S.empty
      in

      (* add the secrets' mirrors to the free variables *)
      let all_variables =
        S.union
          (fun _ l1 l2 -> Some (List.rev_append l1 l2))
          state.fvariables secret_mirrors
      in

      (* send the insecurity query *)
      let insec_state =
        {
          state with
          constraints = !all_constraints;
          constset = !all_constset;
          fvariables = all_variables;
        }
      in
      let t0 = Unix.gettimeofday () in
      let open Engine (F ()) in
      let res =
        match check_sat insec_state with
        | exception Unknown -> Ct_status.CT_Unknown
        | Unsat -> CT_Secure
        | Sat t ->
            let public =
              Model.concrete_values state.fvariables
                (fun x -> not (Expr.is_secret_var x))
                t.model
            in
            let secret1 =
              Model.concrete_values state.fvariables Expr.is_secret_var t.model
            in
            let secret2 =
              Model.concrete_values secret_mirrors (fun _ -> true) t.model
            in
            CT_Insecure { public; secret1; secret2 }
      in
      close ();
      let t1 = Unix.gettimeofday () in
      Ct_stats.add_solver_time (t1 -. t0);
      (res, state)

  let do_check_ct (expr : Expr.t) ~is_cf (state : t) =
    let open Checkct_types in
    let open Ct_status in
    (*TODO : this could probably be made cleaner using functors*)
    let anal_funs =
      [
        ( Taint.get (),
          "taint",
          taint_analysis,
          Ct_stats.add_taint_secure,
          fun _ -> assert false );
        ( ChosenValues.get (),
          "chosen values",
          cv_analysis,
          (fun _ -> assert false),
          Ct_stats.add_cv_insecure );
        ( Relse.get (),
          "RelSE",
          relse_analysis,
          Ct_stats.add_secure,
          Ct_stats.add_insecure );
      ]
    in
    let anal_funs = List.filter (fun (b, _, _, _, _) -> b) anal_funs in
    let rec apply_analysis_functions l state =
      match l with
      | [] ->
          Ct_stats.add_unknown is_cf;
          Logger.debug ~level:3 "Expression status is unknown";
          (CT_Unknown, state)
      | (_, name, anal_func, callback_secure, callback_insecure) :: tl -> (
          let res, state = anal_func expr state in
          match res with
          | CT_Secure ->
              callback_secure is_cf;
              Logger.debug ~level:3 "Proven secure by %s" name;
              (res, state)
          | CT_Insecure model ->
              Logger.debug ~level:2
                "@[<v 0>@[Proven insecure by %s@]@,\
                 @[Insecurity model :@]@,\
                 @[%a@]@]"
                name Insec_model.pp model;
              callback_insecure is_cf;
              (res, state)
          | CT_Unknown -> apply_analysis_functions tl state)
    in

    apply_analysis_functions anal_funs state

  let assume cond state =
    if Expr.is_equal cond Expr.one then (
      incr Query_stats.Preprocess.sat;
      Some state)
    else if Expr.is_equal cond Expr.zero then (
      incr Query_stats.Preprocess.unsat;
      None)
    else if BvSet.mem cond state.constset then (
      incr Query_stats.Preprocess.sat;
      Some state)
    else if BvSet.mem (Expr.lognot cond) state.constset then (
      incr Query_stats.Preprocess.unsat;
      None)
    else
      let state =
        {
          state with
          constraints = cond :: state.constraints;
          constset = BvSet.add cond state.constset;
        }
      in
      if Bitvector.zero = Model.eval state.model cond then (
        let t0 = Unix.gettimeofday () in
        let open Engine (F ()) in
        let r =
          match check_sat state with
          | exception Unknown ->
              incr Query_stats.SMT.err;
              raise Unknown
          | Unsat ->
              incr Query_stats.SMT.unsat;
              None
          | Sat state ->
              incr Query_stats.SMT.sat;
              Some state
        in
        close ();
        let t1 = Unix.gettimeofday () in
        Query_stats.SMT.add_time (t1 -. t0);
        r)
      else (
        incr Query_stats.Preprocess.sat;
        Some state)

  let test cond state =
    if Expr.is_equal cond Expr.one then (
      incr Query_stats.Preprocess.sat;
      True state)
    else if Expr.is_equal cond Expr.zero then (
      incr Query_stats.Preprocess.unsat;
      False state)
    else if BvSet.mem cond state.constset then (
      incr Query_stats.Preprocess.sat;
      True state)
    else if BvSet.mem (Expr.lognot cond) state.constset then (
      incr Query_stats.Preprocess.unsat;
      False state)
    else
      let t =
        {
          state with
          constraints = cond :: state.constraints;
          constset = BvSet.add cond state.constset;
        }
      in
      let ncond = Expr.lognot cond in
      let f =
        {
          state with
          constraints = ncond :: state.constraints;
          constset = BvSet.add ncond state.constset;
        }
      in
      let e = Model.eval state.model cond in
      let s = if Bv.is_zero e then t else f in
      let t0 = Unix.gettimeofday () in
      let open Engine (F ()) in
      let r =
        match check_sat s with
        | exception Unknown ->
            incr Query_stats.SMT.err;
            raise Unknown
        | Unsat ->
            incr Query_stats.SMT.unsat;
            if Bv.is_zero e then False f else True t
        | Sat state ->
            incr Query_stats.SMT.sat;
            if Bv.is_zero e then Both { t = state; f }
            else Both { t; f = state }
      in
      close ();
      let t1 = Unix.gettimeofday () in
      Query_stats.SMT.add_time (t1 -. t0);
      r

  let enumerate =
    let with_solver e ?n ?except state =
      let t0 = Unix.gettimeofday () in
      let open Engine (F ()) in
      let r = enumerate e ?n ?except state in
      close ();
      let t1 = Unix.gettimeofday () in
      Query_stats.SMT.add_time (t1 -. t0);
      r
    in
    fun e ?n ?(except = []) state ->
      match (e, n) with
      | Expr.Cst bv, _ when List.mem bv except = false ->
          incr Query_stats.Preprocess.const;
          [ (bv, state) ]
      | Expr.Cst _, _ ->
          incr Query_stats.Preprocess.const;
          []
      | _, Some 1 ->
          let bv = Model.eval state.model e in
          if List.mem bv except then with_solver e ?n ~except state
          else (
            incr Query_stats.Preprocess.const;
            let cond = Expr.equal e (Expr.constant bv) in
            [
              ( bv,
                {
                  state with
                  constraints = cond :: state.constraints;
                  constset = BvSet.add cond state.constset;
                } );
            ])
      | _, _ -> with_solver e ?n ~except state

  module Translate = struct
    let unary e = function
      | Dba.Unary_op.Not -> Term.Not
      | Dba.Unary_op.UMinus -> Term.Minus
      | Dba.Unary_op.Sext n -> Term.Sext (n - Dba.Expr.size_of e)
      | Dba.Unary_op.Uext n -> Term.Uext (n - Dba.Expr.size_of e)
      | Dba.Unary_op.Restrict interval -> Term.Restrict interval

    let binary op =
      let open Dba.Binary_op in
      match op with
      | Plus -> Term.Plus
      | Minus -> Term.Minus
      | Mult -> Term.Mul
      | DivU -> Term.Udiv
      | DivS -> Term.Sdiv
      | ModU -> Term.Umod
      | ModS -> Term.Smod
      | Eq -> Term.Eq
      | Diff -> Term.Diff
      | LeqU -> Term.Ule
      | LtU -> Term.Ult
      | GeqU -> Term.Uge
      | GtU -> Term.Ugt
      | LeqS -> Term.Sle
      | LtS -> Term.Slt
      | GeqS -> Term.Sge
      | GtS -> Term.Sgt
      | Xor -> Term.Xor
      | And -> Term.And
      | Or -> Term.Or
      | Concat -> Term.Concat
      | LShift -> Term.Lsl
      | RShiftU -> Term.Lsr
      | RShiftS -> Term.Asr
      | LeftRotate -> Term.Rol
      | RightRotate -> Term.Ror

    let rec expr symbolic_state e =
      match e with
      | Dba.Expr.Var { info = Symbol (_, (lazy bv)); _ } | Dba.Expr.Cst bv ->
          (Expr.constant bv, symbolic_state)
      | Dba.Expr.Var { name; size; _ } -> lookup name size symbolic_state
      | Dba.Expr.Load (bytes, endianness, e) ->
          let addr, symbolic_state = expr symbolic_state e in
          (read ~addr bytes endianness symbolic_state, symbolic_state)
      | Dba.Expr.Binary (bop, lop, rop) ->
          let lop, symbolic_state = expr symbolic_state lop in
          let rop, symbolic_state = expr symbolic_state rop in
          (Expr.binary (binary bop) lop rop, symbolic_state)
      | Dba.Expr.Unary (uop, e) ->
          let v, symbolic_state = expr symbolic_state e in
          (Expr.unary (unary e uop) v, symbolic_state)
      | Dba.Expr.Ite (c, then_e, else_e) -> (
          let cond, symbolic_state = expr symbolic_state c in
          match cond with
          | Expr.Cst bv when Bv.is_zero bv -> expr symbolic_state else_e
          | Expr.Cst _ -> expr symbolic_state then_e
          | _ ->
              let then_smt, symbolic_state = expr symbolic_state then_e in
              let else_smt, symbolic_state = expr symbolic_state else_e in
              (Expr.ite cond then_smt else_smt, symbolic_state))
  end

  let assume e t =
    let e, t = Translate.expr t e in
    assume e t

  let test e t =
    let e, t = Translate.expr t e in
    test e t

  let split_on e ?n ?except t =
    let e, t = Translate.expr t e in
    enumerate e ?n ?except t

  let assign name e t =
    let e, t = Translate.expr t e in
    assign name e t

  let write ~addr value dir t =
    let addr, t = Translate.expr t addr in
    let value, t = Translate.expr t value in
    write ~addr value dir t

  let ctstatus_and a b t =
    let open Checkct_types in
    let status, t = a t in
    match status with
    | Ct_status.CT_Insecure _ -> (status, t)
    | CT_Secure -> b t
    | CT_Unknown ->
        let status, t = b t in
        let status =
          match status with CT_Insecure _ -> status | _ -> CT_Unknown
        in
        (status, t)

  let check_ct e ~is_cf t =
    let e, t = Translate.expr t e in
    do_check_ct e ~is_cf t

  let rec check_ct_loads e t =
    match e with
    | Dba.Expr.Var _ | Dba.Expr.Cst _ -> (Checkct_types.Ct_status.CT_Secure, t)
    | Dba.Expr.Load (_, _, addr) ->
        ctstatus_and (check_ct_loads addr) (check_ct ~is_cf:false addr) t
    | Dba.Expr.Binary (_, lop, rop) ->
        ctstatus_and (check_ct_loads lop) (check_ct_loads rop) t
    | Dba.Expr.Unary (_, e) -> check_ct_loads e t
    | Dba.Expr.Ite (c, then_e, else_e) ->
        ctstatus_and
          (ctstatus_and (check_ct_loads c) (check_ct_loads then_e))
          (check_ct_loads else_e) t

  let pp_smt ?slice ppf t =
    let module P = Smt2_solver.Printer in
    let ctx = P.create ~next_id:t.fid () in
    (* visit assertions *)
    List.iter (P.visit_bl ctx) t.constraints;
    (* visit terms *)
    let defs =
      match slice with
      | Some defs ->
          List.map
            (fun (expr, name) ->
              let expr, _ = Translate.expr t expr in
              P.visit_bv ctx expr;
              (expr, name))
            defs
      | None ->
          P.visit_ax ctx t.vmemory;
          List.rev
            (S.fold
               (fun name expr defs ->
                 P.visit_bv ctx expr;
                 (expr, name) :: defs)
               t.vsymbols [])
    in
    Format.pp_open_vbox ppf 0;
    (* print declarations *)
    P.pp_print_decls ppf ctx;
    Format.pp_open_hovbox ppf 0;
    (* print definitions *)
    P.pp_print_defs ppf ctx;
    List.iter
      (fun (bv, name) ->
        Format.fprintf ppf "(define-fun %s () (_ BitVec %d)@ " name
          (Expr.sizeof bv);
        P.pp_print_bv ctx ppf bv;
        Format.fprintf ppf ")@ ")
      defs;
    (* print assertions *)
    List.iter
      (fun bl ->
        Format.pp_print_string ppf "(assert ";
        P.pp_print_bl ctx ppf bl;
        Format.pp_print_char ppf ')';
        Format.pp_print_space ppf ())
      t.constraints;
    Format.pp_close_box ppf ();
    Format.pp_close_box ppf ()

  let as_ascii name t =
    let buf = Buffer.create 16 in
    List.iter (fun var ->
        assert (Expr.sizeof var mod byte_size = 0);
        let rec iter bv =
          let size = Bitvector.size_of bv in
          if size = byte_size then Buffer.add_char buf (Bitvector.to_char bv)
          else
            let byte = Bitvector.extract bv { Interval.lo = 0; hi = 7 } in
            Buffer.add_char buf (Bitvector.to_char byte);
            iter (Bitvector.extract bv { Interval.lo = 8; hi = size - 1 })
        in
        iter (Model.eval t.model var))
    @@ List.rev @@ S.find name t.fvariables;
    Buffer.contents buf

  let pp_stats ppf () =
    Format.fprintf ppf "@[<v 2>SMT queries@,%a@]@,@[<v 2>CT checks@,%a@]"
      Query_stats.pp () Ct_stats.pp ()

  let toml_stats () =
    let open Toml in
    Min.of_key_values
      [
        (Min.key "SMT queries", Types.TTable (Query_stats.toml ()));
        (Min.key "CT checks", Types.TTable (Ct_stats.toml ()));
      ]
end
