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

type size = int

type 'a interval = 'a Interval.t = { lo : 'a; hi : 'a }

type endianness = Machine.endianness = LittleEndian | BigEndian

type unary = U

and binary = B

type _ operator =
  | Not : unary operator
  | Sext : size -> unary operator
  | Uext : size -> unary operator
  | Restrict : int interval -> unary operator
  | Plus : binary operator
  | Minus : _ operator
  | Mul : binary operator
  | Udiv : binary operator (* Corresponds to *)
  | Umod : binary operator (* the truncated division *)
  | Sdiv : binary operator (* of C99 and most *)
  | Smod : binary operator (* processors *)
  | Or : binary operator
  | And : binary operator
  | Xor : binary operator
  | Concat : binary operator
  | Lsl : binary operator
  | Lsr : binary operator
  | Asr : binary operator
  | Rol : binary operator
  | Ror : binary operator
  | Eq : binary operator
  | Diff : binary operator
  | Ule : binary operator
  | Ult : binary operator
  | Uge : binary operator
  | Ugt : binary operator
  | Sle : binary operator
  | Slt : binary operator
  | Sge : binary operator
  | Sgt : binary operator

val pp_op : Format.formatter -> _ operator -> unit

module Bv : sig
  include module type of Bitvector

  val unary : unary operator -> t -> t

  val binary : binary operator -> t -> t -> t

  val extract : lo:size -> hi:size -> t -> t
end

type cst = C

and loc = L

and exp = E

type (_, _, 'a, 'b) t = private
  | Var : {
      hash : int;
      size : size;
      name : string;
      label : 'a;
    }
      -> (exp, _, 'a, _) t
  | Load : {
      hash : int;
      len : size;
      dir : endianness;
      addr : (exp, exp, 'a, 'b) t;
      label : 'b;
    }
      -> (exp, _, 'a, 'b) t
  | Cst : Bitvector.t -> (_, exp, _, _) t
  | Unary : {
      hash : int;
      size : size;
      f : unary operator;
      x : (exp, exp, 'a, 'b) t;
    }
      -> (exp, exp, 'a, 'b) t
  | Binary : {
      hash : int;
      size : size;
      f : binary operator;
      x : (exp, exp, 'a, 'b) t;
      y : (exp, exp, 'a, 'b) t;
    }
      -> (exp, exp, 'a, 'b) t
  | Ite : {
      hash : int;
      size : size;
      c : (exp, exp, 'a, 'b) t;
      t : (exp, exp, 'a, 'b) t;
      e : (exp, exp, 'a, 'b) t;
    }
      -> (exp, exp, 'a, 'b) t

module type S = sig
  type a

  and b

  type nonrec size = size

  type nonrec 'a interval = 'a interval = { lo : 'a; hi : 'a }

  type nonrec endianness = endianness = LittleEndian | BigEndian

  type 'a op = 'a operator =
    | Not : unary op
    | Sext : size -> unary op
    | Uext : size -> unary op
    | Restrict : int interval -> unary op
    | Plus : binary op
    | Minus : _ op
    | Mul : binary op
    | Udiv : binary op (* Corresponds to *)
    | Umod : binary op (* the truncated division *)
    | Sdiv : binary op (* of C99 and most *)
    | Smod : binary op (* processors *)
    | Or : binary op
    | And : binary op
    | Xor : binary op
    | Concat : binary op
    | Lsl : binary op
    | Lsr : binary op
    | Asr : binary op
    | Rol : binary op
    | Ror : binary op
    | Eq : binary op
    | Diff : binary op
    | Ule : binary op
    | Ult : binary op
    | Uge : binary op
    | Ugt : binary op
    | Sle : binary op
    | Slt : binary op
    | Sge : binary op
    | Sgt : binary op

  type ('k, 'l, 'a, 'b) term = ('k, 'l, 'a, 'b) t = private
    | Var : {
        hash : int;
        size : size;
        name : string;
        label : 'a;
      }
        -> (exp, _, 'a, _) term
    | Load : {
        hash : int;
        len : size;
        dir : endianness;
        addr : (exp, exp, 'a, 'b) term;
        label : 'b;
      }
        -> (exp, _, 'a, 'b) term
    | Cst : Bitvector.t -> (_, exp, _, _) term
    | Unary : {
        hash : int;
        size : size;
        f : unary operator;
        x : (exp, exp, 'a, 'b) term;
      }
        -> (exp, exp, 'a, 'b) term
    | Binary : {
        hash : int;
        size : size;
        f : binary operator;
        x : (exp, exp, 'a, 'b) term;
        y : (exp, exp, 'a, 'b) term;
      }
        -> (exp, exp, 'a, 'b) term
    | Ite : {
        hash : int;
        size : size;
        c : (exp, exp, 'a, 'b) term;
        t : (exp, exp, 'a, 'b) term;
        e : (exp, exp, 'a, 'b) term;
      }
        -> (exp, exp, 'a, 'b) term

  type t = (exp, exp, a, b) term

  (** {2 Constructors} *)

  val var : string -> size -> a -> t
  (** [var name bitsize label] *)

  val load : size -> endianness -> t -> b -> t
  (** [load nbytes endianness addr label] *)

  val constant : Bitvector.t -> t
  (** [constant bv] creates a constant expression from the bitvector [bv].
  *)

  val unary : unary op -> t -> t
  (** [unary f x] creates a unary application of [f] on [x].
  *)

  val binary : binary op -> t -> t -> t
  (** [binary f x y] creates a binary application of [f] on [x] and [y].
  *)

  val ite : t -> t -> t -> t
  (** [ite c t e] creates an if-then-else expression [c] ? [t] : [e].
  *)

  val uminus : t -> t

  val add : t -> t -> t

  val sub : t -> t -> t

  val mul : t -> t -> t

  val smod : t -> t -> t

  val umod : t -> t -> t

  val udiv : t -> t -> t

  val sdiv : t -> t -> t

  val append : t -> t -> t

  val equal : t -> t -> t

  val diff : t -> t -> t

  val ule : t -> t -> t

  val uge : t -> t -> t

  val ult : t -> t -> t

  val ugt : t -> t -> t

  val sle : t -> t -> t

  val sge : t -> t -> t

  val slt : t -> t -> t

  val sgt : t -> t -> t

  val logand : t -> t -> t

  val logor : t -> t -> t

  val lognot : t -> t

  val logxor : t -> t -> t

  val shift_left : t -> t -> t

  val shift_right : t -> t -> t

  val shift_right_signed : t -> t -> t
  (** [shift_(left|right) e q] shifts expression [e] by quantity [q], padding
      with zeroes *)

  val rotate_left : t -> t -> t

  val rotate_right : t -> t -> t
  (** [rotate_(left|right) e q] rotates expression [e] by quantity [q] *)

  val sext : size -> t -> t
  (** [sext sz e] performs a signed extension of expression [e] to size [sz] *)

  val uext : size -> t -> t
  (** [uext sz e] performs an unsigned extension expression [e] to size [sz] *)

  val restrict : lo:int -> hi:int -> t -> t
  (** [restrict lo hi e] creates [Dba.ExprUnary(Restrict(lo, hi), e)] if
      [hi >= lo && lo >=0] .
  *)

  val bit_restrict : int -> t -> t
  (** [bit_restrict o e] is [restrict o o e] *)

  (** {3 Specific constants }*)

  val zeros : int -> t
  (** [zeros n] creates a constant expression of value 0 with length [n] *)

  val ones : int -> t
  (** [ones n] creates a constant expression of value 1 with length [n].
      I.e.; it has (n - 1) zeros in binary.
  *)

  val one : t

  val zero : t

  val addi : t -> int -> t

  (** {4 Utils} **)

  val hash : t -> int
  (** [hash t] returns the hash of [t] in constant time.
  *)

  val is_equal : t -> t -> bool

  val compare : t -> t -> int

  val sizeof : t -> size
  (** [sizeof t] returns the bit size of [t] in constant time.
  *)

  val map : ('a -> a) -> ('b -> b) -> (_, _, 'a, 'b) term -> t
end

module Make (A : Sigs.HASHABLE) (B : Sigs.HASHABLE) :
  S with type a := A.t and type b := B.t

val to_exp : (_, _, 'a, 'b) t -> (exp, exp, 'a, 'b) t
(** {4 Conversion} **)

val to_loc : (_, _, 'a, 'b) t -> (exp, loc, 'a, 'b) t option

val to_loc_exn : (_, _, 'a, 'b) t -> (exp, loc, 'a, 'b) t

val to_cst : (_, _, _, _) t -> (cst, exp, _, _) t option

val to_cst_exn : (_, _, _, _) t -> (cst, exp, _, _) t

val pp : Format.formatter -> _ t -> unit
(** {5 Debug} **)
