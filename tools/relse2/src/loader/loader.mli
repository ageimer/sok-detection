(**************************************************************************)
(*  This file is part of BINSEC.                                          *)
(*                                                                        *)
(*  Copyright (C) 2016-2021                                               *)
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

type ('a, 'b, 'c) t_pack = ELF of 'a | PE of 'b | Dump of 'c

type ('a, 'b, 'c) header_pack =
  | ELF_header of 'a
  | PE_header of 'b
  | Dump_header of 'c

include
  Loader_sigs.S
    with type Section.t =
          ( Loader_elf.Section.t,
            Loader_pe.Section.t,
            Loader_dump.Section.t )
          t_pack
     and type Symbol.t =
          (Loader_elf.Symbol.t, Loader_pe.Symbol.t, Loader_dump.Symbol.t) t_pack
     and type Img.t =
          (Loader_elf.Img.t, Loader_pe.Img.t, Loader_dump.Img.t) t_pack
     and type Section.header =
          ( Loader_elf.Section.header,
            Loader_pe.Section.header,
            Loader_dump.Section.header )
          header_pack
     and type Symbol.header =
          ( Loader_elf.Symbol.header,
            Loader_pe.Symbol.header,
            Loader_dump.Symbol.header )
          header_pack
     and type Img.header =
          ( Loader_elf.Img.header,
            Loader_pe.Img.header,
            Loader_dump.Img.header )
          header_pack

module View : sig
  type t

  val create : Virtual_address.t -> Img.t -> Section.t -> t
  (** [create addr img section]
        create a virtual buffer with the content of [section]
        as if [img] was loaded at [add].
    *)

  val get : t -> Virtual_address.t -> Loader_types.u8
  (** [get t addr]
        read a byte at address [addr] in the view [t].

        @raise Not_found if [addr] is outside of [t].
    *)

  val unsafe_get : t -> Virtual_address.t -> Loader_types.u8
  (** [unsafe_get t addr]
        read a byte at address [addr] in the view [t].

        For avanced user only,
        it does not check that [addr] belongs to [t].
    *)
end
