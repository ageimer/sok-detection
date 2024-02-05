/******************************************************************************/
/*  Copyright (c) 2007-2021,                                                  */
/*  Commissariat a l'Énergie Atomique et aux Énergies Alternatives (CEA)      */
/*  All rights reserved.                                                      */
/*                                                                            */
/*  Redistribution and use in source and binary forms, with or without        */
/*  modification, are permitted provided that the following conditions        */
/*  are met:                                                                  */
/*                                                                            */
/*   - Redistributions of source code must retain the above copyright         */
/*     notice, this list of conditions and the following disclaimer.          */
/*                                                                            */
/*   - Redistributions in binary form must reproduce the above copyright      */
/*     notice, this list of conditions and the following disclaimer in the    */
/*     documentation and/or other materials provided with the distribution.   */
/*                                                                            */
/*   - Neither the name of CEA nor the names of its contributors may be used  */
/*     to endorse or promote products derived from this software without      */
/*     specific prior written permission.                                     */
/*                                                                            */
/*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       */
/*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         */
/*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     */
/*  A PARTICULAR PURPOSE ARE DISCLAIMED.                                      */
/*  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY   */
/*  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        */
/*  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   */
/*  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     */
/*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       */
/*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING     */
/*  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE        */
/*  POSSIBILITY OF SUCH DAMAGE.                                               */
/******************************************************************************/

#include <aarch32/decoder.hh>

#include <vector>
#include <iostream>
#include <sstream>
#include <cstdint>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>

extern "C" value arm32dba_decode(value vmode, value vendian,
				 value vitstate, value vaddr, value vopcode) {
  std::stringstream s;
  armsec::Decoder decoder;

  decoder.iset = Long_val(vmode) ? decoder.Thumb : decoder.Arm;
  decoder.bigendian = Long_val(vendian);
  decoder.mode = unisim::component::cxx::processor::arm::PSR::USER_MODE;
  decoder.itstate = Long_val(vitstate);

  decoder.process( s, Int32_val(vaddr), Int32_val(vopcode) );

  return caml_copy_string(s.str().c_str());
}
