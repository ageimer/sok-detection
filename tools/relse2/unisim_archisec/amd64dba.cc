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

#include <amd64/decoder.hh>
#include <vector>
#include <iostream>
#include <sstream>
#include <cstdint>

namespace intel {
  int decode(bool, uint64_t, std::vector<uint8_t>, std::ostream&);
}

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>

uint8_t nibble_value(char n) {
  if (('0' <= n) && (n <= '9'))
    return n - '0';
  else if (('a' <= n) && (n <= 'f'))
    return n - 'a' + 10;
  else if (('A' <= n) && (n <= 'F'))
    return n - 'A' + 10;
  else
    caml_invalid_argument("not a valid hexadecimal digit");
}

extern "C" value amd64dba_decode(value vmode, value vaddr, value vopcode) {
  const char *opcode = String_val(vopcode);
  std::vector<uint8_t> code;
  for (int i = 0; opcode[i] != '\0'; i += 2) {
    code.push_back(nibble_value(opcode[i]) << 4 | nibble_value(opcode[i + 1]));
  }
  std::stringstream s;
  intel::Decoder decoder;

  decoder.mode64 = Long_val(vmode);

  decoder.process(s, Int64_val(vaddr), std::move(code));

  return caml_copy_string(s.str().c_str());
}
