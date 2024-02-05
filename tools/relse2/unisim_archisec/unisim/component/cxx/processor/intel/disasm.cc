/*
 *  Copyright (c) 2007-2019,
 *  Commissariat a l'Energie Atomique (CEA)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   - Neither the name of CEA nor the names of its contributors may be used to
 *     endorse or promote products derived from this software without specific 
 *     prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY 
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#include <unisim/component/cxx/processor/intel/disasm.hh>
#include <unisim/component/cxx/processor/intel/modrm.hh>
#include <iostream>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  std::ostream&
  operator << ( std::ostream& sink, DisasmObject const& dobj )
  {
    dobj( sink );
    return sink;
  }
  
  void DisasmBadReg::operator() ( std::ostream& sink ) const { sink << "(bad)"; }

  void __DisasmG( GObLH const&, std::ostream& sink, unsigned reg )
  {
    sink << (&"%al\0%cl\0%dl\0%bl\0%ah\0%ch\0%dh\0%bh"[(reg % 8)*4]);
  }

  void __DisasmG( GOb const&, std::ostream& sink, unsigned reg )
  {
    if (reg >= 8)
      { sink << "%r" << std::dec << reg << 'b'; return; }
    
    static char const* regname[] = { "%al", "%cl", "%dl", "%bl", "%spl", "%bpl", "%sil", "%dil" };
    sink << regname[reg];
  }

  void __DisasmG( GOw const&, std::ostream& sink, unsigned reg )
  {
    if (reg >= 8)
      sink << "%r" << std::dec << reg << 'w';
    else
      sink << (&"%ax\0%cx\0%dx\0%bx\0%sp\0%bp\0%si\0%di"[reg*4]);
  }
  void __DisasmG( GOd const&, std::ostream& sink, unsigned reg )
  {
    if (reg >= 8)
      sink << "%r" << std::dec << reg << 'd';
    else
      sink << (&"%eax\0%ecx\0%edx\0%ebx\0%esp\0%ebp\0%esi\0%edi"[reg*5]);
  }
  void __DisasmG( GOq const&, std::ostream& sink, unsigned reg )
  {
    if (reg >= 8)
      sink << "%r" << std::dec << reg;
    else
      sink << (&"%rax\0%rcx\0%rdx\0%rbx\0%rsp\0%rbp\0%rsi\0%rdi"[reg*5]);
  }
  
  void __DisasmV( SSE const&, std::ostream& sink, unsigned reg ) { sink << "%xmm" << std::dec << reg; }
  void __DisasmV( XMM const&, std::ostream& sink, unsigned reg ) { sink << "%xmm" << std::dec << reg; }
  void __DisasmV( YMM const&, std::ostream& sink, unsigned reg ) { sink << "%ymm" << std::dec << reg; }
    
  void DisasmPq::operator()  ( std::ostream& sink ) const { sink << "%mm" << std::dec << reg; }
  
  void DisasmCd::operator()  ( std::ostream& sink ) const { sink << "%cr" << std::dec << reg; }
  void DisasmDd::operator()  ( std::ostream& sink ) const { sink << "%db" << std::dec << reg; }
  
  void
  DisasmS::operator () ( std::ostream& sink ) const
  {
    if (segment < 6)
      sink << (&"%es\0%cs\0%ss\0%ds\0%fs\0%gs\0"[segment*4]);
    else
      sink << "%?";
  }
  
  void
  DisasmMS::operator () ( std::ostream& sink ) const
  {
    if (segment == DS) return;
    sink << DisasmS( segment ) << ':';
  }
  
  void PutString( std::ostream& sink, char const* string ) { sink << string; }
  void PutChar( std::ostream& sink, char chr ) { sink << chr; }
  
  void
  DisasmFPR::operator () ( std::ostream& sink ) const
  {
    if (reg == 0) { sink << "%st"; return; }
    sink << "%st(" << unsigned( reg ) << ")";
  }
  
  void
  DisasmBytes::operator() ( std::ostream& sink ) const
  {
    char const* sep = "";
    for (unsigned idx = 0; idx < 2*length; ++idx) {
      unsigned offset = ((idx ^ 1) & 1)*4, byte = idx/2;
      if (offset) { sink << sep; sep = " "; }
      sink << ("0123456789abcdef"[(bytes[byte]>>offset)&0xf]);
    }
  }

  void
  DisasmMnemonic::operator() ( std::ostream& _sink ) const
  {
    _sink << mnemonic;
    struct Bad {};
    switch (opsize)
      {
      default: throw Bad {};
      case   0: break;
      case   8: _sink << SizeID<  8>::gid(); break;
      case  16: _sink << SizeID< 16>::gid(); break;
      case  32: _sink << SizeID< 32>::gid(); break;
      case  64: _sink << SizeID< 64>::gid(); break;
      case 128: _sink << SizeID<128>::gid(); break;
      }
  }

  void
  DisasmSize::operator() ( std::ostream& _sink ) const
  {
    struct Bad {};
    
    switch (opsize)
      {
      default: throw Bad {};
      case   0: break;
      case   8: _sink << 'b'; break;
      case  16: _sink << 'w'; break;
      case  32: _sink << (style == 'i' ? 'd' : 'l'); break;
      case  64: _sink << 'q'; break;
      case 128: _sink << "dq"; break;
      }
  }
  

} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

