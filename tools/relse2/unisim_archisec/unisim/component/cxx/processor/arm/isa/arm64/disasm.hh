/*
 *  Copyright (c) 2015-2016,
 *  Commissariat a l'Energie Atomique (CEA)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   - Neither the name of CEA nor the names of its contributors may be used to
 *     endorse or promote products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 */

/**************************************************************/
/* Disassembling methods                                      */
/**************************************************************/

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_VMSAV8_DISASM_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_VMSAV8_DISASM_HH__

#include <iostream>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
namespace isa {
namespace arm64 {

  struct FPImm;

  struct DisasmObject
  {
    virtual void operator() ( std::ostream& sink ) const = 0;
    virtual ~DisasmObject() {};
    friend std::ostream& operator << ( std::ostream& sink, DisasmObject const& dobj );
  };
  
  struct DisasmC : public DisasmObject
  {
    DisasmC( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "C" << std::dec << rid; }
  };

  struct DisasmCond : public DisasmObject
  {
    DisasmCond( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const;
  };

  struct DisasmGSXR : public DisasmObject
  {
    DisasmGSXR( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { if (rid != 31) sink << 'x' << std::dec << rid; else sink << "sp"; }
  };

  struct DisasmGSWR : public DisasmObject
  {
    DisasmGSWR( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { if (rid != 31) sink << 'w' << std::dec << rid; else sink << "wsp"; }
  };

  struct DisasmGZXR : public DisasmObject
  {
    DisasmGZXR( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { if (rid != 31) sink << 'x' << std::dec << rid; else sink << "xzr"; }
  };

  struct DisasmGZWR : public DisasmObject
  {
    DisasmGZWR( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { if (rid != 31) sink << 'w' << std::dec << rid; else sink << "wzr"; }
  };
  
  template <typename INT>
  struct DisasmImmediate : public DisasmObject
  {
    DisasmImmediate( INT _val, unsigned _base ) : val(_val), base(_base) {} INT val; unsigned base;
    void operator () ( std::ostream& sink ) const
    {
      std::ios::fmtflags bkp( sink.flags() );

      sink << '#';
      switch (base) {
      case 10: sink << std::dec << int64_t( val ); break;
      case 16: sink << "0x" << std::hex << uint64_t( val ); break;
      default: throw 0;
      }

      sink.flags(bkp);
    }
  
  };


  template <typename INT>
  DisasmImmediate<INT> DisasmI( INT const& _val, unsigned _base=10 ) { return DisasmImmediate<INT>( _val, _base ); }

  // struct DisasmXT : public DisasmObject
  // {
  //   DisasmXT(char const* _xt, unsigned _amount) : xt(_xt), amount(_amount) {} char const* xt; unsigned amount;
  //   void operator () (std::ostream& sink) const
  //   {
  //     if (amount)
  //       sink << xt << " " << DisasmI(amount);
  //     else
  //       sink << xt;
  //   }
  // };

  // struct DisasmLsl : public DisasmObject
  // {
  //   DisasmLsl(unsigned _amount) : amount(_amount) {} unsigned amount;
  //   void operator () (std::ostream& sink) const
  //   {
  //     if (amount)
  //       sink << ",lsl " << DisasmI(amount);
  //   }
  // };

  struct DisasmINZ : public DisasmObject
  {
    DisasmINZ( char const* _pre, unsigned _amount ) : pre(_pre), amount(_amount) {} char const* pre; unsigned amount;
    void operator () (std::ostream& sink) const
    {
      if (amount)
        sink << pre << DisasmI(amount);
    }
  };

  struct DisasmBarrierOption : public DisasmObject
  {
    DisasmBarrierOption( unsigned _option ) : option(_option) {} unsigned option;
    void operator() ( std::ostream& sink ) const
    {
      switch (option) {
      default: sink << "#0x0" << ("0123456789abcdef"[option]); break;
      case 0x1: sink << "oshld"; break;
      case 0x2: sink << "oshst"; break;
      case 0x3: sink << "osh"; break;
      case 0x5: sink << "nshld"; break;
      case 0x6: sink << "nshst"; break;
      case 0x7: sink << "nsh"; break;
      case 0x9: sink << "ishld"; break;
      case 0xa: sink << "ishst"; break;
      case 0xb: sink << "ish"; break;
      case 0xd: sink << "ld"; break;
      case 0xe: sink << "st"; break;
      case 0xf: sink << "sy"; break;
      };
    }
  };



  /******  SIMD and FP disassembly *********/
  
  struct DisasmF : public DisasmObject
  {
    DisasmF( FPImm const& _imm ) : imm(_imm) {} FPImm const& imm;
    void operator () ( std::ostream& sink ) const;
  };

  struct DisasmB : public DisasmObject
  {
    DisasmB( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "b" << std::dec << rid; }
  };


  struct DisasmH : public DisasmObject
  {
    DisasmH( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "h" << std::dec << rid; }
  };


  struct DisasmS : public DisasmObject
  {
    DisasmS( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "s" << std::dec << rid; }
  };


  struct DisasmD : public DisasmObject
  {
    DisasmD( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "d" << std::dec << rid; }
  };


  struct DisasmQ : public DisasmObject
  {
    DisasmQ( unsigned _rid ) : rid(_rid) {} unsigned rid;
    void operator () ( std::ostream& sink ) const { sink << "q" << std::dec << rid; }
  };


  struct DisasmTV : public DisasmObject
  {
    DisasmTV( unsigned _rid, unsigned _repeat, unsigned _scale ) : rid(_rid), repeat(_repeat), scale(_scale) {} unsigned rid, repeat, scale;
    void operator () ( std::ostream& sink ) const
    {
      sink << 'v' << std::dec << rid << '.';
      if (repeat)
        sink << repeat;
      sink << "bhsdq"[scale];
    }
  };

  struct DisasmBunch : public DisasmObject
  {
    DisasmBunch( unsigned _rid, unsigned _elems, unsigned _repeat, unsigned _scale )
      : rid(_rid), elems(_elems), repeat(_repeat), scale(_scale) {}
  
    void operator () ( std::ostream& sink ) const
    {
      char const* sep = "";
    
      sink << '{';
      if ((elems > 2) and ((rid+elems) <= 32)) {
        sink << DisasmTV( rid, repeat, scale ) << '-'  << DisasmTV( rid+elems-1, repeat, scale );
      } else {
        for (unsigned idx = 0; idx < elems; ++idx) {
          sink << sep << DisasmTV( (rid+idx)%32, repeat, scale );
          sep = ", ";
        }
      }
      sink << '}';
    }
  
    unsigned rid, elems, repeat, scale;
  };

  struct DisasmSubscript : public DisasmObject
  {
    DisasmSubscript( unsigned _idx ) : idx(_idx) {} unsigned idx;
    void operator () ( std::ostream& sink ) const
    {
      sink << "[" << std::dec << idx << "]";
    }
  };

  struct DisasmMemoryRI : public DisasmObject
  {
    DisasmMemoryRI( unsigned _rn, uint32_t _imm, unsigned _am ) : imm(_imm), rn(_rn), am(_am) {}
    void operator() ( std::ostream& sink ) const;
    uint64_t imm;
    unsigned rn, am;
  };
  
  
} // end of namespace arm64
} // end of namespace isa
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_VMSAV8_DISASM_HH__ */
