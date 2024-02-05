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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_DISASM_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_DISASM_HH__

#include <unisim/util/identifier/identifier.hh>
#include <inttypes.h>
#include <iosfwd>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
  
  struct DisasmObject
  {
    virtual void operator() ( std::ostream& sink ) const = 0;
    virtual ~DisasmObject() {};
  };
  std::ostream& operator << ( std::ostream& sink, DisasmObject const& dobj );

  struct Condition : public unisim::util::identifier::Identifier<Condition>
  {
    enum Code { eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le, al, end } code;
    
    char const* c_str() const
    {
      switch (code)
        {
        default: break;
        case eq: return "eq";
        case ne: return "ne";
        case cs: return "cs";
        case cc: return "cc";
        case mi: return "mi";
        case pl: return "pl";
        case vs: return "vs";
        case vc: return "vc";
        case hi: return "hi";
        case ls: return "ls";
        case ge: return "ge";
        case lt: return "lt";
        case gt: return "gt";
        case le: return "le";
        case al: return "al";
        }
      return "<und>";
    }

    Condition() : code(end) {}
    Condition( Code _code ) : code(_code) {}
    Condition( char const* _code ) : code(end) { init(_code); }
  };
  
  /* Condition opcode bytes disassembling method */
  struct DisasmCondition : public DisasmObject
  {
    DisasmCondition( uint32_t cond )
      : m_cond( cond ), m_explicit_always( implicit_always ) {}
    enum explicit_always_t { implicit_always = 0, explicit_always = 1 };
    DisasmCondition( uint32_t cond, explicit_always_t _explicit_always )
      : m_cond( cond ), m_explicit_always( _explicit_always ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t    m_cond;
    explicit_always_t m_explicit_always;
  };
  
  /* Immediate disassembly */
  struct DisasmI : public DisasmObject
  {
    DisasmI( uint32_t imm ) : m_imm( imm ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_imm;
  };

  /* Immediate shifting disassembly */
  struct DisasmShImm : public DisasmObject
  {
    DisasmShImm( uint32_t shift, uint32_t offset ) : m_shift( shift ), m_offset( offset ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_shift, m_offset;
  };
  
  /* Memory locations disassembly */
  struct DisasmMemoryRI : public DisasmObject
  {
    DisasmMemoryRI( uint32_t _rn, uint32_t _imm, bool _p, bool _w ) : rn(_rn), imm(_imm), p(_p), w(_w) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t rn, imm;
    bool p, w;
  };
  struct DisasmMemoryRR : public DisasmObject
  {
    DisasmMemoryRR( uint32_t _rn, uint32_t _rm, bool _p, bool _u, bool _w ) : rn(_rn), rm(_rm), p(_p), u(_u), w(_w) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t rn, rm;
    bool p, u, w;
  };
  struct DisasmMemoryRRI : public DisasmObject
  {
    DisasmMemoryRRI( uint32_t _rn, uint32_t _rm, uint32_t _shift, uint32_t _imm, bool _p, bool _u, bool _w )
      : rn(_rn), rm(_rm), shift(_shift), imm(_imm), p(_p), u(_u), w(_w) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t rn, rm, shift, imm;
    bool p, u, w;
  };
  
  /* Register shifting disassembly */
  struct DisasmShReg : public DisasmObject
  {
    DisasmShReg( uint32_t shift, uint32_t reg ) : m_shift( shift ), m_reg( reg ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_shift, m_reg;
  };
  
  /* Shift disassembly */
  struct DisasmShift : public DisasmObject
  {
    DisasmShift( uint32_t shift ) : m_shift( shift ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_shift;
  };
  
  /* Barrier option disassembling method */
  struct DisasmBarrierOption : public DisasmObject
  {
    DisasmBarrierOption( uint32_t option ) : m_option( option ) {}
    void operator() ( std::ostream& sink ) const;
    uint8_t m_option;
  };

  /* PSR mask disassembling method */
  struct DisasmPSRMask : public DisasmObject
  {
    DisasmPSRMask( uint8_t r, uint32_t mask ) : m_r( r ), m_mask( mask ) {}
    void operator() ( std::ostream& sink ) const;
    uint8_t m_r, m_mask;
  };

  /* Special Register disassembling method */
  struct DisasmSpecReg : public DisasmObject
  {
    DisasmSpecReg( uint8_t reg ) : m_reg( reg ) {}
    void operator() ( std::ostream& sink ) const;
    uint8_t m_reg;
  };
  
  /* Register disassembling method */
  struct DisasmRegister : public DisasmObject
  {
    DisasmRegister( uint32_t reg ) : m_reg( reg ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_reg;
  };
  
  /* Register list disassembling method */
  struct DisasmRegList : public DisasmObject
  {
    DisasmRegList( uint32_t reglist ) : m_reglist( reglist ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_reglist;
  };
  
  struct DisasmCPR : public DisasmObject
  {
    DisasmCPR( uint32_t reg ) : m_reg( reg ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_reg;
  };
  
  /* Multiple Load Store Mode disassembling method */
  struct DisasmLSMMode : public DisasmObject
  {
    DisasmLSMMode( uint32_t mode ) : m_mode( mode ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_mode;
  };

  /* IT sequence disassembly */
  struct DisasmITSequence : public DisasmObject
  {
    DisasmITSequence( uint32_t _mask ) : m_mask( _mask ) {}
    void operator() ( std::ostream& sink ) const;
    uint32_t m_mask;
  };
  
  struct DisasmBunch : public DisasmObject
  {
    DisasmBunch( unsigned _rid, unsigned _regs ) : rid(_rid), regs(_regs), lane(Each), double_spacing(false) {}
    //    DisasmBunch( unsigned _rid, unsigned _regs, bool _dspc ) : rid(_rid), regs(_regs), lane(Each), double_spacing(_dspc) {}

    DisasmBunch dspc(bool _dspc) { DisasmBunch res(*this); res.double_spacing = _dspc; return res; }
    DisasmBunch lidx(unsigned _lidx) { DisasmBunch res(*this); res.lane = Single; res.lane_index = _lidx; return res; }
    DisasmBunch all_lanes() { DisasmBunch res(*this); res.lane = All; return res; }
  
    void operator () ( std::ostream& sink ) const;
  
    unsigned rid, regs, lane_index;
    enum { Each, All, Single } lane;
    bool double_spacing;
  };

  struct DisasmNeonMemoryRR : public DisasmObject
  {
    DisasmNeonMemoryRR(unsigned _rb, unsigned _ra, unsigned _align)
      : rb(_rb), ra(_ra), align(_align) {}
        
    void operator () (std::ostream& sink) const;
    
    unsigned rb, ra, align;
  };

  struct PSR;
  
  std::ostream& operator << ( std::ostream& sink, PSR const& dobj );

  struct DisasmV : public DisasmObject
  {
    DisasmV(unsigned _vn, unsigned _scale) : vn(_vn), scale(_scale) {}
    void operator () (std::ostream& sink) const;
    unsigned vn, scale;
  };
  
  struct DisasmVIdx : public DisasmObject
  {
    DisasmVIdx(unsigned _idx) : idx(_idx) {}
    void operator () (std::ostream& sink) const;
    unsigned idx;
  };
  
  enum controltype_t { ctNormal, ctBranch, ctCondBranch, ctCall, ctLeave };
  
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_DISASM_HH__ */
