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

#include <inttypes.h>
#include <iostream>
#include <sstream>

#include "unisim/component/cxx/processor/arm/disasm.hh"
#include "unisim/component/cxx/processor/arm/psr.hh"

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

  std::ostream&
  operator << ( std::ostream& sink, DisasmObject const& dobj )
  {
    dobj( sink );
    return sink;
  }

  /* Condition opcode bytes disassembling method */
  void DisasmCondition::operator() ( std::ostream& sink ) const
  {
    if         (m_cond >= 15) {
      sink << "<illegal condition code: " << m_cond << ">";
      return;
    }
    
    if  ((m_cond == 14) and (m_explicit_always == implicit_always))
      return;
    
    sink << Condition(Condition::Code(m_cond)).c_str();
  }

  /* Immediate disassembly */
  void DisasmI::operator() ( std::ostream& sink ) const
  {
    sink << '#' << std::dec << static_cast<int32_t>( m_imm );
  }
  
  void DisasmShImm::operator() ( std::ostream& sink ) const
  {
    if (m_offset) {
      switch (m_shift) {
      case 0: sink << ", lsl #"; break;
      case 1: sink << ", lsr #"; break;
      case 2: sink << ", asr #"; break;
      case 3: sink << ", ror #"; break;
      }
      sink << m_offset;
    } else {
      switch (m_shift) {
      case 0: break;
      case 1: sink << ", lsr #32"; break;
      case 2: sink << ", asr #32"; break;
      case 3: sink << ", rrx"; break;
      }
    }
  }
  
  void DisasmMemoryRI::operator () ( std::ostream& _sink ) const
  {
    _sink << "[" << DisasmRegister(rn) << (p?"":"]") << ", " << DisasmI(imm) << (p?(w?"]!":"]"):"");
  }

  void DisasmMemoryRR::operator () ( std::ostream& _sink ) const
  {
    _sink << "[" << DisasmRegister(rn) << (p?"":"]") << ", " << (u?"":"-") << DisasmRegister(rm) << (p?(w?"]!":"]"):"");
  }
  
  void DisasmMemoryRRI::operator () ( std::ostream& _sink ) const
  {
    _sink << "[" << DisasmRegister(rn) << (p?"":"]") << ", " << (u?"":"-") << DisasmRegister(rm) << DisasmShImm(shift, imm) << (p?(w?"]!":"]"):"");
  }
  
  static char const* const register_dis[] =
    {"r0","r1","r2","r3","r4","r5","r6","r7", "r8","r9","sl","fp","ip","sp","lr","pc"};

  static char const* const sornames[] = { "lsl", "lsr", "asr", "ror" };
  
  void DisasmShReg::operator() ( std::ostream& sink ) const
  {
    sink << sornames[m_shift] << " " << register_dis[m_reg];
  }

  void DisasmShift::operator() ( std::ostream& sink ) const
  {
    sink << sornames[m_shift];
  }

  /* Special Register disassembling method */
  void DisasmSpecReg::operator() ( std::ostream& sink ) const
  {
    switch (m_reg)
      {
      default: sink << "(<undefined> " << (unsigned int)m_reg << ")"; break;
      case 15: sink << "CPSR"; break;
      case 32: sink << "R8_usr"; break;
      case 33: sink << "R9_usr"; break;
      case 34: sink << "R10_usr"; break;
      case 35: sink << "R11_usr"; break;
      case 36: sink << "R12_usr"; break;
      case 37: sink << "SP_usr"; break;
      case 38: sink << "LR_usr"; break;
      case 40: sink << "R8_fiq"; break;
      case 41: sink << "R9_fiq"; break;
      case 42: sink << "R10_fiq"; break;
      case 43: sink << "R11_fiq"; break;
      case 44: sink << "R12_fiq"; break;
      case 45: sink << "SP_fiq"; break;
      case 46: sink << "LR_fiq"; break;
      case 48: sink << "LR_irq"; break;
      case 49: sink << "SP_irq"; break;
      case 50: sink << "LR_svc"; break;
      case 51: sink << "SP_svc"; break;
      case 52: sink << "LR_abt"; break;
      case 53: sink << "SP_abt"; break;
      case 54: sink << "LR_und"; break;
      case 55: sink << "SP_und"; break;
      case 60: sink << "LR_mon"; break;
      case 61: sink << "SP_mon"; break;
      case 62: sink << "ELR_hyp"; break;
      case 63: sink << "SP_hyp"; break;
      case 79: sink << "SPSR"; break;
      case 110: sink << "SPSR_fiq"; break;
      case 112: sink << "SPSR_irq"; break;
      case 114: sink << "SPSR_svc"; break;
      case 116: sink << "SPSR_abt"; break;
      case 118: sink << "SPSR_und"; break;
      case 124: sink << "SPSR_mon"; break;
      case 126: sink << "SPSR_hyp"; break;
      }
  }
  
  /* Register disassembling method */
  void DisasmRegister::operator() ( std::ostream& sink ) const
  {
    sink << register_dis[m_reg];
  }
  
  /* Coprocessor Register disassembling method */
  void DisasmCPR::operator() ( std::ostream& sink ) const
  {
    sink << "cr" << m_reg;
  }
  
  /* Register list disassembling method */
  void DisasmRegList::operator() ( std::ostream& sink ) const
  {
    char const* sep = "";
    for (int reg = 0; reg < 16; ++reg) {
      if (((m_reglist >> reg) & 1) == 0) continue;
      sink << sep << register_dis[reg];
      sep = ", ";
    }
  }
  
  /* Multiple Load Store Mode disassembling method */
  void DisasmLSMMode::operator() ( std::ostream& sink ) const
  {
    static char const* const lsmmod[] = {"da","ia","db","ib"};
    sink << lsmmod[m_mode%4];
  }
  
  /* Barrier option disassembling method */
  void DisasmBarrierOption::operator() ( std::ostream& sink ) const
  {
    switch (m_option) {
    default: sink << "<reserved>"; break;
    case 0xf: sink << "sy"; break;
    case 0xe: sink << "st"; break;
    case 0xb: sink << "ish"; break;
    case 0xa: sink << "ishst"; break;
    case 0x7: sink << "nsh"; break;
    case 0x6: sink << "nshst"; break;
    case 0x3: sink << "osh"; break;
    case 0x2: sink << "oshst"; break;
    };
  }

  /* PSR mask disassembling method */
  void DisasmPSRMask::operator() ( std::ostream& sink ) const
  {
    sink << (m_r ? "SPSR_" : "CPSR_");
    if ((m_mask & 0x08) == 0x08) sink << "f";
    if ((m_mask & 0x04) == 0x04) sink << "s";
    if ((m_mask & 0x02) == 0x02) sink << "x";
    if ((m_mask & 0x01) == 0x01) sink << "c";
  }

  /* IT sequence disassembly */
  void DisasmITSequence::operator() ( std::ostream& sink ) const
  {
    PSR pseudo_psr;
    pseudo_psr.ITSetState( 0, m_mask );
    do {
      sink << (pseudo_psr.ITGetCondition() ? 'e' : 't');
      pseudo_psr.ITAdvance();
    } while (pseudo_psr.InITBlock());
  }
  
  std::ostream&
  operator << ( std::ostream& sink, PSR const& psr )
  {
    std::ostringstream oss;
    oss << std::hex
        <<    "N=" << psr.Get(N)
        <<  ", Z=" << psr.Get(Z)
        <<  ", C=" << psr.Get(C)
        <<  ", V=" << psr.Get(V)
        <<  ", Q=" << psr.Get(Q)
        << ", GE=" << psr.Get(GE)
        <<  ", E=" << psr.Get(E)
        <<  ", J=" << psr.Get(J)
        <<  ", T=" << psr.Get(T)
        << ", IT=" << psr.ITGetState()
        <<  ", A=" << psr.Get(A)
        <<  ", I=" << psr.Get(I)
        <<  ", F=" << psr.Get(F)
        <<  ", M=" << psr.Get(M);
    sink << oss.str();
    return sink;
  }
  
  void DisasmBunch::operator () ( std::ostream& sink ) const
  {
    struct DisasmD : public DisasmObject
    {
      DisasmD(unsigned _idx, DisasmBunch const& _db) : idx(_idx), db(_db) {} unsigned idx; DisasmBunch const& db;
      void operator() ( std::ostream& sink ) const
      {
        sink << DisasmV(idx,3);
        switch (db.lane) {
        case Each:   break;
        case All:    sink << "[]"; break;
        case Single: sink << "[" << std::dec << db.lane_index << "]"; break;
        }
      }
    };
    
    sink << '{';
    if ((regs <= 2) or ((rid+regs) > 32) or double_spacing)
      {
        char const* sep = "";
        
        for (unsigned idx = 0, end = regs << double_spacing; idx < end; sep = ", ", idx += (1 << double_spacing))
          sink << sep << DisasmD((rid+idx)%32, *this);
      }
    else
      sink << DisasmD(rid, *this) << "-" << DisasmD(rid+regs-1, *this);
    sink << '}';
  }

  void DisasmNeonMemoryRR::operator () (std::ostream& sink) const
  {
    sink << "[" << DisasmRegister(rb);
    if (align) sink << " :" << align;
    sink << "]";
    if      (ra == 13) sink << "!";
    else if (ra != 15) sink << ", " << DisasmRegister(ra);
  }

  void DisasmV::operator () (std::ostream& sink) const
  {
    sink << "bjsdq"[scale] << std::dec << vn;
  }
  
  void DisasmVIdx::operator () (std::ostream& sink) const
  {
    sink << "[" << idx << "]";
  }
  

} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim
