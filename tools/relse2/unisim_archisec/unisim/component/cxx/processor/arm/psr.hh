/*
 *  Copyright (c) 2013-2016,
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
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr), Daniel Gracia Perez (daniel.gracia-perez@cea.fr)
 */

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_STATUS_REGISTER_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_STATUS_REGISTER_HH__

#include <unisim/component/cxx/processor/arm/register_field.hh>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
  
  /*** Program Status Register (PSR) ***/
  RegisterField<31,1> const N;      /* Negative Integer Condition Flag */
  RegisterField<30,1> const Z;      /* Zero     Integer Condition Flag */
  RegisterField<29,1> const C;      /* Carry    Integer Condition Flag */
  RegisterField<28,1> const V;      /* Overflow Integer Condition Flag */
  RegisterField<28,4> const NZCV;   /* Compound value for N, Z, C, and V */
  RegisterField<27,1> const Q;      /* Cumulative saturation flag */
  /* RegisterField<25,2> */         /* IT[1:0] */
  RegisterField<24,1> const J;      /* Jazelle execution state bit */
  /* RegisterField<20,4> */         /* RAZ/SBZP */
  RegisterField<19,1> const GE3;    /* Greater than or Equal flag #3, for SIMD instructions */
  RegisterField<18,1> const GE2;    /* Greater than or Equal flag #2, for SIMD instructions */
  RegisterField<17,1> const GE1;    /* Greater than or Equal flag #1, for SIMD instructions */
  RegisterField<16,1> const GE0;    /* Greater than or Equal flag #0, for SIMD instructions */
  RegisterField<16,4> const GE;     /* Compound value for for Greater than or Equal flags */
  /* RegisterField<10,6> */         /* IT[7:2] */
  RegisterField< 9,1> const E;      /* Endianness execution state */
  RegisterField< 8,1> const A;      /* Asynchronous abort mask bit */
  RegisterField< 7,1> const I;      /* IRQ mask bit */
  RegisterField< 6,1> const F;      /* FIQ mask bit */
  RegisterField< 5,1> const T;      /* Thumb execution state bit */
  RegisterField< 0,5> const M;      /* Mode field */
  /* PSR Aliases */

  /*** Floating-Point Status and Control Register (FPSCR) ***/
  /* RegisterField<31,1> */         /* Negative FP Condition Flag (same as integer) */
  /* RegisterField<30,1> */         /* Zero     FP Condition Flag (same as integer) */
  /* RegisterField<29,1> */         /* Carry    FP Condition Flag (same as integer) */
  /* RegisterField<28,1> */         /* Overflow FP Condition Flag (same as integer) */
  RegisterField<27,1> const QC;     /* Cumulative saturation */
  RegisterField<26,1> const AHP;    /* Alternative half-precision */
  RegisterField<25,1> const DN;     /* Default NaN mode */
  RegisterField<24,1> const FZ;     /* Flush-to-zero mode */
  RegisterField<22,2> const RMode;  /* Rounding Mode (0b00:to nearest, 0b01:towards +inf, 0b10:towards -inf, 0b11: towards 0) */
  enum RMode_enum {
    RoundToNearest = 0b00,
    RoundTowardsPlusInfinity = 0b01,
    RoundTowardsMinusInfinity = 0b10,
    RoundTowardsZero = 0b11
  };
  /* RegisterField<20,2> */         /* Stride; ARM deprecates use of nonzero value (older VFP implementations) */
  /* RegisterField<19,1> */         /* Reserved, UNK/SBZP */
  /* RegisterField<16,3> */         /* Len; ARM deprecates use of nonzero value (older VFP implementations) */
  RegisterField<15,1> const IDE;    /* Input Denormal exception trap enable */
  /* RegisterField<13,2> */         /* Reserved, UNK/SBZP */
  RegisterField<12,1> const IXE;    /* Inexact exception trap enable */
  RegisterField<11,1> const UFE;    /* Underflow exception trap enable */
  RegisterField<10,1> const OFE;    /* Overflow exception trap enable */
  RegisterField< 9,1> const DZE;    /* Division by Zero exception trap enable */
  RegisterField< 8,1> const IOE;    /* Invalid Operation exception trap enable */
  RegisterField< 7,1> const IDC;    /* Input Denormal cumulative exception bit */
  /* RegisterField< 5,2> */         /* Reserved, UNK/SBZP */
  RegisterField< 4,1> const IXC;    /* Inexact cumulative exception bit */
  RegisterField< 3,1> const UFC;    /* Underflow cumulative exception bit */
  RegisterField< 2,1> const OFC;    /* Overflow cumulative exception bit */
  RegisterField< 1,1> const DZC;    /* Division by Zero cumulative exception bit */
  RegisterField< 0,1> const IOC;    /* Invalid Operation cumulative exception bit */
  
  struct PSR : public FieldRegister<uint32_t>
  {
    void ITSetState( uint32_t cond, uint32_t mask )
    {
      RegisterField<12,4>().Set( m_value, cond );
      RegisterField<10,2>().Set( m_value, (mask >> 2) & 3 );
      RegisterField<25,2>().Set( m_value, (mask >> 0) & 3 );
    }
    
    uint32_t ITGetState() const
    {
      return (RegisterField<10,6>().Get( m_value ) << 2) | RegisterField<25,2>().Get( m_value );
    }
  
    bool InITBlock() const
    { return RegisterField<10,2>().Get( m_value ) or RegisterField<25,2>().Get( m_value ); }
  
    uint32_t ITGetCondition() const
    { return this->InITBlock() ? RegisterField<12,4>().Get( m_value ) : 14; }
  
    void ITAdvance()
    {
      uint32_t state = (RegisterField<10,6>().Get( m_value ) << 2) | RegisterField<25,2>().Get( m_value );
      state = (state & 7) ? ((state & -32) | ((state << 1) & 31)) : 0;
      RegisterField<10,6>().Set( m_value, state >> 2 );
      RegisterField<25,2>().Set( m_value, state & 3 );
    }

    /* masks for the different running modes */
    static uint32_t const USER_MODE = 0b10000;
    static uint32_t const FIQ_MODE = 0b10001;
    static uint32_t const IRQ_MODE = 0b10010;
    static uint32_t const SUPERVISOR_MODE = 0b10011;
    static uint32_t const MONITOR_MODE = 0b10110;
    static uint32_t const ABORT_MODE = 0b10111;
    static uint32_t const HYPERVISOR_MODE = 0b11010;
    static uint32_t const UNDEFINED_MODE = 0b11011;
    static uint32_t const SYSTEM_MODE = 0b11111;
  };

} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_STATUS_REGISTER_HH__ */
