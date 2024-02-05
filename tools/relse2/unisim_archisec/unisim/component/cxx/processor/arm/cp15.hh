/*
 *  Copyright (c) 2010-2016,
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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ARM926EJS_CP15_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ARM926EJS_CP15_HH__


#include <unisim/component/cxx/processor/arm/register_field.hh>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {


  /** SCTLR Manips
   *
   * Base Register Fields to ease access to the SCTLR System Control
   * Register.  This class factorizes all common SCTLR register
   * fields, though some of them may not be present in a particular
   * ARM processor implementation
   */
  namespace sctlr
  {
    RegisterField<31,1> const IE;      // Instruction Endianness (-v7)
    RegisterField<30,1> const TE;      // Thumb Exception enable (-v7)
    RegisterField<27,1> const NMFI;    // Non-maskable FIQ (NMFI) support (-v7)
    RegisterField<25,1> const EE;      // Exception Endianness. (-v8)
    RegisterField<24,1> const VE;      // Interrupt Vectors Enable
    RegisterField<22,1> const U;       // Alignment Model (-v6)
    RegisterField<21,1> const FI;      // Fast interrupts configuration enable
    RegisterField<14,1> const RR;      // Round Robin select
    RegisterField<13,1> const V;       // Vectors bit
    RegisterField<12,1> const I;       // Instruction cache enable
    RegisterField<11,1> const Z;       // Branch prediction enable.
    RegisterField<10,1> const SW;      // SWP and SWPB enable. This bit enables the use of SWP and SWPB instructions.
    RegisterField< 7,1> const B;       // Endianness model (up to ARMv6)
    RegisterField< 5,1> const CP15BEN; // CP15 barrier enable.
    RegisterField< 2,1> const C;       // Cache enable. This is a global enable bit for data and unified caches.
    RegisterField< 1,1> const A;       // Alignment check enable
    RegisterField< 0,1> const M;       // MMU/MPU enable.
  };


} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ARM926EJS_CP15_HH__
