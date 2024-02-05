/*
 *  Copyright (c) 2013-2018,
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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_MEMORY_ATTRIBUTES_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_MEMORY_ATTRIBUTES_HH__

#include <unisim/component/cxx/processor/arm/register_field.hh>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

  /*** Memory Attributes ***/
  struct MemAttrs
  {
    enum type_t { StronglyOrdered = 0b00, Device = 0b01, Normal = 0b10 };
    enum attr_t { NonCacheable = 0b00, WriteThrough = 0b10, WriteBack = 0b11 /* 0b01: RESERVED */ };
    enum hint_t { NoAllocate = 0b00, WriteAllocate = 0b01, ReadAllocate = 0b10, RWAllocate = 0b11 };
    
    typedef RegisterField< 0,2> type;
    typedef RegisterField< 2,2> innerattrs;
    typedef RegisterField< 4,2> innerhints;
    typedef RegisterField< 2,4> innerattrshints;
    typedef RegisterField< 6,2> outerattrs;
    typedef RegisterField< 8,2> outerhints;
    typedef RegisterField< 6,4> outerattrshints;
    typedef RegisterField<10,1> innertransient;
    typedef RegisterField<11,1> outertransient;
    typedef RegisterField<12,1> shareable;
    typedef RegisterField<13,1> outershareable;

    struct Inner { typedef innerattrs attrs; typedef innerhints hints; typedef innertransient transient; typedef MemAttrs::shareable shareable;  };
    struct Outer { typedef outerattrs attrs; typedef outerhints hints; typedef outertransient transient; typedef outershareable shareable; };
    
    template <typename T, typename S>
    static void
    ConvAttrsHints( S const&, T& props, unsigned rgn )
    {
      struct AttrsHints { MemAttrs::attr_t attrs; MemAttrs::hint_t hints; } const attrshints[] = {
        {MemAttrs::NonCacheable, MemAttrs::NoAllocate},
        {MemAttrs::WriteBack,    MemAttrs::RWAllocate},
        {MemAttrs::WriteThrough, MemAttrs::ReadAllocate},
        {MemAttrs::WriteBack,    MemAttrs::ReadAllocate}
      };
      
      AttrsHints const& ah = attrshints[rgn&3];
      typename S::attrs().Set( props, ah.attrs );
      typename S::hints().Set( props, ah.hints );
    }

    template <typename T, typename S>
    static bool Is( S const&, attr_t chk, T const& value )
    {
      return attr_t( typename S::attrs().Get( value ) ) == chk;
    }

    template <typename T, typename S>
    static bool Flagged( S const&, hint_t chk, T const& value )
    {
      return (typename S::hints().Get( value ) & T(chk)) != T(0);
    }
};
  
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_MEMORY_ATTRIBUTES_HH__ */
