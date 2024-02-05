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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_MODRM_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_MODRM_HH__

#include <unisim/component/cxx/processor/intel/types.hh>
#include <unisim/component/cxx/processor/intel/segments.hh>
#include <unisim/component/cxx/processor/intel/disasm.hh>
#include <iosfwd>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  template <class ARCH>
  struct MOp
  {
    typedef typename ARCH::addr_t addr_t;
    MOp( uint8_t _segment ) : segment( _segment ) {} uint8_t segment;
    virtual ~MOp() {}
    struct Bad {};
    virtual void  disasm_memory_operand( std::ostream& _sink ) const { throw Bad(); };
    virtual addr_t effective_address( ARCH& _arch ) const { throw Bad(); return addr_t( 0 ); };
  };
  
  template <class ARCH>
  struct RMOp
  {
    RMOp( MOp<ARCH> const* _mop ) : mop(_mop) {} MOp<ARCH> const* mop;
    RMOp() = delete;
    RMOp( RMOp const& ) = delete;
    RMOp(RMOp&& _rmop) : mop(_rmop.mop) { _rmop.mop = 0; }
    ~RMOp() { if (ismem()) delete mop; }
    
    bool ismem() const { return (uintptr_t( mop ) > 0x1000); }
    bool isreg() const { return not ismem(); }
    
    MOp<ARCH> const* operator -> () const { return mop; }
    // operator MOp<ARCH> const* () const { return mop; }
    MOp<ARCH> const* memop() const { return mop; }
    //    MOp<ARCH> const* release() { MOp<ARCH> const* res = mop; mop = 0; return res; }
    unsigned ereg() const { return unsigned( uintptr_t( mop ) ); }
  };
  
} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_MODRM_HH__
