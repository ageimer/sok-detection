/*
 *  Copyright (c) 2016-2018,
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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ISA_ARM64_DECODE_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ISA_ARM64_DECODE_HH__

#include <unisim/component/cxx/processor/arm/isa/decode.hh>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
namespace isa {
namespace arm64 {

struct FPImm
{
  FPImm() : smallfp(0) {}
  FPImm( uint8_t _smallfp ) : smallfp(_smallfp) {} uint8_t smallfp;

  template <typename T>
  T toFP() const
  {
    float sign = (smallfp & 0x80) ? -1 : 1;

    float fixed = float( (0b10000 | (smallfp & 0b1111)) << (((smallfp >> 4) & 0b111) ^ 0b100) );
    return sign * (fixed / 128);
  }
  operator float () const { return this->toFP<float>(); }
};

struct DecodeBitMasks
{
  uint64_t wmask, tmask;
  DecodeBitMasks( unsigned n, unsigned imms, unsigned immr)
    : wmask(0), tmask(0)
  {
    unsigned len = (n << 6) | (imms ^ 0b111111);
    if (not len) throw Reject();
    len = (31 - __builtin_clz( len ));
    if (len < 1) throw Reject();
    unsigned esize = (1<<len), levels = esize-1;
    if ((imms & levels) == levels) throw Reject();
    unsigned S = imms & levels, R = immr & levels, D = (S-R) & levels;

    uint64_t welem = ((2ull<<S)-1ull);
    uint64_t telem = ((2ull<<D)-1ull);
    // ROR(welem,R)
    if (R)
      welem = ((welem >> R) | (welem << (esize-R))) & ((2ull<<levels)-1ull);
    // Replicate
    for (unsigned size = esize; size < 64; size *= 2)
      {
        welem = (welem << size) | welem;
        telem = (telem << size) | telem;
      }
    wmask = welem;
    tmask = telem;
  }
};


} // end of namespace arm64
} // end of namespace isa
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_ISA_ARM64_DECODE_HH__ */

