/*
 *  Copyright (c) 2009-2010,
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
 * Authors: Gilles Mouchard (gilles.mouchard@cea.fr)
 */

#ifndef __UNISIM_UTIL_RANDOM_RANDOM_HH__
#define __UNISIM_UTIL_RANDOM_RANDOM_HH__

#include <inttypes.h>

namespace unisim {
namespace util {
namespace random {

// KISS (Keep It Simple Stupid) random generator from George Marsaglia <geo@stat.fsu.edu>
// http://www.math.niu.edu/~rusin/known-math/99/RNG

class Random
{
public:
	static const int32_t Max = +2147483647L;
	static const int32_t Min = -Max - 1L;
	static const uint64_t Amplitude = 4294967296ULL;
	Random();
	Random(int32_t seed_x, int32_t seed_y, int32_t seed_z, int32_t seed_w);
	void Seed(int32_t seed_x, int32_t seed_y, int32_t seed_z, int32_t seed_w);
	int32_t const& State(unsigned idx) const;
        int32_t& State(unsigned idx) { return const_cast<int32_t&>( const_cast<Random const*>(this)->State(idx) ); };
	int32_t Generate();
	int32_t Generate(uint32_t radius);
private:
	int32_t x;
	int32_t y;
	int32_t z;
	int32_t w;
	int32_t carry;
};

} // end of namespace random
} // end of namespace util
} // end of namespace unisim

#endif
