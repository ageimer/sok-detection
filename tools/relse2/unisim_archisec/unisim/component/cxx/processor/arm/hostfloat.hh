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
 
#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_HOSTFLOAT_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_HOSTFLOAT_HH__

#if !defined(WIN32) && !defined(_WIN32) && !defined(WIN64) && !defined(_WIN64)
#include <ieee754.h>
#endif

#include <cmath>

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
inline int issignaling(double d)
{
	uint64_t i;
	memcpy(&i, &d, 8);
	return ((i & ((1ULL << 51) - 1)) != 0) && ((i & (1ULL << 51)) == 0);
}

inline int issignaling(float f)
{
	uint32_t i;
	memcpy(&i, &f, 4);
	return ((i & ((1UL << 22) - 1)) != 0) && ((i & (1ULL << 22)) == 0);
}
#endif

#include <unisim/component/cxx/processor/arm/register_field.hh>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
namespace hostfloat {
  
  struct FP
  {
    typedef double F64;
    typedef float  F32;
    
    template <typename operT> static
    void Neg( operT& acc ) { acc = -acc; }
  
    static inline
    void Abs( double& acc ) { acc = fabs( acc ); }
  
    static inline
    void Abs( float& acc ) { acc = fabsf( acc ); }
    
    template <typename operT> static
    bool
    FlushToZero( operT& op, uint32_t fpscr_val )
    {
      int fptype = std::fpclassify(op);
      if ((fptype != FP_SUBNORMAL) or (fptype == FP_ZERO)) return false;
      op = 0.0;
      return true;
    }
    
    template <typename operT, class ARCH> static
    void Add( operT& acc, operT op2, ARCH& arch, uint32_t fpscr_val ) { acc += op2; }
  
    template <typename operT, class ARCH> static
    void Sub( operT& acc, operT op2, ARCH& arch, uint32_t fpscr_val ) { acc -= op2; }
  
    template <typename operT, class ARCH> static
    void Div( operT& acc, operT op2, ARCH& arch, uint32_t fpscr_val ) { acc /= op2; }
    
    template <typename operT, class ARCH> static
    void Mul( operT& acc, operT op2, ARCH& arch, uint32_t fpscr_val ) { acc *= op2; }
  
    template <typename SOFTDBL> static
    bool IsInvalidMulAdd( SOFTDBL& acc, SOFTDBL const& op1, SOFTDBL const& op2, uint32_t fpscr_val ) { return false; }
    
    template <typename operT, class ARCH> static
    void MulAdd( operT& acc, operT op1, operT op2, ARCH& arch, uint32_t fpscr_val ) { acc += (op1 * op2); }
  
    template <typename fpT, typename intT, class ARCH> static
    void ItoF( fpT& dst, intT src, int fracbits, ARCH& arch, uint32_t fpscr_val ) { dst = fpT( src ) / fpT(1 << fracbits); }
  
    template <typename intT, typename fpT, class ARCH> static
    void FtoI( intT& dst, fpT src, int fracbits, ARCH& arch, uint32_t fpscr_val )
    { dst = intT( src * fpT(1 << fracbits) ); }
  
    template <typename ofpT, typename ifpT, class ARCH> static
    void FtoF( ofpT& dst, ifpT src, ARCH& arch, uint32_t fpscr_val ) { dst = ofpT( src ); }
  
    template <typename operT> static
    bool IsSNaN( operT op ) { return std::isnan( op ) and issignaling( op ); }
  
    template <typename operT> static
    bool IsQNaN( operT op ) { return std::isnan( op ) and not issignaling( op ); }
  
    static inline
    void SetQuietBit( double& op )
    {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
      uint64_t d;
      memcpy(&d, &op, 8);
      d = d | (1ULL << 51);
      memcpy(&op, &d, 8);
#else
      ieee754_double ud;
      ud.d = op;
      ud.ieee_nan.quiet_nan = 1;
      op = ud.d;
#endif
    }
  
    static inline
    void SetQuietBit( float& op )
    {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
      uint32_t f;
      memcpy(&f, &op, 4);
      f = f | (1UL << 22);
      memcpy(&op, &f, 4);
#else
      ieee754_float uf;
      uf.f = op;
      uf.ieee_nan.quiet_nan = 1;
      op = uf.f;
#endif
    }
    
    template <typename FPT> static
    void SetDefaultNan( FPT& result ) { result = (FPT(0) / FPT(0)); }
  
    template <typename operT> static
    void Sqrt( operT& acc, uint32_t fpscr_val ) { acc = sqrt( acc ); }
  
    template <typename operT> static
    int Compare( operT op1, operT op2, uint32_t fpscr_val )
    { return (op1 == op2) ? 0 : (op1 > op2) ? +1 : -1; }
  };
  
} // end of namespace hostfloat
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_HOSTFLOAT_HH__ */
