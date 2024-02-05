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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TYPES_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TYPES_HH__

#include <unisim/util/identifier/identifier.hh>
#include <cstdint>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  template <typename ARCH, unsigned OPSIZE> struct TypeFor {};
  
  template <typename ARCH> struct TypeFor<ARCH, 8> { typedef typename ARCH:: s8_t s; typedef typename ARCH:: u8_t u; };
  template <typename ARCH> struct TypeFor<ARCH,16> { typedef typename ARCH::s16_t s; typedef typename ARCH::u16_t u; };
  template <typename ARCH> struct TypeFor<ARCH,32> { typedef typename ARCH::s32_t s; typedef typename ARCH::u32_t u; typedef typename ARCH::f32_t f; };
  template <typename ARCH> struct TypeFor<ARCH,64> { typedef typename ARCH::s64_t s; typedef typename ARCH::u64_t u; typedef typename ARCH::f64_t f; };
  template <typename ARCH> struct TypeFor<ARCH,80> { typedef typename ARCH::f80_t f; };

  template <unsigned SIZE> struct CTypeFor {};
  
  template <> struct CTypeFor<8> { typedef int8_t s; typedef uint8_t u; };
  template <> struct CTypeFor<16> { typedef int16_t s; typedef uint16_t u; };
  template <> struct CTypeFor<32> { typedef int32_t s; typedef uint32_t u; typedef float f; };
  template <> struct CTypeFor<64> { typedef int64_t s; typedef uint64_t u; typedef double f; };
  template <> struct CTypeFor<80> { typedef double f; };

  struct GObLH { enum { SIZE=8 }; static unsigned size() { return 8; } };
  struct GOb { enum { SIZE=8 };   static unsigned size() { return 8; } };
  struct GOw { enum { SIZE=16 };  static unsigned size() { return 16; } };
  struct GOd { enum { SIZE=32 };  static unsigned size() { return 32; } };
  struct GOq { enum { SIZE=64 };  static unsigned size() { return 64; } };

  struct SSE { enum { SIZE=128 }; static unsigned size() { return 128; } static bool vex() { return false; } };
  struct XMM { enum { SIZE=128 }; static unsigned size() { return 128; } static bool vex() { return true; } };
  struct YMM { enum { SIZE=256 }; static unsigned size() { return 256; } static bool vex() { return true; } };

  template <unsigned SIZE> struct GTypeFor {};
  
  template <> struct GTypeFor<16> { typedef GOw OP; };
  template <> struct GTypeFor<32> { typedef GOd OP; };
  template <> struct GTypeFor<64> { typedef GOq OP; };

  // template <typename T> struct tpinfo {};
  // template <> struct tpinfo< u8_t> { typedef  s8_t stype; typedef  u8_t utype; typedef u16_t twice; enum { is_signed = 0, bitsize =  8 }; };
  // template <> struct tpinfo< s8_t> { typedef  s8_t stype; typedef  u8_t utype; typedef s16_t twice; enum { is_signed = 1, bitsize =  8 }; };
  // template <> struct tpinfo<u16_t> { typedef s16_t stype; typedef u16_t utype; typedef u32_t twice; enum { is_signed = 0, bitsize = 16 }; };
  // template <> struct tpinfo<s16_t> { typedef s16_t stype; typedef u16_t utype; typedef s32_t twice; enum { is_signed = 1, bitsize = 16 }; };
  // template <> struct tpinfo<u32_t> { typedef s32_t stype; typedef u32_t utype; typedef u64_t twice; enum { is_signed = 0, bitsize = 32 }; };
  // template <> struct tpinfo<s32_t> { typedef s32_t stype; typedef u32_t utype; typedef s64_t twice; enum { is_signed = 1, bitsize = 32 }; };

  template <typename ARCH, typename T> struct atpinfo {};
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH:: u8_t>
  { typedef typename ARCH:: s8_t stype; typedef typename ARCH:: u8_t utype; typedef typename ARCH:: u16_t twice; enum nfo { is_signed = 0, is_integral = 1, bitsize =  8 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH:: s8_t>
  { typedef typename ARCH:: s8_t stype; typedef typename ARCH:: u8_t utype; typedef typename ARCH:: s16_t twice; enum nfo { is_signed = 1, is_integral = 1, bitsize =  8 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::u16_t>
  { typedef typename ARCH::s16_t stype; typedef typename ARCH::u16_t utype; typedef typename ARCH:: u32_t twice; enum nfo { is_signed = 0, is_integral = 1, bitsize = 16 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::s16_t>
  { typedef typename ARCH::s16_t stype; typedef typename ARCH::u16_t utype; typedef typename ARCH:: s32_t twice; enum nfo { is_signed = 1, is_integral = 1, bitsize = 16 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::u32_t>
  { typedef typename ARCH::s32_t stype; typedef typename ARCH::u32_t utype; typedef typename ARCH:: u64_t twice; enum nfo { is_signed = 0, is_integral = 1, bitsize = 32 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::s32_t>
  { typedef typename ARCH::s32_t stype; typedef typename ARCH::u32_t utype; typedef typename ARCH:: s64_t twice; enum nfo { is_signed = 1, is_integral = 1, bitsize = 32 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::u64_t>
  { typedef typename ARCH::s64_t stype; typedef typename ARCH::u64_t utype; typedef typename ARCH::u128_t twice; enum nfo { is_signed = 0, is_integral = 1, bitsize = 64 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::s64_t>
  { typedef typename ARCH::s64_t stype; typedef typename ARCH::u64_t utype; typedef typename ARCH::s128_t twice; enum nfo { is_signed = 1, is_integral = 1, bitsize = 64 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::u128_t>
  { typedef typename ARCH::s128_t stype; typedef typename ARCH::u128_t utype;                                    enum nfo { is_signed = 0, is_integral = 1, bitsize = 128 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::s128_t>
  { typedef typename ARCH::s128_t stype; typedef typename ARCH::u128_t utype;                                    enum nfo { is_signed = 1, is_integral = 1, bitsize = 128 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::f32_t> { enum nfo { is_signed = 1, is_integral = 0, bitsize = 32 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::f64_t> { enum nfo { is_signed = 1, is_integral = 0, bitsize = 64 }; };
  template <typename ARCH> struct atpinfo<ARCH,typename ARCH::f80_t> { enum nfo { is_signed = 1, is_integral = 0, bitsize = 80 }; };

  enum x87frnd_mode_t { x87frnd_error = -1, x87frnd_nearest = 0, x87frnd_down = 1, x87frnd_up = 2, x87frnd_toward0 = 3 };
  
  struct XSaveMode : public unisim::util::identifier::Identifier<XSaveMode>
  {
    enum Code { BASE = 0, OPT, C, S, end } code;

    char const* c_str() const
    {
      switch (code)
        {
        default: break;
        case BASE: return "base";
        case  OPT: return "opt";
        case    C: return "c";
        case    S: return "s";
        }
      return "NA";
    }

    XSaveMode() : code(end) {}
    XSaveMode( Code _code ) : code(_code) {}
    XSaveMode( char const* _code ) : code(end) { init( _code ); }
  };

} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TYPES_HH__
