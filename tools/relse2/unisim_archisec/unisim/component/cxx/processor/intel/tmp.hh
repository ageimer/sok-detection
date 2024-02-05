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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TMP_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TMP_HH__

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {
namespace meta {

  template <unsigned _Value>
  struct BitScan { enum { forward = BitScan<((_Value-1) & ~_Value)>::end, reverse = BitScan<(_Value >> 1)>::end, begin = forward, end = reverse+1 }; };
  template <> struct BitScan<0u>{ enum { end = 0 }; };
  
  template <unsigned VAL>
  struct UI {};

  template <typename T> struct __unsigned {};
  template <> struct __unsigned<char> { typedef unsigned char type; };
  template <> struct __unsigned<signed char> { typedef unsigned char type; };
  template <> struct __unsigned<short> { typedef unsigned short type; };
  template <> struct __unsigned<int> { typedef unsigned int type; };
  template <> struct __unsigned<long> { typedef unsigned long type; };
  template <> struct __unsigned<long long> { typedef unsigned long long type; };
  template <> struct __unsigned<unsigned char> { typedef unsigned char type; };
  template <> struct __unsigned<unsigned short> { typedef unsigned short type; };
  template <> struct __unsigned<unsigned int> { typedef unsigned int type; };
  template <> struct __unsigned<unsigned long> { typedef unsigned long type; };
  template <> struct __unsigned<unsigned long long> { typedef unsigned long long type; };

} // end of namespace meta
} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_TMP_HH__
