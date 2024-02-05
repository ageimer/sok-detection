/*
 *  Copyright (c) 2016-2021,
 *  Commissariat a l'Energie Atomique (CEA),
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
 
#ifndef __UNISIM_UTIL_TRUTH_TABLE_TRUTH_TABLE_HH__
#define __UNISIM_UTIL_TRUTH_TABLE_TRUTH_TABLE_HH__

#include <inttypes.h>
#include <unisim/util/inlining/inlining.hh>

namespace unisim {
namespace util {
namespace truth_table {

  template <typename TT, TT ttVAL>
  struct LUT
  {
    typedef LUT<TT, ttVAL> this_type;
    typedef TT tt_type;

    static tt_type const tt = ttVAL;

    template <typename RT> LUT<TT,TT(tt&RT::tt)> operator and ( RT const& ) const { return LUT<TT,TT(tt&RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt|RT::tt)> operator  or ( RT const& ) const { return LUT<TT,TT(tt|RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt^RT::tt)> operator xor ( RT const& ) const { return LUT<TT,TT(tt^RT::tt)>(); }
    LUT<TT,TT(~tt)> operator ! () const { return LUT<TT,TT(~tt)>(); }
  };

  template <typename TT, unsigned INBIT, unsigned Tbits = 8*sizeof(TT)>
  struct InBit
  {
    typedef InBit<TT, INBIT, Tbits> this_type;
    typedef TT tt_type;

    static unsigned const msb = (Tbits-1);
    static tt_type const tt = (((msb >> INBIT) & 1) ? (tt_type(1) << msb) : tt_type(0)) | InBit<tt_type,INBIT,msb>::tt;

    template <typename RT> LUT<TT,TT(tt&RT::tt)> operator and ( RT const& ) const { return LUT<TT,TT(tt&RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt|RT::tt)> operator  or ( RT const& ) const { return LUT<TT,TT(tt|RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt^RT::tt)> operator xor ( RT const& ) const { return LUT<TT,TT(tt^RT::tt)>(); }
    LUT<TT,TT(~tt)> operator ! () const { return LUT<TT,TT(~tt)>(); }
  };

  template <typename TT, unsigned INBIT> struct InBit<TT, INBIT, 1> { static TT const tt = 0; };

  template <typename TT, bool CONST>
  struct Always
  {
    typedef Always<TT, CONST> this_type;
    typedef TT tt_type;

    static tt_type const tt = tt_type(CONST ? -1 : 0);

    template <typename RT> LUT<TT,TT(tt&RT::tt)> operator and ( RT const& ) const { return LUT<TT,TT(tt&RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt|RT::tt)> operator  or ( RT const& ) const { return LUT<TT,TT(tt|RT::tt)>(); }
    template <typename RT> LUT<TT,TT(tt^RT::tt)> operator xor ( RT const& ) const { return LUT<TT,TT(tt^RT::tt)>(); }
    LUT<TT,TT(~tt)> operator ! () const { return LUT<TT,TT(~tt)>(); }
  };
  
} // end of namespace truth_table
} // end of namespace util
} // end of namespace unisim

#endif
