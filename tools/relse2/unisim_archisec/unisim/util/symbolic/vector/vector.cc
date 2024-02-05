/*
 *  Copyright (c) 2017-2020,
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
 
#include <unisim/util/symbolic/vector/vector.hh>
#include <ostream>
#include <iomanip>

namespace unisim {
namespace util {
namespace symbolic {
namespace vector {

  void VMix::Repr( std::ostream& sink ) const
  {
    sink << "VMix( " << l << ", " << r << " )";
  }
  
  void VTransBase::Repr( std::ostream& sink ) const
  {
    sink << "VTrans<";
    GetType()->GetName(sink);
    sink << ">(" << src << ", " << srcsize << ", " << srcpos << ")";
  }

  ExprNode const* corresponding_origin( Expr const& dst, unsigned dpos, unsigned spos )
  {
    struct
    {
      bool seek( ExprNode const* exp, unsigned pos )
      {
        if (auto vt = dynamic_cast<VTransBase const*>( exp ))
          {
            pos += vt->srcpos;
            if (pos >= vt->srcsize)
              return false;
            return seek( vt->src.node, pos );
          }
        if (auto vm = dynamic_cast<VMix const*>( exp ))
          return seek( vm->l.node, pos ) or seek( vm->r.node, pos );
        
        sexp = exp;
        spos = pos;
        return true;
      }
      ExprNode const* sexp;
      unsigned        spos;
    } seeker;

    if (not seeker.seek(dst.node, dpos) or seeker.spos != spos)
      return 0;
    return seeker.sexp;
  }
  
} /* end of namespace vector */
} /* end of namespace symbolic */
} /* end of namespace util */
} /* end of namespace unisim */

