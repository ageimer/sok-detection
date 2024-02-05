/*
 *  Copyright (c) 2012,
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

#include <unisim/util/debug/subprogram.hh>

#ifndef __UNISIM_UTIL_DEBUG_SUBPROGRAM_TCC__
#define __UNISIM_UTIL_DEBUG_SUBPROGRAM_TCC__

#include <sstream>

namespace unisim {
namespace util {
namespace debug {

template <class ADDRESS>
SubProgram<ADDRESS>::SubProgram()
	: ref_count(0)
	, cdecl(0)
{
}

template <class ADDRESS>
SubProgram<ADDRESS>::~SubProgram()
{
	if(cdecl) delete cdecl;
}

template <class ADDRESS>
const std::string& SubProgram<ADDRESS>::BuildCDecl() const
{
	if(!cdecl)
	{
		std::stringstream sstr;
		Type const *return_type = GetReturnType();
		std::string s(return_type->BuildCDecl(0, true));
		sstr << s;
		if(!s.empty() && (s.back() != ' ') && (s.back() != '*')) sstr << " ";
		sstr << GetName() << "(";
		unsigned int arity = GetArity();
		for(unsigned int i = 0; i < arity; ++i)
		{
			if(i != 0) sstr << ", ";
			FormalParameter const *formal_param = GetFormalParameter(i);
			
			Type const *formal_param_type = formal_param->GetType();
			std::string formal_param_name = formal_param->GetName();
			char const *formal_param_name_cstr = formal_param_name.c_str();
			std::string s(formal_param_type->BuildCDecl(&formal_param_name_cstr, true));
			sstr << s;
			if(formal_param_name_cstr)
			{
				if(!s.empty() && (s.back() != ' ') && (s.back() != '*')) sstr << " ";
				sstr << formal_param_name_cstr;
			}
		}
		sstr << ")";
		cdecl = new std::string(sstr.str());
	}
	
	return *cdecl;
}

template <class ADDRESS>
void SubProgram<ADDRESS>::Catch() const
{
	++ref_count;
}

template <class ADDRESS>
void SubProgram<ADDRESS>::Release() const
{
	if(ref_count)
	{
		if(--ref_count == 0)
		{
			delete this;
		}
	}
}

template <class ADDRESS>
template <typename VISITOR> void SubProgram<ADDRESS>::Scan(VISITOR& visitor) const
{
	Type const *return_type = GetReturnType();
	if(!return_type->Visit(visitor)) return;
	unsigned int arity = GetArity();
	for(unsigned int i = 0; i < arity; ++i)
	{
		FormalParameter const *formal_param = GetFormalParameter(i);
		if(!visitor.Visit(formal_param)) break;
	}
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_SUBPROGRAM_TCC__
