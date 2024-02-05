/*
 *  Copyright (c) 2007,
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
 
#ifndef __UNISIM_UTIL_DEBUG_SYMBOL_TCC__
#define __UNISIM_UTIL_DEBUG_SYMBOL_TCC__

#include <iostream>
#include <sstream>
#include <string.h>

namespace unisim {
namespace util {
namespace debug {

using std::endl;
using std::hex;
using std::dec;
using std::stringstream;

template <class T>
Symbol<T>::Symbol(const char *_name, T _addr, T _size, typename unisim::util::debug::Symbol<T>::Type _type, T _memory_atom_size) :
	name(_name),
	addr(_addr),
	size(_size),
	type(_type),
	memory_atom_size(_memory_atom_size)
{
}

template <class T>
std::string Symbol<T>::GetFriendlyName(T addr) const
{
	stringstream sstr;
	
	sstr << name;
	if(type == unisim::util::debug::Symbol<T>::SYM_FUNC)
		sstr << "()";
	if(addr != this->addr && (addr - this->addr) <= size)
		sstr << "+0x" << std::hex << (addr - this->addr) / memory_atom_size << std::dec;
	
	return sstr.str();
}

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim

#endif
