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
 
#ifndef __UNISIM_UTIL_DEBUG_BREAKPOINT_HH__
#define __UNISIM_UTIL_DEBUG_BREAKPOINT_HH__

#include <unisim/util/debug/event.hh>
#include <inttypes.h>
#include <ostream>

namespace unisim {
namespace util {
namespace debug {

template <typename ADDRESS> class Breakpoint;

template <typename ADDRESS>
class Breakpoint : public CustomEvent<ADDRESS, Breakpoint<ADDRESS> >
{
public:
	Breakpoint(ADDRESS _addr) : CustomEvent<ADDRESS, Breakpoint<ADDRESS> >(), addr(_addr), ref(), id(-1) {}
	Breakpoint(ADDRESS _addr, Event<ADDRESS> *_ref) : CustomEvent<ADDRESS, Breakpoint<ADDRESS> >() , addr(_addr), ref(_ref), id(-1) {}
	
	inline int GetId() const { return id; }
	inline ADDRESS GetAddress() const { return addr; }
	inline Event<ADDRESS> *GetReference() const { return ref; }
	inline void SetId(unsigned int _id) { id = _id; }
	
private:
	ADDRESS addr;
	Event<ADDRESS> *ref;
	int id;
};

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const Breakpoint<ADDRESS>& brkp)
{
	os << "breakpoint #" << brkp.GetId() << " at 0x" << std::hex << brkp.GetAddress() << std::dec << " for processor #" << brkp.GetProcessorNumber() << " and front-end #" << brkp.GetFrontEndNumber();
	
	return os;
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
