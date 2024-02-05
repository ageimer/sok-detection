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
 
#ifndef __UNISIM_UTIL_DEBUG_WATCHPOINT_HH__
#define __UNISIM_UTIL_DEBUG_WATCHPOINT_HH__

#include <inttypes.h>
#include <iostream>

#include <unisim/util/debug/event.hh>
#include "unisim/util/debug/memory_access_type.hh"

namespace unisim {
namespace util {
namespace debug {


template <typename ADDRESS> class Watchpoint;

template <typename ADDRESS>
class Watchpoint : public CustomEvent<ADDRESS, Watchpoint<ADDRESS> >
{
public:

	Watchpoint(unisim::util::debug::MemoryAccessType _mat, unisim::util::debug::MemoryType _mt, ADDRESS _addr, uint32_t _size, bool _overlook)
		: CustomEvent<ADDRESS, Watchpoint<ADDRESS> >()
		, mat(_mat)
		, mt(_mt)
		, addr(_addr)
		, size(_size)
		, overlook(_overlook)
		, id(-1)
	{
	}

	inline int GetId() const { return id; }
	inline typename unisim::util::debug::MemoryAccessType GetMemoryAccessType() const { return mat; }
	inline typename unisim::util::debug::MemoryType GetMemoryType() const { return mt; }
	inline ADDRESS GetAddress() const { return addr; }
	inline uint32_t GetSize() const { return size; }
	inline bool Overlooks() const { return overlook; }
	inline bool HasOverlap(ADDRESS addr) const
	{
		ADDRESS a_lo = this->addr;
		ADDRESS a_hi = this->addr + this->size - 1;
		return (addr >= a_lo) && (addr <= a_hi);
	}
	inline bool HasOverlap(ADDRESS addr, uint32_t size) const
	{
		ADDRESS a_lo = this->addr;
		ADDRESS a_hi = this->addr + this->size - 1;
		ADDRESS b_lo = addr;
		ADDRESS b_hi = addr + size - 1;
		ADDRESS ovl_lo = a_lo > b_lo ? a_lo : b_lo;
		ADDRESS ovl_hi = a_hi < b_hi ? a_hi : b_hi;
		
		return ovl_lo <= ovl_hi;
	}
	inline bool Equals(unisim::util::debug::MemoryAccessType _mat, unisim::util::debug::MemoryType _mt, ADDRESS _addr, uint32_t _size, bool _overlook)
	{
		return (mat == _mat) && (mt == _mt) && (addr = _addr) && (size = _size) && (overlook == _overlook);
	}
	
	inline void SetId(int _id) { id = _id; }
	
private:
	typename unisim::util::debug::MemoryAccessType mat;
	typename unisim::util::debug::MemoryType mt;
	ADDRESS addr;
	uint32_t size;
	bool overlook;
	int id;
};

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const Watchpoint<ADDRESS>& wp)
{
	switch(wp.GetMemoryType())
	{
		case unisim::util::debug::MT_DATA:
			os << "data";
			break;
		case unisim::util::debug::MT_INSN:
			os << "instruction";
			break;
	}
	os << " ";
	if((wp.GetMemoryAccessType() & (unisim::util::debug::MAT_WRITE | unisim::util::debug::MAT_READ)) == (unisim::util::debug::MAT_WRITE | unisim::util::debug::MAT_READ))
	{
		os << "read/write";
	}
	else if(wp.GetMemoryAccessType() & unisim::util::debug::MAT_WRITE)
	{
		os << "write";
	}
	else if(wp.GetMemoryAccessType() & unisim::util::debug::MAT_READ)
	{
		os << "read";
	}
	os << " at 0x" << std::hex << wp.GetAddress() << std::dec << " (" << wp.GetSize() << " bytes) watchpoint #" << wp.GetId() << " for processor #" << wp.GetProcessorNumber() << " and front-end #" << wp.GetFrontEndNumber() << " (" << (wp.Overlooks() ? "with" : "without") << " overlook)";
	
	return os;
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
