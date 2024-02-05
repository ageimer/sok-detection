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
 *          Yves Lhuillier (yves.lhuillier@cea.fr)
 */
 
#ifndef __UNISIM_UTIL_DEBUG_WATCHPOINT_REGISTRY_HH__
#define __UNISIM_UTIL_DEBUG_WATCHPOINT_REGISTRY_HH__

#include <unisim/util/debug/memory_access_type.hh>
#include <unisim/util/debug/watchpoint.hh>
#include <unisim/service/interfaces/debug_event.hh>

#include <list>
#include <map>

namespace unisim {
namespace util {
namespace debug {

template <typename ADDRESS, unsigned int MAX_FRONT_ENDS = 1>
class WatchpointMapPage
{
public:
	WatchpointMapPage(ADDRESS addr);
	~WatchpointMapPage();

	unsigned int SetWatchpoint(unisim::util::debug::MemoryAccessType mat, uint32_t offset, uint32_t size, unsigned int front_end_num);
	unsigned int RemoveWatchpoint(unisim::util::debug::MemoryAccessType mat, uint32_t offset, uint32_t size, unsigned int front_end_num);
	bool HasWatchpoint(unisim::util::debug::MemoryAccessType mat, uint32_t offset, uint32_t size, unsigned int front_end_num) const;
	bool HasWatchpoints(unisim::util::debug::MemoryAccessType mat, uint32_t offset, uint32_t size) const;

	typedef uint64_t WORD;
	static const unsigned int NUM_WATCHPOINTS_PER_PAGE = 128; // MUST BE a power of two !
	static const unsigned int BITS_PER_WATCHPOINT = 2;
	static const unsigned int BITS_PER_WATCHPOINTS = BITS_PER_WATCHPOINT * MAX_FRONT_ENDS;
	static const unsigned int WATCHPOINTS_PER_WORD = (8 * sizeof(WORD)) / BITS_PER_WATCHPOINTS;
	ADDRESS base_addr;			/*< base effective address */
	WORD *map;			/*< an array of watchpoint masks for 32 consecutive effective addresses */
	WatchpointMapPage *next;	/*< next watchpoint map page with the same hash index */
};

template <typename ADDRESS, unsigned int NUM_PROCESSORS = 1, unsigned int MAX_FRONT_ENDS = 1>
class WatchpointRegistry
{
public:
	static const uint32_t NUM_HASH_TABLE_ENTRIES = 32;//4096; // MUST BE a power of two !

	WatchpointRegistry();
	virtual ~WatchpointRegistry();

	void Reset();
	void Clear(unsigned int front_end_num);
	Watchpoint<ADDRESS> *SetWatchpoint(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, bool overlook = true, unsigned int prc_num = 0, unsigned int front_end_num = 0);
	bool RemoveWatchpoint(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num = 0, unsigned int front_end_num = 0);
	bool SetWatchpoint(Watchpoint<ADDRESS> *wp);
	bool RemoveWatchpoint(Watchpoint<ADDRESS> *wp);
	bool HasWatchpoint(Watchpoint<ADDRESS> *wp) const;
	bool HasWatchpoints(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num = 0) const;
	bool HasWatchpoints(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num, unsigned int front_end_num) const;
	bool HasWatchpoints(unsigned int prc_num) const;
	bool HasWatchpoints() const;
	
	/* struct Visitor { void Visit(Watchpoint<ADDRESS> *) {} }; */
	template <class VISITOR> bool FindWatchpoints(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num, unsigned int front_end_num, VISITOR& visitor) const;
	
	void ScanWatchpoints(unsigned int prc_num, unsigned int front_end_num, unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;
	void ScanWatchpoints(unsigned int front_end_num, unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;
	void ScanWatchpoints(unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;

private:
	std::multimap<ADDRESS, Watchpoint<ADDRESS> *> watchpoints[NUM_PROCESSORS][MAX_FRONT_ENDS];
	unsigned int watchpoint_count[NUM_PROCESSORS];
	mutable WatchpointMapPage<ADDRESS, MAX_FRONT_ENDS> *mru_page[2][NUM_PROCESSORS];
	mutable WatchpointMapPage<ADDRESS, MAX_FRONT_ENDS> *hash_table[2][NUM_PROCESSORS][NUM_HASH_TABLE_ENTRIES];

	bool SetWatchpointIntoMap(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num, unsigned int front_end_num);
	bool RemoveWatchpointFromMap(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, unsigned int prc_num, unsigned int front_end_num);
	void AllocatePage(unisim::util::debug::MemoryType mt, ADDRESS addr, unsigned int prc_num);
	WatchpointMapPage<ADDRESS, MAX_FRONT_ENDS> *GetPage(unisim::util::debug::MemoryType mt, ADDRESS addr, unsigned int prc_num) const;
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
