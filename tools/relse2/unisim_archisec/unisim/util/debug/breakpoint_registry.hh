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
 
#ifndef __UNISIM_UTIL_DEBUG_BREAKPOINT_REGISTRY_HH__
#define __UNISIM_UTIL_DEBUG_BREAKPOINT_REGISTRY_HH__

#include <unisim/util/debug/breakpoint.hh>
#include <unisim/service/interfaces/debug_event.hh>
#include <list>
#include <map>

namespace unisim {
namespace util {
namespace debug {

template <typename ADDRESS, unsigned int MAX_FRONT_ENDS = 1>
class BreakpointMapPage
{
public:
	BreakpointMapPage(ADDRESS addr);
	~BreakpointMapPage();

	unsigned int SetBreakpoint(uint32_t offset, unsigned int front_end_num);
	unsigned int RemoveBreakpoint(uint32_t offset, unsigned int front_end_num);
	bool HasBreakpoint(uint32_t offset, unsigned int front_end_num) const;
	bool HasBreakpoints(uint32_t offset) const;

	typedef uint64_t WORD;
	static const unsigned int NUM_BREAKPOINTS_PER_PAGE = 256;// MUST BE a power of two !
	static const unsigned int BITS_PER_BREAKPOINT = 1;
	static const unsigned int BITS_PER_BREAKPOINTS = BITS_PER_BREAKPOINT * MAX_FRONT_ENDS;
	static const unsigned int BREAKPOINTS_PER_WORD = (8 * sizeof(WORD)) / BITS_PER_BREAKPOINTS;
	ADDRESS base_addr;			/*< base effective address */
	WORD *map;			/*< an array of breakpoint masks for 64 consecutive effective addresses */
	BreakpointMapPage *next;	/*< next breakpoint map page with the same hash index */
};

template <typename ADDRESS, unsigned int NUM_PROCESSORS = 1, unsigned int MAX_FRONT_ENDS = 1>
class BreakpointRegistry
{
public:
	static const uint32_t NUM_HASH_TABLE_ENTRIES = 32; // MUST BE a power of two !

	BreakpointRegistry();
	virtual ~BreakpointRegistry();

	void Reset();
	void Clear(unsigned int front_end_num);
	Breakpoint<ADDRESS> *SetBreakpoint(ADDRESS addr, unsigned int prc_num = 0, unsigned int front_end_num = 0);
	bool RemoveBreakpoint(ADDRESS addr, unsigned int prc_num = 0, unsigned int front_end_num = 0);
	bool SetBreakpoint(Breakpoint<ADDRESS> *brkp);
	bool RemoveBreakpoint(Breakpoint<ADDRESS> *brkp);
	bool HasBreakpoint(Breakpoint<ADDRESS> *brkp) const;
	bool HasBreakpoints(ADDRESS addr, unsigned int prc_num) const;
	bool HasBreakpoints(ADDRESS addr, unsigned int prc_num, unsigned int front_end_num) const;
	bool HasBreakpoints(unsigned int prc_num) const;
	bool HasBreakpoints() const;
	void ScanBreakpoints(unsigned int prc_num, unsigned int front_end_num, unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;
	void ScanBreakpoints(unsigned int front_end_num, unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;
	void ScanBreakpoints(unisim::service::interfaces::DebugEventScanner<ADDRESS>& scanner) const;

	/* struct Visitor { void Visit(Breakpoint<ADDRESS> *) {} }; */
	template <class VISITOR> bool FindBreakpoints(ADDRESS addr, unsigned int prc_num, unsigned int front_end_num, VISITOR& visitor);
private:
	std::multimap<ADDRESS, Breakpoint<ADDRESS> *> breakpoints[NUM_PROCESSORS][MAX_FRONT_ENDS];
	unsigned int breakpoint_count[NUM_PROCESSORS];
	mutable BreakpointMapPage<ADDRESS, MAX_FRONT_ENDS> *mru_page[NUM_PROCESSORS];
	mutable BreakpointMapPage<ADDRESS, MAX_FRONT_ENDS> *hash_table[NUM_PROCESSORS][NUM_HASH_TABLE_ENTRIES];

	bool SetBreakpointIntoMap(ADDRESS addr, unsigned int prc_num, unsigned int front_end_num);
	bool RemoveBreakpointFromMap(ADDRESS addr, unsigned int prc_num, unsigned int front_end_num);
	void AllocatePage(ADDRESS addr, unsigned int prc_num);
	BreakpointMapPage<ADDRESS, MAX_FRONT_ENDS> *GetPage(ADDRESS addr, unsigned int prc_num) const;
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
