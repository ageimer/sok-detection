/*
 *  Copyright (c) 2009,
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
 
#ifndef __UNISIM_UTIL_DEBUG_PROFILE_TCC__
#define __UNISIM_UTIL_DEBUG_PROFILE_TCC__

#include <iostream>

namespace unisim {
namespace util {
namespace debug {

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::ProfilePage(ADDRESS _key) :
	key(_key),
	next(0),
	cumulative_weight()
{
	weight_coverage_map = new uint64_t[(2 * UNIT_SIZE) / 64]();
	weights = new WEIGHT[UNIT_SIZE]();
	
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::~ProfilePage()
{
	delete[] weight_coverage_map;
	delete[] weights;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
bool ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::IsCovered(ADDRESS offset) const
{
	uint64_t mask = uint64_t(1) << ((2 * offset) % 64);
	return (weight_coverage_map[(2 * offset) / 64] & mask) != 0;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
bool ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::HasWeight(ADDRESS offset) const
{
	uint64_t mask = uint64_t(2) << ((2 * offset) % 64);
	return (weight_coverage_map[(2 * offset) / 64] & mask) != 0;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
ADDRESS ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::GetBaseAddress() const
{
	return key * UNIT_SIZE;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
const WEIGHT& ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::GetWeight(unsigned int offset) const
{
	return weights[offset];
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
const WEIGHT& ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::GetWeight() const
{
	return cumulative_weight;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::Cover(ADDRESS offset, unsigned int length)
{
	if(length > 0)
	{
		do
		{
			uint64_t mask = uint64_t(1) << ((2 * offset) % 64);
			weight_coverage_map[(2 * offset) / 64] |= mask;
		}
		while(++offset, (--length > 0));
	}
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::Accumulate(ADDRESS offset, const WEIGHT& weight)
{
	uint64_t mask = uint64_t(2) << ((2 * offset) % 64);
	weight_coverage_map[(2 * offset) / 64] |= mask;
	weights[offset] += weight;
	cumulative_weight += weight;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>::GetAddressRanges(std::vector<std::pair<ADDRESS, ADDRESS> >& addr_ranges) const
{
	ADDRESS base_addr = GetBaseAddress();
	bool addr_range_in_progress = false;
	std::pair<ADDRESS, ADDRESS> *prev_addr_range = 0;
	std::pair<ADDRESS, ADDRESS> addr_range;
	
	// prologue
	if(IsCovered(0) && !addr_ranges.empty())
	{
		std::pair<ADDRESS, ADDRESS>& _prev_addr_range = addr_ranges.back();
		
		if(base_addr && ((base_addr - 1) == _prev_addr_range.second))
		{
			prev_addr_range = &_prev_addr_range;
			addr_range_in_progress = true;
		}
	}
	
	ADDRESS offset;
	for(offset = 0; offset < UNIT_SIZE; offset++)
	{
		bool is_covered = IsCovered(offset);
		
		if(!addr_range_in_progress && is_covered)
		{
			ADDRESS addr = base_addr + offset;
			(prev_addr_range ? prev_addr_range : &addr_range)->first = addr;
			addr_range_in_progress = true;
		}
		else if(addr_range_in_progress && !is_covered)
		{
			ADDRESS addr = base_addr + offset - 1;
			(prev_addr_range ? prev_addr_range : &addr_range)->second = addr;
			if(prev_addr_range)
			{
				prev_addr_range = 0;
			}
			else
			{
				addr_ranges.push_back(addr_range);
			}
			addr_range_in_progress = false;
		}
	}
	
	// epilogue
	if(addr_range_in_progress)
	{
		(prev_addr_range ? prev_addr_range : &addr_range)->second = base_addr + offset - 1;
		if(!prev_addr_range)
		{
			addr_ranges.push_back(addr_range);
		}
	}
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
std::ostream& operator << (std::ostream& os, const ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>& page)
{
	ADDRESS base_addr = page.GetBaseAddress();
	ADDRESS offset;
	bool first = true;

	for(offset = 0; offset < UNIT_SIZE; offset++)
	{
		if(page.HasWeight(offset))
		{
			const WEIGHT& weight = page.GetWeight(offset);
			
			if(!first)
			{
				os << std::endl;
			}
			else
			{
				first = false;
			}
			os << "0x" << std::hex << (base_addr + offset) << std::dec << ":" << weight;
		}
	}
	return os;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
Profile<ADDRESS, WEIGHT, UNIT_SIZE>::Profile()
	: hash_table()
	, page_map()
	, cumulative_weight()
{
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
Profile<ADDRESS, WEIGHT, UNIT_SIZE>::~Profile()
{
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void Profile<ADDRESS, WEIGHT, UNIT_SIZE>::Clear()
{
	hash_table.Reset();
	page_map.clear();
	cumulative_weight = WEIGHT();
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *Profile<ADDRESS, WEIGHT, UNIT_SIZE>::AllocatePage(ADDRESS addr)
{
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = GetPage(addr);

	if(!page)
	{
		ADDRESS key = addr / UNIT_SIZE;
		page = new ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>(key);
		hash_table.Insert(page);
		page_map.insert(std::pair<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *>(addr & ~(UNIT_SIZE - 1), page));
	}
	
	return page;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *Profile<ADDRESS, WEIGHT, UNIT_SIZE>::GetPage(ADDRESS addr) const
{
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page;

	ADDRESS key = addr / UNIT_SIZE;

	page = hash_table.Find(key);
	
	return page;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void Profile<ADDRESS, WEIGHT, UNIT_SIZE>::Cover(ADDRESS addr, unsigned int length)
{
	if(length > 0)
	{
		do
		{
			ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = AllocatePage(addr);
			
			ADDRESS offset = addr & (UNIT_SIZE - 1);
			ADDRESS size_to_page_boundary = UNIT_SIZE - offset;
			unsigned int l = (length < size_to_page_boundary) ? length : size_to_page_boundary;
			page->Cover(offset, l);

			addr += l;
			length -= l;
		}
		while(length > 0);
	}
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
bool Profile<ADDRESS, WEIGHT, UNIT_SIZE>::IsCovered(ADDRESS addr) const
{
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = GetPage(addr);

	if(!page) return false;
	
	ADDRESS offset = addr & (UNIT_SIZE - 1);
	return page->IsCovered(offset);
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void Profile<ADDRESS, WEIGHT, UNIT_SIZE>::Accumulate(ADDRESS addr, const WEIGHT& weight)
{
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = AllocatePage(addr);

	ADDRESS offset = addr & (UNIT_SIZE - 1);
	page->Accumulate(offset, weight);
	cumulative_weight += weight;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
bool Profile<ADDRESS, WEIGHT, UNIT_SIZE>::GetWeight(ADDRESS addr, WEIGHT& weight) const
{
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = GetPage(addr);

	if(!page) return false;

	ADDRESS offset = addr & (UNIT_SIZE - 1);
	if(!page->HasWeight(offset)) return false;
	
	weight = page->GetWeight(offset);
	
	return true;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
const WEIGHT& Profile<ADDRESS, WEIGHT, UNIT_SIZE>::GetWeight() const
{
	return cumulative_weight;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
void Profile<ADDRESS, WEIGHT, UNIT_SIZE>::GetAddressRanges(std::vector<std::pair<ADDRESS, ADDRESS> >& addr_ranges) const
{
	typename std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *>::const_iterator page_map_it;
	
	for(page_map_it = page_map.begin(); page_map_it != page_map.end(); page_map_it++)
	{
		ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = (*page_map_it).second;
		
		page->GetAddressRanges(addr_ranges);
	}
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
std::ostream& operator << (std::ostream& os, const Profile<ADDRESS, WEIGHT, UNIT_SIZE>& prof)
{
	bool first = true;
	std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *> map = prof.hash_table;
	typename std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *>::const_iterator iter;

	for(iter = map.begin(); iter != map.end(); iter++)
	{
		if(!first)
		{
			os << std::endl;
		}
		else
		{
			first = false;
		}
		os << *(*iter).second;
	}

	return os;
}

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
Profile<ADDRESS, WEIGHT, UNIT_SIZE>::operator std::map<ADDRESS, WEIGHT>() const
{
	std::map<ADDRESS, WEIGHT> map;

	std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *> page_map = hash_table;
	typename std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *>::const_iterator iter;

	for(iter = page_map.begin(); iter != page_map.end(); iter++)
	{
		ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *page = (*iter).second;

		ADDRESS base_addr = page->GetBaseAddress();
		ADDRESS offset;

		for(offset = 0; offset < UNIT_SIZE; offset++)
		{
			if(page->HasWeight(offset))
			{
				const WEIGHT& weight = page->GetWeight(offset);
				map.insert(std::pair<ADDRESS, WEIGHT>(base_addr + offset, weight));
			}
		}
	}
	return map;
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
