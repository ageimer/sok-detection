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
 
#ifndef __UNISIM_UTIL_DEBUG_PROFILE_HH__
#define __UNISIM_UTIL_DEBUG_PROFILE_HH__

#include <unisim/util/hash_table/hash_table.hh>
#include <inttypes.h>
#include <iosfwd>
#include <map>
#include <vector>

namespace unisim {
namespace util {
namespace debug {

const uint32_t DEFAULT_PROFILE_UNIT_SIZE = 1024;

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
class Profile;

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
class ProfilePage;

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
std::ostream& operator << (std::ostream& os, const Profile<ADDRESS, WEIGHT, UNIT_SIZE>& prof);

template <typename ADDRESS, typename WEIGHT, uint32_t UNIT_SIZE>
std::ostream& operator << (std::ostream& os, const ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>& page);

template <typename ADDRESS, typename WEIGHT = uint64_t, uint32_t UNIT_SIZE = DEFAULT_PROFILE_UNIT_SIZE>
class ProfilePage
{
public:
	ProfilePage(ADDRESS _key);
	~ProfilePage();

	bool IsCovered(ADDRESS offset) const;
	bool HasWeight(ADDRESS offset) const;
	void GetAddressRanges(std::vector<std::pair<ADDRESS, ADDRESS> >& addr_ranges) const;
	ADDRESS GetBaseAddress() const;
	void Cover(ADDRESS offset, unsigned int length);
	void Accumulate(ADDRESS offset, const WEIGHT& weight);
	const WEIGHT& GetWeight(unsigned int offset) const;
	const WEIGHT& GetWeight() const;
	
	//friend std::ostream& operator << <ADDRESS, WEIGHT, UNIT_SIZE> (std::ostream& os, const ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE>& page);
private:
	friend class unisim::util::hash_table::HashTable<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> >;
	friend class Profile<ADDRESS, WEIGHT, UNIT_SIZE>;

	ADDRESS key;
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *next;
	
	uint64_t *weight_coverage_map;
	WEIGHT *weights;
	WEIGHT cumulative_weight;
};

template <typename ADDRESS, typename WEIGHT = uint64_t, uint32_t UNIT_SIZE = DEFAULT_PROFILE_UNIT_SIZE>
class Profile
{
public:
	Profile();
	~Profile();
	
	void Clear();
	void Cover(ADDRESS addr, unsigned int length);
	bool IsCovered(ADDRESS addr) const;
	void Accumulate(ADDRESS addr, const WEIGHT& weight);
	bool GetWeight(ADDRESS addr, WEIGHT& weight) const;
	const WEIGHT& GetWeight() const;
	void GetAddressRanges(std::vector<std::pair<ADDRESS, ADDRESS> >& addr_ranges) const;
	friend std::ostream& operator << <ADDRESS, WEIGHT, UNIT_SIZE> (std::ostream& os, const Profile<ADDRESS, WEIGHT, UNIT_SIZE>& prof);
	operator std::map<ADDRESS, WEIGHT>() const;

private:
	unisim::util::hash_table::HashTable<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> > hash_table;
	std::map<ADDRESS, ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *> page_map;
	WEIGHT cumulative_weight;
	
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *AllocatePage(ADDRESS addr);
	ProfilePage<ADDRESS, WEIGHT, UNIT_SIZE> *GetPage(ADDRESS addr) const;
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
