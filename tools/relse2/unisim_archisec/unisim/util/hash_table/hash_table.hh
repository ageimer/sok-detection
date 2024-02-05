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
 
#ifndef __UNISIM_UTIL_HASH_TABLE_HASH_TABLE_HH__
#define __UNISIM_UTIL_HASH_TABLE_HASH_TABLE_HH__

#include <string.h>
#include <map>
#include <unisim/util/inlining/inlining.hh>

namespace unisim {
namespace util {
namespace hash_table {

#if 0
// IMPORTANT: Your ELEMENT class should look like this.
// The inserted elements are destroyed once the hash table is deleted.
// The hash table is optimized for find and inserting, not removing
class Element
{
public:
	KEY key;		/*< 'key' is an unique number (e.g. a memory address) */
	Element *next;	/*< 'next' is a pointer to the next least recently used element which has the same hashed key () */
};
#endif

template <class KEY, class ELEMENT>
class HashTable
{
public:
	static const KEY NUM_HASH_TABLE_ENTRIES = 4096;

	HashTable();
	~HashTable();

	static inline KEY Hash(KEY key) ALWAYS_INLINE;

	inline ELEMENT *Find(KEY key) const ALWAYS_INLINE;

	inline void Insert(ELEMENT *element) ALWAYS_INLINE;

	inline void Remove(ELEMENT *element) ALWAYS_INLINE;

	void Reset();

	operator std::map<KEY, ELEMENT *>() const;
private:
	mutable ELEMENT *mru_element;
	mutable ELEMENT *hash_table[NUM_HASH_TABLE_ENTRIES];
};

template <class KEY, class ELEMENT>
HashTable<KEY, ELEMENT>::HashTable()
{
	mru_element = 0;
	memset(hash_table, 0, sizeof(hash_table));
}

template <class KEY, class ELEMENT>
HashTable<KEY, ELEMENT>::~HashTable()
{
	Reset();
}

template <class KEY, class ELEMENT>
void HashTable<KEY, ELEMENT>::Reset()
{
	KEY index;
	mru_element = 0;
	for(index = 0; index < NUM_HASH_TABLE_ENTRIES; index++)
	{
		ELEMENT *element, *next_element;
		
		element = hash_table[index];
		if(element)
		{
			do
			{
				next_element = element->next;
				delete element;
				element = next_element;
			} while(element);
			hash_table[index] = 0;
		}
	}
}

template <class KEY, class ELEMENT>
inline KEY HashTable<KEY, ELEMENT>::Hash(KEY key)
{
	return key % NUM_HASH_TABLE_ENTRIES;
}

template <class KEY, class ELEMENT>
inline void HashTable<KEY, ELEMENT>::Insert(ELEMENT *element)
{
	KEY index = Hash(element->key);
	element->next = hash_table[index];
	hash_table[index] = element;
	mru_element = element;
}

template <class KEY, class ELEMENT>
inline void HashTable<KEY, ELEMENT>::Remove(ELEMENT *element)
{
	ELEMENT *prev, *cur;
	if(mru_element == element) mru_element = 0;
	KEY index = Hash(element->key);
	cur = hash_table[index];
	if(cur)
	{
		if(cur->key == index)
		{
			hash_table[index] = cur->next;
			return;
		}
		prev = cur;
		cur = cur->next;
		if(cur)
		{
			do
			{
				if(cur->key == index)
				{
					prev->next = cur->next;
					cur->next = 0;
					return;
				}
				prev = cur;
			} while((cur = cur->next) != 0);
		}
	}
}

template <class KEY, class ELEMENT>
inline ELEMENT *HashTable<KEY, ELEMENT>::Find(KEY key) const
{
	if(mru_element && mru_element->key == key) return mru_element;
	ELEMENT *prev, *cur;
	KEY index = Hash(key);
	cur = hash_table[index];
	if(cur)
	{
		if(cur->key == key)
		{
			mru_element = cur;
			return cur;
		}
		prev = cur;
		cur = cur->next;
		if(cur)
		{
			do
			{
				if(cur->key == key)
				{
					prev->next = cur->next;
					cur->next= hash_table[index];
					hash_table[index] = cur;
					mru_element = cur;
					return cur;
				}
				prev = cur;
			} while((cur = cur->next) != 0);
		}
	}
	return 0;
}

template <class KEY, class ELEMENT>
HashTable<KEY, ELEMENT>::operator std::map<KEY, ELEMENT *>() const
{
	std::map<KEY, ELEMENT *> map;
	KEY index;
	for(index = 0; index < NUM_HASH_TABLE_ENTRIES; index++)
	{
		ELEMENT *element;
		
		element = hash_table[index];
		if(element)
		{
			do
			{
				KEY key = element->key;
				map.insert(std::pair<KEY, ELEMENT *>(key, element));
				element = element->next;
			} while(element);
		}
	}
	return map;
}

} // end of namespace hash_table
} // end of namespace util
} // end of namespace unisim

#endif
