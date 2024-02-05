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
 
#ifndef __UNISIM_UTIL_DEBUG_SIMPLE_SYMBOL_TABLE_HH__
#define __UNISIM_UTIL_DEBUG_SIMPLE_SYMBOL_TABLE_HH__

#include <unisim/util/debug/symbol.hh>
#include <unisim/util/debug/symbol_table.hh>
#include <unisim/util/hash_table/hash_table.hh>
#include <list>
#include <map>
#include <vector>
#include <iosfwd>

namespace unisim {
namespace util {
namespace debug {

template <class T>
class SimpleSymbolTable : public SymbolTable<T>
{
public:
	SimpleSymbolTable();
	virtual ~SimpleSymbolTable();
	void Reset();
	void GetSymbols(typename std::list<const unisim::util::debug::Symbol<T> *>& lst, typename unisim::util::debug::Symbol<T>::Type type) const;
	const typename unisim::util::debug::Symbol<T> *FindSymbol(const char *name, T addr, typename unisim::util::debug::Symbol<T>::Type type) const;
	const typename unisim::util::debug::Symbol<T> *FindSymbolByAddr(T addr) const;
	const typename unisim::util::debug::Symbol<T> *FindSymbolByName(const char *name) const;
	const typename unisim::util::debug::Symbol<T> *FindSymbolByName(const char *name, typename unisim::util::debug::Symbol<T>::Type type) const;
	const typename unisim::util::debug::Symbol<T> *FindSymbolByAddr(T addr, typename unisim::util::debug::Symbol<T>::Type type) const ;
	void AddSymbol(const char *name, T addr, T size, typename unisim::util::debug::Symbol<T>::Type type, T memory_atom_size = 1);
	void Dump(std::ostream& os) const;
	void Dump(std::ostream& os, typename unisim::util::debug::Symbol<T>::Type type) const;
private:
	std::list<Symbol<T> *> symbol_registries[unisim::util::debug::Symbol<T>::SYM_HIPROC + 1];
	
	struct LookupTableByAddrEntry
	{
		LookupTableByAddrEntry(T _key, Symbol<T> *_symbol) : key(_key), symbol(_symbol), next(0) {}
		
		T key;
		Symbol<T> *symbol;
		LookupTableByAddrEntry *next;
	};
	
	mutable std::vector<typename unisim::util::debug::Symbol<T>::Type> types;
	unisim::util::hash_table::HashTable<T, LookupTableByAddrEntry> lookup_table_by_addr[unisim::util::debug::Symbol<T>::SYM_HIPROC + 1];
	std::map<std::string, Symbol<T> *> lookup_table_by_name[unisim::util::debug::Symbol<T>::SYM_HIPROC + 1];
	
	void Use(typename unisim::util::debug::Symbol<T>::Type type) const;
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
