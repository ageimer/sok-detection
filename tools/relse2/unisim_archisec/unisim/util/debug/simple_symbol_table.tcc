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
 
#ifndef __UNISIM_UTIL_DEBUG_SIMPLE_SYMBOL_TABLE_TCC__
#define __UNISIM_UTIL_DEBUG_SIMPLE_SYMBOL_TABLE_TCC__

#include <unisim/util/debug/simple_symbol_table.hh>
#include <iostream>
#include <sstream>
#include <string.h>

namespace unisim {
namespace util {
namespace debug {

template <class T>
SimpleSymbolTable<T>::SimpleSymbolTable()
	: SymbolTable<T>()
	, symbol_registries()
	, types()
	, lookup_table_by_addr()
	, lookup_table_by_name()
{
	types.push_back(unisim::util::debug::Symbol<T>::SYM_NOTYPE);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_OBJECT);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_FUNC);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_SECTION);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_FILE);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_COMMON);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_TLS);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_NUM);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_LOOS);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_HIOS);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_LOPROC);
	types.push_back(unisim::util::debug::Symbol<T>::SYM_HIPROC);
}

template <class T>
SimpleSymbolTable<T>::~SimpleSymbolTable()
{
	Reset();
}

template <class T>
void SimpleSymbolTable<T>::Reset()
{
	typename std::list<Symbol<T> *>::iterator symbol_iter;
	unsigned int i;
	
	for(i = 0; i < sizeof(symbol_registries) / sizeof(symbol_registries[0]); i++)
	{
		for(symbol_iter = symbol_registries[i].begin(); symbol_iter != symbol_registries[i].end(); symbol_iter++)
		{
			delete *symbol_iter;
		}
		symbol_registries[i].clear();
		lookup_table_by_addr[i].Reset();
		lookup_table_by_name[i].clear();
	}
}

template <class T>
void SimpleSymbolTable<T>::GetSymbols(typename std::list<const unisim::util::debug::Symbol<T> *>& lst, typename unisim::util::debug::Symbol<T>::Type type) const
{
	typename std::list<Symbol<T> *>::const_iterator symbol_iter;
		
	for(symbol_iter = symbol_registries[type].begin(); symbol_iter != symbol_registries[type].end(); symbol_iter++)
	{
		lst.push_back(*symbol_iter);
	}
}

template <class T>
const typename unisim::util::debug::Symbol<T> *SimpleSymbolTable<T>::FindSymbol(const char *name, T addr, typename unisim::util::debug::Symbol<T>::Type type) const
{
	typename std::list<Symbol<T> *>::const_iterator symbol_iter;
	
	for(symbol_iter = symbol_registries[type].begin(); symbol_iter != symbol_registries[type].end(); symbol_iter++)
	{
		if(strcmp((*symbol_iter)->GetName(), name) == 0 &&
		   addr >= (*symbol_iter)->GetAddress() &&
		   addr < (*symbol_iter)->GetAddress() + (*symbol_iter)->GetSize() &&
		   (*symbol_iter)->GetType() == type)
		{
			return *symbol_iter;
		}
	}
	return 0;
}

template <class T>
const typename unisim::util::debug::Symbol<T> *SimpleSymbolTable<T>::FindSymbolByAddr(T addr) const
{
	for(typename std::vector<typename unisim::util::debug::Symbol<T>::Type>::const_iterator it = types.begin(); it != types.end(); ++it)
	{
		typename unisim::util::debug::Symbol<T>::Type type = *it;
		const unisim::util::debug::Symbol<T> *symbol = FindSymbolByAddr(addr, type);
		if(symbol)
		{
			Use(type);
			return symbol;
		}
	}
	return 0;
}

template <class T>
const typename unisim::util::debug::Symbol<T> *SimpleSymbolTable<T>::FindSymbolByName(const char *name) const
{
	for(typename std::vector<typename unisim::util::debug::Symbol<T>::Type>::const_iterator it = types.begin(); it != types.end(); ++it)
	{
		typename unisim::util::debug::Symbol<T>::Type type = *it;
		const unisim::util::debug::Symbol<T> *symbol = FindSymbolByName(name, type);
		if(symbol)
		{
			Use(type);
			return symbol;
		}
	}
	return 0;
}

template <class T>
const typename unisim::util::debug::Symbol<T> *SimpleSymbolTable<T>::FindSymbolByName(const char *name, typename unisim::util::debug::Symbol<T>::Type type) const
{
	typename std::map<std::string, Symbol<T> *>::const_iterator it = lookup_table_by_name[type].find(name);
	return (it != lookup_table_by_name[type].end()) ? (*it).second : 0;
}

template <class T>
const typename unisim::util::debug::Symbol<T> *SimpleSymbolTable<T>::FindSymbolByAddr(T addr, typename unisim::util::debug::Symbol<T>::Type type) const
{
	LookupTableByAddrEntry *entry = lookup_table_by_addr[type].Find(addr);
	return entry ? entry->symbol : 0;
}

template <class T>
void SimpleSymbolTable<T>::AddSymbol(const char *name, T addr, T size, typename unisim::util::debug::Symbol<T>::Type type, T memory_atom_size)
{
	Symbol<T> *symbol = new Symbol<T>(name, addr, size, type, memory_atom_size);
	symbol_registries[type].push_back(symbol);
	
	for(T i = 0; i < size; i++)
	{
		lookup_table_by_addr[type].Insert(new LookupTableByAddrEntry(addr + i, symbol));
	}
	
	lookup_table_by_name[type].insert(std::pair<std::string, Symbol<T> *>(name, symbol));
}

template <class T>
void SimpleSymbolTable<T>::Dump(std::ostream& os) const
{
	unsigned int i;
	
	for(i = 0; i < sizeof(symbol_registries) / sizeof(symbol_registries[0]); i++)
	{
		Dump(os, (typename Symbol<T>::Type) i);
	}
}

template <class T>
void SimpleSymbolTable<T>::Dump(std::ostream& os, typename unisim::util::debug::Symbol<T>::Type type) const
{
	typename std::list<Symbol<T> *>::const_iterator symbol_iter;
	const char *type_name = "";

	switch(type)
	{
		case unisim::util::debug::Symbol<T>::SYM_NOTYPE:
			type_name = "no type";
			break;
		case unisim::util::debug::Symbol<T>::SYM_OBJECT:
			type_name = "object";
			break;
		case unisim::util::debug::Symbol<T>::SYM_FUNC:
			type_name = "function";
			break;
		case unisim::util::debug::Symbol<T>::SYM_SECTION:
			type_name = "section";
			break;
		case unisim::util::debug::Symbol<T>::SYM_FILE:
			type_name = "file";
			break;
		case unisim::util::debug::Symbol<T>::SYM_COMMON:
			type_name = "common";
			break;
		case unisim::util::debug::Symbol<T>::SYM_TLS:
			type_name = "tls";
			break;
		case unisim::util::debug::Symbol<T>::SYM_NUM:
			type_name = "num";
			break;
		case unisim::util::debug::Symbol<T>::SYM_LOOS:
			type_name = "loos";
			break;
		case unisim::util::debug::Symbol<T>::SYM_HIOS:
			type_name = "hios";
			break;
		case unisim::util::debug::Symbol<T>::SYM_LOPROC:
			type_name = "loproc";
			break;
		case unisim::util::debug::Symbol<T>::SYM_HIPROC:
			type_name = "hiproc";
			break;
	}

	for(symbol_iter = symbol_registries[type].begin(); symbol_iter != symbol_registries[type].end(); symbol_iter++)
	{
		os << type_name << ":" << std::hex << (*symbol_iter)->GetAddress() << std::dec << ": " << (*symbol_iter)->GetName() << " (" << (*symbol_iter)->GetSize() << " bytes)" << std::endl;
	}
}

template <class T>
void SimpleSymbolTable<T>::Use(typename unisim::util::debug::Symbol<T>::Type type) const
{
	if(types.front() != type)
	{
		for(typename std::vector<typename unisim::util::debug::Symbol<T>::Type>::iterator it = types.begin(); it != types.end(); ++it)
		{
			if((*it) == type)
			{
				types.erase(it);
				types.insert(types.begin(), type);
				return;
			}
		}
	}
}

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim

#endif
