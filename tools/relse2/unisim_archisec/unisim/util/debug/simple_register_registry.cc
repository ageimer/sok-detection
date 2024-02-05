/*
 *  Copyright (c) 2019,
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
 
#include <unisim/util/debug/simple_register_registry.hh>
#include <cassert>
#include <cctype>

namespace unisim {
namespace util {
namespace debug {

SimpleRegisterRegistry::~SimpleRegisterRegistry()
{
	std::map<std::string, unisim::service::interfaces::Register *>::iterator reg_iter;

	for(reg_iter = registers_registry.begin(); reg_iter != registers_registry.end(); reg_iter++)
	{
		delete reg_iter->second;
	}
}

std::string SimpleRegisterRegistry::Key(const char *reg_name)
{
	std::string key;
	for(const char *p = reg_name; *p; ++p)
	{
		key += std::tolower(*p);
	}
	return key;
}

void SimpleRegisterRegistry::AddRegisterInterface(unisim::service::interfaces::Register *reg_if)
{
	std::string key(Key(reg_if->GetName()));
	assert(registers_registry.find(key) == registers_registry.end());
	registers_registry[key] = reg_if;
}

unisim::service::interfaces::Register *SimpleRegisterRegistry::GetRegister(const char *name)
{
	std::map<std::string, unisim::service::interfaces::Register *>::iterator reg_iter = registers_registry.find(Key(name));
	if(reg_iter != registers_registry.end())
	{
		return (*reg_iter).second;
	}

	return 0;
}

void SimpleRegisterRegistry::ScanRegisters(unisim::service::interfaces::RegisterScanner& scanner)
{
	std::map<std::string, unisim::service::interfaces::Register *>::iterator reg_iter;
	
	for(reg_iter = registers_registry.begin(); reg_iter != registers_registry.end(); reg_iter++)
	{
		unisim::service::interfaces::Register *reg_if = (*reg_iter).second;
		scanner.Append(reg_if);
	}
}

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim
