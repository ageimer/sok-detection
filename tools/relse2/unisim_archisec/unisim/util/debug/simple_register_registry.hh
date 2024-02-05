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
 
#ifndef __UNISIM_UTIL_DEBUG_SIMPLE_REGISTER_REGISTRY_HH__
#define __UNISIM_UTIL_DEBUG_SIMPLE_REGISTER_REGISTRY_HH__

#include <unisim/service/interfaces/register.hh>
#include <unisim/service/interfaces/registers.hh>
#include <unisim/util/nat_sort/nat_sort.hh>
#include <string>
#include <map>

namespace unisim {
namespace util {
namespace debug {

class SimpleRegisterRegistry
{
public:
	virtual ~SimpleRegisterRegistry();
	void AddRegisterInterface(unisim::service::interfaces::Register *reg_if);
	unisim::service::interfaces::Register *GetRegister(const char *name);
	void ScanRegisters(unisim::service::interfaces::RegisterScanner& scanner);
private:
	std::map<std::string, unisim::service::interfaces::Register *, unisim::util::nat_sort::nat_ltstr> registers_registry;
	
	static std::string Key(const char *reg_name);
};

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_SIMPLE_REGISTER_REGISTRY_HH__
