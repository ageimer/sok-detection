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
 
#include <unisim/util/debug/simple_field_registry.hh>
#include <cassert>
#include <cctype>

namespace unisim {
namespace util {
namespace debug {

SimpleFieldRegistry::~SimpleFieldRegistry()
{
	for(Fields::iterator it = fields.begin(); it != fields.end(); ++it)
	{
		unisim::service::interfaces::Field *field_if = *it;
		delete field_if;
	}
}

void SimpleFieldRegistry::AddFieldInterface(unisim::service::interfaces::Field *field_if)
{
	std::string key(Key(field_if->GetName()));
	assert(fields_by_name.find(key) == fields_by_name.end());
	fields.push_back(field_if);
	fields_by_name[key] = field_if;
}

unisim::service::interfaces::Field *SimpleFieldRegistry::GetField(const char *name)
{
	FieldsByName::iterator it = fields_by_name.find(Key(name));
	return (it != fields_by_name.end()) ? (*it).second : 0;
}

void SimpleFieldRegistry::ScanFields(unisim::service::interfaces::FieldScanner& scanner)
{
	for(Fields::iterator it = fields.begin(); it != fields.end(); ++it)
	{
		scanner.Append(*it);
	}
}

std::string SimpleFieldRegistry::Key(const char *reg_name)
{
	std::string key;
	for(const char *p = reg_name; *p; ++p)
	{
		key += std::tolower(*p);
	}
	return key;
}

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim
