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
 
#ifndef __UNISIM_UTIL_DEBUG_SIMPLE_REGISTER_HH__
#define __UNISIM_UTIL_DEBUG_SIMPLE_REGISTER_HH__

#include <unisim/service/interfaces/register.hh>
#include <string>

namespace unisim {
namespace util {
namespace debug {

using std::string;

template <typename REGISTER_TYPE>
class SimpleRegister : public unisim::service::interfaces::Register
{
public:
	SimpleRegister(const char *name, REGISTER_TYPE *value);
	SimpleRegister(const char *name, const char *description, REGISTER_TYPE *value);
	SimpleRegister(const std::string& name, REGISTER_TYPE *value);
	SimpleRegister(const std::string& name, const std::string& description, REGISTER_TYPE *value);
	virtual ~SimpleRegister();
	virtual const char *GetName() const;
	virtual const char *GetDescription() const;
	virtual void GetValue(void *buffer) const;
	virtual void SetValue(const void *buffer);
	virtual int GetSize() const;
private:
	std::string name;
	std::string description;
	REGISTER_TYPE *value;
};

template <typename REGISTER_TYPE>
SimpleRegister<REGISTER_TYPE>::SimpleRegister(const char *_name, REGISTER_TYPE *_value) :
	name(_name),
	description(),
	value(_value)
{
}

template <typename REGISTER_TYPE>
SimpleRegister<REGISTER_TYPE>::SimpleRegister(const char *_name, const char *_description, REGISTER_TYPE *_value) :
	name(_name),
	description(_description),
	value(_value)
{
}

template <typename REGISTER_TYPE>
SimpleRegister<REGISTER_TYPE>::SimpleRegister(const std::string& _name, REGISTER_TYPE *_value) :
	name(_name),
	description(),
	value(_value)
{
}

template <typename REGISTER_TYPE>
SimpleRegister<REGISTER_TYPE>::SimpleRegister(const std::string& _name, const std::string& _description, REGISTER_TYPE *_value) :
	name(_name),
	description(_description),
	value(_value)
{
}

template <typename REGISTER_TYPE>
SimpleRegister<REGISTER_TYPE>::~SimpleRegister()
{
}

template <typename REGISTER_TYPE>
const char *SimpleRegister<REGISTER_TYPE>::GetName() const
{
	return name.c_str();
}

template <typename REGISTER_TYPE>
const char *SimpleRegister<REGISTER_TYPE>::GetDescription() const
{
	return description.c_str();
}

template <typename REGISTER_TYPE>
void SimpleRegister<REGISTER_TYPE>::GetValue(void *buffer) const
{
	*(REGISTER_TYPE *) buffer = *value;
}


template <typename REGISTER_TYPE>
void SimpleRegister<REGISTER_TYPE>::SetValue(const void *buffer)
{
	*value = *(REGISTER_TYPE *) buffer;
}

template <typename REGISTER_TYPE>
int SimpleRegister<REGISTER_TYPE>::GetSize() const
{
	return sizeof(REGISTER_TYPE);
}

} // end of namespace debug
} // end of namespace service
} // end of namespace unisim

#endif
