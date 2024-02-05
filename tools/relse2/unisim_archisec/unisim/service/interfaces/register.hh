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
 
#ifndef __UNISIM_SERVICE_INTERFACES_REGISTER_HH__
#define __UNISIM_SERVICE_INTERFACES_REGISTER_HH__

#include <unisim/service/interfaces/interface.hh>
#include <inttypes.h>
#include <string.h>
#include <iostream>

namespace unisim {
namespace service {
namespace interfaces {

struct Field : public ServiceInterface
{
	virtual const char *GetName() const = 0;
	virtual const char *GetDescription() const { return ""; }
	virtual unsigned int GetBitOffset() const = 0;
	virtual unsigned int GetBitWidth() const = 0;
	virtual uint64_t GetValue() const = 0;
	virtual void SetValue(uint64_t val) = 0;
};

struct FieldScanner : public ServiceInterface
{
	virtual void Append(Field *field) = 0;
};

struct Register : public ServiceInterface
{
	virtual const char *GetName() const = 0;
	virtual const char *GetDescription() const { return ""; }
	virtual void GetValue(void *buffer) const = 0;
	virtual void SetValue(const void *buffer) = 0;
	inline void Clear();
	virtual int GetSize() const = 0;
	virtual void ScanFields(FieldScanner& scanner) {}
	virtual Field *GetField(const char *name)
	{
		struct FieldFinder : FieldScanner
		{
			FieldFinder(const char *_name) : name(_name), found(0) {}
			virtual void Append(Field *field) { if(strcmp(field->GetName(), name) == 0) found = field; } 
			
			const char *name;
			Field *found;
		};
		
		FieldFinder field_finder(name);
		ScanFields(field_finder);
		return field_finder.found;
	}
	
	inline void GetValue(uint8_t& val) const { GetTypedValue(val); }
	inline void SetValue(const uint8_t& val) { SetTypedValue(val); }
	inline void GetValue(uint16_t& val) const { GetTypedValue(val); }
	inline void SetValue(const uint16_t& val) { SetTypedValue(val); }
	inline void GetValue(uint32_t& val) const { GetTypedValue(val); }
	inline void SetValue(const uint32_t& val) { SetTypedValue(val); }
	inline void GetValue(uint64_t& val) const { GetTypedValue(val); }
	inline void SetValue(const uint64_t& val) { SetTypedValue(val); }
	
	inline void Print(std::ostream& os) const;
private:
	template <typename T> void GetTypedValue(T& val) const;
	template <typename T> void SetTypedValue(const T& val);
};

inline void Register::Clear()
{
	int size = GetSize();
	char zeros[size];
	while (--size>=0) zeros[size] = 0;
	SetValue(&zeros[0]);
}

template <typename T>
void Register::GetTypedValue(T& val) const
{
	switch(GetSize())
	{
		case 1:
			{
				uint8_t val8;
				this->GetValue(&val8);
				val = val8;
			}
			break;
		case 2:
			{
				uint16_t val16;
				this->GetValue(&val16);
				val = val16;
			}
			break;
		case 4:
			{
				uint32_t val32;
				this->GetValue(&val32);
				val = val32;
			}
			break;
		case 8:
			{
				uint64_t val64;
				this->GetValue(&val64);
				val = val64;
			}
			break;
	}
}

template <typename T>
void Register::SetTypedValue(const T& val)
{
	switch(GetSize())
	{
		case 1:
			{
				uint8_t val8 = val;
				this->SetValue(&val8);
			}
			break;
		case 2:
			{
				uint16_t val16 = val;
				this->SetValue(&val16);
			}
			break;
		case 4:
			{
				uint32_t val32 = val;
				this->SetValue(&val32);
			}
			break;
		case 8:
			{
				uint64_t val64 = val;
				this->SetValue(&val64);
			}
			break;
	}
}

inline void Register::Print(std::ostream& os) const
{
	switch(GetSize())
	{
		case 1:
			{
				uint8_t val8;
				this->GetValue(&val8);
				os << +val8;
			}
			break;
		case 2:
			{
				uint16_t val16;
				this->GetValue(&val16);
				os << val16;
			}
			break;
		case 4:
			{
				uint32_t val32;
				this->GetValue(&val32);
				os << val32;
			}
			break;
		case 8:
			{
				uint64_t val64;
				this->GetValue(&val64);
				os << val64;
			}
			break;
	}
}

inline std::ostream& operator << (std::ostream& os, const Register& reg)
{
	reg.Print(os);
	return os;
}

} // end of namespace interfaces
} // end of namespace service
} // end of namespace unisim

#endif
