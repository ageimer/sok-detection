/*
 *  Copyright (c) 2012,
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

#ifndef __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_HH__
#define __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_HH__

#include <unisim/util/endian/endian.hh>
#include <unisim/util/debug/data_object.hh>
#include <unisim/util/json/json.hh>
#include <string>
#include <sstream>
#include <iosfwd>

namespace unisim {
namespace service {
namespace interfaces {

template <class ADDRESS> class DataObjectLookup;

} // end of namespace interfaces
} // end of namespace service
} // end of namespace unisim

namespace unisim {
namespace util {
namespace debug {

template <class ADDRESS> class DataObjectDeserializer;

template <class ADDRESS>
std::istream& operator >> (std::istream& stream, const DataObjectDeserializer<ADDRESS>& data_object_initializer);

// Convert JSON data to data object value
template <class ADDRESS>
class DataObjectDeserializer
{
public:
	enum Status
	{
		OK                       = 0,
		PARSE_ERROR              = 1,
		OPTIMIZED_OUT            = 2,
		TYPE_ERROR               = 4,
		READ_ERROR               = 8,
		WRITE_ERROR              = 16,
		NOT_FOUND                = 32,
		UNSUPPORTED_FLOAT_FORMAT = 64
	};
	
	DataObjectDeserializer(DataObjectRef<ADDRESS>& data_object, const unisim::service::interfaces::DataObjectLookup<ADDRESS> *data_object_lookup_if);
	
	unsigned int Deserialize(std::istream& stream) const;

private:
	DataObjectRef<ADDRESS> data_object;
	const unisim::service::interfaces::DataObjectLookup<ADDRESS> *data_object_lookup_if;
	
	struct ContextStack
	{
		ContextStack(const DataObjectDeserializer<ADDRESS>& data_object_deserializer);
		
		bool Visit(const unisim::util::json::JSON_Value& value);
		bool Visit(const unisim::util::json::JSON_String& value);
		bool Visit(const unisim::util::json::JSON_Object& object);
		bool Visit(const unisim::util::json::JSON_Member& member);
		bool Visit(const unisim::util::json::JSON_Array& array);
		
		void PushMemberContext(const std::string& name);
		void PushArrayContext();
		void PopContext();
		bool InArray() const;
		void NextIndex();
		std::string DataObjectName() const;
		unsigned int GetIndex() const;
		
		struct Context
		{
			enum Type
			{
				CTX_MEMBER,
				CTX_ARRAY
			};
			
			Context();
			Context(Type type, const std::string& name, unsigned int index);
			
			Type type;
			std::string name;
			unsigned int index;
		};
		
		const DataObjectDeserializer<ADDRESS>& data_object_deserializer;
		typedef std::vector<Context> Stack;
		Stack stack;
		unsigned int status;
	};
	
	friend std::istream& operator >> <ADDRESS>(std::istream& stream, const DataObjectDeserializer<ADDRESS>& data_object_deserializer);
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_HH__
