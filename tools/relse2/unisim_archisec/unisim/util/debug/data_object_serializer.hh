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

#ifndef __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_HH__
#define __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_HH__

#include <unisim/util/endian/endian.hh>
#include <unisim/util/debug/data_object.hh>
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

template <class ADDRESS> class DataObjectSerializer;

template <class ADDRESS>
std::ostream& operator << (std::ostream& stream, const DataObjectSerializer<ADDRESS>& data_object_initializer);

// Convert data object value to either JSON data or pseudo C language
template <class ADDRESS>
class DataObjectSerializer
{
public:
	enum Style
	{
		C_LANG,
		JSON
	};
	
	enum Mode
	{
		STRICT,
		LAZY
	};
	
	enum Status
	{
		OK                       = 0,
		OPTIMIZED_OUT            = 1,
		READ_ERROR               = 2,
		NOT_FOUND                = 4,
		UNSUPPORTED_FLOAT_FORMAT = 8
	};
	
	DataObjectSerializer(const DataObjectRef<ADDRESS>& data_object, const unisim::service::interfaces::DataObjectLookup<ADDRESS> *data_object_lookup_if, Style style = JSON, Mode mode = STRICT);
	
	unsigned int Serialize(std::ostream& stream) const;
	
private:
	const DataObjectRef<ADDRESS> data_object;
	const unisim::service::interfaces::DataObjectLookup<ADDRESS> *data_object_lookup_if;
	Style style;
	Mode mode;
	
	struct ContextStack
	{
		ContextStack(const DataObjectSerializer<ADDRESS>& data_object_serializer, std::ostream& stream);
		
		bool Visit(Type const *type);
		bool Visit(CharType const *type);
		bool Visit(IntegerType const *type);
		bool Visit(FloatingPointType const *type);
		bool Visit(BooleanType const *type);
		bool Visit(CompositeType const *type);
		bool Visit(ArrayType const *type);
		bool Visit(PointerType const *type);
		bool Visit(FunctionType const *type);
		bool Visit(EnumType const *type);
		bool Visit(UnspecifiedType const *type);
		bool Visit(Member const *member);
		bool Visit(FormalParameter const *formal_param);
		
		void Unfetchable() const;
		void Unreadable() const;
		void UnprintableFloatingPoint(unsigned int bit_size) const;
		void OptimizedOut() const;
		void NotFound() const;
		void PushContext(const std::string& s);
		void PopContext();
		void NextIndex();
		std::string DataObjectName() const;
		unsigned int GetIndex() const;
		
		struct Context
		{
			Context();
			Context(const std::string& name);
			
			std::string name;
			unsigned int index;
		};
		
		const DataObjectSerializer<ADDRESS>& data_object_serializer;
		std::ostream& stream;
		typedef std::vector<Context> Stack;
		Stack stack;
		unsigned int status;
	};
	
	friend std::ostream& operator << <ADDRESS>(std::ostream& stream, const DataObjectSerializer<ADDRESS>& data_object_serializer);
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_HH__
