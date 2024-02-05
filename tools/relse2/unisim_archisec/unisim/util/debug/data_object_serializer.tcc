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

#ifndef __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_TCC__
#define __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_TCC__

#include <unisim/util/debug/data_object_serializer.hh>
#include <unisim/util/json/json.hh>

namespace unisim {
namespace util {
namespace debug {

template <class ADDRESS>
DataObjectSerializer<ADDRESS>::DataObjectSerializer(const DataObjectRef<ADDRESS>& _data_object, const unisim::service::interfaces::DataObjectLookup<ADDRESS> *_data_object_lookup_if, Style _style, Mode _mode)
	: data_object(_data_object)
	, data_object_lookup_if(_data_object_lookup_if)
	, style(_style)
	, mode(_mode)
{
}

template <class ADDRESS>
unsigned int DataObjectSerializer<ADDRESS>::Serialize(std::ostream& stream) const
{
	const Type *data_object_type = data_object.GetType();
	
	std::string data_object_name = std::string(data_object.GetName());
	typename DataObjectSerializer<ADDRESS>::ContextStack ctx_stack(*this, stream);
	ctx_stack.PushContext(data_object_name);
	data_object_type->Visit(ctx_stack);
	return ctx_stack.status;
}

template <class ADDRESS>
std::ostream& operator << (std::ostream& stream, const DataObjectSerializer<ADDRESS>& data_object_serializer)
{
	data_object_serializer.Serialize(stream);
	return stream;
}

template <class ADDRESS>
DataObjectSerializer<ADDRESS>::ContextStack::ContextStack(const DataObjectSerializer<ADDRESS>& _data_object_serializer, std::ostream& _stream)
	: data_object_serializer(_data_object_serializer)
	, stream(_stream)
	, stack()
	, status(OK)
{
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(Type const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	type->Scan(*this);
	return true;
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(CharType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			if(data_object_serializer.mode == STRICT)
			{
				status |= OPTIMIZED_OUT;
			}
			else
			{
				OptimizedOut();
			}
		}
		else
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_value = 0;
			if(data_object.Read(0, data_object_value, data_object_bit_size))
			{
				if((data_object_value >= 32) && (data_object_value < 128))
				{
					switch(data_object_serializer.style)
					{
						case C_LANG:
							stream << "'" << (char) data_object_value << "' /* 0x" << std::hex << data_object_value << std::dec << " */";
							break;
						case JSON:
							stream << "\"" << (char) data_object_value << "\"";
							break;
					}
				}
				else
				{
					switch(data_object_serializer.style)
					{
						case C_LANG:
							stream << "'\\0x" << std::hex << data_object_value << std::dec << "'";
							break;
						case JSON:
						{
							std::ostringstream sstr;
							sstr.width(4);
							sstr.fill('0');
							sstr << std::hex << data_object_value;
							stream << "\"\\u" << sstr.str() << "\"";
							break;
						}
					}
				}
			}
			else if(data_object_serializer.mode == STRICT)
			{
				status |= READ_ERROR;
			}
			else
			{
				Unreadable();
			}
		}
	}
	else
	{
		if(data_object_serializer.mode == STRICT)
		{
			status |= NOT_FOUND;
		}
		else
		{
			NotFound();
		}
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(IntegerType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			if(data_object_serializer.mode == STRICT)
			{
				status |= OPTIMIZED_OUT;
			}
			else
			{
				OptimizedOut();
			}
		}
		else
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_value = 0;
			if(data_object.Read(0, data_object_value, data_object_bit_size))
			{
				if(((const IntegerType *) type)->IsSigned())
				{
					stream << unisim::util::arithmetic::SignExtend(data_object_value, data_object_bit_size);
				}
				else
				{
					stream << data_object_value;
				}
			}
			else if(data_object_serializer.mode == STRICT)
			{
				status |= READ_ERROR;
			}
			else
			{
				Unreadable();
			}
		}
	}
	else
	{
		if(data_object_serializer.mode == STRICT)
		{
			status |= NOT_FOUND;
		}
		else
		{
			NotFound();
		}
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(FloatingPointType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			if(data_object_serializer.mode == STRICT)
			{
				status |= OPTIMIZED_OUT;
			}
			else
			{
				OptimizedOut();
			}
		}
		else
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_byte_size = (data_object_bit_size + 7 ) / 8;
			
			uint8_t data_object_raw_value[data_object_byte_size];
			if(data_object.Read(0, data_object_raw_value, 0, data_object_bit_size))
			{
				switch(data_object_bit_size)
				{
					case 32:
						{
							uint32_t value = 0;
							memcpy(&value, data_object_raw_value, 4);
							unisim::util::ieee754::SoftFloat sf_value = unisim::util::ieee754::SoftFloat(unisim::util::endian::Target2Host(data_object.GetEndian(), value));
							sf_value.writeDecimal(stream);
						}
						break;
					case 64:
						{
							uint64_t value = 0;
							memcpy(&value, data_object_raw_value, 8);
							unisim::util::ieee754::SoftDouble sd_value = unisim::util::ieee754::SoftDouble(unisim::util::endian::Target2Host(data_object.GetEndian(), value));
							sd_value.writeDecimal(stream);
						}
						break;
					default:
						UnprintableFloatingPoint(data_object_bit_size);
						break;
				}
			}
			else if(data_object_serializer.mode == STRICT)
			{
				status |= READ_ERROR;
			}
			else
			{
				Unfetchable();
			}
		}
	}
	else
	{
		if(data_object_serializer.mode == STRICT)
		{
			status |= NOT_FOUND;
		}
		else
		{
			NotFound();
		}
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(BooleanType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			if(data_object_serializer.mode == STRICT)
			{
				status |= OPTIMIZED_OUT;
			}
			else
			{
				OptimizedOut();
			}
		}
		else
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_value = 0;
			if(data_object.Read(0, data_object_value, data_object_bit_size))
			{
				stream << (data_object_value ? "true" : "false");
			}
			else if(data_object_serializer.mode == STRICT)
			{
				status |= READ_ERROR;
			}
			else
			{
				Unreadable();
			}
		}
	}
	else
	{
		if(data_object_serializer.mode == STRICT)
		{
			status |= NOT_FOUND;
		}
		else
		{
			NotFound();
		}
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(CompositeType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	stream << "{ ";
	type->Scan(*this);
	stream << " }";
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(ArrayType const *array_type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "{ ";
			break;
		case JSON:
			stream << "[ ";
			break;
	}
	int64_t lower_bound = array_type->GetLowerBound();
	int64_t upper_bound = array_type->GetUpperBound();
	for(int64_t subscript = lower_bound; subscript <= upper_bound; ++subscript)
	{
		if(GetIndex()) stream << ", ";
		std::stringstream element_path_sstr;
		element_path_sstr << '[' << subscript << ']';
		PushContext(element_path_sstr.str());
		const Type *type_of_element = array_type->GetTypeOfElement();
		type_of_element->Visit(*this);
		PopContext();
		NextIndex();
	}
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << " }";
			break;
		case JSON:
			stream << " ]";
			break;
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(PointerType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			if(data_object_serializer.mode == STRICT)
			{
				status |= OPTIMIZED_OUT;
			}
			else
			{
				OptimizedOut();
			}
		}
		else
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_value = 0;
			if(data_object.Read(0, data_object_value, data_object_bit_size))
			{
				if(data_object_serializer.style == C_LANG)
				{
					stream << "@0x" << std::hex << data_object_value << std::dec;
				}
				
				if(data_object_value != 0)
				{
					if(TypeIsCharPointer::Test(type))
					{
						bool fail = false;
						std::string s;
						unsigned int i = 0;
						uint64_t char_value = 0;
						do
						{
							std::stringstream char_object_name_sstr;
							char_object_name_sstr << data_object_name << "[" << i << "]";
							std::string char_object_name(char_object_name_sstr.str());
							
							DataObjectRef<ADDRESS> char_object = data_object_serializer.data_object_lookup_if->FindDataObject(char_object_name.c_str());
							
							if(char_object != DataObjectRef<ADDRESS>::Undefined)
							{
								if(char_object.IsOptimizedOut())
								{
									if(data_object_serializer.style == C_LANG) stream << " /* <optimized out> */";
									fail = true;
								}
								else
								{
									if(char_object.Read(0, char_value, 8))
									{
										if(char_value)
										{
											s += (char) char_value;
										}
									}
									else
									{
										if(data_object_serializer.style == C_LANG) stream << " /* <unreadable> */";
										fail = true;
									}
								}
							}
							else
							{
								if(data_object_serializer.style == C_LANG) stream << " /* <not found> */";
								fail = true;
							}
							
							++i;
						}
						while(!fail && char_value);
						
						if(fail)
						{
							if(data_object_serializer.style == JSON)
							{
								stream << data_object_value;
							}
						}
						else
						{
							switch(data_object_serializer.style)
							{
								case JSON:
									stream << "\"" << unisim::util::json::Escape(s) << "\"";
									break;
								case C_LANG:
									stream << " /* \"" << unisim::util::json::Escape(s) << "\" */";
									break;
							}
						}
					}
					else if(data_object_serializer.style == JSON)
					{
						stream << data_object_value;
					}
				}
				else if(data_object_serializer.style == JSON)
				{
					stream << "null";
				}
			}
			else if(data_object_serializer.mode == STRICT)
			{
				status |= READ_ERROR;
			}
			else
			{
				Unreadable();
			}
		}
	}
	else
	{
		NotFound();
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(FunctionType const *type)
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<function>";
			break;
		case JSON:
			stream << "\"<function>\"";
			break;
	}
	
	return true;
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(EnumType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_serializer.data_object_lookup_if->FindDataObject(data_object_name.c_str());
	if(data_object != DataObjectRef<ADDRESS>::Undefined)
	{
		if(!data_object.IsOptimizedOut())
		{
			uint64_t data_object_bit_size = data_object.GetBitSize();
			uint64_t data_object_value = 0;
			if(data_object.Read(0, data_object_value, data_object_bit_size))
			{
				stream << data_object_value;
			}
			else
			{
				Unreadable();
			}
		}
		else
		{
			OptimizedOut();
		}
	}
	else
	{
		NotFound();
	}
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(UnspecifiedType const *type)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<void>";
			break;
		case JSON:
			stream << "\"<void>\"";
			break;
	}
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(Member const *member)
{
	if((data_object_serializer.mode == LAZY) && (status != OK)) return false;
	if(GetIndex()) stream << ", ";
	if(member->HasName())
	{
		std::string member_name = member->GetName();
		switch(data_object_serializer.style)
		{
			case C_LANG:
				stream << '.' << member_name << " = ";
				break;
			case JSON:
				stream << "\"" << member_name << "\" : ";
				break;
		}
		PushContext(std::string(".") + member_name);
		member->Scan(*this);
		PopContext();
	}
	else
	{
		member->Scan(*this);
	}
	NextIndex();
	
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
bool DataObjectSerializer<ADDRESS>::ContextStack::Visit(FormalParameter const *formal_param)
{
	return (data_object_serializer.mode == LAZY) || (status == OK);
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::Unfetchable() const
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<unfetchable>";
			break;
		case JSON:
			stream << "null";
			break;
	}
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::Unreadable() const
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<unreadable>";
			break;
		case JSON:
			stream << "null";
			break;
	}
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::UnprintableFloatingPoint(unsigned int bit_size) const
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<unprintable " << bit_size << "-bit floating-point value>";
			break;
		case JSON:
			stream << "null";
			break;
	}
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::OptimizedOut() const
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<optimized out>";
			break;
		case JSON:
			stream << "null";
			break;
	}
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::NotFound() const
{
	switch(data_object_serializer.style)
	{
		case C_LANG:
			stream << "<not found>";
			break;
		case JSON:
			stream << "null";
			break;
	}
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::PushContext(const std::string& name)
{
	stack.push_back(Context(name));
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::PopContext()
{
	stack.pop_back();
}

template <class ADDRESS>
std::string DataObjectSerializer<ADDRESS>::ContextStack::DataObjectName() const
{
	std::string data_object_name;
	unsigned int n = stack.size();
	for(unsigned int i = 0; i < n; ++i)
	{
		data_object_name += stack[i].name;
	}
	return data_object_name;
}

template <class ADDRESS>
void DataObjectSerializer<ADDRESS>::ContextStack::NextIndex()
{
	++stack.back().index;
}

template <class ADDRESS>
unsigned int DataObjectSerializer<ADDRESS>::ContextStack::GetIndex() const
{
	return stack.back().index;
}

template <class ADDRESS>
DataObjectSerializer<ADDRESS>::ContextStack::Context::Context()
	: name()
	, index(0)
{
}

template <class ADDRESS>
DataObjectSerializer<ADDRESS>::ContextStack::Context::Context(const std::string& _name)
	: name(_name)
	, index(0)
{
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_SERIALIZER_TCC__
