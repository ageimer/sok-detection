/*
 *  Copyright (c) 2022,
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

#ifndef __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_TCC__
#define __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_TCC__

#include <unisim/util/debug/data_object_deserializer.hh>
#include <unisim/util/json/json.tcc>
#include <cstring>

namespace unisim {
namespace util {
namespace debug {

template <class ADDRESS>
DataObjectDeserializer<ADDRESS>::DataObjectDeserializer(DataObjectRef<ADDRESS>& _data_object, const unisim::service::interfaces::DataObjectLookup<ADDRESS> *_data_object_lookup_if)
	: data_object(_data_object)
	, data_object_lookup_if(_data_object_lookup_if)
{
}

template <class ADDRESS>
unsigned int DataObjectDeserializer<ADDRESS>::Deserialize(std::istream& stream) const
{
	unisim::util::json::JSON_Parser<unisim::util::json::JSON_AST_Builder> json_parser;
	unisim::util::json::JSON_AST_Builder json_ast_builder;
	
	unisim::util::json::JSON_Value *root = json_parser.Parse(stream, json_ast_builder);
	
	if(!root) return PARSE_ERROR;

	typename DataObjectDeserializer<ADDRESS>::ContextStack ctx_stack(*this);
	root->Visit(ctx_stack);
	delete root;
	
	return ctx_stack.status;
}

template <class ADDRESS>
std::ostream& operator >> (std::ostream& stream, const DataObjectDeserializer<ADDRESS>& data_object_deserializer)
{
	data_object_deserializer.Deserialize(stream);
	return stream;
}

template <class ADDRESS>
DataObjectDeserializer<ADDRESS>::ContextStack::ContextStack(const DataObjectDeserializer<ADDRESS>& _data_object_deserializer)
	: data_object_deserializer(_data_object_deserializer)
	, stack()
	, status(OK)
{
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::Visit(const unisim::util::json::JSON_Value& json_value)
{
	if(status != OK) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_lookup_if->FindDataObject(data_object_name);
	
	if(data_object != DataObject<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			status |= OPTIMIZED_OUT;
		}
		else
		{
			const unisim::util::debug::Type *data_object_type = data_object.GetType();
			unisim::util::json::JSON_ValueType json_value_type = json_value.GetType();
			
			if(unisim::util::debug::TypeIsFloat::Test(data_object_type))
			{
				double value = 0.0;
				unisim::util::json::JSON_ValueType json_value_type = json_value.GetType();
				switch(json_value_type)
				{
					case unisim::util::json::JSON_INT: value = json_value.AsInteger(); break;
					case unisim::util::json::JSON_UINT: value = json_value.AsUnsignedInteger(); break;
					case unisim::util::json::JSON_FLOAT: value = json_value.AsFloat(); break;
					case unisim::util::json::JSON_BOOLEAN: value = json_value.AsBoolean(); break;
					case unisim::util::json::JSON_BOOLEAN: value = json_value.AsBoolean(); break;
					default: break;
				}
				uint64_t data_object_bit_size = data_object.GetBitSize();
				uint64_t data_object_byte_size = (data_object_bit_size + 7 ) / 8;
				uint8_t data_object_raw_value[data_object_byte_size];
				if(data_object.Read(0, data_object_raw_value, 0, data_object_bit_size))
				{
					if((data_object_bit_size == 32) || (data_object_bit_size == 64))
					{
						if(data_object_bit_size == 32)
						{
							float float_value = (float) value;
							uint32_t raw_float_value;
							::memcpy(&raw_float_value, &float_value, 4);
							raw_float_value = unisim::util::endian::Host2Target(data_object.GetEndian(), raw_float_value);
							::memcpy(data_object_raw_value, &raw_float_value, 4);
						}
						else if(data_object_bit_size == 64)
						{
							double double_value = value;
							uint64_t raw_double_value;
							::memcpy(&raw_double_value, &double_value, 8);
							raw_double_value = unisim::util::endian::Host2Target(data_object.GetEndian(), raw_double_value);
							::memcpy(data_object_raw_value, &raw_double_value, 8);
						}
						
						if(!data_object.Write(0, data_object_raw_value, 0, data_object_bit_size))
						{
							status |= WRITE_ERROR;
						}
					}
					else
					{
						status |= UNSUPPORTED_FLOAT_FORMAT;
					}
				}
				else
				{
					status |= READ_ERROR;
				}
			}
			else
			{
				uint64_t data_object_bit_size = data_object.GetBitSize();
				uint64_t data_object_value = 0;
				unisim::util::json::JSON_ValueType json_value_type = json_value.GetType();
				switch(json_value_type)
				{
					case unisim::util::json::JSON_INT: data_object_value = json_value.AsInteger(); break;
					case unisim::util::json::JSON_UINT: data_object_value = json_value.AsUnsignedInteger(); break;
					case unisim::util::json::JSON_FLOAT: data_object_value = (int64_t) (double) json_value.AsFloat(); break;
					case unisim::util::json::JSON_BOOLEAN: data_object_value = json_value.AsBoolean(); break;
					default: break;
				}
				if(!data_object.Write(0, data_object_value, data_object_bit_size) || !data_object.Commit())
				{
					status |= WRITE_ERROR;
				}
			}
		}
		delete data_object;
	}
	else
	{
		status |= NOT_FOUND;
	}
	
	if(InArray()) NextIndex();
	return status == OK;
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::Visit(const unisim::util::json::JSON_String& value)
{
	if(status != OK) return false;
	std::string data_object_name = DataObjectName();
	DataObjectRef<ADDRESS> data_object = data_object_lookup_if->FindDataObject(data_object_name);
	
	if(data_object != DataObject<ADDRESS>::Undefined)
	{
		if(data_object.IsOptimizedOut())
		{
			status |= OPTIMIZED_OUT;
		}
		else
		{
			const unisim::util::debug::Type *data_object_type = data_object.GetType();
			
			if(unisim::util::debug::TypeIsCharPointer::Test(data_object_type))
			{
				uint64_t data_object_bit_size = data_object.GetBitSize();
				uint64_t data_object_value = 0;
				if(data_object.Read(0, data_object_value, data_object_bit_size))
				{
					if(data_object_value != 0)
					{
						const std::string& s = value;
						unsigned int n = s.length();
						unsigned int i = 0;
						bool fail = false;
						
						while(!fail && (i <= n))
						{
							char char_value = (i < n) ? s[i] : 0;
							++i;
							
							std::stringstream char_object_name_sstr;
							char_object_name_sstr << data_object_name << "[" << i << "]";
							std::string char_object_name(char_object_name_sstr.str());
							
							DataObjectRef<ADDRESS> char_object = data_object_deserializer.data_object_lookup_if->FindDataObject(char_object_name.c_str());
							
							if(char_object != DataObjectRef<ADDRESS>::Undefined)
							{
								if(char_object.IsOptimizedOut())
								{
									status |= OPTIMIZED_OUT;
									fail = true;
								}
								else if(!char_object.Write(0, char_value, 8))
								{
									status |= WRITE_ERROR;
									fail = true;
								}
							}
							else
							{
								status |= NOT_FOUND;
								fail = true;
							}
						}
					}
					else
					{
						status |= WRITE_ERROR;
					}
				}
				else
				{
					status |= READ_ERROR;
				}
			}
			else
			{
				status |= TYPE_ERROR;
			}
		}
		
		delete data_object;
	}
	else
	{
		status |= NOT_FOUND;
	}
	
	if(InArray()) NextIndex();
	return status == OK;
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::Visit(const unisim::util::json::JSON_Object& object)
{
	if(status != OK) return false;
	object.Scan(*this);
	if(InArray()) NextIndex();
	return status == OK;
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::Visit(const unisim::util::json::JSON_Member& member)
{
	if(status != OK) return false;
	PushMemberContext(member.GetName());
	member.Scan(*this);
	PopContext();
	return status == OK;
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::Visit(const unisim::util::json::JSON_Array& array)
{
	if(status != OK) return false;
	PushArrayContext();
	array.Scan(*this);
	PopContext();
	if(InArray()) NextIndex();
	return status == OK;
}

template <class ADDRESS>
void DataObjectDeserializer<ADDRESS>::ContextStack::PushMemberContext(const std::string& name)
{
	stack.push_back(Context(Context::CTX_MEMBER, name, 0));
}

template <class ADDRESS>
void DataObjectDeserializer<ADDRESS>::ContextStack::PushArrayContext()
{
	stack.push_back(Context(Context::CTX_ARRAY, std::string(), 0));
}

template <class ADDRESS>
void DataObjectDeserializer<ADDRESS>::ContextStack::PopContext()
{
	stack.pop_back();
}

template <class ADDRESS>
bool DataObjectDeserializer<ADDRESS>::ContextStack::InArray() const
{
	return (stack.size() != 0) && (stack.back().type == Context::CTX_ARRAY);
}

template <class ADDRESS>
void DataObjectDeserializer<ADDRESS>::ContextStack::NextIndex()
{
	if(stack.size() != 0)
	{
		++stack.back().index;
	}
}

template <class ADDRESS>
std::string DataObjectDeserializer<ADDRESS>::ContextStack::DataObjectName() const
{
	std::string data_object_name;
	unsigned int n = stack.size();
	for(unsigned int i = 0; i < n; ++i)
	{
		const Context& ctx = stack[i];
		
		switch(ctx.type)
		{
			case Context::CTX_MEMBER:
			{
				const std::string& name = ctx.name;
				if(name.length() != 0)
				{
					if(data_object_name.length() != 0)
					{
						data_object_name += '.';
					}
					data_object_name += name;
				}
				break;
			}
			
			case Context::CTX_ARRAY:
			{
				std::ostringstream sstr;
				sstr << '[' << ctx.index << ']';
				data_object_name += sstr.str();
				break;
			}
		}
	}
	return data_object_name;
}

template <class ADDRESS>
unsigned int DataObjectDeserializer<ADDRESS>::ContextStack::GetIndex() const
{
	return stack.back().index;
}

template <class ADDRESS>
DataObjectDeserializer<ADDRESS>::ContextStack::Context::Context()
	: type()
	, name()
	, index(0)
{
}

template <class ADDRESS>
DataObjectDeserializer<ADDRESS>::ContextStack::Context::Context(Type _type, const std::string& _name, unsigned int _index)
	: type(_type)
	, name(_name)
	, index(_index)
{
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_DESERIALIZER_TCC__
