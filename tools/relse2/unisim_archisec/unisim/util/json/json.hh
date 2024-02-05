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

#ifndef __UNISIM_UTIL_JSON_JSON_HH__
#define __UNISIM_UTIL_JSON_JSON_HH__

#include <unisim/util/dictionary/dictionary.hh>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdint.h>
#include <assert.h>

namespace unisim {
namespace util {
namespace json {

// forward declarations

struct JSON_Printer;
struct JSON_Value;
struct JSON_String;
struct JSON_Number;
struct JSON_Integer;
struct JSON_UnsignedInteger;
struct JSON_Float;
struct JSON_Boolean;
struct JSON_Null;
struct JSON_Object;
struct JSON_Member;
struct JSON_Array;
struct JSON_AST_Visitor;
struct JSON_AST_Printer;
struct JSON_AST_Builder;
template <typename VISITOR> struct JSON_Lexer;
template <typename VISITOR> struct JSON_Parser;
struct JSON_Parser_Printer;

// Utility functions

template <typename T>
std::string ToString(const T& v)
{
	std::ostringstream sstr;
	sstr << v;
	return sstr.str();
}

std::string Escape(const std::string& s);

// Value type enumeration
enum JSON_ValueType
{
	JSON_VALUE   = 0,
	JSON_STRING  = 1,
	JSON_INT     = 2,
	JSON_UINT    = 3,
	JSON_FLOAT   = 4,
	JSON_OBJECT  = 5,
	JSON_ARRAY   = 6,
	JSON_BOOLEAN = 7,
	JSON_NULL    = 8
};

std::ostream& operator << (std::ostream& os, const JSON_ValueType& type);

// JSON Value
struct JSON_Value
{
	JSON_Value() : type(JSON_VALUE) {}
	virtual ~JSON_Value() {}
	
	JSON_ValueType GetType() const { return type; }
	
	const JSON_String& AsString() const { assert(type == JSON_STRING); return *(const JSON_String *) this; }
	const JSON_Integer& AsInteger() const { assert(type == JSON_INT); return *(const JSON_Integer *) this; }
	const JSON_UnsignedInteger& AsUnsignedInteger() const { assert(type == JSON_UINT); return *(const JSON_UnsignedInteger *) this; }
	const JSON_Float& AsFloat() const { assert(type == JSON_FLOAT); return *(const JSON_Float *) this; }
	const JSON_Object& AsObject() const { assert(type == JSON_OBJECT); return *(const JSON_Object *) this; }
	const JSON_Array& AsArray() const { assert(type == JSON_ARRAY); return *(const JSON_Array *) this; }
	const JSON_Boolean& AsBoolean() const { assert(type == JSON_BOOLEAN); return *(const JSON_Boolean *) this; }
	const JSON_Null& AsNull() const { assert(type == JSON_NULL); return *(const JSON_Null *) this; }
	
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
	template <typename VISITOR> bool Visit(VISITOR& visitor) const;
protected:
	friend struct JSON_Member;
	friend struct JSON_Object;
	friend struct JSON_Array;

	JSON_Value(JSON_ValueType _type) : type(_type) {}
	
	JSON_ValueType type;
};

std::ostream& operator << (std::ostream& os, const JSON_Value& value);

// JSON String
struct JSON_String : JSON_Value
{
	JSON_String(const std::string& _value) : JSON_Value(JSON_STRING), value(_value) {}
	
	operator const std::string& () const { return value; }
	operator const char * () const { return value.c_str(); }
protected:
	std::string value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_String& value) { return os << '"' << Escape((const std::string&) value) << '"'; }

// JSON number
struct JSON_Number : JSON_Value
{
protected:
	JSON_Number(JSON_ValueType type) : JSON_Value(type) {}
};

// JSON integer number
struct JSON_Integer : JSON_Number
{
	JSON_Integer(int64_t _value) : JSON_Number(JSON_INT), value(_value) {}
	operator int64_t () const { return value; }
protected:
	int64_t value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_Integer& value) { return os << (int64_t) value; }

// JSON unsigned integer number
struct JSON_UnsignedInteger : JSON_Number
{
	JSON_UnsignedInteger(uint64_t _value) : JSON_Number(JSON_UINT), value(_value) {}
	operator uint64_t () const { return value; }
protected:
	uint64_t value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_UnsignedInteger& value) { return os << (uint64_t) value; }

// JSON floating-point number
struct JSON_Float : JSON_Number
{
	JSON_Float(double _value) : JSON_Number(JSON_FLOAT), value(_value) {}
	operator double () const { return value; }
protected:
	double value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_Float& value) { return os << (double) value; }

// JSON boolean value
struct JSON_Boolean : JSON_Value
{
	JSON_Boolean(bool _value) : JSON_Value(JSON_BOOLEAN), value(_value) {}
	operator bool () const { return value; }
protected:
	bool value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_Boolean& v) { return os << (v ? "true" : "false"); }

// JSON null value
struct JSON_Null : JSON_Value
{
	JSON_Null() : JSON_Value(JSON_NULL) {}
protected:
};

inline std::ostream& operator << (std::ostream& os, const JSON_Null&) { return os << "null"; }

// JSON member
struct JSON_Member
{
	JSON_Member(const std::string& _name, JSON_Value *_value) : name(_name), value(_value) {}
	virtual ~JSON_Member() { delete value; }
	
	const std::string& GetName() const { return name; }
	const JSON_Value& GetValue() const { return *value; }
	
	template <typename VISITOR> void Scan(VISITOR& visitor) const
	{
		value->Visit(visitor);
	}
	
protected:
	std::string name;
	JSON_Value *value;
};

inline std::ostream& operator << (std::ostream& os, const JSON_Member& member) { return os << '"' << member.GetName() << "\":" << member.GetValue(); }

// JSON object
struct JSON_Object : JSON_Value
{
	typedef std::vector<JSON_Member *> Members;

	JSON_Object() : JSON_Value(JSON_OBJECT), members() {}
	JSON_Object(const std::vector<JSON_Member *>& _members) : JSON_Value(JSON_OBJECT), members(_members) {}
	virtual ~JSON_Object() { for(Members::iterator it = members.begin(); it != members.end(); ++it) delete *it; }

	JSON_Object& Add(JSON_Member *member) { members.push_back(member); return *this; }
	const Members& GetMembers() const { return members; }
	
	template <typename VISITOR> void Scan(VISITOR& visitor) const
	{
		for(typename Members::const_iterator it = members.begin(); it != members.end(); ++it)
		{
			JSON_Member *member = *it;
			if(!visitor.Visit(*member)) break;
		}
	}
	
protected:
	std::vector<JSON_Member *> members;
};

std::ostream& operator << (std::ostream& os, const JSON_Object& object);

// JSON array
struct JSON_Array : JSON_Value
{
	typedef std::vector<JSON_Value *> Elements;
	
	JSON_Array() : JSON_Value(JSON_ARRAY), elements() {}
	JSON_Array(std::vector<JSON_Value *>& _elements) : JSON_Value(JSON_ARRAY), elements(_elements) {}
	virtual ~JSON_Array() { for(Elements::iterator it = elements.begin(); it != elements.end(); ++it) delete *it; }
	
	JSON_Array& Add(JSON_Value *value) { elements.push_back(value); return *this; }
	const Elements& GetElements() const { return elements; }
	
	template <typename VISITOR> void Scan(VISITOR& visitor) const
	{
		for(typename Elements::const_iterator it = elements.begin(); it != elements.end(); ++it)
		{
			JSON_Value *element = *it;
			if(!element->Visit(visitor)) break;
		}
	}
protected:
	Elements elements;
};

std::ostream& operator << (std::ostream& os, const JSON_Array& array);

// JSON AST printer
struct JSON_AST_Printer
{
	static void Print(std::ostream& stream, const JSON_Value& root);
private:
	struct Visitor
	{
		Visitor(std::ostream& stream, const JSON_Value& value);
		bool Visit(const JSON_String& value);
		bool Visit(const JSON_Integer& value);
		bool Visit(const JSON_UnsignedInteger& value);
		bool Visit(const JSON_Float& value);
		bool Visit(const JSON_Boolean& value);
		bool Visit(const JSON_Null& value);
		bool Visit(const JSON_Object& object);
		bool Visit(const JSON_Member& member);
		bool Visit(const JSON_Array& array);
		void Push();
		void Pop();
		unsigned int GetIndex() const;
		void NextIndex();
		
		std::ostream& stream;
		const JSON_Value& root;
		typedef std::vector<unsigned int> Stack;
		Stack stack;
	};
};

// JSON Parser visitor for building an AST
struct JSON_AST_Builder
{
	typedef JSON_Value *JSON_VALUE_TYPE;
	typedef JSON_String *JSON_STRING_TYPE;
	typedef JSON_Object *JSON_OBJECT_TYPE;
	typedef std::vector<JSON_Member *> *JSON_MEMBERS_TYPE;
	typedef JSON_Member *JSON_MEMBER_TYPE;
	typedef JSON_Array *JSON_ARRAY_TYPE;
	typedef std::vector<JSON_Value *> *JSON_ELEMENTS_TYPE;
	
	JSON_AST_Builder(std::ostream& _err = std::cerr) : err(_err) {}
	
	void BeginObject() {}
	void EndObject() {}
	void BeginArray() {}
	void EndArray() {}
	void Comma() {}
	JSON_String *MemberName(const std::string& name) { return new JSON_String(name); }
	JSON_String *Value(const std::string& value) { return new JSON_String(value); }
	JSON_UnsignedInteger *Value(uint64_t value) { return new JSON_UnsignedInteger(value); }
	JSON_Integer *Value(int64_t value) { return new JSON_Integer(value); }
	JSON_Float *Value(double value) { return new JSON_Float(value); }
	JSON_Boolean *Value(bool value) { return new JSON_Boolean(value); }
	JSON_Null *Value() { return new JSON_Null(); }
	JSON_Object *Object() { return new JSON_Object(); }
	JSON_Object *Object(JSON_MEMBERS_TYPE members) { JSON_Object *object = new JSON_Object(*members); delete members; return object; }
	JSON_MEMBERS_TYPE Members(JSON_MEMBERS_TYPE members, JSON_Member *member) { if(members) members->push_back(member); else members = new std::vector<JSON_Member *>(1, member); return members; }
	JSON_Member *Member(JSON_String *name, JSON_Value *value) { JSON_Member *member = new JSON_Member(*name, value); delete name; return member; }
	JSON_Array *Array() { return new JSON_Array(); }
	JSON_Array *Array(std::vector<JSON_Value *> *elements) { JSON_Array *array = new JSON_Array(*elements); delete elements; return array; }
	JSON_ELEMENTS_TYPE Elements(JSON_ELEMENTS_TYPE elements, JSON_Value *value) { if(elements) elements->push_back(value); else elements = new std::vector<JSON_Value *>(1, value); return elements; }
	
	void Error(const std::string& msg) { err << msg; }
	
	void Release(JSON_Value *value) { delete value; }
	void Release(JSON_String *value) { delete value; }
	void Release(JSON_Object *object) { delete object; }
	void Release(JSON_Member *member) { delete member; }
	void Release(JSON_MEMBERS_TYPE members) { delete members; }
	void Release(JSON_Array *array) { delete array; }
	void Release(JSON_ELEMENTS_TYPE elements) { delete elements; }
private:
	std::ostream& err;
};

// Token
enum Token
{
	TOK_IO_ERROR      = -2,
	TOK_ERROR         = -1,
	TOK_VOID          = 0,
	TOK_STRING        = 1,
	TOK_INT           = 2,
	TOK_UINT          = 3,
	TOK_FLOAT         = 4,
	TOK_TRUE          = 5,
	TOK_FALSE         = 6,
	TOK_NULL          = 7,
	TOK_LEFT_BRACE    = '{',
	TOK_RIGHT_BRACE   = '}',
	TOK_LEFT_BRACKET  = '[',
	TOK_RIGHT_BRACKET = ']',
	TOK_COMMA         = ',',
	TOK_COLON         = ':',
	TOK_EOF           = 127
};

std::ostream& operator << (std::ostream& os, const Token& token);

std::string PrettyString(const Token& token, const std::string& text);

enum JSON_OPTION
{
	OPT_ENABLE_C_COMMENTS,  // enable C-like comments beginning with /* and ending with */
	OPT_ENABLE_CPP_COMMENTS // enable C++-like comments beginning with //
};

// JSON Lexer
template <typename VISITOR>
struct JSON_Lexer
{
	JSON_Lexer();
	~JSON_Lexer();
	
	bool SetOption(JSON_OPTION option, bool value);
	bool GetOption(JSON_OPTION option, bool& value) const;
	bool GetOptionFlag(JSON_OPTION option) const;
	void Reset();
protected:
	Token Next(std::istream& stream, VISITOR& visitor);
	void Back();
	const std::string& GetText() const { return text; }
	const std::string& GetStringValue() const { return str_value; }
	int64_t GetIntValue() const { return int_value; }
	uint64_t GetUIntValue() const { return uint_value; }
	double GetFloatValue() const { return float_value; }
	unsigned int GetLineNo() const { return lineno; }
	unsigned int GetColNo() const { return colno; }
	unsigned int GetTokenLineNo() const { return token_lineno; }
	unsigned int GetTokenColNo() const { return token_colno; }
	void ParseError(std::istream& stream, VISITOR& visitor, const std::string& msg);
private:
	void Append(char c);
	void Scan(std::istream& stream, VISITOR& visitor);
	void ScanError(std::istream& stream, VISITOR& visitor, const std::string& msg);
	void Error(std::istream& stream, VISITOR& visitor, const std::string& msg, bool parse_error);
	
	bool enable_c_comments;
	bool enable_cpp_comments;
	bool eof;
	bool error;
	Token token;
	Token look_ahead;
	std::string line;
	std::string text;
	std::string str_value;
	int64_t int_value;
	uint64_t uint_value;
	double float_value;
	unsigned int lineno;
	unsigned int colno;
	unsigned int token_lineno;
	unsigned int token_colno;
	unisim::util::dictionary::Dictionary<Token> token_dictionary;
};

// JSON Parser
template <typename VISITOR>
struct JSON_Parser : JSON_Lexer<VISITOR>
{
	typedef typename VISITOR::JSON_VALUE_TYPE JSON_VALUE_TYPE;
	typedef typename VISITOR::JSON_STRING_TYPE JSON_STRING_TYPE;
	typedef typename VISITOR::JSON_OBJECT_TYPE JSON_OBJECT_TYPE;
	typedef typename VISITOR::JSON_MEMBERS_TYPE JSON_MEMBERS_TYPE;
	typedef typename VISITOR::JSON_MEMBER_TYPE JSON_MEMBER_TYPE;
	typedef typename VISITOR::JSON_ARRAY_TYPE JSON_ARRAY_TYPE;
	typedef typename VISITOR::JSON_ELEMENTS_TYPE JSON_ELEMENTS_TYPE;
	typedef JSON_Lexer<VISITOR> Lexer;
	
	JSON_Parser();
	~JSON_Parser();
	
	JSON_VALUE_TYPE Parse(std::istream& stream, VISITOR& visitor);
private:
	JSON_VALUE_TYPE ParseValue(std::istream& stream, VISITOR& visitor);
	JSON_OBJECT_TYPE ParseObject(std::istream& stream, VISITOR& visitor);
	JSON_MEMBERS_TYPE ParseMembers(std::istream& stream, VISITOR& visitor, JSON_MEMBERS_TYPE members = JSON_MEMBERS_TYPE());
	JSON_MEMBER_TYPE ParseMember(std::istream& stream, VISITOR& visitor);
	JSON_ARRAY_TYPE ParseArray(std::istream& stream, VISITOR& visitor);
	JSON_ELEMENTS_TYPE ParseElements(std::istream& stream, VISITOR& visitor, JSON_ELEMENTS_TYPE elements = JSON_ELEMENTS_TYPE());
};

// JSON Parser visitor for raw printing of input being parsed
struct JSON_Parser_Printer
{
	typedef bool JSON_VALUE_TYPE;
	typedef std::string JSON_STRING_TYPE;
	typedef bool JSON_OBJECT_TYPE;
	typedef bool JSON_MEMBERS_TYPE;
	typedef bool JSON_MEMBER_TYPE;
	typedef bool JSON_ARRAY_TYPE;
	typedef bool JSON_ELEMENTS_TYPE;

	JSON_Parser_Printer(std::ostream& _out = std::cout, std::ostream& _err = std::cerr) : out(_out), err(_err) {}
	
	void BeginObject() { out << '{'; }
	void EndObject() { out << '}'; }
	void BeginArray() { out << '['; }
	void EndArray() { out << ']'; }
	void Comma() { out << ','; }
	
	const std::string& MemberName(const std::string& name) { out << '"' << Escape(name) << '"'; return name; }
	bool Value(const std::string& value) { out << '"' << Escape(value) << '"'; return true; }
	bool Value(uint64_t value) { out << value; return true; }
	bool Value(int64_t value) { out << value; return true; }
	bool Value(double value) { out << value; return true; }
	bool Value(bool value) { out << (value ? "true" : "false"); return true; }
	bool Value() { out << "null"; return true; }
	bool Object() { return true; }
	bool Object(bool) { return true; }
	bool Members(bool, bool) { return true; }
	bool Member(const std::string& name, bool) { return true; }
	bool Array() { return true; }
	bool Array(bool) { return true; }
	bool Elements(bool, bool) { return true; }
	
	void Error(const std::string& msg) { err << std::endl << msg; }
	
	void Release(bool) {}
	void Release(std::string) {}
private:
	std::ostream& out;
	std::ostream& err;
};

} // end of namespace json
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_JSON_JSON_HH__
