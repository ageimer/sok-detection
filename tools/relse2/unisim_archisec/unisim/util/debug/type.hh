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

#ifndef __UNISIM_UTIL_DEBUG_TYPE_HH__
#define __UNISIM_UTIL_DEBUG_TYPE_HH__

#include <unisim/util/debug/decl_location.hh>
#include <inttypes.h>
#include <string>
#include <vector>
#include <iosfwd>
#include <set>

namespace unisim {
namespace util {
namespace debug {

typedef enum
{
	T_UNKNOWN = 0,
	T_CHAR = 1,
	T_INTEGER = 2,
	T_FLOAT = 3,
	T_BOOL = 4,
	T_STRUCT = 5,
	T_UNION = 6,
	T_CLASS = 7,
	T_INTERFACE = 8,
	T_ARRAY = 9,
	T_POINTER = 10,
	T_TYPEDEF = 11,
	T_FUNCTION = 12,
	T_CONST = 13,
	T_ENUM = 14,
	T_VOID = 15,
	T_VOLATILE = 16
} TYPE_CLASS;

typedef enum
{
	TINIT_TOK_LITERAL = 0,
	TINIT_TOK_BEGIN_OF_STRUCT = 1,
	TINIT_TOK_END_OF_STRUCT = 2,
	TINIT_TOK_STRUCT_MEMBER_SEPARATOR = 3,
	TINIT_TOK_BEGIN_OF_ARRAY = 4,
	TINIT_TOK_END_OF_ARRAY = 5,
	TINIT_TOK_ARRAY_ELEMENT_SEPARATOR = 6
} TypeInitializerToken;

class Type;
class BaseType;
class IntegerType;
class CharType;
class FloatingPointType;
class BooleanType;
class Member;
class CompositeType;
class StructureType;
class UnionType;
class ClassType;
class InterfaceType;
class ArrayType;
class PointerType;
class Typedef;
class FormalParameter;
class FunctionType;
class ConstType;
class Enumerator;
class EnumType;
class UnspecifiedType;
class VolatileType;
class TypeVisitor;

std::ostream& operator << (std::ostream& os, const Type& type);
std::ostream& operator << (std::ostream& os, const Enumerator& enumerator);

class Type
{
public:
	Type();
	Type(const DeclLocation *decl_location);
	Type(TYPE_CLASS type_class);
	Type(TYPE_CLASS type_class, const DeclLocation *decl_location);
	virtual ~Type();
	
	TYPE_CLASS GetClass() const;
	bool IsComposite() const;
	bool IsBase() const;
	bool IsFloat() const;
	bool IsPointer() const;
	bool IsArray() const;
	bool IsUnspecified() const;
	bool IsNamed() const;
	const DeclLocation *GetDeclLocation() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	void Catch() const;
	void Release() const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
	template <typename VISITOR> bool Visit(VISITOR& visitor) const;
private:
	TYPE_CLASS type_class;
	const DeclLocation *decl_location;
	mutable unsigned int ref_count;
	
	friend std::ostream& operator << (std::ostream& os, const Type& type);
};

class NamedType : public Type
{
public:
	NamedType(TYPE_CLASS type_class, const char *name);
	NamedType(TYPE_CLASS type_class, const char *name, const DeclLocation *decl_location);
	const std::string& GetName() const;
	bool HasName() const;
private:
	std::string name;
	bool has_name;
};

class BaseType : public NamedType
{
public:
	BaseType(const char *name, unsigned int bit_size);
	BaseType(const char *name, unsigned int bit_size, const DeclLocation *decl_location);
	BaseType(TYPE_CLASS type_class, const char *name, unsigned int bit_size);
	BaseType(TYPE_CLASS type_class, const char *name, unsigned int bit_size, const DeclLocation *decl_location);
	virtual ~BaseType();
	unsigned int GetBitSize() const;
private:
	unsigned int bit_size;
};

class IntegerType : public BaseType
{
public:
	IntegerType(const char *name, unsigned int bit_size, bool is_signed);
	IntegerType(const char *name, unsigned int bit_size, bool is_signed, const DeclLocation *decl_location);
	virtual ~IntegerType();
	bool IsSigned() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
private:
	bool is_signed;
};

class CharType : public BaseType
{
public:
	CharType(const char *name, unsigned int bit_size, bool is_signed);
	CharType(const char *name, unsigned int bit_size, bool is_signed, const DeclLocation *decl_location);
	virtual ~CharType();
	bool IsSigned() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
private:
	bool is_signed;
};

class FloatingPointType : public BaseType
{
public:
	FloatingPointType(const char *name, unsigned int bit_size);
	FloatingPointType(const char *name, unsigned int bit_size, const DeclLocation *decl_location);
	virtual ~FloatingPointType();
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
private:
};

class BooleanType : public BaseType
{
public:
	BooleanType(const char *name, unsigned int bit_size);
	BooleanType(const char *name, unsigned int bit_size, const DeclLocation *decl_location);
	virtual ~BooleanType();
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
private:
};

class Member
{
public:
	Member(const char *name, const Type *type, uint64_t bit_size);
	virtual ~Member();
	const char *GetName() const;
	bool HasName() const;
	const Type *GetType() const;
	uint64_t GetBitSize() const;
	std::string BuildCDecl() const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	std::string name;
	bool has_name;
	const Type *type;
	uint64_t bit_size;
};

class CompositeType : public NamedType
{
public:
	CompositeType(TYPE_CLASS type_class, const char *name, bool incomplete);
	CompositeType(TYPE_CLASS type_class, const char *name, bool incomplete, const DeclLocation *decl_location);
	virtual ~CompositeType();
	
	void Add(const Member *member);
	bool IsIncomplete() const;
	unsigned int GetMemberCount() const;
	const Member *GetMember(unsigned int idx) const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	bool incomplete;
	std::vector<const Member *> members;
};

class StructureType : public CompositeType
{
public:
	StructureType(const char *name, bool incomplete) : CompositeType(T_STRUCT, name, incomplete) {}
	StructureType(const char *name, bool incomplete, const DeclLocation *decl_location) : CompositeType(T_STRUCT, name, incomplete, decl_location) {}
};

class UnionType : public CompositeType
{
public:
	UnionType(const char *name, bool incomplete) : CompositeType(T_UNION, name, incomplete) {}
	UnionType(const char *name, bool incomplete, const DeclLocation *decl_location) : CompositeType(T_UNION, name, incomplete, decl_location) {}
};

class ClassType : public CompositeType
{
public:
	ClassType(const char *name, bool incomplete) : CompositeType(T_CLASS, name, incomplete) {}
	ClassType(const char *name, bool incomplete, const DeclLocation *decl_location) : CompositeType(T_CLASS, name, incomplete, decl_location) {}
};

class InterfaceType : public CompositeType
{
public:
	InterfaceType(const char *name, bool incomplete) : CompositeType(T_INTERFACE, name, incomplete) {}
	InterfaceType(const char *name, bool incomplete, const DeclLocation *decl_location) : CompositeType(T_INTERFACE, name, incomplete, decl_location) {}
};

class ArrayType : public Type
{
public:
	ArrayType(const Type *type_of_element, unsigned int order, int64_t lower_bound, int64_t upper_bound);
	ArrayType(const Type *type_of_element, unsigned int order, int64_t lower_bound, int64_t upper_bound, const DeclLocation *decl_location);
	virtual ~ArrayType();
	const Type *GetTypeOfElement() const;
	unsigned int GetOrder() const;
	int64_t GetLowerBound() const;
	int64_t GetUpperBound() const;
	int64_t GetCount() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	const Type *type_of_element;
	unsigned int order;
	int64_t lower_bound;
	int64_t upper_bound;
};

class PointerType : public Type
{
public:
	PointerType(const Type *type_of_dereferenced_object);
	PointerType(const Type *type_of_dereferenced_object, const DeclLocation *decl_location);
	virtual ~PointerType();
	const Type *GetTypeOfDereferencedObject() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	const Type *type_of_dereferenced_object;
};

class Typedef : public NamedType
{
public:
	Typedef(const Type *type, const char *name);
	Typedef(const Type *type, const char *name, const DeclLocation *decl_location);
	virtual ~Typedef();
	const Type *GetType() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	const Type *type;
};

class FormalParameter
{
public:
	FormalParameter(const char *name, const Type *type);
	virtual ~FormalParameter();
	const char *GetName() const;
	const Type *GetType() const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	std::string name;
	const Type *type;
};

class FunctionType : public Type
{
public:
	FunctionType(const Type *return_type);
	FunctionType(const Type *return_type, const DeclLocation *decl_location);
	virtual ~FunctionType();
	
	void Add(const FormalParameter *formal_param);
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
	
private:
	const Type *return_type;
	std::vector<const FormalParameter *> formal_params;
};

class ConstType : public Type
{
public:
	ConstType(const Type *type);
	ConstType(const Type *type, const DeclLocation *decl_location);
	virtual ~ConstType();
	const Type *GetType() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	const Type *type;
};

class Enumerator
{
public:
	Enumerator(const char *name, int64_t value);
	Enumerator(const char *name, uint64_t value);
	virtual ~Enumerator();
	const char *GetName() const;
private:
	std::string name;
	bool sign;
	uint64_t value;
	
	friend std::ostream& operator << (std::ostream& os, const Enumerator& enumerator);
};

class EnumType : public NamedType
{
public:
	EnumType(const char *name);
	EnumType(const char *name, const DeclLocation *decl_location);
	virtual ~EnumType();
	void Add(const Enumerator *enumerator);
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	std::vector<const Enumerator *> enumerators;
};

class UnspecifiedType : public Type
{
public:
	UnspecifiedType();
	UnspecifiedType(const DeclLocation *decl_location);
	virtual ~UnspecifiedType();
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
private:
};

class VolatileType : public Type
{
public:
	VolatileType(const Type *type);
	VolatileType(const Type *type, const DeclLocation *decl_location);
	virtual ~VolatileType();
	const Type *GetType() const;
	virtual std::string BuildCDecl(char const **identifier = 0, bool collapsed = false) const;
	template <typename VISITOR> void Scan(VISITOR& visitor) const;
private:
	const Type *type;
};

class TypeResolver
{
public:
	static Type const *Resolve(Type const *type);
private:
	struct Visitor
	{
		Visitor();
		bool Visit(CharType const *type);
		bool Visit(IntegerType const *type);
		bool Visit(FloatingPointType const *type);
		bool Visit(BooleanType const *type);
		bool Visit(CompositeType const *type);
		bool Visit(ArrayType const *type);
		bool Visit(PointerType const *type);
		bool Visit(Typedef const *type);
		bool Visit(FunctionType const *type);
		bool Visit(ConstType const *type);
		bool Visit(EnumType const *type);
		bool Visit(UnspecifiedType const *type);
		bool Visit(VolatileType const *type);
		bool Visit(Member const *member);
		bool Visit(FormalParameter const *formal_param);
		
		Type const *resolved_type;
	};
};

class TypeIsBase
{
public:
	static bool Test(Type const *type);
};

class TypeIsFloat
{
public:
	static bool Test(Type const *type);
};

class TypeIsComposite
{
public:
	static bool Test(Type const *type);
};

class TypeIsPointer
{
public:
	static bool Test(Type const *type);
};

class TypeIsArray
{
public:
	static bool Test(Type const *type);
};

class TypeIsCharPointer
{
public:
	static bool Test(Type const *type);
private:
	struct Visitor
	{
		Visitor();
		bool Visit(Type const *type);
		bool Visit(CharType const *type);
		bool Visit(PointerType const *type);
		bool Visit(Member const *member);
		bool Visit(Typedef const *type);
		bool Visit(ConstType const *type);
		bool Visit(VolatileType const *type);
		bool Visit(FormalParameter const *formal_param);
		int state;
		bool is_char_pointer;
	};
};

template <typename VISITOR> void Type::Scan(VISITOR& visitor) const
{
	switch(type_class)
	{
		case T_UNKNOWN  : break;
		case T_CHAR     : break;
		case T_INTEGER  : break;
		case T_FLOAT    : break;
		case T_BOOL     : break;
		case T_STRUCT   : dynamic_cast<StructureType     const *>(this)->Scan(visitor); break;
		case T_UNION    : dynamic_cast<UnionType         const *>(this)->Scan(visitor); break;
		case T_CLASS    : dynamic_cast<ClassType         const *>(this)->Scan(visitor); break;
		case T_INTERFACE: dynamic_cast<InterfaceType     const *>(this)->Scan(visitor); break;
		case T_ARRAY    : dynamic_cast<ArrayType         const *>(this)->Scan(visitor); break;
		case T_POINTER  : dynamic_cast<PointerType       const *>(this)->Scan(visitor); break;
		case T_TYPEDEF  : dynamic_cast<Typedef           const *>(this)->Scan(visitor); break;
		case T_FUNCTION : dynamic_cast<FunctionType      const *>(this)->Scan(visitor); break;
		case T_CONST    : dynamic_cast<ConstType         const *>(this)->Scan(visitor); break;
		case T_ENUM     : break;
		case T_VOID     : break;
		case T_VOLATILE : dynamic_cast<VolatileType      const *>(this)->Scan(visitor); break;
	}
}

template <typename VISITOR> bool Type::Visit(VISITOR& visitor) const
{
	switch(type_class)
	{
		case T_UNKNOWN  : return false;
		case T_CHAR     : return visitor.Visit(dynamic_cast<CharType          const *>(this));
		case T_INTEGER  : return visitor.Visit(dynamic_cast<IntegerType       const *>(this));
		case T_FLOAT    : return visitor.Visit(dynamic_cast<FloatingPointType const *>(this));
		case T_BOOL     : return visitor.Visit(dynamic_cast<BooleanType       const *>(this));
		case T_STRUCT   : return visitor.Visit(dynamic_cast<StructureType     const *>(this));
		case T_UNION    : return visitor.Visit(dynamic_cast<UnionType         const *>(this));
		case T_CLASS    : return visitor.Visit(dynamic_cast<ClassType         const *>(this));
		case T_INTERFACE: return visitor.Visit(dynamic_cast<InterfaceType     const *>(this));
		case T_ARRAY    : return visitor.Visit(dynamic_cast<ArrayType         const *>(this));
		case T_POINTER  : return visitor.Visit(dynamic_cast<PointerType       const *>(this));
		case T_TYPEDEF  : return visitor.Visit(dynamic_cast<Typedef           const *>(this));
		case T_FUNCTION : return visitor.Visit(dynamic_cast<FunctionType      const *>(this));
		case T_CONST    : return visitor.Visit(dynamic_cast<ConstType         const *>(this));
		case T_ENUM     : return visitor.Visit(dynamic_cast<EnumType          const *>(this));
		case T_VOID     : return visitor.Visit(dynamic_cast<UnspecifiedType   const *>(this));
		case T_VOLATILE : return visitor.Visit(dynamic_cast<VolatileType      const *>(this));
	}
	return false;
}

template <typename VISITOR> void Member::Scan(VISITOR& visitor) const
{
	type->Visit(visitor);
}

template <typename VISITOR> void CompositeType::Scan(VISITOR& visitor) const
{
	unsigned int member_count = members.size();
	for(unsigned int i = 0; i < member_count; i++)
	{
		Member const *member = members[i];
		if(!visitor.Visit(member)) break;
	}
}

template <typename VISITOR> void ArrayType::Scan(VISITOR& visitor) const
{
	type_of_element->Visit(visitor);
}

template <typename VISITOR> void PointerType::Scan(VISITOR& visitor) const
{
	type_of_dereferenced_object->Visit(visitor);
}

template <typename VISITOR> void Typedef::Scan(VISITOR& visitor) const
{
	type->Visit(visitor);
}

template <typename VISITOR> void FormalParameter::Scan(VISITOR& visitor) const
{
	type->Visit(visitor);
}

template <typename VISITOR> void FunctionType::Scan(VISITOR& visitor) const
{
	if(!return_type->Visit(visitor)) return;
	
	unsigned int formal_param_count = formal_params.size();
	for(unsigned int i = 0; i < formal_param_count; i++)
	{
		FormalParameter const *formal_param = formal_params[i];
		if(!visitor.Visit(formal_param)) break;
	}
}

template <typename VISITOR> void ConstType::Scan(VISITOR& visitor) const
{
	type->Visit(visitor);
}

template <typename VISITOR> void EnumType::Scan(VISITOR& visitor) const
{
	unsigned int enumerator_count = enumerators.size();
	for(unsigned int i = 0; i < enumerator_count; i++)
	{
		Enumerator const *enumerator = enumerators[i];
		if(!visitor.Visit(enumerator)) break;
	}
}

template <typename VISITOR> void VolatileType::Scan(VISITOR& visitor) const
{
	type->Visit(visitor);
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_HH__
