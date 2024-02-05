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
 * Authors: Gilles Mouchard (gilles.mouchar@cea.fr)
 *          Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#ifndef __UNISIM_KERNEL_VARIABLE_VARIABLE_HH__
#define __UNISIM_KERNEL_VARIABLE_VARIABLE_HH__

#include <unisim/kernel/kernel.hh>
#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <sstream>
#include <stdint.h>

namespace unisim {
namespace kernel {
namespace variable {

//=============================================================================
//=                            Variable<TYPE>                                 =
//=============================================================================

template <class TYPE>
class Variable : public VariableBase
{
public:
	typedef VariableBase::Type Type;
	Variable(const char *name, Object *owner, TYPE& storage, VariableBase::Type type, const char *description = NULL);

	virtual const char *GetDataTypeName() const;
	virtual DataType GetDataType() const;
	virtual unsigned int GetBitSize() const;
	virtual operator bool () const;
	virtual operator long long () const;
	virtual operator unsigned long long () const;
	virtual operator double () const;
	virtual operator std::string () const;
	virtual VariableBase& operator = (bool value);
	virtual VariableBase& operator = (long long value);
	virtual VariableBase& operator = (unsigned long long value);
	virtual VariableBase& operator = (double value);
	virtual VariableBase& operator = (const char * value);
	
	virtual void Set( TYPE const& value );
	virtual TYPE Get() const { return *storage; }

private:
	TYPE *storage;
};

template <class TYPE>
void Variable<TYPE>::Set( TYPE const& value )
{
	SetModified(*storage != value);
	*storage = value;
	NotifyListeners();
}

template <class TYPE>
class Parameter : public Variable<TYPE>
{
public:
	Parameter(const char *name, Object *owner, TYPE& storage, const char *description = NULL) : Variable<TYPE>(name, owner, storage, VariableBase::VAR_PARAMETER, description) {}
};

template <class TYPE>
class Statistic : public Variable<TYPE>
{
public:
	Statistic(const char *name, Object *owner, TYPE& storage, const char *description = NULL) : Variable<TYPE>(name, owner, storage, VariableBase::VAR_STATISTIC, description) { VariableBase::SetFormat(unisim::kernel::VariableBase::FMT_DEC); }
};

//=============================================================================
//=                  CallBackObject and  TCallBack<TYPE>                      =
//=============================================================================

struct CallBackObject
{
	virtual ~CallBackObject() {}

	virtual bool read(unsigned int offset, const void *buffer, unsigned int data_length) { return false; }

	virtual bool write(unsigned int offset, const void *buffer, unsigned int data_length) {	return false; }

};

template <typename TYPE>
class TCallBack
{
public:
	typedef bool (CallBackObject::*cbwrite)(unsigned int offset, const void*, unsigned int size);
	typedef bool (CallBackObject::*cbread)(unsigned int offset, const void*, unsigned int size);
	
	TCallBack(CallBackObject *owner, unsigned int offset, cbwrite _write, cbread _read)
          : m_owner(owner), m_offset(offset), write(_write), read(_read)
	{}

	bool Write(TYPE const& storage) { return write and (m_owner->*write)(m_offset, &storage, sizeof (TYPE)); }

	bool Read(TYPE& storage) { return read and (m_owner->*read)(m_offset, &storage, sizeof (TYPE)); }
private:
	CallBackObject *m_owner;
	unsigned int m_offset;

	cbwrite write;
	cbread read;
};

template <class TYPE>
class Register : public Variable<TYPE>
{
public:
	Register(const char *name, Object *owner, TYPE& storage, const char *description = NULL)
	  : Variable<TYPE>(name, owner, storage, VariableBase::VAR_REGISTER, description)
	  , m_callback( 0 )
	{}
	
	~Register()
	{
	  delete m_callback;
	}
	
	typedef TCallBack<TYPE> TCB;
	void setCallBack(CallBackObject *owner, unsigned int offset, typename TCB::cbwrite _write, typename TCB::cbread _read)
	{
		if (m_callback) delete m_callback;
		m_callback = new TCB(owner, offset, _write, _read);
	}

	virtual void Set( TYPE const& value ) { if (not WriteBack(value)) Variable<TYPE>::Set( value ); }
	virtual TYPE Get() const { TYPE value; if (not ReadBack(value)) return Variable<TYPE>::Get(); return value; }

//	using Variable<TYPE>::operator=;

	VariableBase& operator = (bool value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (long long value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (unsigned long long value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (double value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (const char * value) { return (Variable<TYPE>::operator = (value)); }

protected:
	bool WriteBack(TYPE const& storage)
	{
		bool status = (m_callback and m_callback->Write(storage));
		if (status) this->NotifyListeners();
		return status;
	}

	bool ReadBack(TYPE& storage) const
	{
		return (m_callback and m_callback->Read(storage));
	}

private:
	TCB* m_callback;
};

template <class TYPE>
class Signal : public Variable<TYPE>
{
public:

	Signal(const char *name, Object *owner, TYPE& storage, const char *description = NULL) : Variable<TYPE>(name, owner, storage, VariableBase::VAR_SIGNAL, description) {}

//	using Variable<TYPE>::operator=;

	VariableBase& operator = (bool value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (long long value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (unsigned long long value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (double value) { return (Variable<TYPE>::operator = (value)); }
	VariableBase& operator = (const char * value) { return (Variable<TYPE>::operator = (value)); }

};

class FormulaOperator
{
public:
	typedef enum
	{
		OP_UNKNOWN,
		OP_ADD,
		OP_SUB,
		OP_MUL,
		OP_DIV,
		OP_LT,
		OP_LTE,
		OP_GT,
		OP_GTE,
		OP_EQ,
		OP_SEL,
		OP_NEG,
		OP_ABS,
		OP_MIN,
		OP_MAX,
		OP_AND,
		OP_OR,
		OP_NEQ,
		OP_NOT
	} Operator;

	FormulaOperator(const char *name);
	FormulaOperator(Operator op);
	operator Operator() const;
private:
	Operator op;
};

template <class TYPE>
class Formula;

template <class TYPE>
std::ostream& operator << (std::ostream& os, const Formula<TYPE>& formula);

template <class TYPE>
class Formula : public VariableBase
{
public:
	typedef VariableBase::Type Type;
	typedef FormulaOperator::Operator Operator;
	
	Formula(const char *name, Object *owner, VariableBase::Type type, FormulaOperator op, VariableBase *child1, VariableBase *child2, VariableBase *child3, const char *description = 0);
	Formula(const char *name, Object *owner, VariableBase::Type type, FormulaOperator op, VariableBase *child1, VariableBase *child2, const char *description = 0);
	Formula(const char *name, Object *owner, VariableBase::Type type, FormulaOperator op, VariableBase *child, const char *description = 0);
	
	virtual const char *GetDataTypeName() const;
	virtual operator bool () const;
	virtual operator long long () const;
	virtual operator unsigned long long () const;
	virtual operator double () const;
	virtual operator std::string () const;
	virtual VariableBase& operator = (bool value);
	virtual VariableBase& operator = (long long value);
	virtual VariableBase& operator = (unsigned long long value);
	virtual VariableBase& operator = (double value);
	virtual VariableBase& operator = (const char * value);
	virtual std::string GetSymbolicValue() const;

private:
	bool IsValid() const;
	TYPE Compute() const;

	Operator op;
	VariableBase *childs[3];
};

template <class TYPE>
class StatisticFormula : public Formula<TYPE>
{
public:
	StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child1, VariableBase *child2, VariableBase *child3, const char *description = 0);
	StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child1, VariableBase *child2, const char *description = 0);
	StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child, const char *description = 0);
};

//=============================================================================
//=                           VariableArray<TYPE>                            =
//=============================================================================

template <class TYPE>
class VariableArray : public VariableBase
{
public:
	typedef VariableBase::Type Type;
	VariableArray(const char *name, Object *owner, TYPE *variables, unsigned int dim, Type type, const char *description = NULL);
	virtual ~VariableArray();

	virtual VariableBase& operator [] (unsigned int index);
	virtual const VariableBase& operator [] (unsigned int index) const;
	void SetFormat(Format fmt);
	virtual unsigned int GetLength() const;
	virtual VariableBase& operator = (const VariableBase& variable);
	virtual const char *GetDataTypeName() const;
	virtual void SetMutable(bool is_mutable);
	virtual void SetVisible(bool is_visible);
	virtual void SetSerializable(bool is_serializable);
	virtual void SetModified(bool is_modified);

private:
	std::vector<VariableBase *> variables;
};

template <class TYPE>
VariableArray<TYPE>::VariableArray(const char *_name, Object *_owner, TYPE *_variables, unsigned int dim, VariableBase::Type type, const char *_description) :
	VariableBase(_name, _owner, VariableBase::VAR_ARRAY, _description),
	variables()
{
	unsigned int i;
	for(i = 0; i < dim; i++)
	{
		std::stringstream sstr;
		
		sstr << _name << "[" << i << "]";
		variables.push_back(new Variable<TYPE>(sstr.str().c_str(), _owner, *(_variables + i), type, _description));
	}
}


template <class TYPE>
VariableArray<TYPE>::~VariableArray()
{
	typename std::vector<VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		delete *variable_iter;
	}
}

template <class TYPE>
VariableBase& VariableArray<TYPE>::operator [] (unsigned int index)
{
	if(index >= variables.size())
	{
		std::cerr << "Subscript out of range" << std::endl;
		return GetVoidVariable();
	}
	return (*variables[index]);
}

template <class TYPE>
const VariableBase& VariableArray<TYPE>::operator [] (unsigned int index) const
{
	if(index >= variables.size())
	{
		std::cerr << "Subscript out of range" << std::endl;
		return GetVoidVariable();
	}
	return (*variables[index]);
}

template <class TYPE>
unsigned int VariableArray<TYPE>::GetLength() const
{
	return (variables.size());
}

template <class TYPE>
VariableBase& VariableArray<TYPE>::operator = (const VariableBase& variable)
{
	unsigned int index;
	unsigned int length = variable.GetLength();
	for(index = 0; index < length && index < variables.size(); index++)
	{
		*variables[index] = variable[index];
	}
	return (*this);
}

template <class TYPE>
void VariableArray<TYPE>::SetFormat(Format fmt)
{
	typename std::vector<VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		(*variable_iter)->SetFormat(fmt);
	}
}

template <class TYPE>
const char *VariableArray<TYPE>::GetDataTypeName() const
{
	return ("array");
}

template <class TYPE>
void VariableArray<TYPE>::SetMutable(bool _is_mutable)
{
	VariableBase::SetMutable(_is_mutable);
	typename std::vector<VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		(*variable_iter)->SetMutable(_is_mutable);
	}
}

template <class TYPE>
void VariableArray<TYPE>::SetVisible(bool _is_visible)
{
	VariableBase::SetVisible(_is_visible);
	typename std::vector<VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		(*variable_iter)->SetVisible(_is_visible);
	}
}

template <class TYPE>
void VariableArray<TYPE>::SetSerializable(bool _is_serializable)
{
	VariableBase::SetSerializable(_is_serializable);
	typename std::vector<VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		(*variable_iter)->SetSerializable(_is_serializable);
	}
}

template <class TYPE>
void VariableArray<TYPE>::SetModified(bool _is_modified)
{
	// Arrays can't be modified, only there elements
}

template <class TYPE>
class ParameterArray : public VariableArray<TYPE>
{
public:
	ParameterArray(const char *name, Object *owner, TYPE *parameters, unsigned int dim, const char *description = NULL) : VariableArray<TYPE>(name, owner, parameters, dim, VariableBase::VAR_PARAMETER, description) {}
};

template <class TYPE>
class StatisticArray : public VariableArray<TYPE>
{
public:
	StatisticArray(const char *name, Object *owner, TYPE *parameters, unsigned int dim, const char *description = NULL) : VariableArray<TYPE>(name, owner, parameters, dim, VariableBase::VAR_STATISTIC, description) {}
};

template <class TYPE>
class RegisterArray : public VariableArray<TYPE>
{
public:
	RegisterArray(const char *name, Object *owner, TYPE *parameters, unsigned int dim, const char *description = NULL) : VariableArray<TYPE>(name, owner, parameters, dim, VariableBase::VAR_REGISTER, description) {}
};

template <class TYPE>
class SignalArray : public VariableArray<TYPE>
{
public:
	SignalArray(const char *name, Object *owner, TYPE *parameters, unsigned int dim, const char *description = NULL) : VariableArray<TYPE>(name, owner, parameters, dim, VariableBase::VAR_SIGNAL, description) {}
};

} // end of namespace variable
} // end of namespace kernel
} // end of namespace unisim

#endif // __UNISIM_KERNEL_VARIABLE_VARIABLE_HH__
