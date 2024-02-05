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
 *          Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <unisim/kernel/variable/variable.hh>
#include <unisim/kernel/kernel.hh>
#include <unisim/kernel/logger/logger_server.hh>
#include <unisim/kernel/logger/logger.hh>
#include <unisim/util/likely/likely.hh>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <limits>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <cstring>

namespace unisim {
namespace kernel {
namespace variable {

//=============================================================================
//=                            Variable<TYPE>                                =
//=============================================================================

template <class TYPE>
Variable<TYPE>::Variable(const char *_name, Object *_owner, TYPE& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <class TYPE>
unsigned int Variable<TYPE>::GetBitSize() const { return sizeof(TYPE) * 8; }

template <class TYPE> Variable<TYPE>::operator bool () const
{
	return bool( Get() );
}

template <class TYPE> Variable<TYPE>::operator long long () const
{
	return (long long)( Get() );
}

template <class TYPE> Variable<TYPE>::operator unsigned long long () const
{
	return (unsigned long long)( Get() );
}

template <class TYPE> Variable<TYPE>::operator double () const
{
	return double( Get() );
}

template <class TYPE> Variable<TYPE>::operator std::string () const
{
	TYPE value = Get();

	std::stringstream sstr;
	switch(GetFormat())
	{
		case FMT_DEFAULT:
		case FMT_HEX:
			sstr << "0x" << std::hex;
			sstr.fill('0');
			sstr.width(2 * sizeof(TYPE));
			sstr << (unsigned long long)( value );
			break;
		case FMT_DEC:
			sstr << std::dec;
			if(std::numeric_limits<TYPE>::is_signed)
				sstr << (long long)( value );
			else
				sstr << (unsigned long long)( value );
			break;
	}
	return sstr.str();
}

template <class TYPE> VariableBase& Variable<TYPE>::operator = (bool value)
{
	if (IsMutable()) {
		Set( value );
	}
	return *this;
}

template <class TYPE> VariableBase& Variable<TYPE>::operator = (long long value)
{
	if (IsMutable()) {
		Set( value );
	}
	return *this;
}

template <class TYPE> VariableBase& Variable<TYPE>::operator = (unsigned long long value)
{
	if (IsMutable()) {
		Set( value );
	}
	return *this;
}

template <class TYPE> VariableBase& Variable<TYPE>::operator = (double value)
{
	if (IsMutable()) {
		Set( value );
	}
	return *this;
}

//=============================================================================
//=                           FormulaOperator                                 =
//=============================================================================

FormulaOperator::FormulaOperator(const char *name)
{
	if((strcmp(name, "+") == 0) || (strcmp(name, "add") == 0) || (strcmp(name, "ADD") == 0)) op = OP_ADD;
	else if((strcmp(name, "-") == 0) || (strcmp(name, "sub") == 0) || (strcmp(name, "SUB") == 0)) op = OP_SUB;
	else if((strcmp(name, "*") == 0) || (strcmp(name, "mul") == 0) || (strcmp(name, "MUL") == 0)) op = OP_MUL;
	else if((strcmp(name, "/") == 0) || (strcmp(name, "div") == 0) || (strcmp(name, "DIV") == 0)) op = OP_DIV;
	else if((strcmp(name, "<") == 0) || (strcmp(name, "lt") == 0) || (strcmp(name, "LT") == 0)) op = OP_LT;
	else if((strcmp(name, "<=") == 0) || (strcmp(name, "=<") == 0) || (strcmp(name, "lte") == 0) || (strcmp(name, "LTE") == 0)) op = OP_LTE;
	else if((strcmp(name, ">") == 0) || (strcmp(name, "gt") == 0) || (strcmp(name, "GT") == 0)) op = OP_GT;
	else if((strcmp(name, ">=") == 0) || (strcmp(name, "=>") == 0) || (strcmp(name, "gte") == 0)) op = OP_GTE;
	else if((strcmp(name, "==") == 0) || (strcmp(name, "=") == 0) || (strcmp(name, "eq") == 0) || (strcmp(name, "EQ") == 0)) op = OP_EQ;
	else if((strcmp(name, "?") == 0) || (strcmp(name, "sel") == 0) || (strcmp(name, "SEL") == 0)) op = OP_SEL;
	else if((strcmp(name, "neg") == 0) || (strcmp(name, "NEG") == 0)) op = OP_NEG;
	else if((strcmp(name, "abs") == 0) || (strcmp(name, "ABS") == 0)) op = OP_ABS;
	else if((strcmp(name, "min") == 0) || (strcmp(name, "MIN") == 0)) op = OP_MIN;
	else if((strcmp(name, "max") == 0) || (strcmp(name, "MAX") == 0)) op = OP_MAX;
	else if((strcmp(name, "&") == 0) || (strcmp(name, "and") == 0) || (strcmp(name, "AND") == 0)) op = OP_AND;
	else if((strcmp(name, "|") == 0) || (strcmp(name, "or") == 0) || (strcmp(name, "OR") == 0)) op = OP_OR;
	else if((strcmp(name, "!=") == 0) || (strcmp(name, "<>") == 0) || (strcmp(name, "ne") == 0) || (strcmp(name, "NE") == 0)) op = OP_NEQ;
	else if((strcmp(name, "!") == 0) || (strcmp(name, "~") == 0) || (strcmp(name, "not") == 0) || (strcmp(name, "NOT") == 0)) op = OP_NOT;
	else op = OP_UNKNOWN;
}

FormulaOperator::FormulaOperator(Operator _op)
	: op(_op)
{
}

FormulaOperator::operator FormulaOperator::Operator() const
{
	return op;
}

//=============================================================================
//=                             Formula<TYPE>                                 =
//=============================================================================

template <class TYPE>
Formula<TYPE>::Formula(const char *_name, Object *_owner, VariableBase::Type _type, FormulaOperator _formula_op, VariableBase *child1, VariableBase *child2, VariableBase *child3, const char *_description)
	: VariableBase(_name, _owner, _type, _description)
	, op(_formula_op)
{
	VariableBase::SetFormat(unisim::kernel::VariableBase::FMT_DEC);
	VariableBase::SetMutable(false);
	childs[0] = child1;
	childs[1] = child2;
	childs[2] = child3;
	if(!IsValid() && Simulator::Instance()->IsWarningEnabled())
	{
		std::cerr << "WARNING! " << VariableBase::GetName() << " is an invalid formula" << std::endl;
	}
}

template <class TYPE>
Formula<TYPE>::Formula(const char *_name, Object *_owner, VariableBase::Type _type, FormulaOperator _formula_op, VariableBase *child1, VariableBase *child2, const char *_description)
	: VariableBase(_name, _owner, _type, _description)
	, op(_formula_op)
{
	VariableBase::SetFormat(unisim::kernel::VariableBase::FMT_DEC);
	VariableBase::SetMutable(false);
	childs[0] = child1;
	childs[1] = child2;
	childs[2] = 0;
	if(!IsValid() && Simulator::Instance()->IsWarningEnabled())
	{
		std::cerr << "WARNING! " << VariableBase::GetName() << " is an invalid formula" << std::endl;
	}
}

template <class TYPE>
Formula<TYPE>::Formula(const char *_name, Object *_owner, VariableBase::Type _type, FormulaOperator _formula_op, VariableBase *child, const char *_description)
	: VariableBase(_name, _owner, _type, _description)
	, op(_formula_op)
{
	VariableBase::SetFormat(unisim::kernel::VariableBase::FMT_DEC);
	VariableBase::SetMutable(false);
	childs[0] = child;
	childs[1] = 0;
	childs[2] = 0;
	if(!IsValid() && Simulator::Instance()->IsWarningEnabled())
	{
		std::cerr << "WARNING! " << VariableBase::GetName() << " is an invalid formula" << std::endl;
	}
}

template <class TYPE>
bool Formula<TYPE>::IsValid() const
{
	switch(op)
	{
		case FormulaOperator::OP_UNKNOWN:
			return false;
		case FormulaOperator::OP_NEG:
		case FormulaOperator::OP_ABS:
		case FormulaOperator::OP_NOT:
			return childs[0] != 0;
		case FormulaOperator::OP_ADD:
		case FormulaOperator::OP_SUB:
		case FormulaOperator::OP_MUL:
		case FormulaOperator::OP_DIV:
		case FormulaOperator::OP_LT:
		case FormulaOperator::OP_LTE:
		case FormulaOperator::OP_GT:
		case FormulaOperator::OP_GTE:
		case FormulaOperator::OP_EQ:
		case FormulaOperator::OP_MIN:
		case FormulaOperator::OP_MAX:
		case FormulaOperator::OP_AND:
		case FormulaOperator::OP_OR:
		case FormulaOperator::OP_NEQ:
			return (childs[0] != 0) && (childs[1] != 0);
		case FormulaOperator::OP_SEL:
			return (childs[0] != 0) && (childs[1] != 0) && (childs[2] != 0);
	}
	return false;
}

template <class TYPE> Formula<TYPE>::operator bool () const { return Compute() ? true : false; }
template <class TYPE> Formula<TYPE>::operator long long () const { return (long long) Compute(); }
template <class TYPE> Formula<TYPE>::operator unsigned long long () const { return (unsigned long long) Compute(); }
template <class TYPE> Formula<TYPE>::operator double () const { return (double) Compute(); }
template <class TYPE> Formula<TYPE>::operator std::string () const
{
	std::stringstream sstr;
	switch(GetFormat())
	{
		case FMT_DEFAULT:
		case FMT_HEX:
			sstr << "0x" << std::hex << (unsigned long long) Compute();
			break;
		case FMT_DEC:
			sstr << std::dec << (unsigned long long) Compute();
			break;
	}
	return sstr.str();
}

/* Note: assigning a formula has no effect */
template <class TYPE> VariableBase& Formula<TYPE>::operator = (bool value) { return *this; }
template <class TYPE> VariableBase& Formula<TYPE>::operator = (long long value) { return *this; }
template <class TYPE> VariableBase& Formula<TYPE>::operator = (unsigned long long value) { return *this; }
template <class TYPE> VariableBase& Formula<TYPE>::operator = (double value) { return *this; }
template <class TYPE> VariableBase& Formula<TYPE>::operator = (const char *value) { return *this; }

template <class TYPE>
TYPE Formula<TYPE>::Compute() const
{
	switch(op)
	{
		case FormulaOperator::OP_UNKNOWN: return TYPE();
		case FormulaOperator::OP_ADD: return (TYPE)(childs[0] ? *childs[0] : TYPE()) + (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_SUB: return (TYPE)(childs[0] ? *childs[0] : TYPE()) - (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_MUL: return (TYPE)(childs[0] ? *childs[0] : TYPE()) * (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_DIV: return (TYPE)(childs[0] ? *childs[0] : TYPE()) / (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_LT: return (TYPE)(childs[0] ? *childs[0] : TYPE()) < (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_LTE: return (TYPE)(childs[0] ? *childs[0] : TYPE()) <= (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_GT: return (TYPE)(childs[0] ? *childs[0] : TYPE()) > (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_GTE: return (TYPE)(childs[0] ? *childs[0] : TYPE()) >= (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_EQ: return (TYPE)(childs[0] ? *childs[0] : TYPE()) == (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_SEL: return (TYPE)(childs[0] ? *childs[0] : TYPE()) ? (TYPE)(childs[1] ? *childs[1] : TYPE()) : (TYPE)(childs[2] ? *childs[2] : TYPE());
		case FormulaOperator::OP_NEG: return -(TYPE)(childs[0] ? *childs[0] : TYPE());
		case FormulaOperator::OP_ABS: return (TYPE)(childs[0] ? *childs[0] : TYPE()) >= TYPE() ? (TYPE)(childs[0] ? *childs[0] : TYPE()) : -(TYPE)(childs[0] ? *childs[0] : TYPE());
		case FormulaOperator::OP_MIN: return (TYPE)(childs[0] ? *childs[0] : TYPE()) < (TYPE)(childs[1] ? *childs[1] : TYPE()) ? (TYPE)(childs[0] ? *childs[0] : TYPE()) : (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_MAX: return (TYPE)(childs[0] ? *childs[0] : TYPE()) > (TYPE)(childs[1] ? *childs[1] : TYPE()) ? (TYPE)(childs[0] ? *childs[0] : TYPE()) : (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_AND: return (TYPE)(childs[0] ? *childs[0] : TYPE()) && (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_OR: return (TYPE)(childs[0] ? *childs[0] : TYPE()) || (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_NEQ: return (TYPE)(childs[0] ? *childs[0] : TYPE()) != (TYPE)(childs[1] ? *childs[1] : TYPE());
		case FormulaOperator::OP_NOT: return !(TYPE)(childs[0] ? *childs[0] : TYPE());
	}
	return 0;
}

template <class TYPE>
std::string Formula<TYPE>::GetSymbolicValue() const
{
	std::stringstream sstr;
	switch(op)
	{
		case FormulaOperator::OP_UNKNOWN:
			sstr << "unknown";
			break;
		case FormulaOperator::OP_NEG:
			sstr << "-";
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_ABS:
			sstr << "ABS(";
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << ")";
			break;
		case FormulaOperator::OP_NOT:
			sstr << "!";
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_ADD:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " + ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_SUB:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " - ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_MUL:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " * ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_DIV:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " / ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_LT:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " < ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_LTE:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " <= ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_GT:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " > ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_GTE:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " >= ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_EQ:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " == ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_MIN:
			sstr << "MIN(";
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << ", ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << ")";
			break;
		case FormulaOperator::OP_MAX:
			sstr << "MAX(";
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << ", ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << ")";
			break;
		case FormulaOperator::OP_AND:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " & ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_OR:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " | ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_NEQ:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " != ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
		case FormulaOperator::OP_SEL:
			if(childs[0])
				sstr << childs[0]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " ? ";
			if(childs[1])
				sstr << childs[1]->GetSymbolicValue();
			else
				sstr << TYPE();
			sstr << " : ";
			if(childs[2])
				sstr << childs[2]->GetSymbolicValue();
			else
				sstr << TYPE();
			break;
	}
	return sstr.str();
}

//=============================================================================
//=                         StatisticFormula<TYPE>                            =
//=============================================================================

template <class TYPE>
StatisticFormula<TYPE>::StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child1, VariableBase *child2, VariableBase *child3, const char *description)
	: Formula<TYPE>(name, owner, VariableBase::VAR_STATISTIC, op, child1, child2, child3, description)
{
}

template <class TYPE>
StatisticFormula<TYPE>::StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child1, VariableBase *child2, const char *description)
	: Formula<TYPE>(name, owner, VariableBase::VAR_STATISTIC, op, child1, child2, description)
{
}

template <class TYPE>
StatisticFormula<TYPE>::StatisticFormula(const char *name, Object *owner, FormulaOperator op, VariableBase *child, const char *description)
	: Formula<TYPE>(name, owner, VariableBase::VAR_STATISTIC, op, child, description)
{
}

//=============================================================================
//=                         specialized Variable<>                           =
//=============================================================================

template <typename T>
static const char *GetSignedDataTypeName(const T *p = 0)
{
	switch(sizeof(T))
	{
		case 1: return "signed 8-bit integer";
		case 2: return "signed 16-bit integer";
		case 4: return "signed 32-bit integer";
		case 8: return "signed 64-bit integer";
	}
	return "?";
}

template <typename T>
static const char *GetUnsignedDataTypeName(const T *p = 0)
{
	switch(sizeof(T))
	{
		case 1: return "unsigned 8-bit integer";
		case 2: return "unsigned 16-bit integer";
		case 4: return "unsigned 32-bit integer";
		case 8: return "unsigned 64-bit integer";
	}
	return "?";
}

template <>
Variable<bool>::Variable(const char *_name, Object *_owner, bool& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type,  _description), storage(&_storage)
{
	AddEnumeratedValue("true");
	AddEnumeratedValue("false");
	Initialize();
}

template <>
const char *Variable<bool>::GetDataTypeName() const
{
	return "boolean";
}

template <>
VariableBase::DataType Variable<bool>::GetDataType() const
{
	return DT_BOOL;
}

template <>
Variable<signed char>::Variable(const char *_name, Object *_owner, signed char& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<signed char>::GetDataTypeName() const
{
	return GetSignedDataTypeName<signed char>(); //"char";
}

template <>
VariableBase::DataType Variable<signed char>::GetDataType() const
{
	return DT_SCHAR;
}

template <>
Variable<short>::Variable(const char *_name, Object *_owner, short& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<short>::GetDataTypeName() const
{
	return GetSignedDataTypeName<short>(); //"short";
}

template <>
VariableBase::DataType Variable<short>::GetDataType() const
{
	return DT_SHORT;
}

template <>
Variable<int>::Variable(const char *_name, Object *_owner, int& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<int>::GetDataTypeName() const
{
	return GetSignedDataTypeName<int>(); //"int";
}

template <>
VariableBase::DataType Variable<int>::GetDataType() const
{
	return DT_INT;
}

template <>
Variable<long>::Variable(const char *_name, Object *_owner, long& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<long>(); //"long";
}

template <>
VariableBase::DataType Variable<long>::GetDataType() const
{
	return DT_LONG;
}

template <>
Variable<long long>::Variable(const char *_name, Object *_owner, long long& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<long long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<long long>(); //"long long";
}

template <>
VariableBase::DataType Variable<long long>::GetDataType() const
{
	return DT_LONG_LONG;
}

template <>
Variable<unsigned char>::Variable(const char *_name, Object *_owner, unsigned char& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<unsigned char>::GetDataTypeName() const
{
	return GetUnsignedDataTypeName<unsigned char>(); //"unsigned char";
}

template <>
VariableBase::DataType Variable<unsigned char>::GetDataType() const
{
	return DT_UCHAR;
}

template <>
Variable<unsigned short>::Variable(const char *_name, Object *_owner, unsigned short& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<unsigned short>::GetDataTypeName() const
{
	return GetUnsignedDataTypeName<unsigned short>(); //"unsigned short";
}

template <>
VariableBase::DataType Variable<unsigned short>::GetDataType() const
{
	return DT_USHORT;
}

template <>
Variable<unsigned int>::Variable(const char *_name, Object *_owner, unsigned int& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<unsigned int>::GetDataTypeName() const
{
	return GetUnsignedDataTypeName<unsigned int>(); //"unsigned int";
}

template <>
VariableBase::DataType Variable<unsigned int>::GetDataType() const
{
	return DT_UINT;
}

template <>
Variable<unsigned long>::Variable(const char *_name, Object *_owner, unsigned long& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<unsigned long>::GetDataTypeName() const
{
	return GetUnsignedDataTypeName<unsigned long>(); //"unsigned long";
}

template <>
VariableBase::DataType Variable<unsigned long>::GetDataType() const
{
	return DT_ULONG;
}

template <>
Variable<unsigned long long>::Variable(const char *_name, Object *_owner, unsigned long long& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<unsigned long long>::GetDataTypeName() const
{
	return GetUnsignedDataTypeName<unsigned long long>(); //"unsigned long long";
}

template <>
VariableBase::DataType Variable<unsigned long long>::GetDataType() const
{
	return DT_ULONG_LONG;
}

template <> 
Variable<double>::Variable(const char *_name, Object *_owner, double& _storage, Type type, const char *_description) :
	VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<double>::GetDataTypeName() const
{
	return "double precision floating-point";
}

template <>
VariableBase::DataType Variable<double>::GetDataType() const
{
	return DT_DOUBLE;
}

template <>
Variable<double>::operator std::string () const
{
	std::stringstream sstr;
	sstr << Get();
	return sstr.str();
}

template <> 
Variable<float>::Variable(const char *_name, Object *_owner, float& _storage, Type type, const char *_description)
  : VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<float>::GetDataTypeName() const
{
	return "single precision floating-point";
}

template <>
VariableBase::DataType Variable<float>::GetDataType() const
{
	return DT_FLOAT;
}

template <>
Variable<float>::operator std::string () const
{
	std::stringstream sstr;
	sstr << Get();
	return sstr.str();
}

template <> 
Variable<std::string>::Variable(const char *_name, Object *_owner, std::string& _storage, Type type, const char *_description)
  : VariableBase(_name, _owner, type, _description), storage(&_storage)
{
	Initialize();
}

template <>
const char *Variable<std::string>::GetDataTypeName() const
{
	return "string";
}

template <>
VariableBase::DataType Variable<std::string>::GetDataType() const
{
	return DT_STRING;
}

template <> Variable<bool>::operator std::string () const
{
	bool value = Get();
	std::stringstream sstr;
	switch(GetFormat())
	{
		case FMT_DEFAULT:
			sstr << (value ? "true" : "false");
			break;
		case FMT_HEX:
			sstr << (value ? "0x1" : "0x0");
			break;
		case FMT_DEC:
			sstr << (value ? "1" : "0");
			break;
	}
	return sstr.str();
}

namespace
{
  long long ParseSigned( char const* value )
  {
    return (strcmp(value, "true") == 0) ? 1 : ((strcmp(value, "false") == 0) ? 0 : strtoll(value, 0, 0));
  }
  unsigned long long ParseUnsigned( char const* value )
  {
    return (strcmp(value, "true") == 0) ? 1 : ((strcmp(value, "false") == 0) ? 0 : strtoull(value, 0, 0));
  }
  double ParseDouble( char const* value )
  {
    return (strcmp(value, "true") == 0) ? 1.0 : ((strcmp(value, "false") == 0) ? 0.0 : strtod(value, 0));
  }
  
}

template <> VariableBase& Variable<bool>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<signed char>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<short>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<int>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<long>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<long long>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseSigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<unsigned char>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseUnsigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<unsigned short>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseUnsigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<unsigned int>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseUnsigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<unsigned long>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseUnsigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<unsigned long long>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseUnsigned( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<float>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseDouble( value ) );
	}
	return *this;
}
template <> VariableBase& Variable<double>::operator = (const char *value)
{
	if (IsMutable()) {
		Set( ParseDouble( value ) );
	}
	return *this;
}

template <> Variable<std::string>::operator bool () const { return ParseSigned(storage->c_str()); }
template <> Variable<std::string>::operator long long () const { return ParseSigned(storage->c_str()); }
template <> Variable<std::string>::operator unsigned long long () const { return ParseSigned(storage->c_str()); }
template <> Variable<std::string>::operator double () const { return ParseDouble(storage->c_str()); }
template <> Variable<std::string>::operator std::string () const { return *storage; }

template <> VariableBase& Variable<std::string>::operator = (bool value)
{
	if (IsMutable()) {
		Set( value ? "true" : "false" );
	}
	return *this;
}
template <> VariableBase& Variable<std::string>::operator = (long long value)
{
	if(IsMutable())
	{
		std::stringstream sstr;
		sstr << "0x" << std::hex << value;
		std::string tmp = sstr.str();
		Set( tmp );
	}
	return *this;
}
template <> VariableBase& Variable<std::string>::operator = (unsigned long long value)
{
	if (IsMutable())
	{
		std::stringstream sstr;
		sstr << "0x" << std::hex << value;
		std::string tmp = sstr.str();
		Set( tmp );
	}
	return *this;
}
template <> VariableBase& Variable<std::string>::operator = (double value)
{
	if (IsMutable())
	{
		std::stringstream sstr;
		sstr << value;
		std::string tmp = sstr.str();
		Set( tmp );
	}
	return *this;
}
template <> VariableBase& Variable<std::string>::operator = (const char *value)
{
	if (IsMutable())
	{
		Set( value );
	}
	return *this;
}

//=============================================================================
//=                         specialized Formula<>                             =
//=============================================================================

template <>
Formula<double>::operator std::string () const
{
	std::stringstream sstr;
	sstr << Compute();
	return sstr.str();
}

template <>
const char *Formula<signed char>::GetDataTypeName() const
{
	return GetSignedDataTypeName<signed char>();
}

template <>
const char *Formula<unsigned char>::GetDataTypeName() const
{
	return GetSignedDataTypeName<unsigned char>();
}

template <>
const char *Formula<short>::GetDataTypeName() const
{
	return GetSignedDataTypeName<short>();
}

template <>
const char *Formula<unsigned short>::GetDataTypeName() const
{
	return GetSignedDataTypeName<unsigned short>();
}

template <>
const char *Formula<int>::GetDataTypeName() const
{
	return GetSignedDataTypeName<int>();
}

template <>
const char *Formula<unsigned int>::GetDataTypeName() const
{
	return GetSignedDataTypeName<unsigned int>();
}

template <>
const char *Formula<long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<long>();
}

template <>
const char *Formula<unsigned long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<unsigned long>();
}

template <>
const char *Formula<long long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<long long>();
}

template <>
const char *Formula<unsigned long long>::GetDataTypeName() const
{
	return GetSignedDataTypeName<unsigned long long>();
}

template <>
const char *Formula<float>::GetDataTypeName() const
{
	return "single precision floating-point";
}

template <>
const char *Formula<double>::GetDataTypeName() const
{
	return "double precision floating-point";
}

//=============================================================================
//=                       template instanciations                             =
//=============================================================================

template class Variable<bool>;
template class Variable<signed char>;
template class Variable<short>;
template class Variable<int>;
template class Variable<long>;
template class Variable<long long>;
template class Variable<unsigned char>;
template class Variable<unsigned short>;
template class Variable<unsigned int>;
template class Variable<unsigned long>;
template class Variable<unsigned long long>;
template class Variable<float>;
template class Variable<double>;
template class Variable<std::string>;

template class VariableArray<bool>;
template class VariableArray<signed char>;
template class VariableArray<short>;
template class VariableArray<int>;
template class VariableArray<long>;
template class VariableArray<long long>;
template class VariableArray<unsigned char>;
template class VariableArray<unsigned short>;
template class VariableArray<unsigned int>;
template class VariableArray<unsigned long>;
template class VariableArray<unsigned long long>;
template class VariableArray<float>;
template class VariableArray<double>;
template class VariableArray<std::string>;

template class Formula<signed char>;
template class Formula<short>;
template class Formula<int>;
template class Formula<long>;
template class Formula<long long>;
template class Formula<unsigned char>;
template class Formula<unsigned short>;
template class Formula<unsigned int>;
template class Formula<unsigned long>;
template class Formula<unsigned long long>;
template class Formula<float>;
template class Formula<double>;

template class StatisticFormula<signed char>;
template class StatisticFormula<short>;
template class StatisticFormula<int>;
template class StatisticFormula<long>;
template class StatisticFormula<long long>;
template class StatisticFormula<unsigned char>;
template class StatisticFormula<unsigned short>;
template class StatisticFormula<unsigned int>;
template class StatisticFormula<unsigned long>;
template class StatisticFormula<unsigned long long>;
template class StatisticFormula<float>;
template class StatisticFormula<double>;

} // end of namespace variable
} // end of namespace kernel
} // end of namespace unisim
