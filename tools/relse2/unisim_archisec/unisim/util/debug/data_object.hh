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

#ifndef __UNISIM_UTIL_DEBUG_DATA_OBJECT_HH__
#define __UNISIM_UTIL_DEBUG_DATA_OBJECT_HH__

#include <unisim/util/endian/endian.hh>
#include <unisim/util/debug/type.hh>
#include <string>
#include <stdexcept>

namespace unisim {
namespace util {
namespace debug {

template <class ADDRESS> class DataObject;
template <class ADDRESS> class DataObjectRef;

namespace {

template <class ADDRESS, typename T>
T Sum(const DataObject<ADDRESS>& data_object, T value)
{
	return T(data_object) + value;
}

template <class ADDRESS, typename T>
T Difference(const DataObject<ADDRESS>& data_object, T value)
{
	return T(data_object) - value;
}

template <class ADDRESS, typename T>
T Difference(T value, const DataObject<ADDRESS>& data_object)
{
	return value - T(data_object);
}

template <class ADDRESS, typename T>
T Multiply(const DataObject<ADDRESS>& data_object, T value)
{
	return T(data_object) * value;
}

template <class ADDRESS, typename T>
T Divide(const DataObject<ADDRESS>& data_object, T value)
{
	return T(data_object) / value;
}

template <class ADDRESS, typename T>
T Divide(T value, const DataObject<ADDRESS>& data_object)
{
	return value / T(data_object);
}

template <class ADDRESS, typename T>
T Modulo(const DataObject<ADDRESS>& data_object, T value)
{
	return T(data_object) % value;
}

template <class ADDRESS, typename T>
T Modulo(T value, const DataObject<ADDRESS>& data_object)
{
	return value % T(data_object);
}

template <class ADDRESS, typename T>
T BitwiseAnd(const DataObject<ADDRESS>& data_object, T value)
{
	return value & T(data_object);
}

template <class ADDRESS, typename T>
T BitwiseOr(const DataObject<ADDRESS>& data_object, T value)
{
	return value | T(data_object);
}

template <class ADDRESS, typename T>
T BitwiseXor(const DataObject<ADDRESS>& data_object, T value)
{
	return value ^ T(data_object);
}

template <class ADDRESS>
long long BitwiseNot(const DataObject<ADDRESS>& data_object)
{
	return ~(long long) data_object;
}

template <class ADDRESS>
long long ShiftRight(const DataObject<ADDRESS>& data_object, unsigned int n)
{
	return (long long) data_object >> n;
}

template <class ADDRESS>
long long ShiftLeft(const DataObject<ADDRESS>& data_object, unsigned int n)
{
	return (long long) data_object << n;
}

template <class ADDRESS>
bool LogicalAnd(const DataObject<ADDRESS>& data_object, bool value)
{
	return value && bool(data_object);
}

template <class ADDRESS>
bool LogicalOr(const DataObject<ADDRESS>& data_object, bool value)
{
	return value || bool(data_object);
}

template <class ADDRESS, typename T>
long long Not(const DataObject<ADDRESS>& data_object)
{
	return !bool(data_object);
}

} // end of anonymous namespace

template <class ADDRESS>
class DataObject
{
public:
	class Error : public std::runtime_error
	{
	public:
		Error(const char *msg);
		Error(const std::string& msg);
	};
	
	class ReadError : Error
	{
	public:
		ReadError(const char *data_object_name);
		ReadError(const std::string& data_object_name);
	};
	
	class WriteError : Error
	{
	public:
		WriteError(const char *data_object_name);
		WriteError(const std::string& data_object_name);
	};
	
	class TypeError : Error
	{
	public:
		TypeError(const char *data_object_name);
		TypeError(const std::string& data_object_name);
	};
	
	class UndefinedReferenceError : Error
	{
	public:
		UndefinedReferenceError();
		UndefinedReferenceError(const char *data_object_name);
		UndefinedReferenceError(const std::string& data_object_name);
	};
	
	virtual ~DataObject() {}
	virtual const char *GetName() const = 0;
	virtual ADDRESS GetBitSize() const = 0;
	virtual const Type *GetType() const = 0;
	virtual unisim::util::endian::endian_type GetEndian() const = 0;
	virtual bool Exists() const = 0;
	virtual bool IsOptimizedOut() const = 0;
	virtual bool GetAddress(ADDRESS& addr) const = 0;
	virtual bool Read(ADDRESS obj_bit_offset, uint64_t& value, ADDRESS bit_size) const = 0;
	virtual bool Write(ADDRESS obj_bit_offset, uint64_t value, ADDRESS bit_size) = 0;
	virtual bool Read(ADDRESS obj_bit_offset, void *buffer, ADDRESS buf_bit_offset, ADDRESS bit_size) const = 0;
	virtual bool Write(ADDRESS obj_bit_offset, const void *buffer, ADDRESS buf_bit_offset, ADDRESS bit_size) = 0;
	
	// conversion operators
	virtual operator bool() const = 0;
	virtual operator signed char() const = 0;
	virtual operator short() const = 0;
	virtual operator int() const = 0;
	virtual operator long() const = 0;
	virtual operator long long() const = 0;
	virtual operator unsigned char() const = 0;
	virtual operator unsigned short() const = 0;
	virtual operator unsigned int() const = 0;
	virtual operator unsigned long() const = 0;
	virtual operator unsigned long long() const = 0;
	virtual operator float() const = 0;
	virtual operator double() const = 0;
	virtual operator std::string() const = 0;

	// assignment operators
	virtual DataObject<ADDRESS>& operator = (bool value) = 0;
	virtual DataObject<ADDRESS>& operator = (signed char value) = 0;
	virtual DataObject<ADDRESS>& operator = (short value) = 0;
	virtual DataObject<ADDRESS>& operator = (int value) = 0;
	virtual DataObject<ADDRESS>& operator = (long value) = 0;
	virtual DataObject<ADDRESS>& operator = (long long value) = 0;
	virtual DataObject<ADDRESS>& operator = (unsigned char value) = 0;
	virtual DataObject<ADDRESS>& operator = (unsigned short value) = 0;
	virtual DataObject<ADDRESS>& operator = (unsigned int value) = 0;
	virtual DataObject<ADDRESS>& operator = (unsigned long value) = 0;
	virtual DataObject<ADDRESS>& operator = (unsigned long long value) = 0;
	virtual DataObject<ADDRESS>& operator = (float value) = 0;
	virtual DataObject<ADDRESS>& operator = (double value) = 0;
	virtual DataObject<ADDRESS>& operator = (const std::string& value) = 0;
	
	// dereferencing operator
	virtual DataObjectRef<ADDRESS> operator * () = 0;
	virtual const DataObjectRef<ADDRESS> operator * () const = 0;
	
	// object property accessors
	virtual DataObjectRef<ADDRESS> operator [] (const char *property_name) = 0;
	virtual const DataObjectRef<ADDRESS> operator [] (const char *property_name) const = 0;
	DataObjectRef<ADDRESS> operator [] (const std::string& property_name) { return this->operator [] (property_name.c_str()); }
	const DataObjectRef<ADDRESS> operator [] (const std::string& property_name) const { return this->operator [] (property_name.c_str()); }
	
	// array item accessors
	virtual DataObjectRef<ADDRESS> operator [] (int64_t subscript) = 0;
	virtual const DataObjectRef<ADDRESS> operator [] (int64_t subscript) const = 0;
	
	// arithmetic operators
	template <typename T> DataObject<ADDRESS>& operator += (T value) { return this->operator = (Sum<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator -= (T value) { return this->operator = (Difference<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator *= (T value) { return this->operator = (Multiply<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator /= (T value) { return this->operator = (Divide<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator %= (T value) { return this->operator = (Divide<ADDRESS, T>(*this, value)); }
	DataObject<ADDRESS>& operator ++ () { return this->operator = (Sum<ADDRESS, long long>(*this, 1LL)); } // Prefix
	DataObject<ADDRESS>& operator -- () { return this->operator = (Difference<ADDRESS, long long>(*this, 1LL)); } // Prefix

	// bitwise operators
	template <typename T> DataObject<ADDRESS>& operator &= (T value) { return this->operator = (BitwiseAnd<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator |= (T value) { return this->operator = (BitwiseOr<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator ^= (T value) { return this->operator = (BitwiseXor<ADDRESS, T>(*this, value)); }
	template <typename T> DataObject<ADDRESS>& operator >>= (unsigned int n) { return this->operator = (ShiftRight<ADDRESS>(*this, n)); }
	template <typename T> DataObject<ADDRESS>& operator <<= (unsigned int n) { return this->operator = (ShiftLeft<ADDRESS>(*this, n)); }

protected:
	DataObject() : ref_count(0) {}
private:
	friend class DataObjectRef<ADDRESS>;
	
	unsigned int ref_count;
	
	template <typename T> int CompareBaseType(T value) const { return this->template operator T() - value; }
	template <typename T> T Sum(T value) const { return this->template operator T() + value; }
	void Acquire() { ++ref_count; }
	void Release() { if(ref_count && (--ref_count == 0)) delete this; }
};

template <class ADDRESS, typename T>
bool operator == (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value) == 0; }

template <class ADDRESS, typename T>
bool operator == (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object) == 0; }

template <class ADDRESS, typename T>
bool operator != (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value) != 0; }

template <class ADDRESS, typename T>
bool operator != (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object) != 0; }

template <class ADDRESS, typename T>
bool operator < (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value) < 0; }

template <class ADDRESS, typename T>
bool operator < (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object) < 0; }

template <class ADDRESS, typename T>
bool operator > (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value) > 0; }

template <class ADDRESS, typename T>
bool operator > (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object) > 0; }

template <class ADDRESS, typename T>
T operator + (const DataObject<ADDRESS>& data_object, T value) { return Sum<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator + (T value, const DataObject<ADDRESS>& data_object) { return Sum<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator - (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator - (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object); }

template <class ADDRESS, typename T>
T operator * (const DataObject<ADDRESS>& data_object, T value) { return Difference<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator * (T value, const DataObject<ADDRESS>& data_object) { return Difference<ADDRESS, T>(value, data_object); }

template <class ADDRESS, typename T>
T operator / (const DataObject<ADDRESS>& data_object, T value) { return Divide<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator / (T value, const DataObject<ADDRESS>& data_object) { return Divide<ADDRESS, T>(value, data_object); }

template <class ADDRESS, typename T>
T operator % (const DataObject<ADDRESS>& data_object, T value) { return Modulo<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator % (T value, const DataObject<ADDRESS>& data_object) { return Modulo<ADDRESS, T>(value, data_object); }

template <class ADDRESS, typename T>
T operator & (const DataObject<ADDRESS>& data_object, T value) { return BitwiseAnd<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator & (T value, const DataObject<ADDRESS>& data_object) { return BitwiseAnd<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator | (const DataObject<ADDRESS>& data_object, T value) { return BitwiseOr<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator | (T value, const DataObject<ADDRESS>& data_object) { return BitwiseOr<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator ^ (const DataObject<ADDRESS>& data_object, T value) { return BitwiseXor<ADDRESS, T>(data_object, value); }

template <class ADDRESS, typename T>
T operator ^ (T value, const DataObject<ADDRESS>& data_object) { return BitwiseXor<ADDRESS, T>(data_object, value); }

template <class ADDRESS>
long long operator ~ (const DataObject<ADDRESS>& data_object) { return BitwiseNot<ADDRESS>(data_object); }

template <class ADDRESS>
long long operator >> (const DataObject<ADDRESS>& data_object, unsigned int n) { return ShiftRight<ADDRESS>(data_object, n); }

template <class ADDRESS>
long long operator << (const DataObject<ADDRESS>& data_object, unsigned int n) { return ShiftLeft<ADDRESS>(data_object, n); }

template <class ADDRESS, typename T>
bool operator && (const DataObject<ADDRESS>& data_object, bool value) { return LogicalAnd<ADDRESS>(data_object, value); }

template <class ADDRESS, typename T>
bool operator && (bool value, const DataObject<ADDRESS>& data_object) { return LogicalAnd<ADDRESS>(data_object, value); }

template <class ADDRESS, typename T>
bool operator || (const DataObject<ADDRESS>& data_object, bool value) { return LogicalOr<ADDRESS>(data_object, value); }

template <class ADDRESS, typename T>
bool operator || (bool value, const DataObject<ADDRESS>& data_object) { return LogicalOr<ADDRESS>(data_object, value); }

template <class ADDRESS>
bool operator ! (const DataObject<ADDRESS>& data_object) { return Not<ADDRESS>(data_object); }

template <class ADDRESS>
class DataObjectRef
{
public:
	static DataObjectRef<ADDRESS> Undefined;
	
	DataObjectRef() : data_object(0) {}
	DataObjectRef(DataObject<ADDRESS> *_data_object) : data_object(_data_object) { if(data_object) data_object->Acquire(); }
	DataObjectRef(const DataObjectRef<ADDRESS>& o) : data_object(o.data_object) { if(data_object) data_object->Acquire(); }
	DataObjectRef<ADDRESS>& operator = (const DataObjectRef<ADDRESS>& o) { if(data_object) data_object->Release(); data_object = o.data_object; if(data_object) data_object->Acquire(); return *this; }
	~DataObjectRef() { if(data_object) data_object->Release(); }
	
	bool IsDefined() const { return data_object != 0; }
	bool IsUndefined() const { return data_object == 0; }
	bool operator == (const DataObjectRef<ADDRESS>& o) const { return data_object == o.data_object; }
	bool operator != (const DataObjectRef<ADDRESS>& o) const { return data_object != o.data_object; }
	
	const char *GetName() const { Check(); return data_object->GetName(); }
	ADDRESS GetBitSize() const { Check(); return data_object->GetBitSize(); }
	const Type *GetType() const { Check(); return data_object->GetType(); }
	unisim::util::endian::endian_type GetEndian() const { Check(); return data_object->GetEndian(); }
	bool Exists() const { Check(); return data_object->Exists(); }
	bool IsOptimizedOut() const { Check(); return data_object->IsOptimizedOut(); }
	bool GetAddress(ADDRESS& addr) const { Check(); return data_object->GetAddress(addr); }
	bool Read(ADDRESS obj_bit_offset, uint64_t& value, ADDRESS bit_size) const { Check(); return data_object->Read(obj_bit_offset, value, bit_size); }
	bool Write(ADDRESS obj_bit_offset, uint64_t value, ADDRESS bit_size) { Check(); return data_object->Write(obj_bit_offset, value, bit_size); }
	bool Read(ADDRESS obj_bit_offset, void *buffer, ADDRESS buf_bit_offset, ADDRESS bit_size) const { Check(); return data_object->Read(obj_bit_offset, buffer, buf_bit_offset, bit_size); }
	bool Write(ADDRESS obj_bit_offset, const void *buffer, ADDRESS buf_bit_offset, ADDRESS bit_size) { Check(); return data_object->Write(obj_bit_offset, buffer, buf_bit_offset, bit_size); }

	// conversion operators
	operator bool() const { Check(); return data_object->operator bool(); }
	operator signed char() const { Check(); return data_object->operator signed char(); }
	operator short() const { Check(); return data_object->operator short(); }
	operator int() const { Check(); return data_object->operator int(); }
	operator long() const { Check(); return data_object->operator long(); }
	operator long long() const { Check(); return data_object->operator long long(); }
	operator unsigned char() const { Check(); return data_object->operator unsigned char(); }
	operator unsigned short() const { Check(); return data_object->operator unsigned short(); }
	operator unsigned int() const { Check(); return data_object->operator unsigned int(); }
	operator unsigned long() const { Check(); return data_object->operator unsigned long(); }
	operator unsigned long long() const { Check(); return data_object->operator unsigned long long(); }
	operator float() const { Check(); return data_object->operator float(); }
	operator double() const { Check(); return data_object->operator double(); }
	operator std::string() const { Check(); return data_object->operator std::string(); }
	operator DataObject<ADDRESS>& () { Check(); return *data_object; }
	operator DataObject<ADDRESS>& () const { Check(); return *data_object; }

	// assignment operators
	DataObjectRef<ADDRESS>& operator = (bool value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (signed char value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (short value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (int value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (long value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (long long value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (unsigned char value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (unsigned short value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (unsigned int value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (unsigned long value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (unsigned long long value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (float value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (double value) { Check(); data_object->operator = (value); return *this; }
	DataObjectRef<ADDRESS>& operator = (const std::string& value) { Check(); data_object->operator = (value); return *this; }
	
	// dereferencing operator
	DataObjectRef<ADDRESS> operator * () { Check(); return data_object->operator *(); }
	const DataObjectRef<ADDRESS> operator * () const { Check(); return data_object->operator *(); }
	
	// object property accessors
	DataObjectRef<ADDRESS> operator [] (const char *property_name) { Check(); return data_object->operator [] (property_name); }
	const DataObjectRef<ADDRESS> operator [] (const char *property_name) const { Check(); return data_object->operator [] (property_name); }
	DataObjectRef<ADDRESS> operator [] (const std::string& property_name) { Check(); return data_object->operator [] (property_name); }
	const DataObjectRef<ADDRESS> operator [] (const std::string& property_name) const { Check(); return data_object->operator [] (property_name); }
	
	// array item accessors
	DataObjectRef<ADDRESS> operator [] (int64_t subscript) { Check(); return data_object->operator [](subscript); }
	const DataObjectRef<ADDRESS> operator [] (int64_t subscript) const { Check(); return data_object->operator [](subscript); }
	
	// arithmetic operators
	template <typename T> DataObjectRef<ADDRESS>& operator += (T value) { Check(); data_object->operator += (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator -= (T value) { Check(); data_object->operator -= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator *= (T value) { Check(); data_object->operator *= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator /= (T value) { Check(); data_object->operator /= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator %= (T value) { Check(); data_object->operator %= (value); return *this; }
	DataObjectRef<ADDRESS>& operator ++ () { Check(); data_object->operator ++ (); return *this; } // Prefix
	DataObject<ADDRESS>& operator -- () { Check(); data_object->operator -- (); return *this; } // Prefix

	// bitwise operators
	template <typename T> DataObjectRef<ADDRESS>& operator &= (T value) { Check(); data_object->operator &= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator |= (T value) { Check(); data_object->operator |= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator ^= (T value) { Check(); data_object->operator ^= (value); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator >>= (unsigned int n) { Check(); data_object->operator >>= (n); return *this; }
	template <typename T> DataObjectRef<ADDRESS>& operator <<= (unsigned int n) { Check(); data_object->operator <<= (n); return *this; }
	
private:
	template <typename T>
	friend bool operator == (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) == value; }

	template <typename T>
	friend bool operator == (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return (*data_object_ref.data_object) == value; }

	template <typename T>
	friend bool operator != (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) != value; }

	template <typename T>
	friend bool operator != (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return (*data_object_ref.data_object) != value; }

	template <typename T>
	friend bool operator < (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) < value; }

	template <typename T>
	friend bool operator < (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value < (*data_object_ref.data_object); }

	template <typename T>
	friend bool operator > (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) > value; }

	template <typename T>
	friend bool operator > (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value > (*data_object_ref.data_object); }

	template <typename T>
	friend T operator + (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) +value; }

	template <typename T>
	friend T operator + (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value + (*data_object_ref.data_object); }

	template <typename T>
	friend T operator - (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) - value; }

	template <typename T>
	friend T operator - (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value - (*data_object_ref.data_object); }

	template <typename T>
	friend T operator * (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) * value; }

	template <typename T>
	friend T operator * (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value * (*data_object_ref.data_object); }

	template <typename T>
	friend T operator / (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) / value; }

	template <typename T>
	friend T operator / (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value / (*data_object_ref.data_object); }

	template <typename T>
	friend T operator % (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) % value;; }

	template <typename T>
	friend T operator % (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value % (*data_object_ref.data_object); }

	template <typename T>
	friend T operator & (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) & value; }

	template <typename T>
	friend T operator & (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value & (*data_object_ref.data_object); }

	template <typename T>
	friend T operator | (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) | value; }

	template <typename T>
	friend T operator | (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value | (*data_object_ref.data_object); }

	template <typename T>
	friend T operator ^ (const DataObjectRef<ADDRESS>& data_object_ref, T value) { data_object_ref.Check(); return (*data_object_ref.data_object) ^ value; }

	template <typename T>
	friend T operator ^ (T value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value ^ (*data_object_ref.data_object); }

	template <typename T>
	friend long long operator ~ (const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return ~(*data_object_ref.data_object); }

	template <typename T>
	friend long long operator >> (const DataObjectRef<ADDRESS>& data_object_ref, unsigned int n) { data_object_ref.Check(); return (*data_object_ref.data_object) >> n; }

	template <typename T>
	friend long long operator << (const DataObjectRef<ADDRESS>& data_object_ref, unsigned int n) { data_object_ref.Check(); return (*data_object_ref.data_object) << n; }

	template <typename T>
	friend bool operator && (const DataObjectRef<ADDRESS>& data_object_ref, bool value) { data_object_ref.Check(); return (*data_object_ref.data_object) && value; }

	template <typename T>
	friend bool operator && (bool value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value && (*data_object_ref.data_object); }

	template <typename T>
	friend bool operator || (const DataObjectRef<ADDRESS>& data_object_ref, bool value) { data_object_ref.Check(); return (*data_object_ref.data_object) || value; }

	template <typename T>
	friend bool operator || (bool value, const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return value || (*data_object_ref.data_object); }

	template <typename T>
	friend bool operator ! (const DataObjectRef<ADDRESS>& data_object_ref) { data_object_ref.Check(); return !(*data_object_ref.data_object); }

	DataObject<ADDRESS> *data_object;
	
	void Check() const { if(!data_object) throw typename DataObject<ADDRESS>::UndefinedReferenceError(); }
};

template <class ADDRESS>
DataObjectRef<ADDRESS> DataObjectRef<ADDRESS>::Undefined;

template <class ADDRESS>
inline DataObject<ADDRESS>::Error::Error(const char *msg)
	: std::runtime_error(msg)
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::Error::Error(const std::string& msg)
	: std::runtime_error(msg)
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::ReadError::ReadError(const char *data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" read error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::ReadError::ReadError(const std::string& data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" read error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::TypeError::TypeError(const char *data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" type error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::TypeError::TypeError(const std::string& data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" type error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::WriteError::WriteError(const char *data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" write error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::WriteError::WriteError(const std::string& data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" write error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::UndefinedReferenceError::UndefinedReferenceError()
	: DataObject<ADDRESS>::Error("undefined reference error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::UndefinedReferenceError::UndefinedReferenceError(const char *data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" undefined reference error")
{
}

template <class ADDRESS>
inline DataObject<ADDRESS>::UndefinedReferenceError::UndefinedReferenceError(const std::string& data_object_name)
	: DataObject<ADDRESS>::Error(std::string("\"") + data_object_name + "\" undefined reference error")
{
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_DATA_OBJECT_HH__
