/*
 *  Copyright (c) 2007-2022,
 *  Commissariat a l'Energie Atomique (CEA),
 *  University of Perpignan (UPVD)
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
 *          Reda Nouacer (reda.nouacer@cea.fr)
 *          Sylvain Collange (sylvain.collange@univ-perp.fr)
 */
 
#ifndef __UNISIM_UTIL_ARITHMETIC_ARITHMETIC_HH__
#define __UNISIM_UTIL_ARITHMETIC_ARITHMETIC_HH__

#include <inttypes.h>
#include <unisim/util/inlining/inlining.hh>
#include <limits>

namespace unisim {
namespace util {
namespace arithmetic {

inline void SignedAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void SignedAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void SignedAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in) ALWAYS_INLINE;

inline void UnsignedAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void UnsignedAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void UnsignedAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in) ALWAYS_INLINE;

inline void SignedSub8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void SignedSub16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void SignedSub32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in) ALWAYS_INLINE;

inline void UnsignedSub8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void UnsignedSub16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in) ALWAYS_INLINE;
inline void UnsignedSub32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in) ALWAYS_INLINE;

inline void SignedSatAdd8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatAdd16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatAdd32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatAdd16(uint32_t& result, uint8_t& does_sat, uint32_t x, uint32_t y) ALWAYS_INLINE;
inline void SignedSatAdd32(uint32_t& result, uint8_t& does_sat, uint32_t x, uint32_t y) ALWAYS_INLINE;

inline void UnsignedSatAdd8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void UnsignedSatAdd16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void UnsignedSatAdd32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) ALWAYS_INLINE;

inline void SignedSatSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void SignedSatSub8(uint8_t& result, uint8_t& does_sat, uint8_t x, uint8_t y) ALWAYS_INLINE;
inline void SignedSatSub16(uint16_t& result, uint8_t& does_sat, uint16_t x, uint16_t y) ALWAYS_INLINE;
inline void SignedSatSub32(uint32_t& result, uint8_t& does_sat, uint32_t x, uint32_t y) ALWAYS_INLINE;

inline void UnsignedSatSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void UnsignedSatSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void UnsignedSatSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) ALWAYS_INLINE;
inline void UnsignedSatSub8(uint8_t& result, uint8_t& overflow, uint8_t x, uint8_t y) ALWAYS_INLINE; 
inline void UnsignedSatSub16(uint16_t& result, uint8_t& overflow, uint16_t x, uint16_t y) ALWAYS_INLINE;
inline void UnsignedSatSub32(uint32_t& result, uint8_t& overflow, uint32_t x, uint32_t y) ALWAYS_INLINE;

inline uint32_t ReverseCarryPropagationAdd(uint32_t x, uint32_t y) ALWAYS_INLINE;

inline uint8_t RotateLeft(uint8_t v, unsigned int n) ALWAYS_INLINE;
inline uint16_t RotateLeft(uint16_t v, unsigned int n) ALWAYS_INLINE;
inline uint32_t RotateLeft(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline uint64_t RotateLeft(uint64_t v, unsigned int n) ALWAYS_INLINE;
inline uint8_t RotateRight(uint8_t v, unsigned int n) ALWAYS_INLINE;
inline uint16_t RotateRight(uint16_t v, unsigned int n) ALWAYS_INLINE;
inline uint32_t RotateRight(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline uint64_t RotateRight(uint64_t v, unsigned int n) ALWAYS_INLINE;

inline int8_t RotateLeft(int8_t v, unsigned int n) ALWAYS_INLINE;
inline int16_t RotateLeft(int16_t v, unsigned int n) ALWAYS_INLINE;
inline int32_t RotateLeft(int32_t v, unsigned int n) ALWAYS_INLINE;
inline int64_t RotateLeft(int64_t v, unsigned int n) ALWAYS_INLINE;
inline int8_t RotateRight(int8_t v, unsigned int n) ALWAYS_INLINE;
inline int16_t RotateRight(int16_t v, unsigned int n) ALWAYS_INLINE;
inline int32_t RotateRight(int32_t v, unsigned int n) ALWAYS_INLINE;
inline int64_t RotateRight(int64_t v, unsigned int n) ALWAYS_INLINE;

inline uint32_t RotateLeft(uint32_t v, unsigned int n, uint8_t& bit_out) ALWAYS_INLINE;
inline uint32_t RotateLeft(uint32_t v, unsigned int n, uint8_t bit_in, uint8_t& bit_out) ALWAYS_INLINE;
inline uint32_t RotateRight(uint32_t v, unsigned int n, uint8_t& bit_out) ALWAYS_INLINE;
inline uint32_t RotateRight(uint32_t v, unsigned int n, uint8_t bit_in, uint8_t& bit_out) ALWAYS_INLINE;
inline uint32_t RotateLeft(uint32_t v, unsigned int n, bool bitin, bool& bitout) ALWAYS_INLINE;
inline uint32_t RotateRight(uint32_t v, unsigned int n, bool bitin, bool& bitout) ALWAYS_INLINE;

inline uint32_t ShiftLeft(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline uint32_t ShiftLeft(uint32_t v, unsigned int n, uint8_t& bit_out) ALWAYS_INLINE;
inline uint32_t ShiftRight(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline uint32_t ShiftRight(uint32_t v, unsigned int n, uint8_t& bit_out) ALWAYS_INLINE;

inline uint32_t ShiftArithmeticRight(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline uint32_t ShiftArithmeticRight(uint32_t v, unsigned int n, uint8_t& bit_out) ALWAYS_INLINE;

inline bool BitScanForward(unsigned int& n, uint32_t v) ALWAYS_INLINE;
inline bool BitScanForward(unsigned int& n, uint64_t v) ALWAYS_INLINE;

inline bool BitScanReverse(unsigned int& n, uint32_t v) ALWAYS_INLINE;
inline bool BitScanReverse(unsigned int& n, uint64_t v) ALWAYS_INLINE;

inline int BitScanForward(unsigned char n) ALWAYS_INLINE;
inline int BitScanForward(unsigned short n) ALWAYS_INLINE;
inline int BitScanForward(unsigned n) ALWAYS_INLINE;
inline int BitScanForward(unsigned long n) ALWAYS_INLINE;
inline int BitScanForward(unsigned long long n) ALWAYS_INLINE;

inline int BitScanReverse(unsigned char n) ALWAYS_INLINE;
inline int BitScanReverse(unsigned short n) ALWAYS_INLINE;
inline int BitScanReverse(unsigned n) ALWAYS_INLINE;
inline int BitScanReverse(unsigned long n) ALWAYS_INLINE;
inline int BitScanReverse(unsigned long long n) ALWAYS_INLINE;

inline unsigned int CountLeadingZeros(uint32_t v) ALWAYS_INLINE;
inline unsigned int CountLeadingZeros(uint64_t v) ALWAYS_INLINE;

inline unsigned int Log2(uint32_t v) ALWAYS_INLINE;
inline unsigned int Log2(uint64_t v) ALWAYS_INLINE;

inline unsigned int CeilLog2(uint32_t v) ALWAYS_INLINE;
inline unsigned int CeilLog2(uint64_t v) ALWAYS_INLINE;

inline int8_t SignExtend(uint8_t v, unsigned int n) ALWAYS_INLINE;
inline int16_t SignExtend(uint16_t v, unsigned int n) ALWAYS_INLINE;
inline int32_t SignExtend(uint32_t v, unsigned int n) ALWAYS_INLINE;
inline int64_t SignExtend(uint64_t v, unsigned int n) ALWAYS_INLINE;

inline int8_t SignExtend(int8_t v, unsigned int n) ALWAYS_INLINE;
inline int16_t SignExtend(int16_t v, unsigned int n) ALWAYS_INLINE;
inline int32_t SignExtend(int32_t v, unsigned int n) ALWAYS_INLINE;
inline int64_t SignExtend(int64_t v, unsigned int n) ALWAYS_INLINE;

inline void EvenParity(uint8_t v, uint8_t& parity_out) ALWAYS_INLINE;
inline void EvenParity(uint16_t v, uint8_t& parity_out) ALWAYS_INLINE;
inline void EvenParity(uint32_t v, uint8_t& parity_out) ALWAYS_INLINE;

inline void OddParity(uint8_t v, uint8_t& parity_out) ALWAYS_INLINE;
inline void OddParity(uint16_t v, uint8_t& parity_out) ALWAYS_INLINE;
inline void OddParity(uint32_t v, uint8_t& parity_out) ALWAYS_INLINE;

//=============================================================================
//=                              Full Adders                                  =
//=============================================================================

// WARNING: signed or unsigned addition affect how overflow flag is computed

// 8-bit signed addition with carrying
// inputs:
//   - x        : 8-bit left operand of addition
//   - y        : 8-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 8-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
inline void SignedAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (carry_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "qQm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (carry_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "qQm" (y) : "cc");
	}
#else
	uint8_t res = x + y + carry_in;
	uint8_t x7 = (x >> 7) & 1;
	uint8_t y7 = (y >> 7) & 1;
	uint8_t res7 = (res >> 7) & 1;
	uint8_t c6 = res7 ^ x7 ^ y7;
	uint8_t c7 = (x7 & y7) | (c6 & (x7 | y7));
	overflow = c7 ^ c6;
	carry_out = c7;
	result = res;
	sign = (int8_t) res < 0;
#endif
}

// 16-bit signed addition with carrying
// inputs:
//   - x        : 16-bit left operand of addition
//   - y        : 16-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 16-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
inline void SignedAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (carry_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (carry_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");
	}
#else
	uint16_t res = x + y + carry_in;
	uint16_t x15 = (x >> 15) & 1;
	uint16_t y15 = (y >> 15) & 1;
	uint16_t res15 = (res >> 15) & 1;
	uint16_t c14 = res15 ^ x15 ^ y15;
	uint16_t c15 = (x15 & y15) | (c14 & (x15 | y15));
	overflow = c15 ^ c14;
	carry_out = c15;
	result = res;
	sign = (int16_t) res < 0;
#endif
}

// 32-bit signed addition with carrying
// inputs:
//   - x        : 32-bit left operand of addition
//   - y        : 32-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 32-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
//
// The 31th 1-bit full adder equations are:
//    (1) result(31) = x(31) ^ y(31) ^ carry(30)
//    (2) carry(31) = x(31).y(31) + carry(30).(x(31) + y(31))
//    (3) overflow = carry(31) ^ carry(30)
//    result is easily computed from x + y + carry_in
//    from (1) we obtain: carry(30) = result(31) ^ x(31) ^ y(31)
//    carry_out is computed from equation (2), overflow from equation (3)
inline void SignedAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (carry_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (carry_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");
	}
#else
	uint32_t res = x + y + carry_in;
	uint32_t x31 = (x >> 31) & 1;
	uint32_t y31 = (y >> 31) & 1;
	uint32_t res31 = (res >> 31) & 1;
	uint32_t c30 = res31 ^ x31 ^ y31;
	uint32_t c31 = (x31 & y31) | (c30 & (x31 | y31));
	overflow = c31 ^ c30;
	carry_out = c31;
	result = res;
	sign = (int32_t) res < 0;
#endif
}

// 8-bit unsigned addition with carrying
// inputs:
//   - x        : 8-bit left operand of addition
//   - y        : 8-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 8-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
void UnsignedAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcb %4, %0\nsetc %1\nsets %2" : "=qQ" (result), "=qQm" (carry_out), "=qQ" (sign) : "0" (x), "qQm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addb %4, %0\nsetc %1\nsets %2" : "=qQ" (result), "=qQm" (carry_out), "=qQ" (sign) : "0" (x), "qQm" (y) : "cc");
	}
	overflow = carry_out;
#else
	uint8_t res = x + y + carry_in;
	uint8_t x7 = (x >> 7) & 1;
	uint8_t y7 = (y >> 7) & 1;
	uint8_t res7 = (res >> 7) & 1;
	uint8_t c6 = res7 ^ x7 ^ y7;
	uint8_t c7 = (x7 & y7) | (c6 & (x7 | y7));
	overflow = carry_out = c7;
	sign = (int8_t) res < 0;
	result = res;
#endif
}

// 16-bit unsigned addition with carrying
// inputs:
//   - x        : 16-bit left operand of addition
//   - y        : 16-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 16-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
void UnsignedAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcw %4, %0\nsetc %1\nsets %2" : "=r" (result), "=qQm" (carry_out), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addw %4, %0\nsetc %1\nsets %2" : "=r" (result), "=qQm" (carry_out), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");
	}
	overflow = carry_out;
#else
	uint16_t res = x + y + carry_in;
	uint16_t x15 = (x >> 15) & 1;
	uint16_t y15 = (y >> 15) & 1;
	uint16_t res15 = (res >> 15) & 1;
	uint16_t c14 = res15 ^ x15 ^ y15;
	uint16_t c15 = (x15 & y15) | (c14 & (x15 | y15));
	overflow = carry_out = c15;
	sign = (int16_t) res < 0;
	result = res;
#endif
}

// 32-bit unsigned addition with carrying
// inputs:
//   - x        : 32-bit left operand of addition
//   - y        : 32-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 32-bit result of addition x + y
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
void UnsignedAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(carry_in)
	{
		__asm__ ("stc\nadcl %4, %0\nsetc %1\nsets %2" : "=r" (result), "=qQ" (carry_out), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("addl %4, %0\nsetc %1\nsets %2" : "=r" (result), "=qQ" (carry_out), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");
	}
	overflow = carry_out;
#else
	uint32_t res = x + y + carry_in;
	uint32_t x31 = (x >> 31) & 1;
	uint32_t y31 = (y >> 31) & 1;
	uint32_t res31 = (res >> 31) & 1;
	uint32_t c30 = res31 ^ x31 ^ y31;
	uint32_t c31 = (x31 & y31) | (c30 & (x31 | y31));
	overflow = carry_out = c31;
	sign = (int32_t) res < 0;
	result = res;
#endif
}

//=============================================================================
//=                           Full Substractors                               =
//=============================================================================

// WARNING: signed or unsigned substraction affect how overflow flag is computed

// 8-bit signed substraction with carrying
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 8-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "q" (y) : "cc");	
	}
	else
	{
		__asm__ ("subb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "q" (y) : "cc");
	}
#else
	uint8_t res = x - y - borrow_in;
	uint8_t x7 = (x >> 7) & 1;
	uint8_t y7 = (y >> 7) & 1;
	uint8_t res7 = (res >> 7) & 1;
	uint8_t b6 = res7 ^ x7 ^ y7;
	uint8_t b7 = ((~x7 & y7) | (b6 & (~x7 | y7))) & 1;
	overflow = b7 ^ b6;
	borrow_out = b7;
	result = res;
	sign = (int8_t) res < 0;
#endif
}

// 16-bit signed substraction with carrying
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 16-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("subw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");
	}
#else
	uint16_t res = x - y - borrow_in;
	uint16_t x15 = (x >> 15) & 1;
	uint8_t y15 = (y >> 15) & 1;
	uint8_t res15 = (res >> 15) & 1;
	uint8_t b14 = res15 ^ x15 ^ y15;
	uint8_t b15 = ((~x15 & y15) | (b14 & (~x15 | y15))) & 1;
	overflow = b15 ^ b14;
	borrow_out = b15;
	result = res;
	sign = (int16_t) res < 0;
#endif
}

// 32-bit signed substraction with carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 32-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
//
// The 31th 1-bit full substractor equations are:
//    (1) result(31) = x(31) ^ y(31) ^ borrow(30)
//    (2) borrow(31) = ~x(31).y(31) + borrow(30).(~x(31) + y(31))
//    (3) overflow = borrow(31) ^ borrow(30)
//    result is easily computed from x - y - borrow_in
//    from (1) we obtain: borrow(30) = result(31) ^ x(31) ^ y(31)
//    borrow_out is computed from equation (2), overflow from equation (3)
inline void SignedSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (borrow_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("subl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (borrow_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");
	}
#else
	uint32_t res = x - y - borrow_in;
	uint32_t x31 = (x >> 31) & 1;
	uint32_t y31 = (y >> 31) & 1;
	uint32_t res31 = (res >> 31) & 1;
	uint32_t b30 = res31 ^ x31 ^ y31;
	uint32_t b31 = ((~x31 & y31) | (b30 & (~x31 | y31))) & 1;
	overflow = b31 ^ b30;
	borrow_out = b31;
	result = res;
	sign = (int32_t) res < 0;
#endif
}

// 8-bit unsigned substraction with carrying
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 8-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "q" (y) : "cc");	
	}
	else
	{
		__asm__ ("subb %5, %0\nsetc %1\nseto %2\nsets %3" : "=qQ" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "q" (y) : "cc");
	}
	overflow = borrow_out;
#else
	uint8_t res = x - y - borrow_in;
	uint8_t x7 = (x >> 7) & 1;
	uint8_t y7 = (y >> 7) & 1;
	uint8_t res7 = (res >> 7) & 1;
	uint8_t b6 = res7 ^ x7 ^ y7;
	uint8_t b7 = ((~x7 & y7) | (b6 & (~x7 | y7))) & 1;
	overflow = borrow_out = b7;
	result = res;
	sign = (int8_t) res < 0;
#endif
}

// 16-bit unsigned substraction with carrying
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 16-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("subw %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQm" (borrow_out), "=qQm" (overflow), "=qQm" (sign) : "0" (x), "rm" (y) : "cc");
	}
	overflow = borrow_out;
#else
	uint16_t res = x - y - borrow_in;
	uint16_t x15 = (x >> 15) & 1;
	uint8_t y15 = (y >> 15) & 1;
	uint8_t res15 = (res >> 15) & 1;
	uint8_t b14 = res15 ^ x15 ^ y15;
	uint8_t b15 = ((~x15 & y15) | (b14 & (~x15 | y15))) & 1;
	overflow = borrow_out = b15;
	result = res;
	sign = (int16_t) res < 0;
#endif
}

// 32-bit unsigned substraction with carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 32-bit result of substraction x - y
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
//
// The 31th 1-bit full substractor equations are:
//    (1) result(31) = x(31) ^ y(31) ^ borrow(30)
//    (2) borrow(31) = ~x(31).y(31) + borrow(30).(~x(31) + y(31))
//    (3) overflow = borrow(31) ^ borrow(30)
//    result is easily computed from x - y - borrow_in
//    from (1) we obtain: borrow(30) = result(31) ^ x(31) ^ y(31)
//    borrow_out is computed from equation (2), overflow from equation (3)
inline void UnsignedSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in) {
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	if(borrow_in)
	{
		__asm__ ("stc\nsbbl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (borrow_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");	
	}
	else
	{
		__asm__ ("subl %5, %0\nsetc %1\nseto %2\nsets %3" : "=r" (result), "=qQ" (borrow_out), "=qQ" (overflow), "=qQ" (sign) : "0" (x), "rm" (y) : "cc");
	}
	overflow = borrow_out;
#else
	uint32_t res = x - y - borrow_in;
	uint32_t x31 = (x >> 31) & 1;
	uint32_t y31 = (y >> 31) & 1;
	uint32_t res31 = (res >> 31) & 1;
	uint32_t b30 = res31 ^ x31 ^ y31;
	uint32_t b31 = ((~x31 & y31) | (b30 & (~x31 | y31))) & 1;
	overflow = borrow_out = b31;
	result = res;
	sign = (int32_t) res < 0;
#endif
}

//=============================================================================
//=                    Full Adders with signed saturation                     =
//=============================================================================

// WARNING: signed or unsigned substraction affect how overflow flag is computed

// 8-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 8-bit result of substraction x - y with saturation
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in)
{
	SignedAdd8(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		sign = !sign;
		result = sign ? 0x7f : 0x80;
	}
}

// 16-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 16-bit result of substraction x - y with saturation
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in)
{
	SignedAdd16(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		result = sign ? 0x7fff : 0x8000;
		sign = !sign;
	}
}

// 32-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
//   - carry_in : input carry (0 or 1) for chaining full substractor
// outputs:
//   - result   : 32-bit result of substraction x - y with saturation
//   - carry_out: output carry (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in)
{
	SignedAdd32(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		result = sign ? 0x7fffffff : 0x80000000;
		sign = !sign;
	}
}

// 16-bit signed substraction with saturation
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
// outputs:
//   - result   : 16-bit result of substraction x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void SignedSatAdd16(uint16_t& result, uint8_t& overflow, uint16_t x, uint16_t y) 
{
	uint8_t carry_out;
	uint8_t sign;
	SignedSatAdd16(result, carry_out, overflow, sign, x, y, 0);
}

// 32-bit signed substraction with saturation
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
// outputs:
//   - result   : 32-bit result of substraction x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void SignedSatAdd32(uint32_t& result, uint8_t& overflow, uint32_t x, uint32_t y) 
{
	uint8_t carry_out;
	uint8_t sign;
	SignedSatAdd32(result, carry_out, overflow, sign, x, y, 0);
}

//=============================================================================
//=                   Full Adders with unsigned saturation                    =
//=============================================================================

// 8-bit unsigned addition with saturation and carrying
// inputs:
//   - x        : 8-bit left operand of addition
//   - y        : 8-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 8-bit result of addition x + y with saturation
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatAdd8(uint8_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t carry_in)
{
	UnsignedAdd8(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		result = 0xff;
		sign = 1;
	}
}

// 16-bit unsigned addition with saturation and carrying
// inputs:
//   - x        : 16-bit left operand of addition
//   - y        : 16-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 16-bit result of addition x + y with saturation
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatAdd16(uint16_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t carry_in)
{
	UnsignedAdd16(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		result = 0xffff;
		sign = 1;
	}
}

// 32-bit unsigned addition with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of addition
//   - y        : 32-bit right operand of addition
//   - carry_in : input carry (0 or 1) for chaining full adders
// outputs:
//   - result   : 32-bit result of addition x + y with saturation
//   - carry_out: output carry (0 or 1) of full adder
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatAdd32(uint32_t& result, uint8_t& carry_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t carry_in)
{
	UnsignedAdd32(result, carry_out, overflow, sign, x, y, carry_in);
	if(overflow)
	{
		result = 0xffffffffUL;
		sign = 1;
	}
}

//=============================================================================
//=                 Full Substractors with signed saturation                  =
//=============================================================================

// 8-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 8-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in)
{
	SignedSub8(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = sign ? 0x7f : 0x80;
		sign = !sign;
	}
}

// 16-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 16-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in)
{
	SignedSub16(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = sign ? 0x7fff : 0x8000;
		sign = !sign;
	}
}

// 32-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 32-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void SignedSatSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in)
{
	SignedSub32(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = sign ? 0x7fffffff : 0x80000000;
		sign = !sign;
	}
}

// 16-bit signed substraction with saturation
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
// outputs:
//   - result   : 16-bit result of addition x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void SignedSatSub16(uint16_t& result, uint8_t& overflow, uint16_t x, uint16_t y) 
{
	uint8_t borrow_out;
	uint8_t sign;
	SignedSatSub16(result, borrow_out, overflow, sign, x, y, 0);
}

// 32-bit signed substraction with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
// outputs:
//   - result   : 32-bit result of addition x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void SignedSatSub32(uint32_t& result, uint8_t& overflow, uint32_t x, uint32_t y) 
{
	uint8_t borrow_out;
	uint8_t sign;
	SignedSatSub32(result, borrow_out, overflow, sign, x, y, 0);
}

//=============================================================================
//=                Full Substractors with unsigned saturation                 =
//=============================================================================

// 8-bit unsigned substraction with saturation and carrying
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 8-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub8(uint8_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint8_t x, uint8_t y, uint8_t borrow_in)
{
	UnsignedSub8(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = 0;
		sign = 0;
	}
}

// 16-bit unsigned substraction with saturation and carrying
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 16-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub16(uint16_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint16_t x, uint16_t y, uint8_t borrow_in)
{
	UnsignedSub16(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = 0;
		sign = 0;
	}
}

// 32-bit unsigned substraction with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
//   - borrow_in : input borrow (0 or 1) for chaining full substractors
// outputs:
//   - result   : 32-bit result of addition x - y with saturation
//   - borrow_out: output borrow (0 or 1) of full substractor
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub32(uint32_t& result, uint8_t& borrow_out, uint8_t& overflow, uint8_t& sign, uint32_t x, uint32_t y, uint8_t borrow_in)
{
	UnsignedSub32(result, borrow_out, overflow, sign, x, y, borrow_in);
	if(overflow)
	{
		result = 0;
		sign = 0;
	}
}

// 8-bit unsigned substraction with saturation
// inputs:
//   - x        : 8-bit left operand of substraction
//   - y        : 8-bit right operand of substraction
// outputs:
//   - result   : 8-bit result of addition x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub8(uint8_t& result, uint8_t& overflow, uint8_t x, uint8_t y) 
{
	uint8_t borrow_out;
	uint8_t sign;
	UnsignedSatSub8(result, borrow_out, overflow, sign, x, y, 0);
}

// 16-bit unsigned substraction with saturation
// inputs:
//   - x        : 16-bit left operand of substraction
//   - y        : 16-bit right operand of substraction
// outputs:
//   - result   : 16-bit result of addition x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub16(uint16_t& result, uint8_t& overflow, uint16_t x, uint16_t y) 
{
	uint8_t borrow_out;
	uint8_t sign;
	UnsignedSatSub16(result, borrow_out, overflow, sign, x, y, 0);
}

// 32-bit unsigned substraction with saturation and carrying
// inputs:
//   - x        : 32-bit left operand of substraction
//   - y        : 32-bit right operand of substraction
// outputs:
//   - result   : 32-bit result of addition x - y with saturation
//   - overflow : overflow flag (0 or 1)
inline void UnsignedSatSub32(uint32_t& result, uint8_t& overflow, uint32_t x, uint32_t y) 
{
	uint8_t borrow_out;
	uint8_t sign;
	UnsignedSatSub32(result, borrow_out, overflow, sign, x, y, 0);
}

//=============================================================================
//=                          Specific Adders                                  =
//=============================================================================

// 32-bit addition with reverse carry propagation
// inputs:
//   - x        : 32-bit left operand of addition
//   - y        : 32-bit right operand of addition
// outputs:
//   - returns 32-bit result of addition x + y with reverse carry propagation
inline uint32_t ReverseCarryPropagationAdd(uint32_t x, uint32_t y)
{
	// Compute the result as if there were no carry generation and propagation at all
	uint32_t r = x ^ y;

	// Compute local carry generation
	uint32_t x_and_y = x & y;
	unsigned int n;

	// Compute the bit index of the first carry generation to save time
	if(!BitScanReverse(n, x_and_y)) return r;

	uint32_t mask = (1 << n);
	uint32_t c = 0;
	uint32_t x_or_y = x | y;

	// propagate carry through remaining bits
	do
	{
		// Update result with carry in
		r = r ^ (mask & c);

		// Compute carry out: carry_out = (x & y) | (carry_in & (x | y))
		c = ((x_and_y | (c & x_or_y)) & mask) >> 1;

		// Go to next bit
		mask = mask >> 1;
	} while(mask);
	return r;
}

//=============================================================================
//=                                Rotates                                    =
//=============================================================================

// Rotate functions: WARNING! only least significative bits of n are used !!!!
// WARNING! bit_out value is zero when rotating of 0 bits

// 8-bit left rotation
// inputs:
//   - v: 8-bit value to rotate
//   - n: lower 3 bits contains rotate amount
// outputs:
//   - returns result of left rotation of v
inline uint8_t RotateLeft(uint8_t v, unsigned int n)
{
	// TODO: inline assembly
	n &= 7;
	return n ? (v << n) | (v >> (8 - n)) : v;
}

// 16-bit left rotation
// inputs:
//   - v: 16-bit value to rotate
//   - n: lower 4 bits contains rotate amount
// outputs:
//   - returns result of left rotation of v
inline uint16_t RotateLeft(uint16_t v, unsigned int n)
{
	// TODO: inline assembly
	n &= 15;
	return n ? (v << n) | (v >> (16 - n)) : v;
}

// 32-bit left rotation
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
// outputs:
//   - returns result of left rotation of v
inline uint32_t RotateLeft(uint32_t v, unsigned int n)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("rol %%cl, %0" : "=r" (v) : "0" (v), "c" (n) : "cc");
	return v;
#else
	n &= 31;
	return n ? (v << n) | (v >> (32 - n)) : v;
#endif
}

// 64-bit left rotation
// inputs:
//   - v: 64-bit value to rotate
//   - n: lower 6 bits contains rotate amount
// outputs:
//   - returns result of left rotation of v
inline uint64_t RotateLeft(uint64_t v, unsigned int n)
{
	// TODO: inline assembly for x86_64
	n &= 63;
	return n ? (v << n) | (v >> (64 - n)) : v;
}

// 8-bit right rotation
// inputs:
//   - v: 8-bit value to rotate
//   - n: lower 3 bits contains rotate amount
// outputs:
//   - returns result of right rotation of v
inline uint8_t RotateRight(uint8_t v, unsigned int n)
{
	// TODO: inline assembly
	n &= 7;
	return n ? (v >> n) | (v << (8 - n)) : v;
}

// 16-bit right rotation
// inputs:
//   - v: 16-bit value to rotate
//   - n: lower 4 bits contains rotate amount
// outputs:
//   - returns result of right rotation of v
inline uint16_t RotateRight(uint16_t v, unsigned int n)
{
	// TODO: inline assembly
	n &= 15;
	return n ? (v >> n) | (v << (16 - n)) : v;
}

// 32-bit right rotation
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
// outputs:
//   - returns result of right rotation of v
inline uint32_t RotateRight(uint32_t v, unsigned int n)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("ror %%cl, %0" : "=r" (v) : "0" (v), "c" (n) : "cc");
	return v;
#else
	n &= 31;
	return n ? (v >> n) | (v << (32 - n)) : v;
#endif
}

// 64-bit right rotation
// inputs:
//   - v: 64-bit value to rotate
//   - n: lower 6 bits contains rotate amount
// outputs:
//   - returns result of right rotation of v
inline uint64_t RotateRight(uint64_t v, unsigned int n)
{
	n &= 63;
	return n ? (v >> n) | (v << (64 - n)) : v;
}

// For convenience, may be removed in the future
inline int8_t RotateLeft(int8_t v, unsigned int n) { return RotateLeft((uint8_t) v, n); }
inline int16_t RotateLeft(int16_t v, unsigned int n) { return RotateLeft((uint16_t) v, n); }
inline int32_t RotateLeft(int32_t v, unsigned int n) { return RotateLeft((uint32_t) v, n); }
inline int64_t RotateLeft(int64_t v, unsigned int n) { return RotateLeft((uint64_t) v, n); }
inline int8_t RotateRight(int8_t v, unsigned int n) { return RotateRight((uint8_t) v, n); }
inline int16_t RotateRight(int16_t v, unsigned int n) { return RotateRight((uint16_t) v, n); }
inline int32_t RotateRight(int32_t v, unsigned int n) { return RotateRight((uint32_t) v, n); }
inline int64_t RotateRight(int64_t v, unsigned int n) { return RotateRight((uint64_t) v, n); }

// 32-bit left rotation
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
// outputs:
//   - bit_out: shifted out bit, zero if rotate amount is zero
//   - returns result of left rotation of v
inline uint32_t RotateLeft(uint32_t v, unsigned int n, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	__asm__ ("rol %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (32 - n)) & 1 : 0;
	return n ? (v << n) | (v >> (32 - n)) : v;
#endif
}

// 32-bit right rotation
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
// outputs:
//   - bit_out: shifted out bit, zero if rotate amount is zero
//   - returns result of right rotation of v
inline uint32_t RotateRight(uint32_t v, unsigned int n, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	__asm__ ("ror %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (n - 1)) & 1 : 0;
	return n ? (v >> n) | (v << (32 - n)): v;
#endif
}

// 32-bit left rotation through an extra bit
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
//   - bit_in: shifted in bit
// outputs:
//   - bit_out: shifted out bit, zero if rotate amount is zero
//   - returns result of left rotation of v
inline uint32_t RotateLeft(uint32_t v, unsigned int n, uint8_t bit_in, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	if(bit_in)
	{
		__asm__ ("stc\nrcl %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	}
	else
	{
		__asm__ ("clc\nrcl %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	}
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (32 - n)) & 1 : 0;
	return n ? (uint32_t) (((uint64_t) v << n) | ((uint64_t) bit_in << (n - 1)) | ((uint64_t) v >> (33 - n))) : v;
#endif
}

// 32-bit right rotation through an extra bit
// inputs:
//   - v: 32-bit value to rotate
//   - n: lower 5 bits contains rotate amount
//   - bit_in: shifted in bit
// outputs:
//   - bit_out: shifted out bit, zero if rotate amount is zero
//   - returns result of right rotation of v
inline uint32_t RotateRight(uint32_t v, unsigned int n, uint8_t bit_in, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	if(bit_in)
	{
		__asm__ ("stc\nrcr %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	}
	else
	{
		__asm__ ("clc\nrcr %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	}
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (n - 1)) & 1 : 0;
	return n ? (uint32_t) (((uint64_t) v >> n) | ((uint64_t) bit_in << (32 - n)) | ((uint64_t) v << (33 - n))) : 0;
#endif
}

//=============================================================================
//=                            Logical Shifts                                 =
//=============================================================================

// WARNING! bit_out value is zero when shifting of 0 bits

// 32-bit left shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - returns result of left shift of v
inline uint32_t ShiftLeft(uint32_t v, unsigned int n)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("shl %%cl, %0" : "=r" (v) : "0" (v), "c" (n) : "cc");
	return v;
#else
	n &= 31;
	return v << n;
#endif
}

// 32-bit left shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - bit_out: shifted out bit, zero if shift amount is zero
//   - returns result of left shift of v
inline uint32_t ShiftLeft(uint32_t v, unsigned int n, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	__asm__ ("shl %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b): "0" (v), "c" (n) : "cc");
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (32 - n)) & 1 : 0;
	return v << n;
#endif
}

// 32-bit right shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - returns result of right shift of v
inline uint32_t ShiftRight(uint32_t v, unsigned int n)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("shr %%cl, %0" : "=r" (v) : "0" (v), "c" (n) : "cc");
	return v;
#else
	n &= 31;
	return v >> n;
#endif
}

// 32-bit right shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - bit_out: shifted out bit, zero if shift amount is zero
//   - returns result of right shift of v
inline uint32_t ShiftRight(uint32_t v, unsigned int n, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	__asm__ ("shr %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (n - 1)) & 1 : 0;
	return v >> n;
#endif
}

//=============================================================================
//=                         Arithmetic Shifts                                 =
//=============================================================================

// WARNING! bit_out value is zero when shifting of 0 bits

// 32-bit arithmetic right shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - returns result of arithmetic right shift of v
inline uint32_t ShiftArithmeticRight(uint32_t v, unsigned int n)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("sar %%cl, %0" : "=r" (v) : "0" (v), "c" (n) : "cc");	
	return v;
#else
	n &= 31;
	return (uint32_t)((signed) v >> n);
#endif
}

// 32-bit arithmetic right shift
// inputs:
//   - v: 32-bit value to shift
//   - n: lower 5 bits contains shift amount
// outputs:
//   - bit_out: shifted out bit, zero if shift amount is zero
//   - returns result of arithmetic right shift of v
inline uint32_t ShiftArithmeticRight(uint32_t v, unsigned int n, uint8_t& bit_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	uint8_t b = 0;
	__asm__ ("sar %%cl, %0\nsetc %1" : "=r" (v), "=qQ" (b) : "0" (v), "c" (n) : "cc");
	bit_out = b;
	return v;
#else
	n &= 31;
	bit_out = n ? (v >> (n - 1)) & 1 : 0;
	return (uint32_t)((signed) v >> n);
#endif
}

//=============================================================================
//=                             Bit Scanning                                  =
//=============================================================================

inline bool BitScanForward(unsigned int& n, uint32_t v)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	bool notfound;
	asm("bsf %2, %0\nsetz %1" : "=r" (n), "=qQ" (notfound) : "r" (v) : "cc");
	return !notfound;
#else
	if(!v) return false;

	unsigned int i = 0;
	if(!(v & 1))
	{
		do
		{
			i++;
			v = v >> 1;
		} while(!(v & 1));
	}
	n = i;
	return true;
#endif
}

inline bool BitScanForward(unsigned int& n, uint64_t v)
{
	unsigned int tmp_n;
	if(BitScanForward(tmp_n, (uint32_t) v))
	{
		n = tmp_n;
		return true;
	}
	if(BitScanForward(tmp_n, (uint32_t)(v >> 32)))
	{
		n = tmp_n + 32;
		return true;
	}
	return false;
}

inline bool BitScanReverse(unsigned int& n, uint32_t v)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	bool notfound;
	asm("bsr %2, %0\nsetz %1" : "=r" (n), "=qQ" (notfound) : "r" (v) : "cc");
	return !notfound;
#else
	if(!v) return false;

	unsigned int i = 31;
	if(!(v & 0x80000000))
	{
		do
		{
			i--;
			v = v << 1;
		} while(!(v & 0x80000000));
	}
	n = i;
	return true;
#endif
}

inline bool BitScanReverse(unsigned int& n, uint64_t v)
{
	unsigned int tmp_n;
	if(BitScanReverse(tmp_n, (uint32_t)(v >> 32)))
	{
		n = tmp_n + 32;
		return true;
	}
	if(BitScanReverse(tmp_n, (uint32_t) v))
	{
		n = tmp_n;
		return true;
	}
	return false;
}

#ifdef __GNUC__

inline int BitScanForward(unsigned char n) { return __builtin_ctz(n); }
inline int BitScanForward(unsigned short n) { return __builtin_ctz(n); }
inline int BitScanForward(unsigned n) { return __builtin_ctz(n); }
inline int BitScanForward(unsigned long n) { return __builtin_ctzl(n); }
inline int BitScanForward(unsigned long long n) { return __builtin_ctzll(n); }

inline int BitScanReverse(unsigned char n) { return std::numeric_limits<unsigned>::digits - 1 - __builtin_clz(n); }
inline int BitScanReverse(unsigned short n) { return std::numeric_limits<unsigned>::digits - 1 - __builtin_clz(n); }
inline int BitScanReverse(unsigned n) { return std::numeric_limits<unsigned>::digits - 1 - __builtin_clz(n); }
inline int BitScanReverse(unsigned long n) { return std::numeric_limits<unsigned long>::digits - 1 - __builtin_clzl(n); }
inline int BitScanReverse(unsigned long long n) { return std::numeric_limits<unsigned long long>::digits - 1 - __builtin_clzll(n); }

#else

template <typename INT>
int
BitScanForward_C(INT value)
{
  if (value)
    for (int bit = 0; ; ++bit, value >>= 1)
      if (value & 1)
        return bit;
  
  return -1;
}

template <typename INT>
int
BitScanReverse_C(INT value)
{
  int bsr = -1;
  
  for (int bit = 0; value; ++bit, value >>= 1)
    if (value & 1)
      bsr = bit;
  
  return bsr;
}

inline int BitScanForward(unsigned char n) { return BitScanForward_C(n); }
inline int BitScanForward(unsigned short n) { return BitScanForward_C(n); }
inline int BitScanForward(unsigned n) { return BitScanForward_C(n); }
inline int BitScanForward(unsigned long n) { return BitScanForward_C(n); }
inline int BitScanForward(unsigned long long n) { return BitScanForward_C(n); }

inline int BitScanReverse(unsigned char n) { return BitScanReverse_C(n); }
inline int BitScanReverse(unsigned short n) { return BitScanReverse_C(n); }
inline int BitScanReverse(unsigned n) { return BitScanReverse_C(n); }
inline int BitScanReverse(unsigned long n) { return BitScanReverse_C(n); }
inline int BitScanReverse(unsigned long long n) { return BitScanReverse_C(n); }

#endif

#ifdef __GNUC__

inline int PopCount(unsigned char v) { return __builtin_popcount(v); }
inline int PopCount(unsigned short v) { return __builtin_popcount(v); }
inline int PopCount(unsigned v) { return __builtin_popcount(v); }
inline int PopCount(unsigned long v) { return __builtin_popcountl(v); }
inline int PopCount(unsigned long long v) { return __builtin_popcountll(v); }

#else /* ! __GNUC__ */

int PopCount(uint64_t v)
{
  v = (v & 0xaaaaaaaaaaaaaaaaull) >>  1 + (v & 0x5555555555555555ull);
  v = (v & 0xccccccccccccccccull) >>  2 + (v & 0x3333333333333333ull);
  v = (v & 0xf0f0f0f0f0f0f0f0ull) >>  4 + (v & 0x0f0f0f0f0f0f0f0full);
  v = (v & 0xff00ff00ff00ff00ull) >>  8 + (v & 0x00ff00ff00ff00ffull);
  v = (v & 0xffff0000ffff0000ull) >> 16 + (v & 0x0000ffff0000ffffull);
  v = (v & 0xffffffff00000000ull) >> 32 + (v & 0x00000000ffffffffull);
  
  return int(v);
}
#endif

inline unsigned int CountLeadingZeros(uint32_t v)
{
	unsigned int n;
	return BitScanReverse(n, v) ? 31 - n : 32;
}

inline unsigned int CountLeadingZeros(uint64_t v)
{
	unsigned int n;
	return BitScanReverse(n, v) ? 63 - n : 64;
}

//=============================================================================
//=                              Base 2 Logarithm                             =
//=============================================================================

inline unsigned int Log2(uint32_t v)
{
	unsigned int n;
	return BitScanReverse(n, v) ? n : 0;
}

inline unsigned int Log2(uint64_t v)
{
	unsigned int n;
	return BitScanReverse(n, v) ? n : 0;
}

inline unsigned int CeilLog2(uint32_t v)
{
	unsigned int log2v = Log2(v);
	return (v > (1ULL << log2v)) ? log2v + 1 : log2v;
}

inline unsigned int CeilLog2(uint64_t v)
{
	unsigned int log2v = Log2(v);
	return (v > (1ULL << log2v)) ? log2v + 1 : log2v;
}

//=============================================================================
//=                       2's complement sign Extension                       =
//=============================================================================

inline int8_t SignExtend(uint8_t v, unsigned int n)
{
	unsigned int m = (8 * sizeof(v)) - n;
	// FIXME: this operation is undefined
	return (int8_t) (v << m) >> m; 
}

inline int16_t SignExtend(uint16_t v, unsigned int n)
{
	unsigned int m = (8 * sizeof(v)) - n;
	// FIXME: this operation is undefined
	return (int16_t) (v << m) >> m; 
}

inline int32_t SignExtend(uint32_t v, unsigned int n)
{
	unsigned int m = (8 * sizeof(v)) - n;
	// FIXME: this operation is undefined
	return (int32_t) (v << m) >> m; 
}

inline int64_t SignExtend(uint64_t v, unsigned int n)
{
	unsigned int m = (8 * sizeof(v)) - n;
	// FIXME: this operation is undefined
	return (int64_t) (v << m) >> m; 
}

inline int8_t SignExtend(int8_t v, unsigned int n)
{
	return SignExtend((uint8_t) v, n);
}

inline int16_t SignExtend(int16_t v, unsigned int n)
{
	return SignExtend((uint16_t) v, n);
}

inline int32_t SignExtend(int32_t v, unsigned int n)
{
	return SignExtend((uint32_t) v, n);
}

inline int64_t SignExtend(int64_t v, unsigned int n)
{
	return SignExtend((uint64_t) v, n);
}

//=============================================================================
//=                                  Parity                                   =
//=============================================================================

inline void EvenParity(uint8_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orb %1, %1\nsetp %0\n" : "=qQm" (parity_out) : "qQ" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

inline void EvenParity(uint16_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orw %1, %1\nsetp %0\n" : "=qQm" (parity_out) : "r" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

inline void EvenParity(uint32_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orl %1, %1\nsetp %0\n" : "=qQm" (parity_out) : "r" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

inline void OddParity(uint8_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orb %1, %1\nsetnp %0\n" : "=qQm" (parity_out) : "qQ" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

inline void OddParity(uint16_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orw %1, %1\nsetnp %0\n" : "=qQm" (parity_out) : "r" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

inline void OddParity(uint32_t v, uint8_t& parity_out)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && (defined(__i386) || defined(__x86_64))
	__asm__ ("orl %1, %1\nsetnp %0\n" : "=qQm" (parity_out) : "r" (v) : "cc");
#else
	unsigned int n = 8 * sizeof(v);
	uint8_t par = 0;
	do
	{
		par = par ^ v;
	}
	while(v >>= 1,--n);
	parity_out = par & 1;
#endif
}

} // end of namespace arithmetic
} // end of namespace util
} // end of namespace unisim

#endif
