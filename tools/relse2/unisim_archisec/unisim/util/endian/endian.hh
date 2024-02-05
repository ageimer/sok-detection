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
 */
 
#ifndef __UNISIM_UTIL_ENDIAN_ENDIAN_HH__
#define __UNISIM_UTIL_ENDIAN_ENDIAN_HH__

#include <iostream>
#include <inttypes.h>
#include <string.h>

#if defined(__APPLE_CC__)
#include <sys/types.h>
#else
#include <sys/param.h>
#endif

#if !defined(BYTE_ORDER)
#if defined(__BYTE_ORDER)
#define BYTE_ORDER __BYTE_ORDER
#elif defined(__BYTE_ORDER__)
#define BYTE_ORDER __BYTE_ORDER__
#else
#error "Unknown host byte order"
#endif
#endif

#if !defined(LITTLE_ENDIAN)
#if defined(__LITTLE_ENDIAN)
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#elif defined(__LITTLE_ENDIAN__)
#define LITTLE_ENDIAN __LITTLE_ENDIAN__
#else
#error "Unknown host byte order"
#endif
#endif

#if !defined(BIG_ENDIAN)
#if defined(__BIG_ENDIAN)
#define BIG_ENDIAN __BIG_ENDIAN
#elif defined(__BIG_ENDIAN__)
#define BIG_ENDIAN __BIG_ENDIAN__
#else
#error "Unknown host byte order"
#endif
#endif

#include <unisim/util/inlining/inlining.hh>

namespace unisim {
namespace util {
namespace endian {

typedef enum
{
	E_BIG_ENDIAN = 0,
	E_LITTLE_ENDIAN = 1,
	E_UNKNOWN_ENDIAN = 2
} endian_type;

inline bool IsHostLittleEndian() ALWAYS_INLINE;
inline bool IsHostBigEndian() ALWAYS_INLINE;
inline endian_type GetHostEndian() ALWAYS_INLINE;

inline void BSwap(uint8_t& value) ALWAYS_INLINE;
inline void BSwap(uint16_t& value) ALWAYS_INLINE;
inline void BSwap(uint8_t value[3]) ALWAYS_INLINE;
inline void BSwap(uint32_t& value) ALWAYS_INLINE;
inline void BSwap(uint64_t& value) ALWAYS_INLINE;

inline uint8_t ByteSwap(uint8_t value) ALWAYS_INLINE;
inline uint16_t ByteSwap(uint16_t value) ALWAYS_INLINE;
inline uint32_t ByteSwap(uint32_t value) ALWAYS_INLINE;
inline uint64_t ByteSwap(uint64_t value) ALWAYS_INLINE;

inline uint8_t Host2BigEndian(uint8_t value) ALWAYS_INLINE;
inline uint8_t BigEndian2Host(uint8_t value) ALWAYS_INLINE;
inline uint8_t Host2LittleEndian(uint8_t value) ALWAYS_INLINE;
inline uint8_t LittleEndian2Host(uint8_t value) ALWAYS_INLINE;
inline uint16_t Host2BigEndian(uint16_t value) ALWAYS_INLINE;
inline uint16_t BigEndian2Host(uint16_t value) ALWAYS_INLINE;
inline uint16_t Host2LittleEndian(uint16_t value) ALWAYS_INLINE;
inline uint16_t LittleEndian2Host(uint16_t value) ALWAYS_INLINE;
inline uint32_t Host2BigEndian(uint32_t value) ALWAYS_INLINE;
inline uint32_t BigEndian2Host(uint32_t value) ALWAYS_INLINE;
inline uint32_t Host2LittleEndian(uint32_t value) ALWAYS_INLINE;
inline uint32_t LittleEndian2Host(uint32_t value) ALWAYS_INLINE;
inline uint64_t Host2BigEndian(uint64_t value) ALWAYS_INLINE;
inline uint64_t BigEndian2Host(uint64_t value) ALWAYS_INLINE;
inline uint64_t Host2LittleEndian(uint64_t value) ALWAYS_INLINE;
inline uint64_t LittleEndian2Host(uint64_t value) ALWAYS_INLINE;

inline int8_t Host2BigEndian(int8_t value) ALWAYS_INLINE;
inline int8_t BigEndian2Host(int8_t value) ALWAYS_INLINE;
inline int8_t Host2LittleEndian(int8_t value) ALWAYS_INLINE;
inline int8_t LittleEndian2Host(int8_t value) ALWAYS_INLINE;
inline int16_t Host2BigEndian(int16_t value) ALWAYS_INLINE;
inline int16_t BigEndian2Host(int16_t value) ALWAYS_INLINE;
inline int16_t Host2LittleEndian(int16_t value) ALWAYS_INLINE;
inline int16_t LittleEndian2Host(int16_t value) ALWAYS_INLINE;
inline int32_t Host2BigEndian(int32_t value) ALWAYS_INLINE;
inline int32_t BigEndian2Host(int32_t value) ALWAYS_INLINE;
inline int32_t Host2LittleEndian(int32_t value) ALWAYS_INLINE;
inline int32_t LittleEndian2Host(int32_t value) ALWAYS_INLINE;
inline int64_t Host2BigEndian(int64_t value) ALWAYS_INLINE;
inline int64_t BigEndian2Host(int64_t value) ALWAYS_INLINE;
inline int64_t Host2LittleEndian(int64_t value) ALWAYS_INLINE;
inline int64_t LittleEndian2Host(int64_t value) ALWAYS_INLINE;

inline uint8_t Host2Target(endian_type target_endian, uint8_t value) ALWAYS_INLINE;
inline uint16_t Host2Target(endian_type target_endian, uint16_t value) ALWAYS_INLINE;
inline uint32_t Host2Target(endian_type target_endian, uint32_t value) ALWAYS_INLINE;
inline uint64_t Host2Target(endian_type target_endian, uint64_t value) ALWAYS_INLINE;

inline uint8_t Target2Host(endian_type target_endian, uint8_t value) ALWAYS_INLINE;
inline uint16_t Target2Host(endian_type target_endian, uint16_t value) ALWAYS_INLINE;
inline uint32_t Target2Host(endian_type target_endian, uint32_t value) ALWAYS_INLINE;
inline uint64_t Target2Host(endian_type target_endian, uint64_t value) ALWAYS_INLINE;

inline int8_t Host2Target(endian_type target_endian, int8_t value) ALWAYS_INLINE;
inline int16_t Host2Target(endian_type target_endian, int16_t value) ALWAYS_INLINE;
inline int32_t Host2Target(endian_type target_endian, int32_t value) ALWAYS_INLINE;
inline int64_t Host2Target(endian_type target_endian, int64_t value) ALWAYS_INLINE;

inline int8_t Target2Host(endian_type target_endian, int8_t value) ALWAYS_INLINE;
inline int16_t Target2Host(endian_type target_endian, int16_t value) ALWAYS_INLINE;
inline int32_t Target2Host(endian_type target_endian, int32_t value) ALWAYS_INLINE;
inline int64_t Target2Host(endian_type target_endian, int64_t value) ALWAYS_INLINE;

inline bool IsHostLittleEndian()
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return true;
#else
	return false;
#endif
}

inline bool IsHostBigEndian()
{
#if BYTE_ORDER == BIG_ENDIAN
	return true;
#else
	return false;
#endif
}

inline endian_type GetHostEndian()
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return E_LITTLE_ENDIAN;
#else
	return E_BIG_ENDIAN;
#endif
}

inline void BSwap(uint8_t& value)
{
}
	
inline void BSwap(uint16_t& value)
{
#ifdef __GNUC__
	value = __builtin_bswap16(value);
#else
	value = (value >> 8) | (value << 8);
#endif
}

inline void BSwap(uint8_t value[3])
{
	uint8_t tmp = value[0];
	value[0] = value[1];
	value[1] = tmp;
}

inline void BSwap(uint32_t& value)
{
#ifdef __GNUC__
	value = __builtin_bswap32(value);
#else
	value = (value >> 24) | ((value >> 8) & 0x0000ff00UL) | ((value << 8) & 0x00ff0000UL) | (value << 24);
#endif
}

inline void BSwap(uint64_t& value)
{
#ifdef __GNUC__
	value = __builtin_bswap64(value);
#else
	value = (value >> 56) | ((value & 0x00ff000000000000ULL) >> 40) |
	        ((value & 0x0000ff0000000000ULL) >> 24) | ((value & 0x000000ff00000000ULL) >> 8) |
	        ((value & 0x00000000ff000000ULL) << 8) | ((value & 0x0000000000ff0000ULL) << 24) |
	        ((value & 0x000000000000ff00ULL) << 40) | ((value << 56));
#endif
}

inline void BSwap(uint32_t *buffer, uint32_t count)
{
	if(count)
	{
		do
		{
			BSwap(*buffer++);
		} while(--count);
	}
}

inline uint8_t ByteSwap(uint8_t value)
{
	BSwap(value);
	return value;
}

inline uint16_t ByteSwap(uint16_t value)
{
	BSwap(value);
	return value;
}

inline uint32_t ByteSwap(uint32_t value)
{
	BSwap(value);
	return value;
}

inline uint64_t ByteSwap(uint64_t value)
{
	BSwap(value);
	return value;
}

inline uint8_t Host2BigEndian(uint8_t value)
{
	return value;
}

inline uint8_t BigEndian2Host(uint8_t value)
{
	return value;
}

inline uint8_t Host2LittleEndian(uint8_t value)
{
	return value;
}

inline uint8_t LittleEndian2Host(uint8_t value)
{
	return value;
}

inline uint16_t Host2BigEndian(uint16_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint16_t BigEndian2Host(uint16_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint16_t Host2LittleEndian(uint16_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint16_t LittleEndian2Host(uint16_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint32_t Host2BigEndian(uint32_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint32_t BigEndian2Host(uint32_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint32_t Host2LittleEndian(uint32_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint32_t LittleEndian2Host(uint32_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint64_t Host2BigEndian(uint64_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint64_t BigEndian2Host(uint64_t value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint64_t Host2LittleEndian(uint64_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline uint64_t LittleEndian2Host(uint64_t value)
{
#if BYTE_ORDER == BIG_ENDIAN
	BSwap(value);
#endif
	return value;
}

inline int8_t Host2BigEndian(int8_t value) { return Host2BigEndian((uint8_t) value); }
inline int8_t BigEndian2Host(int8_t value) { return BigEndian2Host((uint8_t) value); }
inline int8_t Host2LittleEndian(int8_t value) { return Host2LittleEndian((uint8_t) value); }
inline int8_t LittleEndian2Host(int8_t value) { return LittleEndian2Host((uint8_t) value); }

inline int16_t Host2BigEndian(int16_t value) { return Host2BigEndian((uint16_t) value); }
inline int16_t BigEndian2Host(int16_t value) { return BigEndian2Host((uint16_t) value); }
inline int16_t Host2LittleEndian(int16_t value) { return Host2LittleEndian((uint16_t) value); }
inline int16_t LittleEndian2Host(int16_t value) { return LittleEndian2Host((uint16_t) value); }

inline int32_t Host2BigEndian(int32_t value) { return Host2BigEndian((uint32_t) value); }
inline int32_t BigEndian2Host(int32_t value) { return BigEndian2Host((uint32_t) value); }
inline int32_t Host2LittleEndian(int32_t value) { return Host2LittleEndian((uint32_t) value); }
inline int32_t LittleEndian2Host(int32_t value) { return LittleEndian2Host((uint32_t) value); }

inline int64_t Host2BigEndian(int64_t value) { return Host2BigEndian((uint64_t) value); }
inline int64_t BigEndian2Host(int64_t value) { return BigEndian2Host((uint64_t) value); }
inline int64_t Host2LittleEndian(int64_t value) { return Host2LittleEndian((uint64_t) value); }
inline int64_t LittleEndian2Host(int64_t value) { return LittleEndian2Host((uint64_t) value); }

inline uint8_t Host2Target(endian_type target_endian, uint8_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? Host2BigEndian(value) : Host2LittleEndian(value);
}

inline uint16_t Host2Target(endian_type target_endian, uint16_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? Host2BigEndian(value) : Host2LittleEndian(value);
}

inline uint32_t Host2Target(endian_type target_endian, uint32_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? Host2BigEndian(value) : Host2LittleEndian(value);
}

inline uint64_t Host2Target(endian_type target_endian, uint64_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? Host2BigEndian(value) : Host2LittleEndian(value);
}

inline uint8_t Target2Host(endian_type target_endian, uint8_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? BigEndian2Host(value) : LittleEndian2Host(value);
}

inline uint16_t Target2Host(endian_type target_endian, uint16_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? BigEndian2Host(value) : LittleEndian2Host(value);
}

inline uint32_t Target2Host(endian_type target_endian, uint32_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? BigEndian2Host(value) : LittleEndian2Host(value);
}

inline uint64_t Target2Host(endian_type target_endian, uint64_t value)
{
	return (target_endian == E_BIG_ENDIAN) ? BigEndian2Host(value) : LittleEndian2Host(value);
}

inline int8_t Host2Target(endian_type target_endian, int8_t value) { return Host2Target(target_endian, (uint8_t) value); }
inline int16_t Host2Target(endian_type target_endian, int16_t value) { return Host2Target(target_endian, (uint16_t) value); }
inline int32_t Host2Target(endian_type target_endian, int32_t value) { return Host2Target(target_endian, (uint32_t) value); }
inline int64_t Host2Target(endian_type target_endian, int64_t value) { return Host2Target(target_endian, (uint64_t) value); }

inline int8_t Target2Host(endian_type target_endian, int8_t value) { return Host2Target(target_endian, (uint8_t) value); }
inline int16_t Target2Host(endian_type target_endian, int16_t value) { return Host2Target(target_endian, (uint16_t) value); }
inline int32_t Target2Host(endian_type target_endian, int32_t value) { return Host2Target(target_endian, (uint32_t) value); }
inline int64_t Target2Host(endian_type target_endian, int64_t value) { return Host2Target(target_endian, (uint64_t) value); }

inline void BigEndian2Host(uint16_t *dst, uint16_t *src, uint32_t count)
{
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(dst, src, sizeof(uint16_t) * count);
#else
	if(count)
	{
		do
		{
			*dst++ = BigEndian2Host(*src++);
		} while(--count);
	}
#endif
}

inline void BigEndian2Host(uint32_t *dst, uint32_t *src, uint32_t count)
{
#if BYTE_ORDER == BIG_ENDIAN
	memcpy(dst, src, sizeof(uint32_t) * count);
#else
	if(count)
	{
		do
		{
			*dst++ = BigEndian2Host(*src++);
		} while(--count);
	}
#endif
}

inline void LittleEndian2Host(uint16_t *dst, uint16_t *src, uint32_t count)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	memcpy(dst, src, sizeof(uint16_t) * count);
#else
	if(count)
	{
		do
		{
			*dst++ = LittleEndian2Host(*src++);
		} while(--count);
	}
#endif
}

inline void LittleEndian2Host(uint32_t *dst, uint32_t *src, uint32_t count)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	memcpy(dst, src, sizeof(uint32_t) * count);
#else
	if(count)
	{
		do
		{
			*dst++ = LittleEndian2Host(*src++);
		} while(--count);
	}
#endif
}

inline void Target2Host(endian_type target_endian, uint16_t *dst, uint16_t *src, uint32_t count)
{
	if(target_endian == E_BIG_ENDIAN)
		BigEndian2Host(dst, src, count);
	else
		LittleEndian2Host(dst, src, count);
}

inline void Target2Host(endian_type target_endian, uint32_t *dst, uint32_t *src, uint32_t count)
{
	if(target_endian == E_BIG_ENDIAN)
		BigEndian2Host(dst, src, count);
	else
		LittleEndian2Host(dst, src, count);
}

inline std::ostream& operator << (std::ostream& os, const endian_type& endian)
{
	switch(endian)
	{
		case E_BIG_ENDIAN    : os << "big-endian"; break;
		case E_LITTLE_ENDIAN : os << "little-endian"; break;
		case E_UNKNOWN_ENDIAN:
		default              : os << "unknown-endian"; break;
	}
	
	return os;
}

} // end of namespace endian
} // end of namespace util
} // end of namespace unisim

	
#endif
