/*
 *  Copyright (c) 2007-2016,
 *  Commissariat a l'Energie Atomique (CEA)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *   - Neither the name of CEA nor the names of its contributors may be used to
 *     endorse or promote products derived from this software without specific
 *     prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXTENSION_REGISTER_BANK_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXTENSION_REGISTER_BANK_HH__

#include <stdexcept>
#include <cstring>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

  template <typename T>
  struct ExtTypeInfo
  {
    enum { bytecount = sizeof (T) };
    static void ToBytes( uint8_t* dst, T src )
    {
      for (unsigned idx = 0; idx < sizeof (T); ++idx)
        { dst[idx] = src & 0xff; src >>= 8; }
    }
    static void FromBytes( T& dst, uint8_t const* src )
    {
      T tmp = 0;
      for (unsigned idx = sizeof (T); idx-- > 0;)
        { tmp <<= 8; tmp |= uint32_t( src[idx] ); }
      dst = tmp;
    }
  };

  template <> struct ExtTypeInfo<float>
  {
    enum bytecount_t { bytecount = 4 };
    static void ToBytes( uint8_t* dst, float const& src ) { ExtTypeInfo<uint32_t>::ToBytes( dst, reinterpret_cast<uint32_t const&>( src ) ); }
    static void FromBytes( float& dst, uint8_t const* src ) { ExtTypeInfo<uint32_t>::FromBytes( reinterpret_cast<uint32_t&>( dst ), src ); }
  };

  template <> struct ExtTypeInfo<double>
  {
    enum bytecount_t { bytecount = 8 };
    static void ToBytes( uint8_t* dst, double const& src ) { ExtTypeInfo<uint64_t>::ToBytes( dst, reinterpret_cast<uint64_t const&>( src ) ); }
    static void FromBytes( double& dst, uint8_t const* src ) { ExtTypeInfo<uint64_t>::FromBytes( reinterpret_cast<uint64_t&>( dst ), src ); }
  };
  
  enum ecstate_t { invalid = 0, valid = 1, exclusive = 3 };

  struct Invalidate
  {
    unsigned start, size, bufsize;
    uint8_t  buffer[16];
  
    Invalidate( unsigned idx, unsigned _size ) : start( idx*_size ), size( _size ), bufsize( 0 ) {}
  };

  struct Copy
  {
    unsigned start, size, mask;
    uint8_t* buffer;
  
    template <unsigned sizeT>
    Copy( unsigned idx, uint8_t (&_buffer) [sizeT] ) : start( idx*sizeT ), size( sizeT ), mask( 0 ), buffer( &_buffer[0] ) {}
  };

  template <typename valT, unsigned countT>
  struct ExtRegCache
  {
    valT        regs[countT];
    uint8_t     state[countT];
  
    ExtRegCache() { for (unsigned idx = 0; idx < countT; ++idx) state[idx] = invalid; }
  
    enum regsize_t { regsize = ExtTypeInfo<valT>::bytecount };
  
    void Do( Invalidate& inval )
    {
      if (inval.start % inval.size) throw std::logic_error("Misaligned extended register manipulation");
      unsigned idx = inval.start / regsize;
      if (idx >= countT) return;
      if (inval.size >= regsize)
        {
          if (inval.size % regsize) throw std::logic_error("Misaligned extended register manipulation");
          unsigned end = idx + (inval.size / regsize);
          if (end > countT) throw std::logic_error("Misaligned extended register manipulation");
          while (idx < end) { state[idx] = invalid; ++idx; }
        }
      else
        {
          if (regsize % inval.size) throw std::logic_error("Misaligned extended register manipulation");
          if (state[idx] == invalid) return;
          state[idx] = invalid;
          if (inval.bufsize >= regsize) return;
          inval.bufsize = regsize;
          ExtTypeInfo<valT>::ToBytes( &inval.buffer[0], regs[idx] );
        }
    }
  
    void Do( Copy& copy )
    {
      if (copy.start % copy.size) throw std::logic_error("Misaligned extended register manipulation");
      unsigned idx = copy.start / regsize;
      if (idx >= countT) return;
      if (copy.size == regsize)
        {
          if (state[idx] == invalid) return;
          state[idx] = valid;
          if (not copy.buffer) return;
          ExtTypeInfo<valT>::ToBytes( copy.buffer, regs[idx] );
          copy.buffer = 0;
        }
      else if (copy.size > regsize)
        {
          if (copy.size % regsize) throw std::logic_error("Misaligned extended register manipulation");
          unsigned end = idx + (copy.size / regsize);
          if (end > countT) throw std::logic_error("Misaligned extended register manipulation");
          unsigned mask = ((1 << regsize) - 1);
          for (uint8_t* ptr = copy.buffer; idx < end; ++idx, ptr += regsize, mask <<= regsize) {
            if (state[idx] == invalid) continue;
            state[idx] = valid;
            if (not copy.buffer) continue;
            ExtTypeInfo<valT>::ToBytes( ptr, regs[idx] );
            copy.mask |= mask;
          }
          if (copy.mask == unsigned((1 << copy.size)-1)) copy.buffer = 0;
        }
      else
        {
          if (regsize % copy.size) throw std::logic_error("Misaligned extended register manipulation");
          if (state[idx] == invalid) return;
          state[idx] = valid;
          if (not copy.buffer) return;
          uint8_t buffer[regsize];
          ExtTypeInfo<valT>::ToBytes( &buffer[0], regs[idx] );
          std::memcpy( copy.buffer, &buffer[copy.start%regsize], copy.size );
          copy.buffer = 0;
        }
    }
  
    template <typename dirT>
    valT const&
    GetReg( dirT& dir, unsigned idx )
    {
      // Force validity
      if (state[idx] == invalid) {
        uint8_t buffer[regsize];
        Copy copy( idx, buffer );
        dir.DoAll( copy );
        state[idx] = valid;
        ExtTypeInfo<valT>::FromBytes( regs[idx], &buffer[0] );
      }
      return regs[idx];
    }
  
    template <typename dirT>
    void
    SetReg( dirT& dir, unsigned idx, valT const& value )
    {
      // Force exclusivity
      if (state[idx] != exclusive) {
        Invalidate invalidate( idx, regsize );
        dir.DoAll( invalidate );
        if (invalidate.bufsize) {
          for (unsigned count = invalidate.bufsize / regsize, vidx = idx & ~(count - 1), end = vidx + count; vidx < end; ++vidx) {
            if (state[vidx] != invalid) continue;
            ExtTypeInfo<valT>::FromBytes( regs[vidx], &invalidate.buffer[vidx*regsize] );
            state[vidx] = valid;
          }
        }
        state[idx] = exclusive;
      }
      regs[idx] = value;
    }
  };

} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXTENSION_REGISTER_BANK_HH__ */
