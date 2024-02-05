/*
 *  Copyright (c) 2013-2016,
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
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_REGISTER_FIELD_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_REGISTER_FIELD_HH__

#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {
  
  /** RegisterField
   *
   * This structure allows to declare names referring to bitfields of
   * status/control ARM registers (e.g. PSR, FPSCR). It is implemented
   * as a templated Traits structure that contains the position and
   * size of the bitfield. It also contains convenience methods for
   * getting/setting bitfield values in registers values (provided
   * this values behave like scalar integers)
   */
  template <unsigned posT, unsigned sizeT>
  struct RegisterField
  {
    enum pos_e { pos = posT };
    enum size_e { size = sizeT };
    
    template <typename T>
    T getmask() const { return ((T(2) << int(size-1))-T(1)) << int(pos); }
    
    template <typename T>
    T Get( T const& reg ) const
    {
      return (reg & getmask<T>()) >> int(pos);
    }
    template <typename T>
    T Mask( T const& reg ) const
    {
      return reg & getmask<T>();
    }
    template <typename T, typename R>
    void Set( T& reg, R const& value ) const
    {
      T const mask = getmask<T>();
      reg = (reg & ~mask) | ((T(value) << int(pos)) & mask);
    }
    // template <typename T>
    // T Set( T const& value ) const
    // {
    //   T const mask = getmask<T>();
    //   return (value << int(pos)) & mask;
    // }
    // template <typename T>
    // T Insert( T const& reg, T const& value ) const
    // {
    //   T const mask = getmask<T>();
    //   return (reg & ~mask) | ((value << int(pos)) & mask);
    // }
    template <typename T>
    T Swap( T& reg, T const& value ) const
    {
      T const mask = getmask<T>();
      T res = (reg & mask) >> int(pos);
      reg = (reg & ~mask) | ((value << int(pos)) & mask);
      return res;
    }
  };
  
  /* Common bitfields */
  RegisterField<0,32> const ALL32;  /* Raw 32 bits of the any status/control register*/
  RegisterField<0,64> const ALL64;  /* Raw 64 bits of the any status/control register*/
  
  template <typename T>
  struct FieldRegister
  {
    T m_value;
    
    FieldRegister() : m_value() {}
    FieldRegister( T _value ) : m_value( _value ) {}
    
    template <typename RF>
    T Get( RF const& rf ) const { return rf.Get( m_value ); }
    template <typename RF>
    void     Set( RF const& rf, T value ) { return rf.Set( m_value, value ); }
    
    /* Raw bits accessor */
    T& bits() { return m_value; }
  };
  

} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_REGISTER_FIELD_HH__ */
