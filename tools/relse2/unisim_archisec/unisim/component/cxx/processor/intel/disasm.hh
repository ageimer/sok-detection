/*
 *  Copyright (c) 2007-2019,
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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_DISASM_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_DISASM_HH__

#include <unisim/component/cxx/processor/intel/segments.hh>
#include <unisim/component/cxx/processor/intel/tmp.hh>
#include <unisim/component/cxx/processor/intel/types.hh>
#include <limits>
#include <iosfwd>
#include <stdint.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  struct DisasmObject
  {
    virtual void operator() ( std::ostream& sink ) const = 0;
    virtual ~DisasmObject() {};
  };
  
  std::ostream& operator << ( std::ostream& sink, DisasmObject const& dobj );
  
  /* General purpose registers */
  void __DisasmG( GObLH const&, std::ostream& sink, unsigned reg );
  void __DisasmG( GOb const&,   std::ostream& sink, unsigned reg );
  void __DisasmG( GOd const&,   std::ostream& sink, unsigned reg );
  void __DisasmG( GOw const&,   std::ostream& sink, unsigned reg );
  void __DisasmG( GOq const&,   std::ostream& sink, unsigned reg );
  
  template <class OPFACE>
  struct _DisasmG : public DisasmObject
  {
    _DisasmG( unsigned _reg ) : reg( _reg ) {} unsigned reg;
    void operator() ( std::ostream& sink ) const { __DisasmG( OPFACE(), sink, reg ); }
  };
  
  template <class GOP>
  _DisasmG<GOP> DisasmG( GOP const&, unsigned reg ) { return _DisasmG<GOP>( reg ); }
  
  /* SSE/AVX registers */
  void __DisasmV( SSE const&, std::ostream& sink, unsigned reg );
  void __DisasmV( XMM const&, std::ostream& sink, unsigned reg );
  void __DisasmV( YMM const&, std::ostream& sink, unsigned reg );

  template <typename VR>
  struct _DisasmV : public DisasmObject
  {
    _DisasmV( unsigned _reg ) : reg( _reg ) {} unsigned reg;
    void operator() (std::ostream& sink ) const { __DisasmV( VR(), sink, reg ); }
  };
  
  template <typename VR>
  _DisasmV<VR> DisasmV( VR const&, unsigned reg ) { return _DisasmV<VR>( reg ); }
  
  /* MMX registers*/
  struct DisasmPq : public DisasmObject
  {
    DisasmPq( unsigned _reg ) : reg( _reg ) {} unsigned reg;
    void operator() ( std::ostream& sink ) const;
  };

  /* Debug registers */
  struct DisasmDd : public DisasmObject
  {
    DisasmDd( unsigned _reg ) : reg( _reg ) {} unsigned reg;
    void operator() ( std::ostream& sink ) const;
  };
  /* Control registers */
  struct DisasmCd : public DisasmObject
  {
    DisasmCd( unsigned _reg ) : reg( _reg ) {} unsigned reg;
    void operator() ( std::ostream& sink ) const;
  };

  /* Segments */
  struct DisasmS : public DisasmObject
  {
    DisasmS( unsigned _seg ) : segment( _seg ) {} unsigned segment;
    void operator () ( std::ostream& sink ) const;
  };
  struct DisasmMS : public DisasmObject
  {
    DisasmMS( unsigned _seg ) : segment( _seg ) {} unsigned segment;
    void operator () ( std::ostream& sink ) const;
  };
  
  template <class ARCH> struct RMOp;
  
  template <class ARCH, class REGDIS>
  struct DisasmRegOrMem : public DisasmObject
  {
    DisasmRegOrMem( RMOp<ARCH> const& _rmop ) : rmop( _rmop ) {}

    
    void operator() ( std::ostream& sink ) const
    {
      typedef REGDIS DisasmReg;
      
      if (rmop.ismem())   rmop->disasm_memory_operand( sink );
      else                            sink << DisasmReg( rmop.ereg() );
    }
    
    RMOp<ARCH> const& rmop;    
  };

  typedef _DisasmG<GObLH> DisasmGb;
  typedef _DisasmG<GOw>   DisasmGw;
  typedef _DisasmG<GOd>   DisasmGd;
  typedef _DisasmG<GOq>   DisasmGq;
  
  template <class ARCH>
  DisasmRegOrMem<ARCH,DisasmGb>  DisasmEb( RMOp<ARCH> const& rmop ) { return DisasmRegOrMem<ARCH,DisasmGb>( rmop ); }
  
  template <class ARCH>
  DisasmRegOrMem<ARCH,DisasmGw>  DisasmEw( RMOp<ARCH> const& rmop ) { return DisasmRegOrMem<ARCH,DisasmGw>( rmop ); }

  template <class ARCH>
  DisasmRegOrMem<ARCH,DisasmGd>  DisasmEd( RMOp<ARCH> const& rmop ) { return DisasmRegOrMem<ARCH,DisasmGd>( rmop ); }
  
  template <class ARCH, class OPFACE>
  DisasmRegOrMem< ARCH, _DisasmG<OPFACE> > DisasmE( OPFACE const&, RMOp<ARCH> const& rmop ) { return DisasmRegOrMem< ARCH, _DisasmG<OPFACE> >( rmop ); }
  
  template  <class ARCH, class VR>
  DisasmRegOrMem< ARCH, _DisasmV<VR> > DisasmW( VR const&, RMOp<ARCH> const& rmop ) { return DisasmRegOrMem< ARCH, _DisasmV<VR> >( rmop ); }
  
  template <class ARCH>
  DisasmRegOrMem<ARCH,DisasmPq>  DisasmQq( RMOp<ARCH> const& rmop ) { return DisasmRegOrMem<ARCH,DisasmPq>( rmop ); }
  
  struct DisasmBadReg : public DisasmObject
  {
    DisasmBadReg( unsigned _reg ) {}
    void operator() ( std::ostream& sink ) const;
  };
  
  template <class ARCH>
  DisasmRegOrMem<ARCH,DisasmBadReg> DisasmM( RMOp<ARCH> const& rmop ) { return DisasmRegOrMem<ARCH,DisasmBadReg>( rmop ); }
  
  void PutString( std::ostream& sink, char const* string );
  void PutChar( std::ostream& sink, char chr );
  template <typename T>
  void PutHex( std::ostream& sink, T value )
  {
    uintptr_t const bcnt = sizeof(T);
    char buf[4+2*bcnt];
    char* ptr = &buf[sizeof(buf)];
    *--ptr = '\0';
    for (uintptr_t idx = 0; idx < 2*sizeof (T); idx++) {
      *--ptr = "0123456789abcdef"[value&0xf];
      value >>= 4;
      if (not value) break;
    }
    *--ptr = 'x';
    *--ptr = '0';
    PutString( sink, ptr );
  }
  /* Immediate disassembly */
  template <typename T>
  struct DisasmHex : public DisasmObject
  {
    DisasmHex( T _value ) : value( _value ) {} T value;
    
    void operator () ( std::ostream& sink ) const
    {
      typename meta::__unsigned<T>::type uv = value;
      if (std::numeric_limits<T>::is_signed and value < T(0))
        { PutChar(sink, '-'); uv = -value; }
      PutHex( sink, uv );
    }
  };
  
  template <typename T>
  struct DisasmImm : public DisasmObject
  {
    DisasmImm( T _value ) : value( _value ) {} T value;
    void operator () (std::ostream& sink) const
    {
      PutChar( sink, '$' );
      PutHex( sink, value );
    }
  };

  template <typename T> DisasmHex<T> DisasmX( T imm ) { return DisasmHex<T>( imm ); }
  template <typename T> DisasmImm<T> DisasmI( T imm ) { return DisasmImm<T>( imm ) ; }
  
  struct DisasmCond : public DisasmObject
  {
    DisasmCond( unsigned _cond ) : cond( _cond ) {} unsigned cond;
    
    void operator() ( std::ostream& _sink ) const
    {
      static char const* conds[] = {"o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"};
      PutString( _sink, (cond & -16) ? "?" : conds[cond] );
    }
    
  };

  template <unsigned OPSIZE> struct SizeID {};
  template <> struct SizeID<  8> { static char const* gid() { return "b"; }  static char const* iid() { return "b"; } };
  template <> struct SizeID< 16> { static char const* gid() { return "w"; }  static char const* iid() { return "w"; } };
  template <> struct SizeID< 32> { static char const* gid() { return "l"; }  static char const* iid() { return "d"; } static char const* fid() { return "s"; } };
  template <> struct SizeID< 64> { static char const* gid() { return "q"; }  static char const* iid() { return "q"; } static char const* fid() { return "d"; } };
  template <> struct SizeID<128> { static char const* gid() { return "dq"; } static char const* iid() { return "dq"; } };
  
  struct DisasmMnemonic : public DisasmObject
  {
    DisasmMnemonic( char const* _mnemonic, unsigned _opsize ) : mnemonic( _mnemonic ), opsize(_opsize) {}
    char const* mnemonic;
    unsigned opsize;
    
    void operator() ( std::ostream& _sink ) const;
  };
  
  struct DisasmSize : public DisasmObject
  {
    DisasmSize(unsigned _opsize, char _style) : opsize(_opsize), style(_style) {}
    unsigned opsize;
    char style;
    
    void operator() ( std::ostream& _sink ) const;
  };
  
  struct DisasmFPR : public DisasmObject
  {
    DisasmFPR( uint8_t _reg ) : reg( _reg ) {} uint8_t reg;
    
    void operator() ( std::ostream& _sink ) const;
  };
  
  struct DisasmBytes : public DisasmObject
  {
    DisasmBytes( uint8_t const* _bytes, unsigned _length ) : bytes( _bytes ), length( _length ) {} uint8_t const* bytes; unsigned length;
    
    void operator() ( std::ostream& _sink ) const;
  };

} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_DISASM_HH__
