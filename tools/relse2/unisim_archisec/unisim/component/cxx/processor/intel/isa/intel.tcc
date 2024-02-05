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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_TCC__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_TCC__

#include <unisim/component/cxx/processor/intel/isa/intel.hh>
#include <unisim/component/cxx/processor/intel/modrm.hh>
#include <unisim/component/cxx/processor/intel/execute.hh>
#include <unisim/component/cxx/processor/intel/math.hh>
#include <unisim/component/cxx/processor/intel/types.hh>
#include <unisim/component/cxx/processor/intel/tmp.hh>

#include <iostream>
#include <typeinfo>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  /* Instruction classes. Classes are ordered by precedence: last will
   * be prefered if multiple match. */
  enum operation_t { CALL = 0, JCC, LOOP, JMP, RETURN, INTRETURN, INTERRUPT, SYSCALL, ENTER_LEAVE,
                     ADD, OR, ADC, SBB, AND, SUB, XOR, CMP, ROL, ROR, RCL, RCR, SHL, SHR, SAR,
                     TEST, NOT, NEG, DIV, IDIV, MUL, IMUL, LEA, INCDEC, SETCC, SHD, ZCNT, POPCNT, BZHI,
                     CMC, AHF, CSX, XLAT, ADJUST, BOUND, ADF,
                     FWAIT, F2XM1, FABS, FADD, FBLD, FBSTP, FCHS, FCLEX, FCMOV, FCOM, FCOMI,
                     FINCDECSTP, FDIV, FDIVR, FFREE, FICOM, FILD, FINIT, FIST, FISTTP,
                     FLD, FLDCONST, FLSCW, FLSENV, FMUL, FNOP, FPREM, FRNDINT, FSCALE, FMATH,
                     FLSSTATE, FST, FSTSW, FSUB, FSUBR, FTST, FUCOM, FXAM, FXCH, FOBSOLETE,
                     PUSH, POP, MOV, MOVZX, MOVSX, STD, ARPL, CMPXCHG,
                     CMPXCHG8B, XCHG, XADD, HINT, NOP, CMOVCC, BT, BTC, BTR, BTS, BSWAP, MOVNTI, LFP,
                     MOVS, STOS, CMPS, SCAS, LODS, OUTS, INS, CPUID, RDTSC, XBV, CVT, HLT, FENCE,
                     PUNPCK, PBM, MOVGV, MOVDQ, MOVFP, MOVFPC, PCMPEQ, PALIGNR, VBINARY, VFPUNARY,
                     PMOVMSKB, VMOVSD, VMOVZX, MXCSR, UCOMIS, PREFETCH, VFPCVT, PMINMAX, PMULUDQ,
                     VSHIMM, MOVQ, BROADCAST, EXTRACT, INSERT, PACK_S, PSHUFD, PSHUFB, PSHIFT,
                     PSHDQ, PTEST, PINSR, PCMPSTR, VFPCMP, SHUFP, VZEROUPPER, XSAVE,
                     operation_count };

  template <class ARCH>
  void
  Operation<ARCH>::execute( ARCH& arch ) const
  {
    arch.noexec( *this );
  };
  
  
  template <typename INT>
  struct ImmValue { int index; INT value; ImmValue( int idx ) : index( idx ), value() {} };
  
  template <typename LEFT, typename RIGHT>
  struct AndSeq
  {
    typedef AndSeq<LEFT,RIGHT> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    LEFT left;
    RIGHT right;
    
    AndSeq( LEFT const& _left, RIGHT const& _right ) : left( _left ), right( _right ) {}
    
    template <typename PROPERTY>
    uint8_t const* get( PROPERTY& out, uint8_t const* bytes )
    {
      if ((bytes = left.get( out, bytes )))
        bytes = right.get( out, bytes );
      return bytes;
    }
  };

  template <unsigned SIZE>
  struct OpSize
  {
    typedef OpSize<SIZE> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& value, uint8_t const* bytes ) { return bytes; }
    
    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes ) { return (cb.opsize() != SIZE) ? 0 : bytes; }
  };
  
  template <uint8_t _66, uint8_t REP>
  struct SSE_PFX
  {
    typedef SSE_PFX<_66, REP> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }

    template <typename PROPERTY> uint8_t const* get( PROPERTY& value, uint8_t const* bytes ) { return bytes; }

    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes ) { return (cb.opsz_66 == _66) and (cb.rep == REP) ? bytes : 0; }
  };

  typedef SSE_PFX<0,2> simdF2;
  typedef SSE_PFX<0,3> simdF3;
  typedef SSE_PFX<1,0> simd66;
  typedef SSE_PFX<0,0> simd__;

  template <unsigned SIZE>
  struct AddrSize
  {
    typedef AddrSize<SIZE> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& value, uint8_t const* bytes ) { return bytes; }
    
    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes ) { return (cb.addrsize() != SIZE) ? 0 : bytes; }
  };
  
  template <typename intT, unsigned BYTECOUNT>
  intT getimm( uint8_t const* _bytes )
  {
    if (sizeof(intT) < BYTECOUNT) { struct Bad {}; throw Bad (); }
    intT tmp = 0;
    for (unsigned byte = 0; byte < BYTECOUNT; ++byte)
      tmp |= (intT( _bytes[byte] ) << (8*byte));
    unsigned const bitshift = 8*(sizeof(intT) - BYTECOUNT);
    tmp = (tmp << bitshift) >> bitshift;
    return tmp;
  }

  template <unsigned SIZE>
  struct Imm
  {
    static unsigned const size = SIZE;
    typedef Imm<SIZE> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + (SIZE/8); }
    
    template <typename INT>
    uint8_t const* get( ImmValue<INT>& out, uint8_t const* bytes )
    {
      if (out.index == 0)
        {
          out.index = -1;
          out.value = INT( getimm<typename CTypeFor<SIZE>::s,SIZE/8>( bytes ) );
          return 0;
        }
      if (out.index > 0) 
        out.index -= 1;
      return bytes + (SIZE/8);
    }
  };

  struct RMOpFabric
  {
    RMOpFabric( CodeBase const& cb )
      : addrclass(cb.addrclass()), segment(cb.segment), rexb(0), rexx(0)
    {
      rexb = cb.rex_b;
      rexx = cb.rex_x;
    }
    
    virtual ~RMOpFabric() {}
    struct Bad {};
    virtual void newM    (                               uint8_t base ) { throw Bad(); }
    virtual void newSIB  ( uint8_t scale, uint8_t index, uint8_t base ) { throw Bad(); }
    virtual void newSID  ( uint8_t scale, uint8_t index,               int32_t disp ) { throw Bad(); }
    virtual void newD    (                                             int64_t disp ) { throw Bad(); }
    virtual void newRR   (                                             int32_t disp ) { throw Bad(); }
    virtual void newBD   (                               uint8_t base, int32_t disp ) { throw Bad(); }
    virtual void newSIBD ( uint8_t scale, uint8_t index, uint8_t base, int32_t disp ) { throw Bad(); }
    virtual void makeROp ( unsigned reg ) { throw Bad(); }

    uint8_t addrclass    : 2;
    uint8_t segment      : 3;
    uint8_t rexb         : 1;
    uint8_t rexx         : 1;
    
    unsigned get_rm( uint8_t const* bytes ) const { return ((bytes[0] >> 0) & 7) | (rexb << 3); }
    unsigned get_scale( uint8_t const* bytes ) const { return  (bytes[1] >> 6) & 3; }
    unsigned get_index( uint8_t const* bytes ) const { return ((bytes[1] >> 3) & 7) | (rexx << 3) ; }
    unsigned get_base( uint8_t const* bytes ) const  { return ((bytes[1] >> 0) & 7) | (rexb << 3); }
    unsigned address_size() const { return 8 << addrclass; }
  };

  struct VarValue { uint8_t value; VarValue() : value() {} };
  
  template <int BITS>
  struct OpCodeVar
  {
    OpCodeVar( uint8_t byte ) : code(byte>>BITS) {} uint8_t code;
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + 1; }
    uint8_t const* get( CodeBase const& out, uint8_t const* bytes ) { return (bytes[0] >> BITS) == code ? bytes + 1 : 0; }
    uint8_t const* get( VarValue& out, uint8_t const* bytes ) { out.value = bytes[0] & ((1<<BITS)-1); return 0; }
  };

  template <int BITS> struct Var { typedef OpCodeVar<BITS> B; };

  struct OpCodeReg
  {
    OpCodeReg( uint8_t byte ) : code(byte>>3), rexb() {}

    uint8_t code : 5;
    uint8_t rexb : 1;
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + 1; }

    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes ) { rexb = cb.rex_b; return (bytes[0] >> 3) == code ? bytes + 1 : 0; }
    uint8_t const* get( RMOpFabric& out, uint8_t const* bytes ) { out.makeROp( (bytes[0] & 7) | (rexb << 3) ); return 0; }
  };

  struct Reg { typedef OpCodeReg B; };

  struct MRMOpCode
  {
    MRMOpCode( uint8_t _code ) : code(_code) {} uint8_t code;
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + 0; }
    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes ) { return ((bytes[0] >> 3) & 7) == code ? bytes + 0 : 0; }
  };
  
  struct Lockable {};
  
  template <unsigned LENGTH>
  struct OpCode
  {
    typedef OpCode<LENGTH> this_type;
    template <typename RHS> AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }

    typedef OpCode<LENGTH-1> Head;
    template <typename RHS>
    AndSeq<Head, typename RHS::B> operator + ( RHS const& rhs ) { return AndSeq<Head, typename RHS::B>( &ref[0], ref[LENGTH-1] ); }

    typedef AndSeq<this_type, MRMOpCode> WithMRMOpCode;
    WithMRMOpCode operator / ( int code ) { return WithMRMOpCode( *this, MRMOpCode( code ) ); }
    
    OpCode( uint8_t const* _ref ) : ref(), lockable(false) { for (unsigned idx = 0; idx < LENGTH; ++idx ) ref[idx] = _ref[idx]; }
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + LENGTH; }
    
    uint8_t const*
    get( CodeBase const& cb, uint8_t const* bytes )
    {
      if (cb.f0() and not lockable)
        return 0;
      for (unsigned idx = 0; idx < LENGTH; ++idx)
        if (ref[idx] != bytes[idx]) return 0;
      return bytes + LENGTH;
    }

    uint8_t const*
    get( Lockable&, uint8_t const* bytes )
    {
      lockable = true;
      return bytes+2;
    }
    
    uint8_t ref[LENGTH];
    bool lockable;
  };
  
  template <unsigned LENGTH>
  OpCode<LENGTH-1> opcode( char const (&ref)[LENGTH] )
  { return OpCode<LENGTH-1>( reinterpret_cast<uint8_t const*>( &ref[0] ) ); }

  struct VexV { VexV() : idx() {} unsigned idx; };
  
  template <unsigned LENGTH>
  struct Vex
  {
    typedef Vex<LENGTH> this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }

    typedef Vex<LENGTH-1> Head;
    template <typename RHS>
    AndSeq<Head, typename RHS::B> operator + ( RHS const& rhs ) { return AndSeq<Head, typename RHS::B>( &ref[0], ref[LENGTH-1] ); }

    typedef AndSeq<this_type, MRMOpCode> WithMRMOpCode;
    WithMRMOpCode operator / ( int code ) { return WithMRMOpCode( *this, MRMOpCode( code ) ); }
    
    Vex( uint8_t const* _ref ) : ref(), len(0) { for (unsigned idx = 0; idx < LENGTH; ++idx ) ref[idx] = _ref[idx]; }
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + len; }
    
    uint8_t const*
    get( CodeBase const& cb, uint8_t const* bytes )
    {
      if (cb.f0())
        return 0;
      // SSE mandatory prefix
      unsigned ridx = 1, bidx = 0;
      if (char(ref[0]) == '*') { /* prefix wildcard, x86 abuse ('*' == 0x2a) */ }
      else if (ref[0] == 0x66) { if (not cb.opsz_66 or cb.rep)      return 0; }
      else if (ref[0] == 0xf2) { if (    cb.opsz_66 or cb.rep != 2) return 0; }
      else if (ref[0] == 0xf3) { if (    cb.opsz_66 or cb.rep != 3) return 0; }
      else   { ridx = 0;         if (    cb.opsz_66 or cb.rep)      return 0; }
      
      if      (bytes[0] == 0xc5)
        {
          bidx = 2;
          if (ref[ridx++] != 0x0f) return 0;
        }
      else if (bytes[0] == 0xc4)
        {
          bidx = 3;
          if (ref[ridx++] != 0x0f) return 0;
          switch (bytes[1] & 0x1f)
            {
            default : return 0;
            case 0b00001: break;
            case 0b00010: if (ref[ridx++] != 0x38) return 0; break;
            case 0b00011: if (ref[ridx++] != 0x3a) return 0; break;
            }
        }
      
      for (; ridx < LENGTH; ++ridx, ++bidx)
        if (ref[ridx] != bytes[bidx]) return 0;

      len = bidx;
      return bytes + len;
    }
  
    uint8_t const* get( VexV& v, uint8_t const* bytes )
    {
      v.idx = (bytes[2-(bytes[0] & 1)] >> 3) % 16;
      return (bytes[0] | 1) == 0xc5 ? 0 : bytes + len;
    }
    uint8_t ref[LENGTH];
    uint8_t len;
  };
  
  template <unsigned LENGTH>
  Vex<LENGTH-1> vex( char const (&ref)[LENGTH] )
  { return Vex<LENGTH-1>( reinterpret_cast<uint8_t const*>( &ref[0] ) ); }
  
  template <class ARCH,unsigned ADDRSIZE>
  struct ModM : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModM( uint8_t _seg, uint8_t _base ) : MOp<ARCH>( _seg ), base( _base ) {} uint8_t base;

    typedef typename GTypeFor<ADDRSIZE>::OP OP;
    void disasm_memory_operand( std::ostream& sink ) const { sink << DisasmMS( MOp<ARCH>::segment ) << '(' << DisasmG( OP(), base ) << ')'; };
    
    addr_t effective_address( ARCH& arch ) const { return addr_t( arch.regread( OP(), base ) ); }
  };

  template <class ARCH,unsigned ADDRSIZE>
  struct ModSIB : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModSIB( uint8_t _seg, uint8_t _scale, uint8_t _index, uint8_t _base ) : MOp<ARCH>( _seg ), scale( _scale ), index( _index ), base( _base ) {} uint8_t scale, index, base;
    
    typedef typename GTypeFor<ADDRSIZE>::OP OP;
    void disasm_memory_operand( std::ostream& sink ) const
    {
      sink << DisasmMS( MOp<ARCH>::segment ) << '(' << DisasmG( OP(), base ) << ',' << DisasmG( OP(), index ) << ',' << (1 << scale) << ')';
    }
    
    addr_t effective_address( ARCH& arch ) const { return addr_t( arch.regread( OP(), base ) + (arch.regread( OP(), index ) << scale) ); }
  };
  
  template <class ARCH, unsigned ADDRSIZE>
  struct ModSID : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModSID( uint8_t _seg, uint8_t _scale, uint8_t _index, int32_t _disp ) : MOp<ARCH>( _seg ), scale( _scale ), index( _index ), disp( _disp ) {}
    uint8_t scale, index; int32_t disp;
    
    typedef typename GTypeFor<ADDRSIZE>::OP OP;
    void disasm_memory_operand( std::ostream& sink ) const
    {
      sink << DisasmMS( MOp<ARCH>::segment ) << DisasmX(disp) << "(," << DisasmG( OP(), index ) << ',' << (1 << scale) << ')';
    }

    addr_t effective_address( ARCH& arch ) const { return addr_t( disp ) + addr_t(arch.regread( OP(), index ) << scale); }
  };
  
  template <class ARCH, typename DISP>
  struct ModD : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModD( uint8_t _seg, DISP _disp ) : MOp<ARCH>( _seg ), disp( _disp ) {} DISP disp;
    
    void disasm_memory_operand( std::ostream& sink ) const { sink << DisasmMS( MOp<ARCH>::segment ) << DisasmX(typename meta::__unsigned<DISP>::type(disp)); }
    
    addr_t effective_address( ARCH& arch ) const { return addr_t( disp ); };
  };

  template <class ARCH>
  struct ModRR : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModRR( uint8_t _seg, int32_t _disp ) : MOp<ARCH>( _seg ), disp( _disp ) {} int32_t disp;
    
    void disasm_memory_operand( std::ostream& sink ) const { sink << DisasmMS( MOp<ARCH>::segment ) << DisasmX(disp) << "(%rip)"; }
    
    addr_t effective_address( ARCH& arch ) const { return addr_t( disp ) + arch.getnip(); };
  };

  template <class ARCH, unsigned ADDRSIZE>
  struct ModSIBD : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModSIBD( uint8_t _seg, uint8_t _scale, uint8_t _index, uint8_t _base, int32_t _disp )
      : MOp<ARCH>( _seg ), disp( _disp ), scale( _scale ), index( _index ), base( _base ) {}
    int32_t disp; uint8_t scale, index, base;
    
    typedef typename GTypeFor<ADDRSIZE>::OP OP;
    void disasm_memory_operand( std::ostream& sink ) const
    { sink << DisasmMS( MOp<ARCH>::segment ) << DisasmX(disp) << '(' << DisasmG( OP(), base ) << ',' << DisasmG( OP(), index ) << ',' << (1 << scale) << ')'; };

    addr_t effective_address( ARCH& arch ) const { return addr_t(arch.regread( OP(), base ) + (arch.regread( OP(), index ) << scale)) + addr_t( disp ); };
  };
  
  template <class ARCH, unsigned ADDRSIZE>
  struct ModBD : public MOp<ARCH>
  {
    typedef typename ARCH::addr_t addr_t;
    ModBD( uint8_t _seg, uint8_t _base, int32_t _disp ) : MOp<ARCH>( _seg ), base( _base ), disp( _disp ) {} uint8_t base; int32_t disp;
    
    typedef typename GTypeFor<ADDRSIZE>::OP OP;
    void disasm_memory_operand( std::ostream& sink ) const { sink << DisasmMS( MOp<ARCH>::segment ) << DisasmX(disp) << '(' << DisasmG( OP(), base ) << ')'; };

    addr_t effective_address( ARCH& arch ) const { return addr_t( arch.regread( OP(), base ) ) + addr_t( disp ); };
  };
  
  template <class ARCH>
  MOp<ARCH>* make_rop( unsigned reg )  { return (MOp<ARCH>*)( uintptr_t( reg ) ); }

  template <class ARCH>
  struct RMOpFabricT : RMOpFabric
  {
    RMOpFabricT( CodeBase const& cb ) : RMOpFabric( cb ), mop() {} MOp<ARCH>* mop;
    struct Bad {};
    void newM( uint8_t base ) override
    {
      if      (address_size() == 16) mop = new ModM<ARCH,16>( segment, base );
      else if (address_size() == 32) mop = new ModM<ARCH,32>( segment, base );
      else if (address_size() == 64) mop = new ModM<ARCH,64>( segment, base );
      else throw Bad();
    }
    void newSIB( uint8_t scale, uint8_t index, uint8_t base ) override
    {
      if      (address_size() == 16) mop = new ModSIB<ARCH,16>( segment, scale, index, base );
      else if (address_size() == 32) mop = new ModSIB<ARCH,32>( segment, scale, index, base );
      else if (address_size() == 64) mop = new ModSIB<ARCH,64>( segment, scale, index, base );
      else throw Bad();
    }
    void newSID( uint8_t scale, uint8_t index, int32_t disp ) override
    {
      if      (address_size() == 16) mop = new ModSID<ARCH,16>( segment, scale, index, disp );
      else if (address_size() == 32) mop = new ModSID<ARCH,32>( segment, scale, index, disp );
      else if (address_size() == 64) mop = new ModSID<ARCH,64>( segment, scale, index, disp );
      else throw Bad();
    }
    void newD( int64_t disp ) override
    {
      if      (address_size() == 16) mop = new ModD<ARCH,int16_t>( segment, disp );
      else if (address_size() == 32) mop = new ModD<ARCH,int32_t>( segment, disp );
      else if (address_size() == 64) mop = new ModD<ARCH,int64_t>( segment, disp );
      else throw Bad();
    }
    void newRR( int32_t disp ) override { mop = new ModRR<ARCH>( segment, disp ); }
    void newBD( uint8_t base, int32_t disp ) override
    {
      if      (address_size() == 16) mop = new ModBD<ARCH,16>( segment, base, disp );
      else if (address_size() == 32) mop = new ModBD<ARCH,32>( segment, base, disp );
      else if (address_size() == 64) mop = new ModBD<ARCH,64>( segment, base, disp );
      else throw Bad();
    }
    void newSIBD( uint8_t scale, uint8_t index, uint8_t base, int32_t disp ) override
    {
      if      (address_size() == 16) mop = new ModSIBD<ARCH,16>( segment, scale, index, base, disp );
      else if (address_size() == 32) mop = new ModSIBD<ARCH,32>( segment, scale, index, base, disp );
      else if (address_size() == 64) mop = new ModSIBD<ARCH,64>( segment, scale, index, base, disp );
      else throw Bad();
    }
    void makeROp( unsigned reg ) override { mop = (MOp<ARCH>*)( uintptr_t( reg ) ); }
  };
  
  template <typename PATTERN>
  PATTERN lockable( PATTERN&& pattern )
  {
    auto _ = (uint8_t const*)"";
    Lockable l;
    if ((pattern.get( l, _ ) - _) != 5)
      { struct Bad {}; throw Bad(); }
    return PATTERN( std::move(pattern) );
  }
  
  struct RM
  {
    typedef RM this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    struct Forge { virtual void build( RMOpFabric& out, uint8_t const* bytes ) const = 0; virtual unsigned length() const = 0; virtual bool is_reg() const { return false; }};
    Forge*  forge;
    
    enum accept_t { standard, regonly, memonly, lockable };
    accept_t accept;
    
    RM(accept_t _accept = standard) : forge(), accept(_accept) {}

    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + forge->length(); }

    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes )
    {
      forge = get_forge( cb, bytes );
      switch (accept)
        {
        default: break;
        case regonly:  if (not forge->is_reg()) return 0; break;
        case lockable: if (not cb.f0()) break; /* else continue with memonly */
        case memonly:  if (    forge->is_reg()) return 0; break;
        }
      return bytes + forge->length();
    }

    static Forge* get_forge( CodeBase const& cb, uint8_t const* bytes )
    {
      switch (cb.addrclass())
        {
        default:
          throw std::runtime_error("unsupported address size");
          break;
        
        case 2: case 3:
          {
            uint8_t mod = (*bytes >> 6) & 3;
            // uint8_t gn =  (*bytes >> 3) & 7;
            uint8_t rm =  (*bytes >> 0) & 7;
            bytes += 1;
            
            if (mod == 3)
              {
                /* 0b11[2]:gn[3]:0b101[3]  */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.makeROp( out.get_rm(bytes) ); }
                  unsigned length() const { return 1; }
                  bool is_reg() const { return true; }
                } _; return &_;
              }
      
            if (rm == 4)
              {
                /* 0b00[2]:gn[3]:0b100[3]:> <:SIB  */
                
                // uint8_t scale = (*bytes >> 6) & 3;
                uint8_t index = (*bytes >> 3) & 7;
                uint8_t base =  (*bytes >> 0) & 7;
                index |= cb.rex_x << 3; /* rex.x is decoded */
                
                
                bytes += 1;
                if (mod == 2)
                  {
                    if (index != 4)
                      {
                        /* 0b10[2]:gn[3]:0b100[3]:> <:scale[2]:index[3]:base[3]:> <:sext disp[32] */ 
                        static struct : Forge {
                          void build( RMOpFabric& out, uint8_t const* bytes ) const
                          { out.newSIBD( out.get_scale(bytes), out.get_index(bytes), out.get_base(bytes), getimm<int32_t,4>( &bytes[2] ) ); }
                          unsigned length() const { return 6; }
                        } _; return &_;
                      }
                    
                    /* 0b10[2]:gn[3]:0b100[3]:> <:scale[2]:0b100[3]:base[3]:> <:sext disp[32] */ 
                    static struct : Forge {
                      void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newBD( out.get_base(bytes), getimm<int32_t,4>( &bytes[2] ) ); }
                      unsigned length() const { return 6; }
                    } _; return &_;
                  }
                
                if (mod == 1)
                  {
                    if (index != 4)
                      {
                        /* 0b01[2]:gn[3]:0b100[3]:> <:scale[2]:index[3]:base[3]:> <:sext <32> disp[8] (mod_SIBD8) */
                        static struct : Forge {
                          void build( RMOpFabric& out, uint8_t const* bytes ) const
                          { out.newSIBD( out.get_scale(bytes), out.get_index(bytes), out.get_base(bytes), getimm<int8_t,1>( &bytes[2] ) ); }
                          unsigned length() const { return 3; }
                        } _; return &_;
                      }
                    
                    /* 0b01[2]:gn[3]:0b100[3]:> <:scale[2]:0b100[3]:base[3]:> <:sext <32> disp[8] (mod_SIBD8) */
                    static struct : Forge {
                      void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newBD( out.get_base(bytes), getimm<int8_t,1>( &bytes[2] ) ); }
                      unsigned length() const { return 3; }
                    } _; return &_;
                  }
                
                /* mod == 0*/
                if (base == 5)
                  {
                    if (index != 4)
                      {
                        /* 0b00[2]:gn[3]:0b100[3]:> <:scale[2]:index[3]:0b101[3]:> <:sext disp[32] */
                        static struct : Forge {
                          void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newSID( out.get_scale(bytes), out.get_index(bytes), getimm<int32_t,4>( &bytes[2] ) ); }
                          unsigned length() const { return 6; }
                        } _; return &_;
                      }
                    
                    /* 0b00[2]:gn[3]:0b100[3]:> <:scale[2]:0b100[3]:0b101[3]:> <:sext disp[32] */
                    static struct : Forge {
                      void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newD( getimm<int32_t,4>( &bytes[2] ) ); }
                      unsigned length() const { return 6; }
                    } _; return &_;
                  }
                
                if (index != 4)
                  {
                    /* 0b00[2]:gn[3]:0b100[3]:> <:scale[2]:index[3]: base[3] */
                    static struct : Forge {
                      void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newSIB( out.get_scale(bytes), out.get_index(bytes), out.get_base(bytes) ); }
                      unsigned length() const { return 2; }
                    } _; return &_;
                  }
                
                /* 0b00[2]:gn[3]:0b100[3]:> <:scale[2]:0b100[3]: base[3] */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newM( out.get_base(bytes) ); }
                  unsigned length() const { return 2; }
                } _; return &_;
              }

            /* No SIB */
      
            if (mod == 1)
              {
                /* 0b01[2]:gn[3]:   rm[3]:> <:sext<32> disp[8] (mod_M1RxD8) */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newBD( out.get_rm(bytes), getimm<int8_t,1>( &bytes[1] ) ); }
                  unsigned length() const { return 2; }
                } _; return &_;
              }
            
            if (mod == 2)
              {
                /* 0b10[2]:gn[3]:   rm[3]:> <:sext disp[32] (mod_M2RxD8) */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newBD( out.get_rm(bytes), getimm<int32_t,4>( &bytes[1] ) ); }
                  unsigned length() const { return 5; }
                } _; return &_;
              }

            if (rm != 5)
              {
                /* 0b00[2]:gn[3]:   rm[3] */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newM( out.get_rm(bytes) ); }
                  unsigned length() const { return 1; }
                } _; return &_;
              }
            
            /* 0b00[2]:gn[3]:0b101[3]:> <:sext disp[32] */
            if (cb.mode64())
              {
                /* amd64 RIP-relative mode */
                static struct : Forge {
                  void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newRR( getimm<int32_t,4>( &bytes[1] ) ); }
                  unsigned length() const { return 5; }
                } _; return &_;
              }

            /* ia32 absolute addressing mode (5 bytes form) */
            static struct : Forge {
              void build( RMOpFabric& out, uint8_t const* bytes ) const { out.newD( getimm<int32_t,4>( &bytes[1] ) ); }
              unsigned length() const { return 5; }
            } _; return &_;
          }
          break;
        }

      struct Bad {}; throw Bad();
      return 0;
    }

    uint8_t const* get( RMOpFabric& out, uint8_t const* bytes )
    {
      if (not forge)
        throw forge;
      forge->build( out, bytes );
      return 0;
    }

    uint8_t const*
    get( Lockable&, uint8_t const* bytes )
    {
      switch (accept)
        {
        default: break;
        case regonly: { struct Bad {}; throw Bad(); }
        case standard: accept = lockable; break;
        }
      return bytes + 3;
    }
    
    struct GN { GN() : idx() {} unsigned idx; };
    uint8_t const* get( GN& gr, uint8_t const* bytes ) { gr.idx = (bytes[0] >> 3) & 7; return 0; }
    
    //    unsigned get_rm( uint8_t const* bytes ) const { return ((bytes[0] >> 0) & 7) | (rexb << 3); }
    bool is_reg( uint8_t const* bytes ) const { return (bytes[0] >> 6) == 3; }

    // unsigned get_scale( uint8_t const* bytes ) const { return  (bytes[1] >> 6) & 3; }
    // unsigned get_index( uint8_t const* bytes ) const { return ((bytes[1] >> 3) & 7) | (rexx << 3) ; }
    // unsigned get_base( uint8_t const* bytes ) const  { return ((bytes[1] >> 0) & 7) | (rexb << 3); }

    //    unsigned addr_size() { return 8 << adsz; }
  };

  struct Moffs
  {
    typedef Moffs this_type;
    template <typename RHS>
    AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
    uint8_t length;
    
    Moffs() : length() {}
    
    template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return bytes + length; }
    
    uint8_t const* get( CodeBase const& cb, uint8_t const* bytes )
    {
      length = 1 << cb.addrclass();
      return bytes + length;
    }
    
    uint8_t const* get( RMOpFabric& out, uint8_t const* bytes )
    {
      int64_t value = 0;
      for (int idx = length; --idx >= 0;)
        value = (value << 8) | bytes[idx];
      out.newD( value );
      return 0;
    }
  };
  
  // template <bool REGONLY>
  // struct RM_RegOrMem
  // {
  //   typedef RM_RegOrMem<REGONLY> this_type;
  //   template <typename RHS>
  //   AndSeq<this_type, RHS> operator & ( RHS const& rhs ) { return AndSeq<this_type, RHS>( *this, rhs ); }
    
  //   RM rm;

  //   template <typename PROPERTY> uint8_t const* get( PROPERTY& out, uint8_t const* bytes ) { return rm.get( out, bytes ); }
  //   uint8_t const* get( CodeBase const& cb, uint8_t const* bytes )
  //   {
  //     uint8_t const* res = rm.get( cb, bytes );
  //     if (res and (rm.forge->is_reg() xor (REGONLY))) return 0;
  //     return res;
  //   }
  // };
  
  // typedef RM_RegOrMem<true>  RM_reg;
  // typedef RM_RegOrMem<false> RM_mem;

  inline RM RM_reg() { return RM(RM::regonly); }
  inline RM RM_mem() { return RM(RM::memonly); }
  
  template <class ARCH>
  struct BaseMatch
  {
    BaseMatch( InputCode<ARCH> const* _ic ) : ic(_ic) {}
    operator bool () const { return ic; }
    InputCode<ARCH> const* ic;
  };
  template <class ARCH, typename PATTERN>
  struct Match : BaseMatch<ARCH>
  {
    Match( InputCode<ARCH> const* ic, PATTERN const& _pattern )
      : BaseMatch<ARCH>( ic ), pattern( _pattern ) {}

    InputCode<ARCH> const& icode() const { return *BaseMatch<ARCH>::ic; };
    // TODO: following functions should be const
    
    OpBase<ARCH> opbase()
    {
      struct GetLength {} getlength;
      unsigned length = (pattern.get( getlength, icode().opcode() ) - &icode().bytes[0]);
      return OpBase<ARCH>( icode().header, icode().mode, length );
    }

    template <typename PROPERTY> void find( PROPERTY& out, uint8_t const* bytes )
    {
      if (pattern.get( out, bytes )) { struct Bad {}; throw Bad(); }
    }
    
    // template <typename INT>
    // INT imm( unsigned idx = 0 ) { ImmValue<INT> res( idx ); find( res, icode().opcode() ); return res.value; }
    
    template <typename INT>
    INT i( INT it, unsigned idx = 0 ) { ImmValue<INT> res( idx ); find( res, icode().opcode() ); return res.value; }
    
    MOp<ARCH>* rmop() { RMOpFabricT<ARCH> res( icode() ); find( static_cast<RMOpFabric&>(res), icode().opcode() ); return res.mop; }
    
    uint8_t var() { VarValue res; find( res, icode().opcode() ); return res.value; }
    
    uint8_t greg()
    {
      RM::GN gn;
      find( gn, icode().opcode() );
      return (icode().rex_r << 3) | gn.idx;
    }
    
    uint8_t ereg()
    {
      struct _ : RMOpFabric { _( CodeBase const& cb ) : RMOpFabric( cb ), idx() {} unsigned idx; void makeROp(unsigned reg) override { idx = reg; } } res(icode());
      find( static_cast<RMOpFabric&>(res), icode().opcode() );
      return res.idx;
    }

    uint8_t vreg()
    {
      VexV v;
      find( v, icode().opcode() );
      return v.idx ^ 15;
    }
    
    PATTERN pattern;
  };
  
  template <class ARCH, typename PATTERN>
  Match<ARCH,PATTERN> match( InputCode<ARCH> const& ic, PATTERN&& pattern )
  {
    bool good = bool( pattern.get( static_cast<CodeBase const&>( ic ), ic.opcode() ) );
    return Match<ARCH,PATTERN>( good ? &ic : 0, pattern );
  }
  
  // Empty template for decoding tables
  template <class ARCH, operation_t IDX> struct DC {};
  
  // Decoding tables and behavioral description
#include <unisim/component/cxx/processor/intel/isa/branch.hh>
#include <unisim/component/cxx/processor/intel/isa/integer.hh>
#include <unisim/component/cxx/processor/intel/isa/floatingpoint.hh>
#include <unisim/component/cxx/processor/intel/isa/move.hh>
#include <unisim/component/cxx/processor/intel/isa/string.hh>
#include <unisim/component/cxx/processor/intel/isa/special.hh>
#include <unisim/component/cxx/processor/intel/isa/simd.hh>
  
  // Recursive decoding structure
  template <class ARCH, operation_t IDX>
  struct DR
  {
    Operation<ARCH>*
    get( InputCode<ARCH> const& ic )
    {
      DC<ARCH,operation_t(IDX-1)> dc; if (Operation<ARCH>* op = dc.get( ic )) return op;
      DR<ARCH,operation_t(IDX-1)> dr; return dr.get( ic );
    }
  };
  
  // Recursion stop
  template <class ARCH>
  struct DR<ARCH,operation_t(0)>
  {
    Operation<ARCH>* get( InputCode<ARCH> const& ) { return 0; }
  };
  
  template <class ARCH>
  Operation<ARCH>*
  getoperation( InputCode<ARCH> const& ic )
  {
    DR<ARCH,operation_count> dr;
    return dr.get( ic );
  }

} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_TCC__
