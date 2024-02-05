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

/* TODO:
 * - In 64 bit mode, for some branch instructions (if not all) operand-size is forced to 64 whatever the actual operand size is ...
 * - Some instructions may incoherently depend on StackAddressSize and OperandSize (e.g. Enter & Leave)
 * - some branch struct offsets should depend on operand size
 * - the dissasembly of non-default targetting mode needs a suffix
 */
template <class ARCH, unsigned IPSIZE>
struct NearCallJ : public Operation<ARCH>
{
  NearCallJ( OpBase<ARCH> const& opbase, int32_t _offset ) : Operation<ARCH>( opbase ), offset( _offset ) {} int32_t offset;
    
  void disasm( std::ostream& sink ) const { sink << "call " << "0x" << std::hex << (Operation<ARCH>::address + Operation<ARCH>::length + offset); };
    
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    typedef typename TypeFor<ARCH,IPSIZE>::u ip_t;
    addr_t nip = arch.getnip();
    arch.template push<IPSIZE>( ip_t( nip ) );
    arch.setnip( addr_t( ip_t( nip + addr_t( offset ) ) ), ARCH::ipcall );
  }
};

template <class ARCH, class IOP>
struct NearCallE : public Operation<ARCH>
{
  NearCallE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
    
  void disasm( std::ostream& sink ) const { sink << "call *" << DisasmE( IOP(), rmop ); }
    
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    typedef typename TypeFor<ARCH,IOP::SIZE>::u ip_t;
    auto target = arch.rmread( IOP(), rmop );
    arch.template push<IOP::SIZE>( ip_t( arch.getnip() ) );
    arch.setnip( addr_t( target ), ARCH::ipcall );
  }
};
  
template <class ARCH, unsigned OPSIZE>
struct FarCallA : public Operation<ARCH>
{
  FarCallA( OpBase<ARCH> const& opbase, int32_t _offset, int16_t _seg ) : Operation<ARCH>( opbase ), offset( _offset ), mseg( _seg ) {} int32_t offset; int16_t mseg;
    
  void disasm( std::ostream& sink ) const { sink << "lcall " << "0x" << std::hex << (Operation<ARCH>::address + Operation<ARCH>::length + offset); };
};
  
template <class ARCH, unsigned OPSIZE>
struct FarCallE : public Operation<ARCH>
{
  FarCallE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  
  void disasm( std::ostream& sink ) const { sink << "lcall " << '*' << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,CALL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.rep != 0) return 0;
  
  if (auto _ = match( ic, OpSize<16>() & opcode( "\xe8" ) & Imm<16>() ))
    
    return ic.mode64() ? 0 : new NearCallJ<ARCH,16>( _.opbase(), _.i( int32_t() ) );

  if (auto _ = match( ic, opcode( "\xe8" ) & Imm<32>() ))
    {
      if (ic.mode64()) return new NearCallJ<ARCH,64>( _.opbase(), _.i( int32_t() ) );
      else             return new NearCallJ<ARCH,32>( _.opbase(), _.i( int32_t() ) );
    }
    
  if (auto _ = match( ic, opcode( "\xff" ) /2 & RM() ))
    {
      if      (ic.mode64())       return new NearCallE<ARCH,GOq>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 16) return new NearCallE<ARCH,GOw>( _.opbase(), _.rmop() );
      else                        return new NearCallE<ARCH,GOd>( _.opbase(), _.rmop() );
    }

  if (not ic.mode64())
    {
      if (auto _ = match( ic, OpSize<16>() & opcode( "\x9a" ) & Imm<16>() & Imm<16>() ))
    
        return new FarCallA<ARCH,16>( _.opbase(), _.i( int32_t(), 0 ), _.i( int16_t(), 1 ) );
    
      if (auto _ = match( ic, OpSize<32>() & opcode( "\x9a" ) & Imm<32>() & Imm<16>() ))
    
        return new FarCallA<ARCH,32>( _.opbase(), _.i( int32_t(), 0 ), _.i( int16_t(), 1 ) );
    }
    
  if (auto _ = match( ic, opcode( "\xff" ) /3 & RM() ))
    {
      if      (ic.opsize() == 16) return new FarCallE<ARCH,16>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new FarCallE<ARCH,32>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new FarCallE<ARCH,64>( _.opbase(), _.rmop() );
      else return 0;
    }
    
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct JccJ : public Operation<ARCH>
{
  JccJ( OpBase<ARCH> const& opbase, uint8_t _cond, int32_t _offset ) : Operation<ARCH>( opbase ), offset( _offset ), cond( _cond ) {} int32_t offset; uint8_t cond;
    
  void disasm( std::ostream& sink ) const { sink << 'j' << DisasmCond( cond ) << " 0x" << std::hex << (Operation<ARCH>::address + Operation<ARCH>::length + offset); }
    
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    typedef typename TypeFor<ARCH,OPSIZE>::u ip_t;
    if (arch.Test( eval_cond( arch, cond ) ))
      arch.setnip( addr_t( ip_t( arch.getnip() + addr_t( offset ) ) ) ); 
  }
};
  
template <class ARCH> struct DC<ARCH,JCC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, (opcode( "\x70" ) + Var<4>()) & Imm<8>() ))
    {
      if      (ic.mode64())       return new JccJ<ARCH,64>( _.opbase(), _.var(), _.i( int32_t() ) );
      else if (ic.opsize() == 16) return new JccJ<ARCH,16>( _.opbase(), _.var(), _.i( int32_t() ) );
      else                        return new JccJ<ARCH,32>( _.opbase(), _.var(), _.i( int32_t() ) );
    }
    
  if (auto _ = match( ic, OpSize<16>() & (opcode( "\x0f\x80" ) + Var<4>()) & Imm<16>() ))
    
    return ic.mode64() ? 0 : new JccJ<ARCH,16>( _.opbase(), _.var(), _.i( int32_t() ) );
    
  if (auto _ = match( ic, OpSize<32>() & (opcode( "\x0f\x80" ) + Var<4>()) & Imm<32>() ))
    {
      if (ic.mode64()) return new JccJ<ARCH,64>( _.opbase(), _.var(), _.i( int32_t() ) );
      else             return new JccJ<ARCH,32>( _.opbase(), _.var(), _.i( int32_t() ) );
    }
  
  return 0;
}};

template <class ARCH, unsigned MOD, class COUNT, unsigned IPSIZE>
struct Loop : public Operation<ARCH>
{
  int8_t offset;
    
  Loop( OpBase<ARCH> const& opbase, int8_t _offset )
    : Operation<ARCH>( opbase ), offset( _offset )
  {}
  
  void disasm( std::ostream& sink ) const
  {
    if      (MOD == 0) sink << "loopne ";
    else if (MOD == 1) sink << "loope ";
    else if (MOD == 2) sink << "loop ";
    else if (MOD == 3) sink << "j" << (&"\0\0c\0ec\0\0rc"[COUNT::SIZE/8]) << "x ";
    sink << "0x" << std::hex << (Operation<ARCH>::address + Operation<ARCH>::length + offset);
  };
    
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,COUNT::SIZE>::u count_t;
    typedef typename TypeFor<ARCH,IPSIZE>::u ip_t;
    typedef typename ARCH::addr_t addr_t;
    typedef typename ARCH::bit_t bit_t;
    
    // Decrement count register
    count_t count = arch.regread( COUNT(), 1 );
    if (MOD != 3)
      {
        count -= count_t( 1 );
        arch.regwrite( COUNT(), 1, count );
      }
    // Stop if count is zero
    if (arch.Test( count == count_t(0) )) return;
    // or ZF is set (loopne)
    if ((MOD == 0) and arch.Test(arch.flagread( ARCH::FLAG::ZF ) == bit_t( 1 ))) return;
    // or ZF is cleared (loope)
    if ((MOD == 1) and arch.Test(arch.flagread( ARCH::FLAG::ZF ) == bit_t( 0 ))) return;
    // else jump short
    arch.setnip( addr_t( ip_t( arch.getnip() + addr_t( offset ) ) ) );
  }
};

template <class ARCH> struct DC<ARCH,LOOP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xe0" ) & Imm<8>() ))
    /* LOOPNE */
    return newLoopMod<0>( ic, _.opbase(), _.i( int8_t() ) );
    
  if (auto _ = match( ic, opcode( "\xe1" ) & Imm<8>() ))
    /* LOOPE */
    return newLoopMod<1>( ic, _.opbase(), _.i( int8_t() ) );
  
  if (auto _ = match( ic, opcode( "\xe2" ) & Imm<8>() ))
    /* LOOP */
    return newLoopMod<2>( ic, _.opbase(), _.i( int8_t() ) );

  if (auto _ = match( ic, opcode( "\xe3" ) & Imm<8>() ))
    /* JCX */
    return newLoopMod<3>( ic, _.opbase(), _.i( int8_t() ) );

  return 0;
}
template <unsigned MOD>
Operation<ARCH>* newLoopMod( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, int8_t offset )
{
  if (ic.mode64())
    {
      if (ic.opsize() == 32) return new Loop<ARCH,MOD,GOd,64>( opbase, offset );
      if (ic.opsize() == 64) return new Loop<ARCH,MOD,GOq,64>( opbase, offset );
    }
  else
    {
      if (ic.addrsize() == 16 and ic.opsize() == 16) return new Loop<ARCH,MOD,GOw,16>( opbase, offset );
      if (ic.addrsize() == 16 and ic.opsize() == 32) return new Loop<ARCH,MOD,GOw,32>( opbase, offset );
      if (ic.addrsize() == 32 and ic.opsize() == 16) return new Loop<ARCH,MOD,GOd,16>( opbase, offset );
      if (ic.addrsize() == 32 and ic.opsize() == 32) return new Loop<ARCH,MOD,GOd,32>( opbase, offset );
    }
  return 0;
}};
  
template <class ARCH, class OP>
struct JmpE : public Operation<ARCH>
{
  JmpE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
    
  void disasm( std::ostream& sink ) const { sink << "jmp " << '*' << DisasmE( OP(), rmop ); }
     
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    arch.setnip( addr_t( arch.rmread( OP(), rmop ) ) );
  }
};

template <class ARCH, unsigned OPSIZE>
struct JmpJ : public Operation<ARCH>
{
  JmpJ( OpBase<ARCH> const& opbase, int32_t _offset ) : Operation<ARCH>( opbase ), offset( _offset ) {} int32_t offset;
  
  void disasm( std::ostream& sink ) const { sink << "jmp 0x" << std::hex << (Operation<ARCH>::address + Operation<ARCH>::length + offset); }
     
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u ip_t;
    typedef typename ARCH::addr_t addr_t;
    arch.setnip( addr_t( ip_t( arch.getnip() + addr_t( offset ) ) ) );
  }
};
  
template <class ARCH, unsigned OPSIZE>
struct JmpA : public Operation<ARCH>
{
  JmpA( OpBase<ARCH> const& opbase, int32_t _offset, int16_t _seg ) : Operation<ARCH>( opbase ), offset( _offset ), mseg( _seg ) {} int32_t offset; int16_t mseg;
  
  void disasm( std::ostream& sink ) const { sink << "ljmp " << DisasmI( mseg ) << ',' << DisasmI( offset ); }
};
  
template <class ARCH, unsigned OPSIZE>
struct JmpM : public Operation<ARCH>
{
  JmpM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
    
  void disasm( std::ostream& sink ) const { sink << "ljmp " << '*' << DisasmM( rmop ); }
};
  
template <class ARCH> struct DC<ARCH,JMP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xff" ) /4 & RM() ))
    {
      if      (ic.mode64())       return new JmpE<ARCH,GOq>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 16) return new JmpE<ARCH,GOw>( _.opbase(), _.rmop() );
      else                        return new JmpE<ARCH,GOd>( _.opbase(), _.rmop() );
    }
    
  if (auto _ = match( ic, opcode( "\xeb" ) & Imm<8>() ))
    {
      if      (ic.mode64())       return new JmpJ<ARCH,64>( _.opbase(), _.i( int32_t() ) );
      if      (ic.opsize() == 16) return new JmpJ<ARCH,16>( _.opbase(), _.i( int32_t() ) );
      else                        return new JmpJ<ARCH,32>( _.opbase(), _.i( int32_t() ) );
    }
    
  if (auto _ = match( ic, OpSize<16>() & opcode( "\xe9" ) & Imm<16>() ))
    
    return ic.mode64() ? 0 : new JmpJ<ARCH,16>( _.opbase(), _.i( int32_t() ) );
    
  if (auto _ = match( ic, OpSize<32>() & opcode( "\xe9" ) & Imm<32>() ))
    {
      if (ic.mode64()) return new JmpJ<ARCH,64>( _.opbase(), _.i( int32_t() ) );
      else             return new JmpJ<ARCH,32>( _.opbase(), _.i( int32_t() ) );
    }
  
  if (auto _ = match( ic, OpSize<16>() & opcode( "\xea" ) & Imm<16>() & Imm<16>() ))
    
    return ic.mode64() ? 0 : new JmpA<ARCH,16>( _.opbase(), _.i( int32_t() ), _.i( int16_t() ) );
    
  if (auto _ = match( ic, OpSize<32>() & opcode( "\xea" ) & Imm<32>() & Imm<16>() ))
    
    return ic.mode64() ? 0 : new JmpA<ARCH,32>( _.opbase(), _.i( int32_t() ), _.i( int16_t() ) );
    
  if (auto _ = match( ic, opcode( "\xff" ) /5 & RM() ))
    {
      if      (ic.opsize() == 16) return new JmpM<ARCH,16>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new JmpM<ARCH,32>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new JmpM<ARCH,64>( _.opbase(), _.rmop() );
      else return 0;
    }
    
  return 0;
}};
  
template <class ARCH, unsigned OPSIZE>
struct NearReturn : public Operation<ARCH>
{
  NearReturn( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
    
  void disasm( std::ostream& sink ) const { sink << "ret"; }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u ip_t;
    typedef typename ARCH::addr_t addr_t;
    ip_t return_address = arch.template pop<OPSIZE>();
    arch.setnip( addr_t( return_address ), ARCH::ipret );
  }
};
  
template <class ARCH, unsigned OPSIZE>
struct NearParamReturn : public Operation<ARCH>
{
  NearParamReturn( OpBase<ARCH> const& opbase, uint16_t _paramsize ) : Operation<ARCH>( opbase ), paramsize( _paramsize ) {} uint16_t paramsize;

  void disasm( std::ostream& sink ) const { sink << "ret " << DisasmI( paramsize ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u ip_t;
    typedef typename ARCH::addr_t addr_t;
    ip_t return_address = arch.template pop<OPSIZE>();
    arch.shrink_stack( addr_t( paramsize ) );
    arch.setnip( addr_t( return_address ), ARCH::ipret );
  }
};
  
template <class ARCH, unsigned OPSIZE>
struct FarReturn : public Operation<ARCH>
{
  FarReturn( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
    
  void disasm( std::ostream& sink ) const { sink << "lret "; }
};
  
template <class ARCH, unsigned OPSIZE>
struct FarParamReturn : public Operation<ARCH>
{
  FarParamReturn( OpBase<ARCH> const& opbase, uint16_t _paramsize ) : Operation<ARCH>( opbase ), paramsize( _paramsize ) {} uint16_t paramsize;

  void disasm( std::ostream& sink ) const { sink << "lret " << DisasmI( paramsize ); }
};
  
template <class ARCH> struct DC<ARCH,RETURN> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc3" ) ))
    {
      if      (ic.mode64())       return new NearReturn<ARCH,64>( _.opbase() );
      else if (ic.opsize() == 16) return new NearReturn<ARCH,16>( _.opbase() );
      else                        return new NearReturn<ARCH,32>( _.opbase() );
    }
    
  if (auto _ = match( ic, opcode( "\xc2" ) & Imm<16>() ))
    {
      if      (ic.mode64())       return new NearParamReturn<ARCH,64>( _.opbase(), _.i( uint16_t() ) );
      else if (ic.opsize() == 16) return new NearParamReturn<ARCH,16>( _.opbase(), _.i( uint16_t() ) );
      else                        return new NearParamReturn<ARCH,32>( _.opbase(), _.i( uint16_t() ) );
    }
    
  if (auto _ = match( ic, opcode( "\xcb" ) ))
    {
      if      (ic.opsize() == 16) return new FarReturn<ARCH,16>( _.opbase() );
      else if (ic.opsize() == 32) return new FarReturn<ARCH,32>( _.opbase() );
      else if (ic.opsize() == 64) return new FarReturn<ARCH,64>( _.opbase() );
      else return 0;
    }
    
  if (auto _ = match( ic, opcode( "\xca" ) & Imm<16>() ))
    {
      if      (ic.opsize() == 16) return new FarParamReturn<ARCH,16>( _.opbase(), _.i( uint16_t() ) );
      else if (ic.opsize() == 32) return new FarParamReturn<ARCH,32>( _.opbase(), _.i( uint16_t() ) );
      else if (ic.opsize() == 64) return new FarParamReturn<ARCH,64>( _.opbase(), _.i( uint16_t() ) );
    }
    
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct InterruptReturn : public Operation<ARCH>
{
  InterruptReturn( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}

  void disasm( std::ostream& sink ) const { sink << "iret "; }
};

template <class ARCH> struct DC<ARCH,INTRETURN> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xcf" ) ))

    {
      if      (ic.opsize() == 16) return new InterruptReturn<ARCH,16>( _.opbase() );
      else if (ic.opsize() == 32) return new InterruptReturn<ARCH,32>( _.opbase() );
      else if (ic.opsize() == 64) return new InterruptReturn<ARCH,64>( _.opbase() );
      else return 0;
    }
    
  return 0;
}};

template <class ARCH>
struct Interrupt : public Operation<ARCH>
{
  Interrupt( OpBase<ARCH> const& opbase, uint8_t _num ) : Operation<ARCH>( opbase ), vector_number( _num ) {} uint8_t vector_number;

  void disasm( std::ostream& sink ) const { sink << "int " << DisasmI( vector_number ); }

  void execute( ARCH& arch ) const { arch.interrupt( 0xcd, vector_number ); }
};

template <class ARCH>
struct Interrupt3 : public Operation<ARCH>
{
  Interrupt3( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}

  void disasm( std::ostream& sink ) const { sink << "int3"; }
  
  void execute( ARCH& arch ) const { arch.interrupt( 0xcc, 0x3 ); }
};

template <class ARCH>
struct InterruptOF : public Operation<ARCH>
{
  InterruptOF( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}

  void disasm( std::ostream& sink ) const { sink << "into"; }
  
  void execute( ARCH& arch ) const { arch.interrupt( 0xce, 0x4 ); }
};

template <class ARCH> struct DC<ARCH,INTERRUPT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xcc" ) ))
  
    return new Interrupt3<ARCH>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xcd" ) & Imm<8>() ))
  
    return new Interrupt<ARCH>( _.opbase(), _.i( uint8_t() ) );
  
  if (auto _ = match( ic, opcode( "\xce" ) ))
  
    return ic.mode64() ? 0 : new Interrupt3<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct SysCall : public Operation<ARCH>
{
  SysCall( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}

  void disasm( std::ostream& sink ) const { sink << "syscall"; }

  void execute( ARCH& arch ) const { arch.syscall(); }
};

template <class ARCH> struct DC<ARCH,SYSCALL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\x05" ) ))
  
    return new SysCall<ARCH>( _.opbase() );

  return 0;
}};
  
template <class ARCH, unsigned OPSIZE>
struct Enter : public Operation<ARCH>
{
  uint16_t allocsize; uint8_t nestinglevel;
  Enter( OpBase<ARCH> const& opbase, uint16_t _allocsize, uint8_t _nestinglevel )
    : Operation<ARCH>( opbase ), allocsize( _allocsize ), nestinglevel( _nestinglevel ) {}

  void disasm( std::ostream& sink ) const { sink << "enter " << DisasmI( allocsize ) << ',' << DisasmI( nestinglevel ); }
};

template <class ARCH, class GOP/*, unsigned SPSIZE*/>
struct Leave : public Operation<ARCH>
{
  Leave( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  
  void disasm( std::ostream& sink ) const { sink << "leave"; }
  
  void execute( ARCH& arch ) const
  {
    /* TODO: STACKSIZE */
    if (GOP::size() != ARCH::GR::size()) arch.unimplemented();
    arch.regwrite( GOP(), 4, arch.regread( GOP(), 5 ) );
    arch.regwrite( GOP(), 5, arch.template pop<GOP::SIZE>() );
  }
};

template <class ARCH> struct DC<ARCH,ENTER_LEAVE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  
  if (auto _ = match( ic, opcode( "\xc8" ) & Imm<16>() & Imm<8>() ))
  
    {
      if      (ic.opsize() == 16) return new Enter<ARCH,16>( _.opbase(), _.i( uint16_t() ), _.i( uint8_t() ) );
      else if (!ic.mode64()) return new Enter<ARCH,32>( _.opbase(), _.i( uint16_t() ), _.i( uint8_t() ) );
      else if (ic.mode64()) return new Enter<ARCH,64>( _.opbase(), _.i( uint16_t() ), _.i( uint8_t() ) );
      else return 0;
    }
  
  if (auto _ = match( ic, opcode( "\xc9" ) ))
  
    {
      if      (ic.opsize() == 16) return new Leave<ARCH,GOw>( _.opbase() );
      else if (!ic.mode64()) return new Leave<ARCH,GOd>( _.opbase() );
      else if (ic.mode64()) return new Leave<ARCH,GOq>( _.opbase() );
    }
  return 0;
}};
  
