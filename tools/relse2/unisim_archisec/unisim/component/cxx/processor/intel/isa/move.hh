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

template <class ARCH, class OP>
struct PushReg : public Operation<ARCH>
{
  PushReg( OpBase<ARCH> const& opbase, uint8_t _rn ) : Operation<ARCH>( opbase ), rn( _rn ) {} uint8_t rn;
  void disasm( std::ostream& sink ) const { sink << "push " << DisasmG( OP(), rn ); }
  void execute( ARCH& arch ) const { arch.template push<OP::SIZE>( arch.regread( OP(), rn ) ); }
};

template <class ARCH, unsigned OPSIZE>
struct PushImm : public Operation<ARCH>
{
  typedef typename CTypeFor<OPSIZE>::u imm_type;
  PushImm( OpBase<ARCH> const& opbase, imm_type _imm ) : Operation<ARCH>( opbase ), imm( _imm ) {} imm_type imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "push", (OPSIZE!=32)*OPSIZE ) << ' ' << DisasmI( imm ); }
  void execute( ARCH& arch ) const { arch.template push<OPSIZE>( typename TypeFor<ARCH,OPSIZE>::u( imm ) ); }
};

template <class ARCH, class OP>
struct Push : public Operation<ARCH>
{
  Push( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm ) : Operation<ARCH>( opbase ), rm( _rm ) {} RMOp<ARCH> rm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "push", rm.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const { arch.template push<OP::SIZE>( arch.rmread( OP(), rm ) ); }
};

template <class ARCH, unsigned OPSIZE>
struct PushSeg : public Operation<ARCH>
{
  PushSeg( OpBase<ARCH> const& opbase, uint8_t _seg ) : Operation<ARCH>( opbase ), seg( _seg ) {} uint8_t seg;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "push", (OPSIZE!=32)*OPSIZE ) << ' ' << DisasmS( seg ); }
  void execute( ARCH& arch ) const { arch.template push<OPSIZE>( typename TypeFor<ARCH,OPSIZE>::u( arch.segregread( seg ) ) ); }
};

template <class ARCH, class OP>
struct PushAll : public Operation<ARCH>
{
  PushAll( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "pusha", (OP::SIZE!=32)*OP::SIZE ); }
  void execute( ARCH& arch ) const
  {
    auto temp = arch.regread( OP(), 4 );
    for (int rn = 0; rn < 8; ++rn) arch.template push<OP::SIZE>( (rn == 4) ? temp : arch.regread( OP(), rn ) );
  }
};

template <class ARCH, unsigned OPSIZE>
struct Pushf : public Operation<ARCH>
{
  Pushf( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "pushf", (OPSIZE!=32)*OPSIZE ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
    u_type flags =
      /*CF*/ (u_type(arch.flagread( ARCH::FLAG::CF )) <<  0) |
      /* 1*/ (u_type(1)                          <<  1) |
      /*PF*/ (u_type(arch.flagread( ARCH::FLAG::PF )) <<  2) |
      /* 0*/ (u_type(0)                          <<  3) |
      /*AF*/ (u_type(arch.flagread( ARCH::FLAG::AF )) <<  4) |
      /* 0*/ (u_type(0)                          <<  5) |
      /*ZF*/ (u_type(arch.flagread( ARCH::FLAG::ZF )) <<  6) |
      /*SF*/ (u_type(arch.flagread( ARCH::FLAG::SF )) <<  7) |
      /*DF*/ (u_type(arch.flagread( ARCH::FLAG::DF )) << 10) |
      /*OF*/ (u_type(arch.flagread( ARCH::FLAG::OF )) << 11);

    arch.template push<OPSIZE>( flags );
  }
};

template <class ARCH> struct DC<ARCH,PUSH> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xff" ) /6 & RM() ))

    {
      if (ic.opsize()==16) return new Push<ARCH,GOw>( _.opbase(), _.rmop() );
      if (ic.mode64())
	return new Push<ARCH,GOq>( _.opbase(), _.rmop() );
      if (ic.opsize()==32)
	return new Push<ARCH,GOd>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, opcode("\x50") + Reg() ))

    {
      if (ic.opsize()==16) return new PushReg<ARCH,GOw>( _.opbase(), _.ereg() );
      if (ic.mode64())     return new PushReg<ARCH,GOq>( _.opbase(), _.ereg() );
      if (ic.opsize()==32) return new PushReg<ARCH,GOd>( _.opbase(), _.ereg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x6a" ) & Imm<8>() ))

    {
      if (ic.opsize()==16)
	return new PushImm<ARCH,16>( _.opbase(), _.i( int16_t() )  );
      if (ic.mode64())
	return new PushImm<ARCH,64>( _.opbase(), _.i( int64_t() )  );
      if (ic.opsize()==32)
	return new PushImm<ARCH,32>( _.opbase(), _.i( int32_t() )  );
      return 0;
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\x68" ) & Imm<16>() ))

    return new PushImm<ARCH,16>( _.opbase(), _.i( int16_t() )  );

  if (auto _ = match( ic, opcode( "\x68" ) & Imm<32>() ))
    {
      if (ic.mode64())
	return new PushImm<ARCH,64>( _.opbase(), _.i( int64_t() )  );
      if (ic.opsize()==32)
	return new PushImm<ARCH,32>( _.opbase(), _.i( int32_t() )  );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xa0" ) ))
    return newPushSeg( ic.mode64() ? 64 : ic.opsize(), _.opbase(), FS );
  if (auto _ = match( ic, opcode( "\x0f\xa8" ) ))
    return newPushSeg( ic.mode64() ? 64 : ic.opsize(), _.opbase(), GS );

  if (not ic.mode64())
    {
      if (auto _ = match( ic, opcode( "\x06" ) ))
        return newPushSeg( ic.opsize(), _.opbase(), ES );
      if (auto _ = match( ic, opcode( "\x0e" ) ))
        return newPushSeg( ic.opsize(), _.opbase(), CS );
      if (auto _ = match( ic, opcode( "\x16" ) ))
        return newPushSeg( ic.opsize(), _.opbase(), SS );
      if (auto _ = match( ic, opcode( "\x1e" ) ))
        return newPushSeg( ic.opsize(), _.opbase(), DS );

      if (auto _ = match( ic, opcode( "\x60" ) ))

        {
          if (ic.opsize()==16) return new PushAll<ARCH,GOw>( _.opbase() );
          if (ic.opsize()==32) return new PushAll<ARCH,GOd>( _.opbase() );
          return 0;
        }
    }

  if (auto _ = match( ic, opcode( "\x9c" ) ))

    {
      if (ic.opsize()==16) return new Pushf<ARCH,16>( _.opbase() );
      if (ic.mode64())     return new Pushf<ARCH,64>( _.opbase() );
      if (ic.opsize()==32) return new Pushf<ARCH,32>( _.opbase() );
    }

  return 0;
}
Operation<ARCH>*
newPushSeg( unsigned opsize, OpBase<ARCH> const& opbase, uint8_t _seg )
{
  if (opsize==16) return new PushSeg<ARCH,16>( opbase, _seg );
  if (opsize==32) return new PushSeg<ARCH,32>( opbase, _seg );
  if (opsize==64) return new PushSeg<ARCH,64>( opbase, _seg );
  return 0;
}
};

template <class ARCH, class OP>
struct PopReg : public Operation<ARCH>
{
  PopReg( OpBase<ARCH> const& opbase, uint8_t _rn ) : Operation<ARCH>( opbase ), rn( _rn ) {} uint8_t rn;
  void disasm( std::ostream& sink ) const { sink << "pop " << DisasmG( OP(), rn ); }
  void execute( ARCH& arch ) const { arch.regwrite( OP(), rn, arch.template pop<OP::SIZE>() ); }
};

template <class ARCH, class OP>
struct Pop : public Operation<ARCH>
{
  Pop( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm ) : Operation<ARCH>( opbase ), rm( _rm ) {} RMOp<ARCH> rm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "pop", rm.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rm, arch.template pop<OP::SIZE>() ); }
};

template <class ARCH, unsigned OPSIZE>
struct PopSeg : public Operation<ARCH>
{
  PopSeg( OpBase<ARCH> const& opbase, uint8_t _seg ) : Operation<ARCH>( opbase ), seg( _seg ) {} uint8_t seg;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "pop", (OPSIZE!=32)*OPSIZE ) << ' ' << DisasmS( seg ); }
  void execute( ARCH& arch ) const { arch.segregwrite( seg, typename ARCH::u16_t( arch.template pop<OPSIZE>() )  ); }
};

template <class ARCH, class OP>
struct PopAll : public Operation<ARCH>
{
  PopAll( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "popa", (OP::SIZE!=32)*OP::SIZE ); }
  void execute( ARCH& arch ) const
  {
    for (int rn = 0; rn < 8; ++rn) {
      typename TypeFor<ARCH,OP::SIZE>::u value = arch.template pop<OP::SIZE>();
      if (rn != 4) arch.regwrite( OP(), rn, value );
    }
  }
};

template <class ARCH, unsigned OPSIZE>
struct Popf : public Operation<ARCH>
{
  Popf( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "popf", (OPSIZE!=32)*OPSIZE ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
    typedef typename ARCH::bit_t bit_t;
    u_type flags = arch.template pop<OPSIZE>();
    u_type const bitmask(1);

    arch.flagwrite( ARCH::FLAG::CF, bit_t( (flags >>  0) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::PF, bit_t( (flags >>  2) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::AF, bit_t( (flags >>  4) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::ZF, bit_t( (flags >>  6) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::SF, bit_t( (flags >>  7) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::DF, bit_t( (flags >> 10) & bitmask ) );
    arch.flagwrite( ARCH::FLAG::OF, bit_t( (flags >> 11) & bitmask ) );
  }
};

template <class ARCH> struct DC<ARCH,POP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x8f" ) /0 & RM() ))

    {
      if (ic.opsize()==16) return new Pop<ARCH,GOw>( _.opbase(), _.rmop() );
      if (ic.mode64())     return new Pop<ARCH,GOq>( _.opbase(), _.rmop() );
      if (ic.opsize()==32) return new Pop<ARCH,GOd>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x58" ) + Reg() ))

    {
      if (ic.opsize()==16) return new PopReg<ARCH,GOw>( _.opbase(), _.ereg() );
      if (ic.mode64())     return new PopReg<ARCH,GOq>( _.opbase(), _.ereg() );
      if (ic.opsize()==32) return new PopReg<ARCH,GOd>( _.opbase(), _.ereg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xa1" ) )) return newPopSeg( ic.opsize(), _.opbase(), FS );
  if (auto _ = match( ic, opcode( "\x0f\xa9" ) )) return newPopSeg( ic.opsize(), _.opbase(), GS );

  if (not ic.mode64())
    {
      if (auto _ = match( ic, opcode( "\x07" ) )) return newPopSeg( ic.opsize(), _.opbase(), ES );
      if (auto _ = match( ic, opcode( "\x17" ) )) return newPopSeg( ic.opsize(), _.opbase(), SS );
      if (auto _ = match( ic, opcode( "\x1f" ) )) return newPopSeg( ic.opsize(), _.opbase(), DS );

      if (auto _ = match( ic, opcode( "\x61" ) ))

        {
          if (ic.opsize()==16) return new PopAll<ARCH,GOw>( _.opbase() );
          if (ic.opsize()==32) return new PopAll<ARCH,GOd>( _.opbase() );
          return 0;
        }
    }

  if (auto _ = match( ic, opcode( "\x9d" ) ))

    {
      if (ic.opsize()==16) return new Popf<ARCH,16>( _.opbase() );
      if (ic.mode64())     return new Popf<ARCH,64>( _.opbase() );
      if (ic.opsize()==32) return new Popf<ARCH,32>( _.opbase() );
    }

  return 0;
}
Operation<ARCH>*
newPopSeg( unsigned opsize, OpBase<ARCH> const& opbase, uint8_t _seg )
{
  if (opsize==16) return new PopSeg<ARCH,16>( opbase, _seg );
  if (opsize==32) return new PopSeg<ARCH,32>( opbase, _seg );
  if (opsize==64) return new PopSeg<ARCH,64>( opbase, _seg );
  return 0;
}
};

template <class ARCH, class OP, bool GTOE>
struct MovRM : public Operation<ARCH>
{
  MovRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "mov " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm );
    else      sink << "mov " << DisasmE( OP(), rm ) << ',' << DisasmG( OP(), gn );
  }
  void execute( ARCH& arch ) const {
    if (GTOE) arch.rmwrite( OP(), rm, arch.regread( OP(), gn ) );
    else      arch.regwrite( OP(), gn, arch.rmread( OP(), rm ) );
  }
};

template <class ARCH, class OP>
struct MovImm : public Operation<ARCH>
{
  typedef typename CTypeFor<OP::SIZE>::u imm_type;
  MovImm( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, imm_type _imm ) : Operation<ARCH>( opbase ), rm( _rm ), imm( _imm ) {} RMOp<ARCH> rm; imm_type imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "mov", rm.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rm, typename TypeFor<ARCH,OP::SIZE>::u( imm ) ); }
};

template <class ARCH, class OP, bool STOE>
struct MovSeg : public Operation<ARCH>
{
  MovSeg( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _seg ) : Operation<ARCH>( opbase ), seg( _seg ), rm( std::move(_rm) ) {} uint8_t seg; RMOp<ARCH> rm;
  void disasm( std::ostream& sink ) const {
    if (STOE) sink << "mov " << DisasmS( seg ) << ',' << DisasmE( OP(), rm );
    else      sink << "mov " << DisasmE( OP(), rm ) << ',' << DisasmS( seg );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u16_t u16_t;

    if (STOE) arch.rmwrite( OP(), rm, typename TypeFor<ARCH,OP::SIZE>::u( arch.segregread( seg ) ) );
    else      arch.segregwrite( seg, u16_t( arch.rmread( OP(), rm ) ) );
  }
};

template <class ARCH> struct DC<ARCH,MOV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // MOV -- Move
  if (auto _ = match( ic, opcode( "\x88" ) & RM() ))
    {
      if (ic.rex_p) return new MovRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new MovRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }
  if (auto _ = match( ic, opcode( "\x89" ) & RM() ))

    {
      if (ic.opsize()==16) return new MovRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new MovRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new MovRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x8a" ) & RM() ))

    {
      if (ic.rex_p) return new MovRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new MovRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\x8b" ) & RM() ))

    {
      if (ic.opsize()==16) return new MovRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new MovRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new MovRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x8c" ) & RM() ))

    return newMovSeg<true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, opcode( "\x8e" ) & RM() ))

    return newMovSeg<false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, opcode( "\xa0" ) & Moffs() ))

    {
      if (ic.rex_p) return new MovRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), 0 );
      else          return new MovRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), 0 );
    }

  if (auto _ = match( ic, opcode( "\xa1" ) & Moffs() ))

    {
      if (ic.opsize()==16) return new MovRM<ARCH,GOw,false>( _.opbase(), _.rmop(), 0 );
      if (ic.opsize()==32) return new MovRM<ARCH,GOd,false>( _.opbase(), _.rmop(), 0 );
      if (ic.opsize()==64) return new MovRM<ARCH,GOq,false>( _.opbase(), _.rmop(), 0 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xa2" ) & Moffs() ))

    {
      if (ic.rex_p) return new MovRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), 0 );
      else          return new MovRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), 0 );
    }

  if (auto _ = match( ic, opcode( "\xa3" ) & Moffs() ))

    {
      if (ic.opsize()==16) return new MovRM<ARCH,GOw,true>( _.opbase(), _.rmop(), 0 );
      if (ic.opsize()==32) return new MovRM<ARCH,GOd,true>( _.opbase(), _.rmop(), 0 );
      if (ic.opsize()==64) return new MovRM<ARCH,GOq,true>( _.opbase(), _.rmop(), 0 );
      return 0;
    }

  if (auto _ = match( ic, (opcode( "\xb0" ) + Reg()) & Imm<8>() ))

    {
      if (ic.rex_p) return new MovImm<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new MovImm<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & (opcode( "\xb8" ) + Reg()) & Imm<16>() ))

    return new MovImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & (opcode( "\xb8" ) + Reg()) & Imm<32>() ))

    return new MovImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & (opcode( "\xb8" ) + Reg()) & Imm<64>() ))

    return new MovImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int64_t() ) );

  if (auto _ = match( ic, opcode( "\xc6" ) /0 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new MovImm<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new MovImm<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\xc7" ) /0 & RM() & Imm<16>() ))

    return new MovImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\xc7" ) /0 & RM() & Imm<32>() ))

    return new MovImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\xc7" ) /0 & RM() & Imm<32>() ))

    return new MovImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int64_t() ) );

  return 0;
}
template <bool DIR> Operation<ARCH>* newMovSeg( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (gn >= 6) return 0; /* Intel manual only says encoding reserved, do not use... */
  if (ic.opsize()==16) return new MovSeg<ARCH,GOw,DIR>( opbase, std::move(rm), gn );
  if (ic.opsize()==32) return new MovSeg<ARCH,GOd,DIR>( opbase, std::move(rm), gn );
  if (ic.opsize()==64) return new MovSeg<ARCH,GOq,DIR>( opbase, std::move(rm), gn );
  return 0;
}
};

template <class ARCH, class SOP, class DOP>
struct Movzx : public Operation<ARCH>
{
  Movzx( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const {
    sink << "movz" << SizeID<SOP::SIZE>::gid() << SizeID<DOP::SIZE>::gid() << ' ' << DisasmE( SOP(), rm ) << ',' << DisasmG( DOP(), gn );
  }
  typedef typename TypeFor<ARCH,DOP::SIZE>::u u_type;
  void execute( ARCH& arch ) const { arch.regwrite( DOP(), gn, u_type( arch.rmread( SOP(), rm ) ) ); }
};

template <class ARCH> struct DC<ARCH,MOVZX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // MOVZX -- Move with Zero-Extend
  if (auto _ = match( ic, opcode( "\x0f\xb6" ) & RM() ))
    {
      if (ic.rex_p)
        {
          if (ic.opsize()==16) return new Movzx<ARCH,GOb,GOw>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==32) return new Movzx<ARCH,GOb,GOd>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==64) return new Movzx<ARCH,GOb,GOq>( _.opbase(), _.rmop(), _.greg() );
        }
      else
        {
          if (ic.opsize()==16) return new Movzx<ARCH,GObLH,GOw>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==32) return new Movzx<ARCH,GObLH,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xb7" ) & RM() ))

    {
      if (ic.opsize()==32) return new Movzx<ARCH,GOw,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new Movzx<ARCH,GOd,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class SOP, class DOP>
struct Movsx : public Operation<ARCH>
{
  Movsx( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const {
    sink << "movs" << SizeID<SOP::SIZE>::gid() << SizeID<DOP::SIZE>::gid() << ' ' << DisasmE( SOP(), rm ) << ',' << DisasmG( DOP(), gn );
  }
  typedef typename TypeFor<ARCH,SOP::SIZE>::s ssrc_type;
  typedef typename TypeFor<ARCH,DOP::SIZE>::u udst_type;
  typedef typename TypeFor<ARCH,DOP::SIZE>::s sdst_type;
  void execute( ARCH& arch ) const { arch.regwrite( DOP(), gn, udst_type( sdst_type( ssrc_type( arch.rmread( SOP(), rm ) ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,MOVSX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // MOVSX -- Move with Zero-Extend
  if (auto _ = match( ic, opcode( "\x0f\xbe" ) & RM() ))

    {
      if (ic.rex_p)
        {
          if (ic.opsize()==16) return new Movsx<ARCH,GOb,GOw>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==32) return new Movsx<ARCH,GOb,GOd>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==64) return new Movsx<ARCH,GOb,GOq>( _.opbase(), _.rmop(), _.greg() );
        }
      else
        {
          if (ic.opsize()==16) return new Movsx<ARCH,GObLH,GOw>( _.opbase(), _.rmop(), _.greg() );
          if (ic.opsize()==32) return new Movsx<ARCH,GObLH,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xbf" ) & RM() ))

    {
      if (ic.opsize()==32) return new Movsx<ARCH,GOw,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new Movsx<ARCH,GOw,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, OpSize<64>() & opcode( "\x63" ) & RM() ))

    return new Movsx<ARCH,GOd,GOq>( _.opbase(), _.rmop(), _.greg() );

  return 0;
}};

template <class ARCH>
struct WriteDF : public Operation<ARCH>
{
  WriteDF( OpBase<ARCH> const& opbase, uint8_t _df ) : Operation<ARCH>( opbase ), df( _df ) {} uint8_t df;
  void disasm( std::ostream& sink ) const { sink << (df ? "std" : "cld"); }
  void execute( ARCH& arch ) const { arch.flagwrite( ARCH::FLAG::DF, typename ARCH::bit_t( df ) ); }
};

template <class ARCH> struct DC<ARCH,STD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xfc" ) + Var<1>() ))

    return new WriteDF<ARCH>( _.opbase(), _.var() );

  return 0;
}};

template <class ARCH>
struct Arpl : public Operation<ARCH>
{
  Arpl( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "arpl " << DisasmG( GOw(), gn ) << ',' << DisasmE( GOw(), rm ); }
};

template <class ARCH> struct DC<ARCH,ARPL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.mode64()) return 0;

  if (auto _ = match( ic, opcode( "\x63" ) & RM() ))

    return new Arpl<ARCH>( _.opbase(), _.rmop(), _.greg() );

  return 0;
}};

template <class ARCH, class OP>
struct CmpXchg : public Operation<ARCH>
{
  CmpXchg( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "cmpxchg " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }

  void execute( ARCH& arch ) const
  {
    auto dst_operand = arch.rmread( OP(), rm );

    eval_sub( arch, arch.regread( OP(), 0 ), dst_operand );

    if (arch.Test(arch.flagread(ARCH::FLAG::ZF)))
      arch.rmwrite( OP(), rm, arch.regread( OP(), gn ) );
    else
      arch.regwrite( OP(), 0, dst_operand );
    // """To simplify the interface to the processor’s bus, the
    // destination operand receives a write cycle without regard to
    // the result of the comparison.  The destination operand is
    // written back if the comparison fails; otherwise, the source
    // operand is written into the destination.  (The processor never
    // produces a locked read without also producing a locked
    // write.)"""  TODO: should we add `arch.rmwrite( OP(), rm,
    // dst_operand );` to the else clause ?
  }
};

template <class ARCH> struct DC<ARCH,CMPXCHG> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // CMPXCHG -- Compare and Exchange
  if (auto _ = match( ic, lockable( opcode( "\x0f\xb0" ) & RM() ) ))
    {
      if (ic.rex_p) return new CmpXchg<ARCH,GOb>  ( _.opbase(), _.rmop(), _.greg() );
      else          return new CmpXchg<ARCH,GObLH>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\x0f\xb1" ) & RM() ) ))
    {
      if (ic.opsize()==16) return new CmpXchg<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new CmpXchg<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new CmpXchg<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct CmpXchgBytes : public Operation<ARCH>
{
  typedef typename ARCH::addr_t addr_t;
  CmpXchgBytes( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm ) : Operation<ARCH>( opbase ), rm( _rm ) {} RMOp<ARCH> rm;
  void disasm( std::ostream& sink ) const { sink << "cmpxchg" << std::dec << OP::SIZE / 4 << "b " << DisasmM( rm ); }
  void execute( ARCH& arch ) const
  {
    addr_t mem_addr0 = rm->effective_address(arch);
    addr_t mem_addr1 = mem_addr0 + addr_t(OP::SIZE / 8);
    auto mem_operand0 =
      arch.template memread<OP::SIZE>( rm->segment, mem_addr0 );
    auto mem_operand1 =
      arch.template memread<OP::SIZE>( rm->segment, mem_addr1 );
    typename ARCH::bit_t equal0 = (arch.regread( OP(), 0 ) == mem_operand0);
    typename ARCH::bit_t equal1 = (arch.regread( OP(), 2 ) == mem_operand1);
    typename ARCH::bit_t equal = equal0 & equal1;
    arch.flagwrite( ARCH::FLAG::ZF, equal );
    if (arch.Test( equal )) {
      arch.template memwrite<OP::SIZE>( rm->segment, mem_addr0,
					arch.regread( OP(), 3 ) );
      arch.template memwrite<OP::SIZE>( rm->segment, mem_addr1,
					arch.regread( OP(), 1 ) );
    } else {
      arch.regwrite( OP(), 0, mem_operand0 );
      arch.regwrite( OP(), 2, mem_operand1 );
    }
  }
};

template <class ARCH> struct DC<ARCH,CMPXCHG8B> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // CMPXCHG8B/CMPXCHG16B -- Compare and Exchange Bytes
  if (auto _ = match( ic, lockable( opcode( "\x0f\xc7" ) /1 & RM_mem() ) ))

    {
      if (ic.opsize()==32) return new CmpXchgBytes<ARCH,GOd>( _.opbase(), _.rmop() );
      if (ic.opsize()==64) return new CmpXchgBytes<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Xchg : public Operation<ARCH>
{
  Xchg( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "xchg " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const
  {
    // Perform all reads before any write occurs
    u_type a = arch.regread( OP(), gn );
    u_type b = arch.rmread( OP(), rm );
    // rmwrite must go first as it may perform additional register reads for ModR/M address generation
    arch.rmwrite( OP(), rm, a );
    arch.regwrite( OP(), gn, b );
  }
};

template <class ARCH> struct DC<ARCH,XCHG> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode("\x90") + Reg() ))

    if (MOp<ARCH>* x = _.rmop()) // xchg %a, %a => see nop
      {
        if (ic.opsize()==16) return new Xchg<ARCH,GOw>( _.opbase(), x, 0 );
        if (ic.opsize()==32) return new Xchg<ARCH,GOd>( _.opbase(), x, 0 );
        if (ic.opsize()==64) return new Xchg<ARCH,GOq>( _.opbase(), x, 0 );
        return 0;
      }

  if (auto _ = match( ic, lockable( opcode( "\x86" ) & RM() ) ))

    {
      if (ic.rex_p) return new Xchg<ARCH,GOb>  ( _.opbase(), _.rmop(), _.greg() );
      else          return new Xchg<ARCH,GObLH>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\x87" ) & RM() ) ))

    {
      if (ic.opsize()==16) return new Xchg<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new Xchg<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new Xchg<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH>
struct Hint : public Operation<ARCH>
{
  Hint(OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn, uint8_t _id ) : Operation<ARCH>( opbase ), rm(_rm), gn(_gn), id(_id) {} RMOp<ARCH> rm; uint8_t gn; uint8_t id;
  void disasm( std::ostream& sink ) const { sink << "hint<1" << int(id) << "> " << DisasmG( GOq(), gn ) << ',' << DisasmE( GOq(), rm ); }
  void execute( ARCH& arch ) const {}
};

template <class ARCH> struct DC<ARCH,HINT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, (opcode( "\x0f\x18" ) + Var<3>()) & RM() ))

    return new Hint<ARCH>( _.opbase(), _.rmop(), _.greg(), _.var() );

  return 0;
}};

template <class ARCH>
struct Nop : public Operation<ARCH>
{
  Nop( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "nop"; }
  void execute( ARCH& arch ) const {}
};

template <class ARCH> struct DC<ARCH,NOP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // NOP -- No Operation
  if (auto _ = match( ic, opcode( "\x90" ) ))

    return new Nop<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\x0f\x1f" ) /0 & RM() ))

    return new Nop<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH, class OP>
struct XAddEG : public Operation<ARCH>
{
  XAddEG( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "xadd " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    u_type a = arch.rmread( OP(), rm ), b = arch.regread( OP(), gn );
    u_type sum = eval_add( arch, a, b );
    arch.rmwrite( OP(), rm, sum  );
    arch.regwrite( OP(), gn, a );
  }
};

template <class ARCH> struct DC<ARCH,XADD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // XADD -- Exchange and Add
  if (auto _ = match( ic, lockable( opcode( "\x0f\xc0" ) & RM() ) ))

    {
      if (ic.rex_p) return new XAddEG<ARCH,GOb>  ( _.opbase(), _.rmop(), _.greg() );
      else          return new XAddEG<ARCH,GObLH>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\x0f\xc1" ) & RM() ) ))

    {
      if (ic.opsize()==16) return new XAddEG<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new XAddEG<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new XAddEG<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Cmovcc : public Operation<ARCH>
{
  Cmovcc( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn, uint8_t _cc )
    : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ), cc( _cc ) {} RMOp<ARCH> rm; uint8_t gn; uint8_t cc;
  void disasm( std::ostream& sink ) const { sink << "cmov" << DisasmCond( cc ) << ' ' << DisasmE( OP(), rm ) << ',' << DisasmG( OP(), gn ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u valtype;
    valtype res = (arch.Test( eval_cond( arch, cc ) )) ? arch.rmread( OP(), rm ) : arch.regread( OP(), gn );
    arch.regwrite( OP(), gn, res );
  }
};

template <class ARCH> struct DC<ARCH,CMOVCC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // CMOVcc -- Conditional Move
  if (auto _ = match( ic, (opcode( "\x0f\x40" ) + Var<4>()) & RM() ))

    {
      if (ic.opsize()==16) return new Cmovcc<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), _.var() );
      if (ic.opsize()==32) return new Cmovcc<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), _.var() );
      if (ic.opsize()==64) return new Cmovcc<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), _.var() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct BtImm : public Operation<ARCH>
{
  BtImm( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _imm ) : Operation<ARCH>( opbase ), rm( _rm ), imm( _imm ) {} RMOp<ARCH> rm; uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "bt", rm.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u valtype;
    valtype opr = arch.rmread( OP(), rm );
    typename ARCH::bit_t res( (opr >> (imm % OP::SIZE)) & valtype( 1 ) );
    arch.flagwrite( ARCH::FLAG::CF, res );
  }
};

template <class ARCH, class OP>
struct BtRM : public Operation<ARCH>
{
  BtRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "bt " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::addr_t addr_t;

    enum { BITSHIFT = meta::BitScan<OP::SIZE>::forward, LOGOPBYTES = meta::BitScan<OP::SIZE/8>::forward };

    typename TypeFor<ARCH,OP::SIZE>::s str_bit( arch.regread( OP(), gn ) );

    addr_t offset = addr_t((str_bit >> BITSHIFT) << LOGOPBYTES);
    u_type opr_bit = u_type(str_bit) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );
  }
};

template <class ARCH> struct DC<ARCH,BT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // BT -- BitOpcode
  if (auto _ = match( ic, opcode( "\x0f\xba" ) /4 & RM() & Imm<8>() ))

    {
      if (ic.opsize()==16) return new BtImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==32) return new BtImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==64) return new BtImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xa3" ) & RM() ))

    {
      if (ic.opsize()==16) return new BtRM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new BtRM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new BtRM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct BtcImm : public Operation<ARCH>
{
  BtcImm( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _imm ) : Operation<ARCH>( opbase ), rm( _rm ), imm( _imm ) {} RMOp<ARCH> rm; uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "btc", rm.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

    u_type opr_bit = u_type(imm) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );

    u_type next_str_opr = str_opr ^ (u_type( 1 ) << opr_bit);
    if (rm.ismem()) {
      arch.template memwrite<OP::SIZE>( rm->segment, rm->effective_address( arch ), next_str_opr );
    } else {
      arch.regwrite( OP(), rm.ereg(), next_str_opr );
    }

  }
};

template <class ARCH, class OP>
struct BtcRM : public Operation<ARCH>
{
  BtcRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "btc " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::addr_t addr_t;

    enum { BITSHIFT = meta::BitScan<OP::SIZE>::forward, LOGOPBYTES = meta::BitScan<OP::SIZE/8>::forward };

    typename TypeFor<ARCH,OP::SIZE>::s str_bit( arch.regread( OP(), gn ) );

    addr_t offset = addr_t((str_bit >> BITSHIFT) << LOGOPBYTES);
    u_type opr_bit = u_type(str_bit) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );

    u_type next_str_opr = str_opr ^ (u_type( 1 ) << opr_bit);
    if (rm.ismem()) {
      arch.template memwrite<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset, next_str_opr );
    } else {
      arch.regwrite( OP(), rm.ereg(), next_str_opr );
    }

  }
};

template <class ARCH> struct DC<ARCH,BTC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // BTC -- Bit Test and Complement

  if (auto _ = match( ic, lockable( opcode( "\x0f\xba" ) /7 & RM() ) & Imm<8>() ))

    {
      if (ic.opsize()==16) return new BtcImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==32) return new BtcImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==64) return new BtcImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, lockable( opcode( "\x0f\xbb" ) & RM() ) ))

    {
      if (ic.opsize()==16) return new BtcRM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new BtcRM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new BtcRM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct BtrImm : public Operation<ARCH>
{
  BtrImm( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _imm ) : Operation<ARCH>( opbase ), rm( _rm ), imm( _imm ) {} RMOp<ARCH> rm; uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "btr", rm.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;


  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

    u_type opr_bit = u_type(imm) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );

    u_type next_str_opr = str_opr & (~(u_type( 1 ) << opr_bit));
    if (rm.ismem()) {
      arch.template memwrite<OP::SIZE>( rm->segment, rm->effective_address( arch ), next_str_opr );
    } else {
      arch.regwrite( OP(), rm.ereg(), next_str_opr );
    }

  }
};

template <class ARCH, class OP>
struct BtrRM : public Operation<ARCH>
{
  BtrRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "btr " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;


  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::addr_t addr_t;

    enum { BITSHIFT = meta::BitScan<OP::SIZE>::forward, LOGOPBYTES = meta::BitScan<OP::SIZE/8>::forward };

    typename TypeFor<ARCH,OP::SIZE>::s str_bit( arch.regread( OP(), gn ) );

    addr_t offset = addr_t((str_bit >> BITSHIFT) << LOGOPBYTES);
    u_type opr_bit = u_type(str_bit) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );

    u_type next_str_opr = str_opr & (~(u_type( 1 ) << opr_bit));
    if (rm.ismem()) {
      arch.template memwrite<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset, next_str_opr );
    } else {
      arch.regwrite( OP(), rm.ereg(), next_str_opr );
    }

  }
};

template <class ARCH> struct DC<ARCH,BTR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // BTR -- Bit Test and Reset

  if (auto _ = match( ic, lockable( opcode( "\x0f\xba" ) /6 & RM() ) & Imm<8>() ))

    {
      if (ic.opsize()==16) return new BtrImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==32) return new BtrImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==64) return new BtrImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, lockable( opcode( "\x0f\xb3" ) & RM() ) ))

    {
      if (ic.opsize()==16) return new BtrRM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new BtrRM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new BtrRM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct BtsImm : public Operation<ARCH>
{
  BtsImm( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _imm ) : Operation<ARCH>( opbase ), rm( _rm ), imm( _imm ) {} RMOp<ARCH> rm; uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "bts", rm.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const {
    unsigned bitoffset = imm % OP::SIZE;
    u_type opr = arch.rmread( OP(), rm );
    arch.flagwrite( ARCH::FLAG::CF,
            typename ARCH::bit_t( (opr >> bitoffset) & u_type( 1 ) ) );
    arch.rmwrite( OP(), rm, opr | (u_type( 1 ) << bitoffset) );
  }
};

template <class ARCH, class OP>
struct BtsRM : public Operation<ARCH>
{
  BtsRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "bts " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rm ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;


  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::addr_t addr_t;

    enum { BITSHIFT = meta::BitScan<OP::SIZE>::forward, LOGOPBYTES = meta::BitScan<OP::SIZE/8>::forward };

    typename TypeFor<ARCH,OP::SIZE>::s str_bit( arch.regread( OP(), gn ) );

    addr_t offset = addr_t((str_bit >> BITSHIFT) << LOGOPBYTES);
    u_type opr_bit = u_type(str_bit) % u_type(OP::SIZE);
    u_type str_opr = rm.ismem() ? arch.template memread<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset ) : arch.regread( OP(), rm.ereg() );

    arch.flagwrite( ARCH::FLAG::CF, typename ARCH::bit_t( (str_opr >> opr_bit) & u_type( 1 ) ) );

    u_type next_str_opr = str_opr | (u_type( 1 ) << opr_bit);
    if (rm.ismem()) {
      arch.template memwrite<OP::SIZE>( rm->segment, rm->effective_address( arch ) + offset, next_str_opr );
    } else {
      arch.regwrite( OP(), rm.ereg(), next_str_opr );
    }

  }
};

template <class ARCH> struct DC<ARCH,BTS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // BTS -- Bit Test and Reset

  if (auto _ = match( ic, lockable( opcode( "\x0f\xba" ) /5 & RM() ) & Imm<8>() ))

    {
      if (ic.opsize()==16) return new BtsImm<ARCH,GOw>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==32) return new BtsImm<ARCH,GOd>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      if (ic.opsize()==64) return new BtsImm<ARCH,GOq>( _.opbase(), _.rmop(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, lockable( opcode( "\x0f\xab" ) & RM() ) ))

    {
      if (ic.opsize()==16) return new BtsRM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new BtsRM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new BtsRM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Bswap : public Operation<ARCH>
{
  Bswap( OpBase<ARCH> const& opbase, uint8_t _rn ) : Operation<ARCH>( opbase ), rn( _rn ) {} uint8_t rn;
  void disasm( std::ostream& sink ) const { sink << "bswap " << DisasmG( OP(), rn ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const
  {
    u_type src = arch.regread( OP(), rn ), dst = ByteSwap(src);
    arch.regwrite( OP(), rn, dst );
  }
};

template <class ARCH> struct DC<ARCH,BSWAP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\xc8" ) + Reg() ))

    {
      if (ic.opsize()==16) return new Bswap<ARCH,GOw>( _.opbase(), _.ereg() );
      if (ic.opsize()==32) return new Bswap<ARCH,GOd>( _.opbase(), _.ereg() );
      if (ic.opsize()==64) return new Bswap<ARCH,GOq>( _.opbase(), _.ereg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Movnti : public Operation<ARCH>
{
  Movnti( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const override { sink << "movnti " << DisasmG( OP(), gn ) << ',' << DisasmM( rm ); }
  void execute( ARCH& arch ) const override { arch.rmwrite( OP(), rm, arch.regread( OP(), gn ) ); }
};

template <class ARCH> struct DC<ARCH,MOVNTI> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\xc3" ) & RM_mem() ))

    {
      if (ic.opsize()==16) return new Movnti<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==32) return new Movnti<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      if (ic.opsize()==64) return new Movnti<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct LoadFarPointer : public Operation<ARCH>
{
  LoadFarPointer( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn, uint8_t _seg )
    : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ), seg( _seg ) {} RMOp<ARCH> rm; uint8_t gn; uint8_t seg;
  void disasm( std::ostream& sink ) const { sink << "l" << DisasmS( seg ) << ' ' << DisasmM( rm ) << ',' << DisasmG( OP(), gn ); }
};

template <class ARCH> struct DC<ARCH,LFP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // LDS/LES/LFS/LGS/LSS -- Load Far Pointer

  if (auto _ = match( ic, opcode( "\xc5" ) & RM_mem() ))

    {
      if (ic.mode64()) return 0;
      if (ic.opsize()==16) return new LoadFarPointer<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), DS );
      if (ic.opsize()==32) return new LoadFarPointer<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), DS );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xb2" ) & RM_mem() ))

    {
      if (ic.opsize()==16) return new LoadFarPointer<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), SS );
      if (ic.opsize()==32) return new LoadFarPointer<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), SS );
      if (ic.opsize()==64) return new LoadFarPointer<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), SS );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xc4" ) & RM_mem() ))

    {
      if (ic.mode64()) return 0;
      if (ic.opsize()==16) return new LoadFarPointer<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), ES );
      if (ic.opsize()==32) return new LoadFarPointer<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), ES );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xb4" ) & RM_mem() ))

    {
      if (ic.opsize()==16) return new LoadFarPointer<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), FS );
      if (ic.opsize()==32) return new LoadFarPointer<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), FS );
      if (ic.opsize()==64) return new LoadFarPointer<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), FS );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xb5" ) & RM_mem() ))

    {
      if (ic.opsize()==16) return new LoadFarPointer<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), GS );
      if (ic.opsize()==32) return new LoadFarPointer<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), GS );
      if (ic.opsize()==64) return new LoadFarPointer<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), GS );
      return 0;
    }

  return 0;
}};

template <class ARCH>
struct PrefetchNop : public Operation<ARCH>
{
  PrefetchNop( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, char const* _mnemo ) : Operation<ARCH>( opbase ), rm( _rm ), mnemo( _mnemo ) {} RMOp<ARCH> rm; char const* mnemo;
  void disasm( std::ostream& sink ) const { sink << mnemo << " " << DisasmM( rm ); }
  void execute( ARCH& arch ) const {}
};

template <class ARCH> struct DC<ARCH,PREFETCH> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // PREFETCH -- Prefetch Data Into Caches
  if (auto _ = match( ic, opcode( "\x0f\x18" ) /1 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetcht0" );

  if (auto _ = match( ic, opcode( "\x0f\x18" ) /2 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetcht1" );

  if (auto _ = match( ic, opcode( "\x0f\x18" ) /3 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetcht2" );

  if (auto _ = match( ic, opcode( "\x0f\x18" ) /0 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetchnta" );

  if (auto _ = match( ic, opcode( "\x0f\x0d" ) /1 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetchw" );

  if (auto _ = match( ic, opcode( "\x0f\x0d" ) /2 & RM_mem() ))

    return new PrefetchNop<ARCH>( _.opbase(), _.rmop(), "prefetchwt1" );

  return 0;
}};

