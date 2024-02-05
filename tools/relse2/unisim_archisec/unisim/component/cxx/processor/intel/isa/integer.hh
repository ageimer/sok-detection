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

// TODO: check for clearing operation (sub and xor with same registers)

template <class ARCH, class OP, bool GTOE>
struct AddRM : public Operation<ARCH>
{
  AddRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn )
    : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {}
  RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const
  {
    if (GTOE) sink << "add " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "add " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_add( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_add( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct AddRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  AddRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "add", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_add( arch, arch.rmread( OP(), rmop ), u_type( imm ) ) ); }
};

template <class ARCH> struct DC<ARCH,ADD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\000" ) & RM() ) ))
    {
      if (ic.rex_p) return new AddRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new AddRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\001" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new AddRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AddRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AddRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\002" ) & RM() ))
    {
      if (ic.rex_p) return new AddRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new AddRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\003" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new AddRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AddRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AddRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\004" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AddRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new AddRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\005" ) & Imm<16>() ))
    return new AddRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\005" ) & Imm<32>() ))
    return new AddRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\005" ) & Imm<32>() ))
    return new AddRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /0 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AddRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new AddRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /0 & RM() ) & Imm<16>() ))
    return new AddRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /0 & RM() ) & Imm<32>() ))
    return new AddRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /0 & RM() ) & Imm<32>() ))
    return new AddRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /0 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new AddRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new AddRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new AddRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct OrRM : public Operation<ARCH>
{
  OrRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "or " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "or " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_or( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_or( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct OrRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  OrRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "or", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_or( arch, arch.rmread( OP(), rmop ), u_type( imm ) ) ); }
};

template <class ARCH> struct DC<ARCH,OR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\010" ) & RM() ) ))
    {
      if (ic.rex_p) return new OrRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new OrRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\011" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new OrRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new OrRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new OrRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\012" ) & RM() ))
    {
      if (ic.rex_p) return new OrRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new OrRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\013" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new OrRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new OrRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new OrRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\014" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new OrRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new OrRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\015" ) & Imm<16>() ))
    return new OrRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\015" ) & Imm<32>() ))
    return new OrRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\015" ) & Imm<32>() ))
    return new OrRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /1 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new OrRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new OrRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /1 & RM() ) & Imm<16>() ))
    return new OrRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /1 & RM() ) & Imm<32>() ))
    return new OrRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /1 & RM() ) & Imm<32>() ))
    return new OrRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /1 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new OrRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new OrRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new OrRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct AdcRM : public Operation<ARCH>
{
  AdcRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "adc " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "adc " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_adc( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_adc( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct AdcRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  AdcRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "adc", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_adc( arch, arch.rmread( OP(), rmop ), u_type(imm) ) ); }
};

template <class ARCH> struct DC<ARCH,ADC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\020" ) & RM() ) ))
    {
      if (ic.rex_p) return new AdcRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new AdcRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\021" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new AdcRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AdcRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AdcRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\022" ) & RM() ))
    {
      if (ic.rex_p) return new AdcRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new AdcRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\023" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new AdcRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AdcRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AdcRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\024" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AdcRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new AdcRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\025" ) & Imm<16>() ))
    return new AdcRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\025" ) & Imm<32>() ))
    return new AdcRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\025" ) & Imm<32>() ))
    return new AdcRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /2 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AdcRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new AdcRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /2 & RM() ) & Imm<16>() ))
    return new AdcRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /2 & RM() ) & Imm<32>() ))
    return new AdcRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /2 & RM() ) & Imm<32>() ))
    return new AdcRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /2 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new AdcRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new AdcRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new AdcRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct SbbRM : public Operation<ARCH>
{
  SbbRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "sbb " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "sbb " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_sbb( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_sbb( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct SbbRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  SbbRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "sbb", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_sbb( arch, arch.rmread( OP(), rmop ), u_type(imm) ) ); }
};

template <class ARCH> struct DC<ARCH,SBB> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\030" ) & RM() ) ))
    {
      if (ic.rex_p) return new SbbRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new SbbRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\031" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new SbbRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new SbbRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new SbbRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\032" ) & RM() ))
    {
      if (ic.rex_p) return new SbbRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new SbbRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\033" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new SbbRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new SbbRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new SbbRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\034" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new SbbRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new SbbRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\035" ) & Imm<16>() ))
    return new SbbRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\035" ) & Imm<32>() ))
    return new SbbRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\035" ) & Imm<32>() ))
    return new SbbRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /3 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new SbbRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new SbbRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /3 & RM() ) & Imm<16>() ))
    return new SbbRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /3 & RM() ) & Imm<32>() ))
    return new SbbRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /3 & RM() ) & Imm<32>() ))
    return new SbbRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /3 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new SbbRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new SbbRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new SbbRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct AndRM : public Operation<ARCH>
{
  AndRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "and " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "and " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_and( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_and( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct AndRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  AndRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "and", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_and( arch, arch.rmread( OP(), rmop ), u_type(imm) ) ); }
};

template <class ARCH, class OP>
struct Andn : public Operation<ARCH>
{
  Andn( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _vn, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), vn( _vn ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t vn, gn;

  void disasm( std::ostream& sink ) const {
    sink << "andn " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), vn ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    u_type res = eval_and( arch, arch.rmread( OP(), rmop ),
			   ~u_type(arch.regread( OP(), vn )) );
    arch.regwrite( OP(), gn, res );
  }
};

template <class ARCH> struct DC<ARCH,AND> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\040" ) & RM() ) ))
    {
      if (ic.rex_p) return new AndRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new AndRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\041" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new AndRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AndRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AndRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\042" ) & RM() ))
    {
      if (ic.rex_p) return new AndRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new AndRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\043" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new AndRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new AndRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new AndRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\044" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AndRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new AndRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\045" ) & Imm<16>() ))
    return new AndRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\045" ) & Imm<32>() ))
    return new AndRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\045" ) & Imm<32>() ))
    return new AndRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /4 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new AndRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new AndRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /4 & RM() ) & Imm<16>() ))
    return new AndRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /4 & RM() ) & Imm<32>() ))
    return new AndRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /4 & RM() ) & Imm<32>() ))
    return new AndRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /4 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new AndRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new AndRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new AndRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  if (auto _ = match( ic, vex( "\x0f\x38\xf2" ) & RM() )) {
    if (ic.f0() || not ic.vex() || ic.vlen() != 128) return 0;
    if (ic.w())
      return new Andn<ARCH,GOq>( _.opbase(), _.rmop(), _.vreg(), _.greg() );
    else
      return new Andn<ARCH,GOd>( _.opbase(), _.rmop(), _.vreg(), _.greg() );
  }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct SubRM : public Operation<ARCH>
{
  SubRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "sub " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "sub " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_sub( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_sub( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct SubRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  SubRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "sub", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_sub( arch, arch.rmread( OP(), rmop ), u_type(imm) ) ); }
};

template <class ARCH> struct DC<ARCH,SUB> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\050" ) & RM() ) ))
    {
      if (ic.rex_p) return new SubRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new SubRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\051" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new SubRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new SubRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new SubRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\052" ) & RM() ))
    {
      if (ic.rex_p) return new SubRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new SubRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\053" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new SubRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new SubRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new SubRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\054" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new SubRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new SubRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\055" ) & Imm<16>() ))
    return new SubRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\055" ) & Imm<32>() ))
    return new SubRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\055" ) & Imm<32>() ))
    return new SubRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /5 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new SubRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new SubRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /5 & RM() ) & Imm<16>() ))
    return new SubRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /5 & RM() ) & Imm<32>() ))
    return new SubRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /5 & RM() ) & Imm<32>() ))
    return new SubRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /5 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new SubRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new SubRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new SubRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct XorRM : public Operation<ARCH>
{
  XorRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "xor " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "xor " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) {
      u_type res = eval_xor( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
      arch.rmwrite( OP(), rmop, res );
    } else {
      u_type res = eval_xor( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
      arch.regwrite( OP(), gn, res );
    }
  }
};

template <class ARCH, class OP>
struct XorRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  XorRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "xor", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_xor( arch, arch.rmread( OP(), rmop ), u_type(imm) ) ); }
};

template <class ARCH> struct DC<ARCH,XOR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\060" ) & RM() ) ))
    {
      if (ic.rex_p) return new XorRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new XorRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, lockable( opcode( "\061" ) & RM() ) ))
    {
      if      (ic.opsize() == 16) return new XorRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new XorRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new XorRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\062" ) & RM() ))
    {
      if (ic.rex_p) return new XorRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new XorRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\063" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new XorRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new XorRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new XorRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\064" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new XorRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new XorRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\065" ) & Imm<16>() ))
    return new XorRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\065" ) & Imm<32>() ))
    return new XorRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\065" ) & Imm<32>() ))
    return new XorRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x80" ) /6 & RM() ) & Imm<8>() ))
    {
      if (ic.rex_p) return new XorRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new XorRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & lockable( opcode( "\x81" ) /6 & RM() ) & Imm<16>() ))
    return new XorRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & lockable( opcode( "\x81" ) /6 & RM() ) & Imm<32>() ))
    return new XorRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & lockable( opcode( "\x81" ) /6 & RM() ) & Imm<32>() ))
    return new XorRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, lockable( opcode( "\x83" ) /6 & RM() ) & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new XorRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new XorRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new XorRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool GTOE>
struct CmpRM : public Operation<ARCH>
{
  CmpRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const {
    if (GTOE) sink << "cmp " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop );
    else      sink << "cmp " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    if (GTOE) eval_sub( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) );
    else      eval_sub( arch, arch.regread( OP(), gn ), arch.rmread( OP(), rmop ) );
  }
};

template <class ARCH, class OP>
struct CmpRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  CmpRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "cmp", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { eval_sub( arch, arch.rmread( OP(), rmop ), u_type(imm) ); }
};

template <class ARCH> struct DC<ARCH,CMP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\070" ) & RM() ))
    {
      if (ic.rex_p) return new CmpRM<ARCH,GOb,  true>( _.opbase(), _.rmop(), _.greg() );
      else          return new CmpRM<ARCH,GObLH,true>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\071" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new CmpRM<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new CmpRM<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new CmpRM<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\072" ) & RM() ))
    {
      if (ic.rex_p) return new CmpRM<ARCH,GOb,  false>( _.opbase(), _.rmop(), _.greg() );
      else          return new CmpRM<ARCH,GObLH,false>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\073" ) & RM() ))
    {
      if      (ic.opsize() == 16) return new CmpRM<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new CmpRM<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new CmpRM<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    };

  if (auto _ = match( ic, opcode( "\074" ) & Imm<8>() ))
    {
      if (ic.rex_p) return new CmpRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new CmpRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\075" ) & Imm<16>() ))
    return new CmpRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\075" ) & Imm<32>() ))
    return new CmpRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\075" ) & Imm<32>() ))
    return new CmpRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, opcode( "\x80" ) /7 & RM() & Imm<8>() ))
    {
      if (ic.rex_p) return new CmpRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new CmpRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\x81" ) /7 & RM() & Imm<16>() ))
    return new CmpRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\x81" ) /7 & RM() & Imm<32>() ))
    return new CmpRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\x81" ) /7 & RM() & Imm<32>() ))
    return new CmpRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, opcode( "\x83" ) /7 & RM() & Imm<8>() ))
    {
      if      (ic.opsize() == 16) return new CmpRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new CmpRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new CmpRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );
      return 0;
    }

  return 0;
}};

/* ROL */

template <class ARCH, class OP>
struct RolRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  RolRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rol", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate( arch, LSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct RolRMCL : public Operation<ARCH>
{
  RolRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rol", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate( arch, LSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH> struct DC<ARCH,ROL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /0 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new RolRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new RolRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /0 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new RolRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new RolRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new RolRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /0 & RM() ))

    {
      if (ic.rex_p) return new RolRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new RolRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /0 & RM() ))

    {
      if      (ic.opsize() == 16) return new RolRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new RolRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new RolRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /0 & RM() ))

    {
      if (ic.rex_p) return new RolRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new RolRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /0 & RM() ))

    {
      if      (ic.opsize() == 16) return new RolRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new RolRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new RolRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

/* ROR */

template <class ARCH, class OP>
struct RorRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  RorRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "ror", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate( arch, RSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct RorRMCL : public Operation<ARCH>
{
  RorRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "ror", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate( arch, RSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH, class OP>
struct Rorx : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  Rorx( OpBase<ARCH> const& opbase, uint8_t _imm, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm( _imm ), gn(_gn) {} RMOp<ARCH> rmop; uint8_t imm, gn;

  void disasm( std::ostream& sink ) const {
    sink << "rorx" << SizeID<OP::SIZE>::iid() << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn );
  }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

  void execute( ARCH& arch ) const
  {
    intptr_t const bitsize = atpinfo<ARCH,u_type>::bitsize;
    u8_t const u8bitsize( bitsize );
    u_type arg1 = arch.rmread( OP(), rmop );
    u8_t arg2 = u8_t( imm );
    u8_t sharg = arg2 & shift_counter<ARCH,u_type>::mask();
    sharg = sharg % u8bitsize;
    u_type res = (arg1 << (u8bitsize - sharg)) | (arg1 >> sharg);
    arch.regwrite( OP(), gn, res );
  }
};

template <class ARCH> struct DC<ARCH,ROR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /1 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new RorRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new RorRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /1 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new RorRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new RorRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new RorRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /1 & RM() ))

    {
      if (ic.rex_p) return new RorRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new RorRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /1 & RM() ))

    {
      if      (ic.opsize() == 16) return new RorRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new RorRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new RorRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /1 & RM() ))

    {
      if (ic.rex_p) return new RorRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new RorRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /1 & RM() ))

    {
      if      (ic.opsize() == 16) return new RorRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new RorRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new RorRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, vex( "\xf2\x0f\x3a\xf0" ) & RM() & Imm<8>() )) {
    if (ic.f0() || not ic.vex() || ic.vreg() || ic.vlen() != 128) return 0;
    if (ic.w())
      return new Rorx<ARCH,GOq>( _.opbase(), _.i( int8_t() ), _.rmop(), _.greg() );
    else
      return new Rorx<ARCH,GOd>( _.opbase(), _.i( int8_t() ), _.rmop(), _.greg() );
  }

  return 0;
}};

/* RCL */

template <class ARCH, class OP>
struct RclRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  RclRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rcl", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate_carry( arch, LSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct RclRMCL : public Operation<ARCH>
{
  RclRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rcl", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate_carry( arch, LSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH> struct DC<ARCH,RCL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /2 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new RclRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new RclRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /2 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new RclRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new RclRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new RclRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /2 & RM() ))

    {
      if (ic.rex_p) return new RclRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new RclRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /2 & RM() ))

    {
      if      (ic.opsize() == 16) return new RclRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new RclRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new RclRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /2 & RM() ))

    {
      if (ic.rex_p) return new RclRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new RclRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /2 & RM() ))

    {
      if      (ic.opsize() == 16) return new RclRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new RclRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new RclRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

/* RCR */

template <class ARCH, class OP>
struct RcrRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  RcrRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rcr", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate_carry( arch, RSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct RcrRMCL : public Operation<ARCH>
{
  RcrRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "rcr", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_rotate_carry( arch, RSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH> struct DC<ARCH,RCR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /3 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new RcrRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new RcrRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /3 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new RcrRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new RcrRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new RcrRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /3 & RM() ))

    {
      if (ic.rex_p) return new RcrRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new RcrRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /3 & RM() ))

    {
      if      (ic.opsize() == 16) return new RcrRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new RcrRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new RcrRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /3 & RM() ))

    {
      if (ic.rex_p) return new RcrRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new RcrRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /3 & RM() ))

    {
      if      (ic.opsize() == 16) return new RcrRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new RcrRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new RcrRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

/* SHL */

template <class ARCH, class OP>
struct ShlRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  ShlRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "shl", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_shift( arch, LSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct ShlRMCL : public Operation<ARCH>
{
  ShlRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "shl", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_shift( arch, LSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH, class OP>
struct Shlx : public Operation<ARCH>
{
  Shlx( OpBase<ARCH> const& opbase, uint8_t _gn, MOp<ARCH> const* _rmop, uint8_t _vn ) : Operation<ARCH>( opbase ), rmop( _rmop ), vn( _vn ), gn( _gn ) {}
  RMOp<ARCH> rmop;
  uint8_t vn, gn;

  void disasm( std::ostream& sink ) const { sink << "shlx " << DisasmG( OP(), vn ) << ',' << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const {
    typedef typename TypeFor<ARCH,OP::SIZE>::u val_t;
    arch.regwrite( OP(), gn, arch.rmread( OP(), rmop ) << (arch.regread( OP(), vn ) & val_t(OP::SIZE - 1)) );
  }
};

template <class ARCH> struct DC<ARCH,SHL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /4 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new ShlRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new ShlRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /4 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new ShlRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new ShlRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new ShlRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /4 & RM() ))

    {
      if (ic.rex_p) return new ShlRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new ShlRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /4 & RM() ))

    {
      if      (ic.opsize() == 16) return new ShlRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new ShlRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new ShlRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /4 & RM() ))

    {
      if (ic.rex_p) return new ShlRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new ShlRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /4 & RM() ))

    {
      if      (ic.opsize() == 16) return new ShlRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new ShlRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new ShlRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, vex( "\x66\x0f\x38\xf7" ) & RM() ))

    {
      if ((not ic.vex()) || (ic.vlen() != 128)) return 0;
      if (ic.w())
	return new Shlx<ARCH,GOq>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
      else
	return new Shlx<ARCH,GOd>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
    }

  return 0;
}};

/* SHR */

template <class ARCH, class OP>
struct ShrRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  ShrRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "shr", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_shift( arch, RSHIFT(), arch.rmread( OP(), rmop ), u8_t( imm ) ) ); }
};

template <class ARCH, class OP>
struct ShrRMCL : public Operation<ARCH>
{
  ShrRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "shr", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_shift( arch, RSHIFT(), arch.rmread( OP(), rmop ), arch.regread( GOb(), 1 ) ) ); }
};

template <class ARCH, class OP>
struct Shrx : public Operation<ARCH>
{
  Shrx( OpBase<ARCH> const& opbase, uint8_t _gn, MOp<ARCH> const* _rmop, uint8_t _vn ) : Operation<ARCH>( opbase ), rmop( _rmop ), vn( _vn ), gn( _gn ) {}
  RMOp<ARCH> rmop;
  uint8_t vn, gn;

  void disasm( std::ostream& sink ) const { sink << "shrx " << DisasmG( OP(), vn ) << ',' << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const {
    typedef typename TypeFor<ARCH,OP::SIZE>::u val_t;
    arch.regwrite( OP(), gn, arch.rmread( OP(), rmop ) >> (arch.regread( OP(), vn ) & val_t(OP::SIZE - 1)) );
  }
};

template <class ARCH> struct DC<ARCH,SHR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /5 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new ShrRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new ShrRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /5 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new ShrRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new ShrRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new ShrRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /5 & RM() ))

    {
      if (ic.rex_p) return new ShrRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new ShrRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /5 & RM() ))

    {
      if      (ic.opsize() == 16) return new ShrRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new ShrRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new ShrRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /5 & RM() ))

    {
      if (ic.rex_p) return new ShrRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new ShrRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /5 & RM() ))

    {
      if      (ic.opsize() == 16) return new ShrRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new ShrRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new ShrRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, vex( "\xf2\x0f\x38\xf7" ) & RM() ))

    {
      if ((not ic.vex()) || (ic.vlen() != 128)) return 0;
      if (ic.w())
	return new Shrx<ARCH,GOq>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
      else
	return new Shrx<ARCH,GOd>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
    }

  return 0;
}};

/* SAR */

template <class ARCH, class OP>
struct SarRMI : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  SarRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; uint8_t imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "sar", rmop.ismem()*OP::SIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u uval_t;
    typedef typename TypeFor<ARCH,OP::SIZE>::s sval_t;

    arch.rmwrite( OP(), rmop, uval_t(eval_shift( arch, RSHIFT(), sval_t(arch.rmread( OP(), rmop )), u8_t( imm ) )) );
  }
};

template <class ARCH, class OP>
struct SarRMCL : public Operation<ARCH>
{
  SarRMCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "sar", rmop.ismem()*OP::SIZE ) << ' ' << "%cl," << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u uval_t;
    typedef typename TypeFor<ARCH,OP::SIZE>::s sval_t;
    arch.rmwrite( OP(), rmop, uval_t(eval_shift( arch, RSHIFT(), sval_t(arch.rmread( OP(), rmop )), arch.regread( GOb(), 1 ) )) );
  }
};

template <class ARCH, class OP>
struct Sarx : public Operation<ARCH>
{
  Sarx( OpBase<ARCH> const& opbase, uint8_t _gn, MOp<ARCH> const* _rmop, uint8_t _vn ) : Operation<ARCH>( opbase ), rmop( _rmop ), vn( _vn ), gn( _gn ) {}
  RMOp<ARCH> rmop;
  uint8_t vn, gn;

  void disasm( std::ostream& sink ) const { sink << "sarx " << DisasmG( OP(), vn ) << ',' << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const {
    typedef typename TypeFor<ARCH,OP::SIZE>::u val_t;
    typedef typename TypeFor<ARCH,OP::SIZE>::s sval_t;
    arch.regwrite( OP(), gn, val_t(sval_t(arch.rmread( OP(), rmop )) >> sval_t(arch.regread( OP(), vn ) & val_t(OP::SIZE - 1))) );
  }
};

template <class ARCH> struct DC<ARCH,SAR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xc0" ) /7 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new SarRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new SarRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, opcode( "\xc1" ) /7 & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new SarRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 32) return new SarRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else if (ic.opsize() == 64) return new SarRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd0" ) /7 & RM() ))

    {
      if (ic.rex_p) return new SarRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), 1 );
      else          return new SarRMI<ARCH,GObLH>( _.opbase(), _.rmop(), 1 );
    }

  if (auto _ = match( ic, opcode( "\xd1" ) /7 & RM() ))

    {
      if      (ic.opsize() == 16) return new SarRMI<ARCH,GOw>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 32) return new SarRMI<ARCH,GOd>( _.opbase(), _.rmop(), 1 );
      else if (ic.opsize() == 64) return new SarRMI<ARCH,GOq>( _.opbase(), _.rmop(), 1 );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xd2" ) /7 & RM() ))

    {
      if (ic.rex_p) return new SarRMCL<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new SarRMCL<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xd3" ) /7 & RM() ))

    {
      if      (ic.opsize() == 16) return new SarRMCL<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new SarRMCL<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new SarRMCL<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, vex( "\xf3\x0f\x38\xf7" ) & RM() ))

    {
      if ((not ic.vex()) || (ic.vlen() != 128)) return 0;
      if (ic.w())
	return new Sarx<ARCH,GOq>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
      else
	return new Sarx<ARCH,GOd>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
    }

  return 0;
}};

template <class ARCH, class OP>
struct TestRMG : public Operation<ARCH>
{
  TestRMG( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "test " << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { eval_and( arch, arch.rmread( OP(), rmop ), arch.regread( OP(), gn ) ); }
};

template <class ARCH, class OP>
struct TestRMI : public Operation<ARCH>
{
  enum { OPSIZE=OP::SIZE };
  typedef typename CTypeFor<OPSIZE>::s imm_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  TestRMI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, imm_type _imm ) : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm) {} RMOp<ARCH> rmop; imm_type imm;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "test", rmop.ismem()*OPSIZE ) << ' ' << DisasmI( imm ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { eval_and( arch, arch.rmread( OP(), rmop ), u_type(imm) ); }
};

template <class ARCH> struct DC<ARCH,TEST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x84" ) & RM() ))

    {
      if (ic.rex_p) return new TestRMG<ARCH,GOb>  ( _.opbase(), _.rmop(), _.greg() );
      else          return new TestRMG<ARCH,GObLH>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, opcode( "\x85" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new TestRMG<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new TestRMG<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new TestRMG<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\xf6" ) /0 & RM() & Imm<8>() ))

    {
      if (ic.rex_p) return new TestRMI<ARCH,GOb>  ( _.opbase(), _.rmop(), _.i( int8_t() ) );
      else          return new TestRMI<ARCH,GObLH>( _.opbase(), _.rmop(), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\xf7" ) /0 & RM() & Imm<16>() ))

    return new TestRMI<ARCH,GOw>( _.opbase(), _.rmop(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\xf7" ) /0 & RM() & Imm<32>() ))

    return new TestRMI<ARCH,GOd>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\xf7" ) /0 & RM() & Imm<32>() ))

    return new TestRMI<ARCH,GOq>( _.opbase(), _.rmop(), _.i( int32_t() ) );

  if (auto _ = match( ic, opcode( "\xa8" ) & Imm<8>() ))

    {
      if (ic.rex_p) return new TestRMI<ARCH,GOb>  ( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
      else          return new TestRMI<ARCH,GObLH>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int8_t() ) );
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\xa9" ) & Imm<16>() ))

    return new TestRMI<ARCH,GOw>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\xa9" ) & Imm<32>() ))

    return new TestRMI<ARCH,GOd>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\xa9" ) & Imm<32>() ))

    return new TestRMI<ARCH,GOq>( _.opbase(), make_rop<ARCH>( 0 ), _.i( int32_t() ) );

  return 0;
}};

template <class ARCH, class OP>
struct NotRM : public Operation<ARCH>
{
  NotRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "not", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, ~(arch.rmread( OP(), rmop )) ); }
};

template <class ARCH> struct DC<ARCH,NOT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\xf6" ) /2 & RM() ) ))

    {
      if (ic.rex_p) return new NotRM<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new NotRM<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, lockable( opcode( "\xf7" ) /2 & RM() ) ))

    {
      if      (ic.opsize() == 16) return new NotRM<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new NotRM<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new NotRM<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct NegRM : public Operation<ARCH>
{
  NegRM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "neg", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, eval_sub( arch, typename TypeFor<ARCH,OP::SIZE>::u( 0 ), arch.rmread( OP(), rmop ) ) ); }
};

template <class ARCH> struct DC<ARCH,NEG> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, lockable( opcode( "\xf6" ) /3 & RM() ) ))

    {
      if (ic.rex_p) return new NegRM<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new NegRM<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, lockable( opcode( "\xf7" ) /3 & RM() ) ))

    {
      if      (ic.opsize() == 16) return new NegRM<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new NegRM<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new NegRM<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct DivE : public Operation<ARCH>
{
  DivE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "div", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    u_type hi =  arch.regread( OP(), 2 ), lo = arch.regread( OP(), 0 );
    eval_div( arch, hi, lo, arch.rmread( OP(), rmop ) );
    arch.regwrite( OP(), 2, hi );
    arch.regwrite( OP(), 0, lo );
  }
};

template <class ARCH, class OP>
struct DivE8 : public Operation<ARCH>
{
  DivE8( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "div", rmop.ismem()*8 ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typename ARCH::u8_t hi = arch.regread( GObLH(), 4 ), lo = arch.regread( GObLH(), 0 );
    eval_div( arch, hi, lo, arch.rmread( OP(), rmop ) );
    arch.regwrite( GObLH(), 4, hi );
    arch.regwrite( GObLH(), 0, lo );
  }
};

template <class ARCH> struct DC<ARCH,DIV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xf6" ) /6 & RM() ))

    {
      if (ic.rex_p) return new DivE8<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new DivE8<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xf7" ) /6 & RM() ))

    {
      if      (ic.opsize() == 16) return new DivE<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new DivE<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new DivE<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct IDivE : public Operation<ARCH>
{
  IDivE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "idiv", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    s_type hi = s_type( arch.regread( OP(), 2 ) ), lo = s_type( arch.regread( OP(), 0 ) );
    eval_div( arch, hi, lo, s_type( arch.rmread( OP(), rmop ) ) );
    arch.regwrite( OP(), 2, u_type( hi ) );
    arch.regwrite( OP(), 0, u_type( lo ) );
  }
};

template <class ARCH, class OP>
struct IDivE8 : public Operation<ARCH>
{
  IDivE8( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "idiv", rmop.ismem()*8 ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::s8_t s_type;
    typedef typename ARCH::u8_t u_type;
    s_type hi = s_type( arch.regread( GObLH(), 4 ) ), lo = s_type( arch.regread( GObLH(), 0 ) );
    eval_div( arch, hi, lo, s_type( arch.rmread( OP(), rmop ) ) );
    arch.regwrite( GObLH(), 4, u_type( hi ) );
    arch.regwrite( GObLH(), 0, u_type( lo ) );
  }
};

template <class ARCH> struct DC<ARCH,IDIV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xf6" ) /7 & RM() ))

    {
      if (ic.rex_p) return new IDivE8<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new IDivE8<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xf7" ) /7 & RM() ))

    {
      if      (ic.opsize() == 16) return new IDivE<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new IDivE<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new IDivE<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct MulE : public Operation<ARCH>
{
  MulE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "mul", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typename TypeFor<ARCH,OP::SIZE>::u hi, lo = arch.regread( OP(), 0 );
    eval_mul( arch, hi, lo, arch.rmread( OP(), rmop ) );
    arch.regwrite( OP(), 2, hi );
    arch.regwrite( OP(), 0, lo );
  }
};

template <class ARCH, class OP>
struct MulE8 : public Operation<ARCH>
{
  MulE8( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "mul", rmop.ismem()*8 ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typename ARCH::u8_t hi, lo = arch.regread( GObLH(), 0 );
    eval_mul( arch, hi, lo, arch.rmread( OP(), rmop ) );
    arch.regwrite( GObLH(), 4, hi );
    arch.regwrite( GObLH(), 0, lo );
  }
};

template <class ARCH> struct DC<ARCH,MUL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xf6" ) /4 & RM() ))

    {
      if (ic.rex_p) return new MulE8<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new MulE8<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xf7" ) /4 & RM() ))

    {
      if      (ic.opsize() == 16) return new MulE<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new MulE<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new MulE<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct IMulE : public Operation<ARCH>
{
  IMulE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "imul", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    s_type hi(0), lo = s_type( arch.regread( OP(), 0 ) );
    eval_mul( arch, hi, lo, s_type( arch.rmread( OP(), rmop ) ) );
    arch.regwrite( OP(), 2, u_type( hi ) );
    arch.regwrite( OP(), 0, u_type( lo ) );
  }
};

template <class ARCH, class OP>
struct IMulE8 : public Operation<ARCH>
{
  IMulE8( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "imul", rmop.ismem()*8 ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::s8_t s_type;
    typedef typename ARCH::u8_t u_type;
    s_type hi, lo = s_type( arch.regread( GObLH(), 0 ) );
    eval_mul( arch, hi, lo, s_type( arch.rmread( OP(), rmop ) ) );
    arch.regwrite( GObLH(), 4, u_type( hi ) );
    arch.regwrite( GObLH(), 0, u_type( lo ) );
  }
};

template <class ARCH, class OP>
struct IMulGE : public Operation<ARCH>
{
  IMulGE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "imul " << DisasmE( OP(), rmop )  << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const { arch.regwrite( OP(), gn, arch.regread( OP(), gn ) * arch.rmread( OP(), rmop ) ); }
};

template <class ARCH, class OP>
struct IMulGEI : public Operation<ARCH>
{
  typedef typename CTypeFor<OP::SIZE>::s imm_type;

  IMulGEI( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn, imm_type _imm )
    : Operation<ARCH>( opbase ), rmop( _rmop ), imm(_imm), gn( _gn ) {} RMOp<ARCH> rmop; imm_type imm; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "imul " << DisasmI( imm ) << ',' << DisasmE( OP(), rmop )  << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;

    s_type acc( arch.rmread( OP(), rmop ) ), src( imm ), hi(0);
    eval_mul( arch, hi, acc, src );
    arch.regwrite( OP(), gn, u_type( acc ) );
    // twice res  = twice( imm ) * twice( s_type( arch.rmread( OP(), rmop ) ) );
    // bit_t flag = res != twice( s_type( res ) );
    // arch.flagwrite( ARCH::FLAG::OF, flag );
    // arch.flagwrite( ARCH::FLAG::CF, flag );
  }
};

template <class ARCH> struct DC<ARCH,IMUL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xf6" ) /5 & RM() ))

    {
      if (ic.rex_p) return new IMulE8<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new IMulE8<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, opcode( "\xf7" ) /5 & RM() ))

    {
      if      (ic.opsize() == 16) return new IMulE<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new IMulE<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new IMulE<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xaf" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new IMulGE<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new IMulGE<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new IMulGE<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x6b" ) & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new IMulGEI<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), _.i( int16_t() ) );
      else if (ic.opsize() == 32) return new IMulGEI<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), _.i( int32_t() ) );
      else if (ic.opsize() == 64) return new IMulGEI<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), _.i( int64_t() ) );
      return 0;
    }

  if (auto _ = match( ic, OpSize<16>() & opcode( "\x69" ) & RM() & Imm<16>() ))

    return new IMulGEI<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), _.i( int16_t() ) );

  if (auto _ = match( ic, OpSize<32>() & opcode( "\x69" ) & RM() & Imm<32>() ))

    return new IMulGEI<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), _.i( int32_t() ) );

  if (auto _ = match( ic, OpSize<64>() & opcode( "\x69" ) & RM() & Imm<32>() ))

    return new IMulGEI<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), _.i( int64_t() ) );

  return 0;
}};

template <class ARCH, class OP>
struct Lea : public Operation<ARCH>
{
  Lea( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "lea " << DisasmM( rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const { arch.regwrite( OP(), gn, typename TypeFor<ARCH,OP::SIZE>::u( rmop->effective_address( arch ) ) ); }
};

template <class ARCH> struct DC<ARCH,LEA> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x8d" ) & RM_mem() ))

    {
      if      (ic.opsize() == 16) return new Lea<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new Lea<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new Lea<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Inc : public Operation<ARCH>
{
  Inc( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "inc", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    // CF is not affected
    bit_t savedCF = arch.flagread( ARCH::FLAG::CF );
    arch.rmwrite( OP(), rmop, eval_add( arch, arch.rmread( OP(), rmop ), u_type( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::CF, savedCF );
  }
};

template <class ARCH, class OP>
struct Dec : public Operation<ARCH>
{
  Dec( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;

  void disasm( std::ostream& sink ) const { sink << DisasmMnemonic( "dec", rmop.ismem()*OP::SIZE ) << ' ' << DisasmE( OP(), rmop ); }

  typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    // CF is not affected
    bit_t savedCF = arch.flagread( ARCH::FLAG::CF );
    arch.rmwrite( OP(), rmop, eval_sub( arch, arch.rmread( OP(), rmop ), u_type( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::CF, savedCF );
  }
};

template <class ARCH> struct DC<ARCH,INCDEC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x40" ) + Reg() ))

    {
      if      (ic.mode64())       return 0;
      else if (ic.opsize() == 16) return new Inc<ARCH,GOw>( _.opbase(), make_rop<ARCH>( _.ereg() ) );
      else if (ic.opsize() == 32) return new Inc<ARCH,GOd>( _.opbase(), make_rop<ARCH>( _.ereg() ) );
      return 0;
    }

  if (auto _ = match( ic, lockable( opcode( "\xfe" ) /0 & RM() ) ))

    {
      if (ic.rex_p) return new Inc<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new Inc<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, lockable( opcode( "\xff" ) /0 & RM() ) ))

    {
      if      (ic.opsize() == 16) return new Inc<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new Inc<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new Inc<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x48" ) + Reg() ))

    {
      if      (ic.mode64())       return 0;
      if      (ic.opsize() == 16) return new Dec<ARCH,GOw>( _.opbase(), make_rop<ARCH>( _.ereg() ) );
      else if (ic.opsize() == 32) return new Dec<ARCH,GOd>( _.opbase(), make_rop<ARCH>( _.ereg() ) );
      return 0;
    }

  if (auto _ = match( ic, lockable( opcode( "\xfe" ) /1 & RM() ) ))

    {
      if (ic.rex_p) return new Dec<ARCH,GOb>  ( _.opbase(), _.rmop() );
      else          return new Dec<ARCH,GObLH>( _.opbase(), _.rmop() );
    }

  if (auto _ = match( ic, lockable( opcode( "\xff" ) /1 & RM() ) ))

    {
      if      (ic.opsize() == 16) return new Dec<ARCH,GOw>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 32) return new Dec<ARCH,GOd>( _.opbase(), _.rmop() );
      else if (ic.opsize() == 64) return new Dec<ARCH,GOq>( _.opbase(), _.rmop() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct SetCC : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  SetCC( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _cc ) : Operation<ARCH>( opbase ), rmop( _rmop ), cc( _cc ) {} RMOp<ARCH> rmop; uint8_t cc;

  void disasm( std::ostream& sink ) const { sink << "set" << DisasmCond( cc ) << ' ' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const { arch.rmwrite( OP(), rmop, u8_t( eval_cond( arch, cc ) ) ); }
};

template <class ARCH> struct DC<ARCH,SETCC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, (opcode( "\x0f\x90" ) + Var<4>()) & RM() ))
    {
      if (ic.rex_p) return new SetCC<ARCH,GOb>  ( _.opbase(), _.rmop(), _.var() );
      else          return new SetCC<ARCH,GObLH>( _.opbase(), _.rmop(), _.var() );
    }

  return 0;
}};

template <class ARCH, class OP>
struct ShldIM : public Operation<ARCH>
{
  ShldIM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn, uint8_t _sh )
    : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ), shift( _sh & c_shift_counter<OP::SIZE>::mask() ) {} RMOp<ARCH> rmop; uint8_t gn; uint8_t shift;

  void disasm( std::ostream& sink ) const { sink << "shld " << DisasmI( shift ) << ',' << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::bit_t bit_t;

    if (not shift)
      return;

    if (shift >= OP::SIZE)
      {
        // TODO: should set destination operand undefined
        // typename ARCH::FLAG::Code flags[] = {ARCH::FLAG::AF, ARCH::FLAG::CF, ARCH::FLAG::OF, ARCH::FLAG::PF, ARCH::FLAG::SF, ARCH::FLAG::ZF};
        // for (auto flag: flags)
        //   arch.flagwrite(flag, bit_t(false), bit_t(false));
        arch.unimplemented();
      }

    // TODO: should merge with the eval_shift architecture
    u_type const msb = u_type( 1 ) << (OP::SIZE-1);
    unsigned const rshift = OP::SIZE - shift;

    u_type acc = arch.rmread( OP(), rmop );
    u_type res = (acc << shift) | (arch.regread( OP(), gn ) >> rshift);

    arch.rmwrite( OP(), rmop, res );

    arch.flagwrite( ARCH::FLAG::AF, bit_t(false), bit_t(false) );
    arch.flagwrite( ARCH::FLAG::CF, bit_t((acc << (shift - 1)) & msb) );
    arch.flagwrite( ARCH::FLAG::OF, bit_t( (acc ^ res) & msb ), bit_t(shift == 1) );
    eval_PSZ( arch, res );
  }
};

template <class ARCH, class OP>
struct ShldCL : public Operation<ARCH>
{
  ShldCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn )
    : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "shld %cl," << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u8_t u8_t;
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    u8_t shift = arch.regread( GOb(), 1 );
    u_type result = eval_shift( arch, LSHIFT(), arch.rmread( OP(), rmop ), shift );
    shift &= shift_counter<ARCH,u_type>::mask();
    if (arch.Test(shift != u8_t(0)))
      result |= arch.regread( OP(), gn ) >> (u8_t(OP::SIZE) - shift);
    arch.rmwrite( OP(), rmop, result );
  }
};

template <class ARCH, class OP>
struct ShrdIM : public Operation<ARCH>
{
  ShrdIM( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn, uint8_t _sh )
    : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ), shift( _sh & c_shift_counter<OP::SIZE>::mask() ) {} RMOp<ARCH> rmop; uint8_t gn; uint8_t shift;

  void disasm( std::ostream& sink ) const { sink << "shrd " << DisasmI( shift ) << ',' << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typename TypeFor<ARCH,OP::SIZE>::u result = eval_shift( arch, RSHIFT(), arch.rmread( OP(), rmop ), typename ARCH::u8_t(shift) );
    if (shift)
      result |= arch.regread( OP(), gn ) << (OP::SIZE - shift);
    arch.rmwrite( OP(), rmop, result );
  }
};

template <class ARCH, class OP>
struct ShrdCL : public Operation<ARCH>
{
  ShrdCL( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn )
    : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "shrd %cl," << DisasmG( OP(), gn ) << ',' << DisasmE( OP(), rmop ); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u8_t u8_t;
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    u8_t shift = arch.regread( GOb(), 1 );
    u_type result = eval_shift( arch, RSHIFT(), arch.rmread( OP(), rmop ), shift );
    shift &= shift_counter<ARCH,u_type>::mask();
    if (arch.Test(shift != u8_t(0)))
      result |= arch.regread( OP(), gn ) << (u8_t(OP::SIZE) - shift);
    arch.rmwrite( OP(), rmop, result );
  }
};

template <class ARCH> struct DC<ARCH,SHD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\xa4" ) & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new ShldIM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      else if (ic.opsize() == 32) return new ShldIM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      else if (ic.opsize() == 64) return new ShldIM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xa5" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new ShldCL<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new ShldCL<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new ShldCL<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xac" ) & RM() & Imm<8>() ))

    {
      if      (ic.opsize() == 16) return new ShrdIM<ARCH,GOw>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      else if (ic.opsize() == 32) return new ShrdIM<ARCH,GOd>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      else if (ic.opsize() == 64) return new ShrdIM<ARCH,GOq>( _.opbase(), _.rmop(), _.greg(), _.i( uint8_t() ) );
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xad" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new ShrdCL<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new ShrdCL<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new ShrdCL<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP, bool LEAD>
struct BitScan : public Operation<ARCH>
{
  BitScan( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << (LEAD ? "bsr " : "bsf ") << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::bit_t bit_t;
    u_type src = arch.rmread( OP(), rmop );

    bit_t src_is_zero = (src == u_type( 0 ));
    arch.flagwrite( ARCH::FLAG::ZF, src_is_zero );
    arch.flagwrite( ARCH::FLAG::CF, bit_t(false), bit_t(false) );
    arch.flagwrite( ARCH::FLAG::OF, bit_t(false), bit_t(false) );
    arch.flagwrite( ARCH::FLAG::SF, bit_t(false), bit_t(false) );
    arch.flagwrite( ARCH::FLAG::AF, bit_t(false), bit_t(false) );
    arch.flagwrite( ARCH::FLAG::PF, bit_t(false), bit_t(false) );
    if (arch.Test( src_is_zero )) return;

    u_type res = LEAD ? (BitScanReverse( src )) : BitScanForward( src );

    arch.regwrite( OP(), gn, res );
  }
};

template <class ARCH, class OP, bool LEAD>
struct CountZeros : public Operation<ARCH>
{
  CountZeros( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << (LEAD ? "lzcnt " : "tzcnt ") << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u u_type;
    typedef typename ARCH::bit_t bit_t;
    u_type src = arch.rmread( OP(), rmop ), res;

    bit_t src_is_zero = (src == u_type( 0 ));
    arch.flagwrite( ARCH::FLAG::CF, src_is_zero );

    if (arch.Test( src_is_zero )) {
      res = u_type( OP::SIZE );
      arch.flagwrite( ARCH::FLAG::ZF, bit_t(0) );
    }
    else {
      res = LEAD ? (u_type(OP::SIZE-1) - BitScanReverse( src )) : BitScanForward( src );
      arch.flagwrite( ARCH::FLAG::ZF, res == u_type(0) );
    }

    for (typename ARCH::FLAG::Code flag : {ARCH::FLAG::PF, ARCH::FLAG::SF, ARCH::FLAG::AF, ARCH::FLAG::OF, })
      arch.flagwrite( flag, bit_t(false), bit_t(false) );

    arch.regwrite( OP(), gn, res );
  }
};

template <class ARCH> struct DC<ARCH,ZCNT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\xbc" ) & RM() ))

    {
      if (not ic.f3()) {
        if      (ic.opsize() == 16) return new BitScan<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 32) return new BitScan<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 64) return new BitScan<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      } else {
        if      (ic.opsize() == 16) return new CountZeros<ARCH,GOw,false>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 32) return new CountZeros<ARCH,GOd,false>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 64) return new CountZeros<ARCH,GOq,false>( _.opbase(), _.rmop(), _.greg() );
      }
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\xbd" ) & RM() ))

    {
      if (not ic.f3()) {
        if      (ic.opsize() == 16) return new BitScan<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 32) return new BitScan<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 64) return new BitScan<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      } else {
        if      (ic.opsize() == 16) return new CountZeros<ARCH,GOw,true>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 32) return new CountZeros<ARCH,GOd,true>( _.opbase(), _.rmop(), _.greg() );
        else if (ic.opsize() == 64) return new CountZeros<ARCH,GOq,true>( _.opbase(), _.rmop(), _.greg() );
      }
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Popcnt : public Operation<ARCH>
{
  Popcnt( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn )  : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;

  void disasm( std::ostream& sink ) const { sink << "popcnt " << DisasmE( OP(), rmop ) << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u op_type;
    //    op_type const zero = op_type( 0 );
    op_type const lsb = op_type( 1 );
    op_type src = arch.rmread( OP(), rmop ), cnt = op_type( 0 );

    for (unsigned idx = 0; idx < OP::SIZE; ++idx)
      cnt += ((src >> idx) & lsb);

    arch.regwrite( OP(), gn, cnt );
  }
};

template <class ARCH> struct DC<ARCH,POPCNT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, simdF3() & opcode( "\x0f\xb8" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new Popcnt<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new Popcnt<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 64) return new Popcnt<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH>
struct Cmc : public Operation<ARCH>
{
  Cmc( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "cmc"; }
  void execute( ARCH& arch ) const { arch.flagwrite( ARCH::FLAG::CF, not arch.flagread( ARCH::FLAG::CF ) ); }
};

template <class ARCH> struct DC<ARCH,CMC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xf5" ) ))

    return new Cmc<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH>
struct Sahf : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  Sahf( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "sahf"; }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    u8_t ah = arch.regread( GObLH(), 4 );
    arch.flagwrite( ARCH::FLAG::SF, bit_t( (ah >> 7) & u8_t( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::ZF, bit_t( (ah >> 6) & u8_t( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::AF, bit_t( (ah >> 4) & u8_t( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::PF, bit_t( (ah >> 2) & u8_t( 1 ) ) );
    arch.flagwrite( ARCH::FLAG::CF, bit_t( (ah >> 0) & u8_t( 1 ) ) );
  }
};

template <class ARCH>
struct Lahf : public Operation<ARCH>
{
  typedef typename ARCH::u8_t u8_t;
  Lahf( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "lahf"; }
  void execute( ARCH& arch ) const
  {
    u8_t ah =
      (u8_t( arch.flagread( ARCH::FLAG::SF ) ) << 7) |
      (u8_t( arch.flagread( ARCH::FLAG::ZF ) ) << 6) |
      (u8_t(                 0   ) << 5) |
      (u8_t( arch.flagread( ARCH::FLAG::AF ) ) << 4) |
      (u8_t(                 0   ) << 3) |
      (u8_t( arch.flagread( ARCH::FLAG::PF ) ) << 2) |
      (u8_t(                 1   ) << 1) |
      (u8_t( arch.flagread( ARCH::FLAG::CF ) ) << 0);
    arch.regwrite( GObLH(), 4, ah );
  }
};

template <class ARCH> struct DC<ARCH,AHF> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, opcode( "\x9e" ) ))

    return new Sahf<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\x9f" ) ))

    return new Lahf<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH, class GOP>
struct Csxe : public Operation<ARCH>
{
  Csxe( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  char const* mnemonic () const { switch (GOP::size()) { case 16: return "cbtw"; case 32: return "cwtde"; case 64: return "cdtqe"; } return "c<bad>e"; }
  void disasm( std::ostream& sink ) const { sink << mnemonic(); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOP::SIZE>::s sop_type;
    typedef typename TypeFor<ARCH,GOP::SIZE>::u uop_type;
    arch.regwrite( GOP(), 0, uop_type( sop_type( arch.regread( GOP(), 0 ) << (GOP::SIZE / 2) ) >> (GOP::SIZE / 2) ) );
  }
};

template <class ARCH, class GOP>
struct Csx : public Operation<ARCH>
{
  Csx( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  char const* mnemonic () const { switch (GOP::size()) { case 16: return "cwtd"; case 32: return "cdtq"; case 64: return "cqto"; } return "c<bad>"; }
  void disasm( std::ostream& sink ) const { sink << mnemonic(); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOP::SIZE>::s sop_type;
    typedef typename TypeFor<ARCH,GOP::SIZE>::u uop_type;
    arch.regwrite( GOP(), 2, uop_type( sop_type( arch.regread( GOP(), 0 ) ) >> (GOP::SIZE-1) ) );
  }
};

template <class ARCH> struct DC<ARCH,CSX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x98" ) ))

    {
      if (ic.opsize() == 16) return new Csxe<ARCH,GOw>( _.opbase() );
      if (ic.opsize() == 32) return new Csxe<ARCH,GOd>( _.opbase() );
      if (ic.opsize() == 64) return new Csxe<ARCH,GOq>( _.opbase() );
      return 0;
    }

  if (auto _ = match( ic,  opcode( "\x99" ) ))

    {
      if (ic.opsize() == 16) return new Csx<ARCH,GOw>( _.opbase() );
      if (ic.opsize() == 32) return new Csx<ARCH,GOd>( _.opbase() );
      if (ic.opsize() == 64) return new Csx<ARCH,GOq>( _.opbase() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Xlat : public Operation<ARCH>
{
  Xlat( OpBase<ARCH> const& opbase, uint8_t _segment ) : Operation<ARCH>( opbase ), segment( _segment ) {} uint8_t segment;
  void disasm( std::ostream& sink ) const { sink << "xlat"; }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OP::SIZE>::u uop_t;
    typedef typename ARCH::addr_t addr_t;
    arch.regwrite( GOb(), 0, arch.template memread<8>( segment, addr_t( arch.regread( OP(), 3 ) + uop_t( arch.regread( GOb(), 0 ) ) ) ) );
  }
};

template <class ARCH> struct DC<ARCH,XLAT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd7" ) ))

    {
      if      (ic.addrsize() == 16) return new Xlat<ARCH,GOw>( _.opbase(), ic.segment );
      else if (ic.addrsize() == 32) return new Xlat<ARCH,GOd>( _.opbase(), ic.segment );
      else if (ic.addrsize() == 64) return new Xlat<ARCH,GOq>( _.opbase(), ic.segment );
      return 0;
    }

  return 0;
}};

template <class ARCH>
struct AAA : public Operation<ARCH>
{
  AAA( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "aaa"; }
};

template <class ARCH>
struct AAS : public Operation<ARCH>
{
  AAS( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "aas"; }
};

template <class ARCH>
struct DAA : public Operation<ARCH>
{
  DAA( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "daa"; }
};

template <class ARCH>
struct DAS : public Operation<ARCH>
{
  DAS( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "das"; }
};

template <class ARCH>
struct AAD : public Operation<ARCH>
{
  AAD( OpBase<ARCH> const& opbase, uint8_t _imm ) : Operation<ARCH>( opbase ), imm(_imm) {} uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << "aad" << DisasmI( imm ); }
};

template <class ARCH>
struct AAM : public Operation<ARCH>
{
  AAM( OpBase<ARCH> const& opbase, uint8_t _imm ) : Operation<ARCH>( opbase ), imm(_imm) {} uint8_t imm;
  void disasm( std::ostream& sink ) const { sink << "aam" << DisasmI( imm ); }
};

template <class ARCH> struct DC<ARCH,ADJUST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.mode64()) return 0;

  if (auto _ = match( ic, opcode( "\xd5" ) & Imm<8>() ))

    return new AAD<ARCH>( _.opbase(), _.i( uint8_t() ) );

  if (auto _ = match( ic, opcode( "\xd4" ) & Imm<8>() ))

    return new AAM<ARCH>( _.opbase(), _.i( uint8_t() ) );

  if (auto _ = match( ic, opcode( "\x27" ) ))
 
    return new DAA<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\x2f" ) ))

    return new DAS<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\x37" ) ))

    return new AAA<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\x3f" ) ))

    return new AAS<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH, class OP>
struct Bound : public Operation<ARCH>
{
  Bound( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "bound " << DisasmG( OP(), gn ) << ',' << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,BOUND> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.mode64()) return 0;

  if (auto _ = match( ic, opcode( "\x62" ) & RM() ))

    {
      if      (ic.opsize() == 16) return new Bound<ARCH,GOw>( _.opbase(), _.rmop(), _.greg() );
      else if (ic.opsize() == 32) return new Bound<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
      return 0;
    }

  return 0;
}};

template <class ARCH, class OP>
struct Adcx : public Operation<ARCH>
{
  Adcx( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "adcx " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }
};

template <class ARCH, class OP>
struct Adox : public Operation<ARCH>
{
  Adox( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, uint8_t _gn ) : Operation<ARCH>( opbase ), rmop( _rmop ), gn( _gn ) {} RMOp<ARCH> rmop; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "adox " << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }
};

template <class ARCH> struct DC<ARCH,ADF> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  /* ADCX -- Unsigned Integer Addition of Two Operands with Carry Flag */
  if (auto _ = match( ic, simd66() & opcode( "\x0f\x38\xf6" ) & RM() ))

    {
      if (ic.opsize() == 64) return new Adcx<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      else                   return new Adcx<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
    }

  if (auto _ = match( ic, simdF3() & opcode( "\x0f\x38\xf6" ) & RM() ))

    {
      if (ic.opsize() == 64) return new Adox<ARCH,GOq>( _.opbase(), _.rmop(), _.greg() );
      else                   return new Adox<ARCH,GOd>( _.opbase(), _.rmop(), _.greg() );
    }

  return 0;
}};

template <class ARCH, class OP>
struct Bzhi : public Operation<ARCH>
{
  Bzhi( OpBase<ARCH> const& opbase, uint8_t _gn, MOp<ARCH> const* _rmop, uint8_t _vn ) : Operation<ARCH>( opbase ), rmop( _rmop ), vn( _vn ), gn( _gn ) {}
  RMOp<ARCH> rmop;
  uint8_t vn, gn;

  void disasm( std::ostream& sink ) const { sink << "bzhi " << DisasmG( OP(), vn ) << ',' << DisasmE( OP(), rmop ) << ',' << DisasmG( OP(), gn ); }

  void execute( ARCH& arch ) const {
    typedef typename TypeFor<ARCH,OP::SIZE>::u val_t;
    typedef typename ARCH::bit_t bit_t;
    val_t index = val_t(arch.regread( GOb(), vn ));
    bit_t carry = index >= val_t(OP::SIZE);
    val_t mask =
      ((val_t(carry) - val_t(1)) & (val_t(1) << index)) - val_t(1);
    arch.regwrite( OP(), gn, arch.rmread( OP(), rmop ) & mask );
    arch.flagwrite( ARCH::FLAG::CF, carry );
  }
};

template <class ARCH> struct DC<ARCH,BZHI> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, vex( "\x0f\x38\xf5" ) & RM() ))

    {
      if ((not ic.vex()) || (ic.vlen() != 128)) return 0;
      if (ic.mode64() && ic.w())
	return new Bzhi<ARCH,GOq>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
      else
	return new Bzhi<ARCH,GOd>( _.opbase(), _.greg(), _.rmop(), ic.vreg() );
    }

  return 0;
}};
