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

template <class ARCH>
struct F2xm1 : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  F2xm1( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "f2xm1"; }
  void execute( ARCH& arch ) const { arch.fwrite( 0, power( f64_t( 2.0 ), arch.fread( 0 ) ) - f64_t( 1.0 ) ); }
};

template <class ARCH> struct DC<ARCH,F2XM1> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // F2XM1 - Compute 2^x - 1
  if (auto _ = match( ic, opcode( "\xd9\xf0" ) ))
  
    return new F2xm1<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Fabs : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fabs( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fabs"; }
  void execute( ARCH& arch ) const
  {
    f64_t val = arch.fread( 0 );
    if (arch.Test( val < f64_t( 0.0 ) ))
      val = -val;
    arch.fwrite( 0, val );
  }
};

template <class ARCH> struct DC<ARCH,FABS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FABS - Absolute Value
  if (auto _ = match( ic, opcode( "\xd9\xe1" ) ))
  
    return new Fabs<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fadd : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fadd( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fadd" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) + f64_t( arch.template frmread<OPSIZE>( rmop ) ) ); }
};

template <class ARCH, bool P>
struct FaddReg : public Operation<ARCH>
{
  FaddReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fadd" << (P ? "p " : " ") << DisasmFPR(src) << ',' << DisasmFPR(dst); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( dst ) + arch.fread( src ) ); if (P) arch.fpop(); }
};

template <class ARCH, class OP>
struct Fiadd : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fiadd( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fiadd" << ((OP::SIZE==32) ? "l " : " ") << DisasmM( rmop ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) + f64_t( s_type( arch.rmread( OP(), rmop ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,FADD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd8" ) /0 & RM_mem() ))
  
    return new Fadd<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /0 & RM_mem() ))
  
    return new Fadd<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /0 & RM_reg() ))
  
    return new FaddReg<ARCH,false>( _.opbase(), _.ereg(), 0 );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /0 & RM_reg() ))
  
    return new FaddReg<ARCH,false>( _.opbase(), 0, _.ereg() );

  if (auto _ = match( ic, opcode( "\xde" ) /0 & RM_reg() ))
  
    return new FaddReg<ARCH,true>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /0 & RM_mem() ))
  
    return new Fiadd<ARCH,GOd>( _.opbase(), _.rmop() ); 
  
  if (auto _ = match( ic, opcode( "\xde" ) /0 & RM_mem() ))
  
    return new Fiadd<ARCH,GOw>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Fbld : public Operation<ARCH>
{
  Fbld( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fbld " << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FBLD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdf" ) /4 & RM_mem() ))
  
    return new Fbld<ARCH>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Fbstp_m80 : public Operation<ARCH>
{
  Fbstp_m80( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fbstp " << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FBSTP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdf" ) /6 & RM_mem() ))
  
    return new Fbstp_m80<ARCH>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Fchs : public Operation<ARCH>
{
  Fchs( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fchs"; }
  void execute( ARCH& arch ) const { arch.fwrite( 0, - arch.fread( 0 ) ); }
};

template <class ARCH> struct DC<ARCH,FCHS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xe0" ) ))
  
    return new Fchs<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Fnclex : public Operation<ARCH>
{
  Fnclex( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fnclex"; }
};

template <class ARCH> struct DC<ARCH,FCLEX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdb\xe2" ) ))
  
    return new Fnclex<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH, unsigned COND>
struct Fcmovcc : public Operation<ARCH>
{
  Fcmovcc( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fcmov" << (COND & 1 ? "n" : "") << (&"b\0\0e\0\0be\0u"[3*(COND >> 1)]) << " %st(" << unsigned(stidx) << "),%st";}
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    bit_t ok( false );
    switch (COND) {
    case 0: ok = arch.flagread( ARCH::FLAG::CF ); break; // fcmovb
    case 1: ok = not arch.flagread( ARCH::FLAG::CF ); break; // fcmovnb
    case 2: ok = arch.flagread( ARCH::FLAG::ZF ); break; // fcmove
    case 3: ok = not arch.flagread( ARCH::FLAG::ZF ); break; // fcmovne
    case 4: ok = arch.flagread( ARCH::FLAG::CF ) or arch.flagread( ARCH::FLAG::ZF ); break; // fcmovbe
    case 5: ok = not arch.flagread( ARCH::FLAG::CF ) and not arch.flagread( ARCH::FLAG::ZF ); break; // fcmovnbe
    case 6: ok = arch.flagread( ARCH::FLAG::PF ); break; // fcmovu
    case 7: ok = not arch.flagread( ARCH::FLAG::PF ); break; // fcmovnu
    }
    if (arch.Test( ok ))
      arch.fwrite( 0, arch.fread( stidx ) );
  }
};

template <class ARCH> struct DC<ARCH,FCMOV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FCMOVcc -- Floating-Point Conditional Move
  
  if (auto _ = match( ic, opcode( "\xda" ) /0 & RM_reg() ))
  
    return new Fcmovcc<ARCH,0>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /1 & RM_reg() ))
  
    return new Fcmovcc<ARCH,2>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /2 & RM_reg() ))
  
    return new Fcmovcc<ARCH,4>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /3 & RM_reg() ))
  
    return new Fcmovcc<ARCH,6>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /0 & RM_reg() ))
  
    return new Fcmovcc<ARCH,1>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /1 & RM_reg() ))
  
    return new Fcmovcc<ARCH,3>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /2 & RM_reg() ))
  
    return new Fcmovcc<ARCH,5>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /3 & RM_reg() ))
  
    return new Fcmovcc<ARCH,7>( _.opbase(), _.ereg() );
  
  return 0;
}};

template <class ARCH, bool P>
struct Fcom_m32 : public Operation<ARCH>
{
  Fcom_m32( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fcom" << (P?"p":"") << "s " << DisasmM( rmop ); }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fread( 0 );
    f64_t b = f64_t( arch.template frmread<32>( rmop ) );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);
    
    arch.flagwrite( ARCH::FLAG::C3, notge == notle );
    arch.flagwrite( ARCH::FLAG::C2, notge and notle );
    arch.flagwrite( ARCH::FLAG::C0, notge );
    if (P) arch.fpop();
  }
};

template <class ARCH, bool P>
struct Fcom_m64 : public Operation<ARCH>
{
  Fcom_m64( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fcom" << (P?"p":"") << "l " << DisasmM( rmop ); }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fread( 0 );
    f64_t b = arch.template frmread<64>( rmop );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::C3, notge == notle );
    arch.flagwrite( ARCH::FLAG::C2, notge and notle );
    arch.flagwrite( ARCH::FLAG::C0, notge );
    if (P) arch.fpop();
  }
};

template <class ARCH, bool P>
struct Fcom_stn_st0 : public Operation<ARCH>
{
  Fcom_stn_st0( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fcom" << (P?"p":"") << " %st(" << unsigned(stidx) << ")"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fread( 0 );
    f64_t b = arch.fread( stidx );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::C3, notge == notle );
    arch.flagwrite( ARCH::FLAG::C2, notge and notle );
    arch.flagwrite( ARCH::FLAG::C0, notge );
    if (P) arch.fpop();
  }
};

template <class ARCH>
struct Fcompp : public Operation<ARCH>
{
  Fcompp( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fcompp"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fpop();
    f64_t b = arch.fpop();
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::C3, notge == notle );
    arch.flagwrite( ARCH::FLAG::C2, notge and notle );
    arch.flagwrite( ARCH::FLAG::C0, notge );
  }
};

template <class ARCH> struct DC<ARCH,FCOM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FCOM/FCOMP/FCOMPP -- Compare Floating Point Values

  if (auto _ = match( ic, opcode( "\xd8" ) /2 & RM_mem() ))
  
    return new Fcom_m32<ARCH,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /2 & RM_mem() ))
  
    return new Fcom_m64<ARCH,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /2 & RM_reg() ))
  
    return new Fcom_stn_st0<ARCH,false>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /3 & RM_mem() ))

    return new Fcom_m32<ARCH,true>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdc" ) /3 & RM_mem() ))
  
    return new Fcom_m64<ARCH,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /3 & RM_reg() ))

    return new Fcom_stn_st0<ARCH,true>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xde\xd9" ) ))
  
    return new Fcompp<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, bool P>
struct Fcomi_st0_stn : public Operation<ARCH>
{
  Fcomi_st0_stn( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fcomi" << (P?"p":"") << " %st(" << unsigned(stidx) << "),%st"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fread( 0 );
    f64_t b = arch.fread( stidx );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::ZF, notge == notle );
    arch.flagwrite( ARCH::FLAG::PF, notge and notle );
    arch.flagwrite( ARCH::FLAG::CF, notge );
    if (P) arch.fpop();
  }
};

template <class ARCH, bool P>
struct Fucomi_st0_stn : public Operation<ARCH>
{
  Fucomi_st0_stn( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fucomi" << (P?"p":"") << " %st(" << unsigned(stidx) << "),%st"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::f64_t f64_t;
    
    f64_t a = arch.fread( 0 );
    f64_t b = arch.fread( stidx );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::ZF, notge == notle );
    arch.flagwrite( ARCH::FLAG::PF, notge and notle );
    arch.flagwrite( ARCH::FLAG::CF, notge );
    if (P) arch.fpop();
  }
};

template <class ARCH> struct DC<ARCH,FCOMI> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FCOMI/FCOMIP/FUCOMI/FUCOMIP -- Compare Floating Point Values and Set EFLAGS

  if (auto _ = match( ic, opcode( "\xdb" ) /6 & RM_reg() ))
  
    return new Fcomi_st0_stn<ARCH,false>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdf" ) /6 & RM_reg() ))
  
    return new Fcomi_st0_stn<ARCH,true>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /5 & RM_reg() ))
  
    return new Fucomi_st0_stn<ARCH,false>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xdf" ) /5 & RM_reg() ))
  
    return new Fucomi_st0_stn<ARCH,true>( _.opbase(), _.ereg() );
  
  return 0;
}};

template <class ARCH>
struct Fdecstp : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fdecstp( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fdecstp"; }
};

template <class ARCH>
struct Fincstp : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fincstp( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fincstp"; }
};

template <class ARCH> struct DC<ARCH,FINCDECSTP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xf6" ) ))

    return new Fdecstp<ARCH>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xf7" ) ))

    return new Fincstp<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fdiv : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fdiv( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fdiv" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  // void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) / f64_t( arch.template frmread<OPSIZE>( rmop ) ) ); }
};

template <class ARCH, bool P>
struct FdivReg : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FdivReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fdiv" << (P ? "p " : " ") << DisasmFPR(src) << ',' << DisasmFPR(dst); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( dst ) / arch.fread( src ) ); if (P) arch.fpop(); }
};

template <class ARCH, class OP>
struct Fidiv : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fidiv( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fidiv " << DisasmM( rmop ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) / f64_t( s_type( arch.rmread( OP(), rmop ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,FDIV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FDIV/FDIVP/FIDIV -- Floating-Point Divide
 
  if (auto _ = match( ic,  opcode( "\xd8" ) /6 & RM_mem() ))
  
    return new Fdiv<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic,  opcode( "\xdc" ) /6 & RM_mem() ))
  
    return new Fdiv<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /6 & RM_reg() ))
  
    return new FdivReg<ARCH,false>( _.opbase(), _.ereg(), 0 );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /7 & RM_reg() ))
  
    return new FdivReg<ARCH,false>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /7 & RM_reg() ))
  
    return new FdivReg<ARCH,true>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /6 & RM_mem() ))
  
    return new Fidiv<ARCH,GOw>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xde" ) /6 & RM_mem() ))
  
    return new Fidiv<ARCH,GOd>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fdivr : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fdivr( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fdivr" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fwrite( 0, f64_t( arch.template frmread<OPSIZE>( rmop ) ) / arch.fread( 0 ) ); }
};

template <class ARCH, bool P>
struct FdivrReg : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FdivrReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fdivr" << (P ? "p " : " ") << DisasmFPR(src) << ',' << DisasmFPR(dst); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( src ) / arch.fread( dst ) ); if (P) arch.fpop(); }
};

template <class ARCH, class OP>
struct Fidivr : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fidivr( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fidivr" << ((OP::SIZE==32) ? "l " : " ") << DisasmM( rmop ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
  void execute( ARCH& arch ) const { arch.fwrite( 0, f64_t( s_type( arch.rmread( OP(), rmop ) ) ) / arch.fread( 0 ) ); }
};

template <class ARCH> struct DC<ARCH,FDIVR> { Operation<ARCH>* get( InputCode<ARCH> const& ic ) 
{
  // FDIVR/FDIVRP/FIDIVR -- Reverse Divide
  
  if (auto _ = match( ic, opcode( "\xd8" ) /7 & RM_mem() ))
  
    return new Fdivr<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /7 & RM_mem() ))
  
    return new Fdivr<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /7 & RM_reg() ))

    return new FdivrReg<ARCH,false>( _.opbase(), _.ereg(), 0 );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /6 & RM_reg() ))
  
    return new FdivrReg<ARCH,false>( _.opbase(), 0, _.ereg() );

  if (auto _ = match( ic, opcode( "\xde" ) /6 & RM_reg() ))
  
    return new FdivrReg<ARCH,true>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /7 & RM_mem() ))
  
    return new Fidivr<ARCH,GOd>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xde" ) /7 & RM_mem() ))
  
    return new Fidivr<ARCH,GOw>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Ffree : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Ffree( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "ffree %st(" << unsigned(stidx) << ")"; }
};

template <class ARCH> struct DC<ARCH,FFREE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FFREE -- Free Floating-Point Register
  
  if (auto _ = match( ic, opcode( "\xdd" ) /0 & RM_reg() ))
  
    return new Ffree<ARCH>( _.opbase(), _.ereg() );
  
  return 0;
}};

template <class ARCH, bool P>
struct Ficom_m32 : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Ficom_m32( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "ficom" << (P?"p":"") << "l " << DisasmEd( rmop ); }
};

template <class ARCH, bool P>
struct Ficom_m16 : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Ficom_m16( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "ficom" << (P?"p":"") << " " << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FICOM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FICOM/FICOMP -- Compare Integer
  
  if (auto _ = match( ic, opcode( "\xde" ) /2 & RM_mem() ))
  
    return new Ficom_m16<ARCH,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /2 & RM_mem() ))
  
    return new Ficom_m32<ARCH,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /3 & RM_mem() ))
  
    return new Ficom_m16<ARCH,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /3 & RM_mem() ))
  
    return new Ficom_m32<ARCH,true>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH, class OP>
struct Fild : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fild( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  
  void disasm( std::ostream& sink ) const { sink << "fild" << (&"ll "[2-meta::BitScan<OP::SIZE/16>::forward]) << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fpush( f64_t( typename TypeFor<ARCH,OP::SIZE>::s( arch.rmread( OP(), rmop ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,FILD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FILD -- Load Integer
  
  if (auto _ = match( ic, opcode( "\xdf" ) /0 & RM_mem() ))
  
    return new Fild<ARCH,GOw>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdb" ) /0 & RM_mem() ))
  
    return new Fild<ARCH,GOd>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdf" ) /5 & RM_mem() ))

    return new Fild<ARCH,GOq>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Fninit : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fninit( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fninit"; }
  void execute( ARCH& arch ) const { arch.finit(); }
};

template <class ARCH> struct DC<ARCH,FINIT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FINIT/FNINIT -- Initialize Floating-Point Unit
  
  if (auto _ = match( ic, opcode( "\xdb\xe3" ) ))
  
    return new Fninit<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE, bool P>
struct Fist : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fist( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fist" << (&"ll "[2-meta::BitScan<OPSIZE/16>::forward]) << DisasmM( rmop ); }
  typedef typename TypeFor<ARCH,OPSIZE>::s s_type;
  typedef typename TypeFor<ARCH,OPSIZE>::u u_type;
  // void execute( ARCH& arch ) const { rmop->write_e<OPSIZE>( arch, u_type( s_type( firound( arch.fread( 0 ), arch.fcwreadRC() ) ) ) ); if (P) arch.fpop(); }
};

template <class ARCH> struct DC<ARCH,FIST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FIST/FISTP -- Store Integer
  
  if (auto _ = match( ic, opcode( "\xdf" ) /2 & RM_mem() ))
  
    return new Fist<ARCH,16,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /2 & RM_mem() ))
  
    return new Fist<ARCH,32,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdf" ) /3 & RM_mem() ))
  
    return new Fist<ARCH,16,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /3 & RM_mem() ))
  
    return new Fist<ARCH,32,true>( _.opbase(), _.rmop() );   
  
  if (auto _ = match( ic, opcode( "\xdf" ) /7 & RM_mem() ))
  
    return new Fist<ARCH,64,true>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fisttp : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fisttp( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fisttp" << (&"ll "[2-meta::BitScan<OPSIZE/16>::forward]) << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FISTTP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FISTTP -- Store Integer with Truncation
  
  if (auto _ = match( ic, opcode( "\xdf" ) /1 & RM_mem() ))
  
    return new Fisttp<ARCH,16>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /1 & RM_mem() ))
  
    return new Fisttp<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdd" ) /1 & RM_mem() ))
  
    return new Fisttp<ARCH,64>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fld : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fld( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fld" << ((OPSIZE==32) ? "s " : (OPSIZE==64) ? "l " : "t ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fpush( f64_t( arch.template frmread<OPSIZE>( rmop ) ) ); }
};

template <class ARCH>
struct Fld_stn : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fld_stn( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fld %st(" << unsigned(stidx) << ")"; }
  void execute( ARCH& arch ) const { arch.fpush( arch.fread( stidx ) ); }
};

template <class ARCH> struct DC<ARCH,FLD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FLD -- Load Floating Point Value

  if (auto _ = match( ic, opcode( "\xd9" ) /0 & RM_mem() ))
  
    return new Fld<ARCH,32>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdd" ) /0 & RM_mem() ))

    return new Fld<ARCH,64>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdb" ) /5 & RM_mem() ))

    return new Fld<ARCH,80>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xd9" ) /0 & RM_reg() ))
  
    return new Fld_stn<ARCH>( _.opbase(), _.ereg() );
 
  return 0;
}};

enum fldconst { FLD1 = 0, FLDL2T, FLDL2E, FLDPI, FLDLG2, FLDLN2, FLDZ };

template <class ARCH, fldconst FLDCONST>
struct FldConst : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FldConst( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const
  {
    switch (FLDCONST)
      {
      default:     sink << "fld<bad>"; break;
      case FLD1:   sink << "fld1";     break;
      case FLDL2T: sink << "fldl2t";   break;
      case FLDL2E: sink << "fldl2e";   break;
      case FLDPI:  sink << "fldpi";    break;
      case FLDLG2: sink << "fldlg2";   break;
      case FLDLN2: sink << "fldln2";   break;
      case FLDZ:   sink << "fldz";     break;
      }
  }
  void execute( ARCH& arch ) const
  {
    switch (FLDCONST)
      {
      default:     arch.unimplemented();                          break;
      case FLD1:   arch.fpush( f64_t( 1.0 ) );                    break;
      case FLDL2T: arch.unimplemented();                          break;
      case FLDL2E: arch.fpush( f64_t( 1.4426950408889634 ) );     break;
      case FLDPI:  arch.fpush( f64_t( 3.14159265358979323846 ) ); break;
      case FLDLG2: arch.unimplemented();                          break;
      case FLDLN2: arch.fpush( f64_t( 0.69314718055994530941 ) ); break;
      case FLDZ:   arch.fpush( f64_t( 0.0 ) );                    break;
      }
  }
};

template <class ARCH> struct DC<ARCH,FLDCONST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xe8" ) ))
  
    return new FldConst<ARCH,FLD1>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xe9" ) ))
  
    return new FldConst<ARCH,FLDL2T>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xea" ) ))
  
    return new FldConst<ARCH,FLDL2E>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xeb" ) ))
  
    return new FldConst<ARCH,FLDPI>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xec" ) ))
  
    return new FldConst<ARCH,FLDLG2>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xed" ) ))
  
    return new FldConst<ARCH,FLDLN2>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xee" ) ))
  
    return new FldConst<ARCH,FLDZ>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct FldCW : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FldCW( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fldcw " << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fcwwrite( arch.rmread( GOw(), rmop ) ); }
};

template <class ARCH>
struct FstCW : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FstCW( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fnstcw " << DisasmEd( rmop ); }
  void execute( ARCH& arch ) const { arch.rmwrite( GOw(), rmop, arch.fcwread() ); }
};

template <class ARCH> struct DC<ARCH,FLSCW> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FLDCW/FSTCW/FNSTCW -- Load/Store x87 FPU Control Word
  
  if (auto _ = match( ic, opcode( "\xd9" ) /5 & RM_mem() ))
  
    return new FldCW<ARCH>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd9" ) /7 & RM_mem() ))
  
    return new FstCW<ARCH>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Fldenv : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fldenv( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, bool _o16 ) : Operation<ARCH>( opbase ), rmop( _rmop ), o16( _o16 ) {} RMOp<ARCH> rmop; bool o16;
  void disasm( std::ostream& sink ) const { sink << "fldenv" << (o16 ? "s " : " ") << DisasmM( rmop ); }
};

template <class ARCH>
struct Fstenv : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fstenv( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, bool _o16 ) : Operation<ARCH>( opbase ), rmop( _rmop ), o16( _o16 ) {} RMOp<ARCH> rmop; bool o16;
  void disasm( std::ostream& sink ) const { sink << "fnstenvs " << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FLSENV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FLDENV/FSTENV/FNSTENV -- Load/Store x87 FPU Environment
  
  if (auto _ = match( ic, opcode( "\xd9" ) /4 & RM_mem() ))
  
    return new Fldenv<ARCH>( _.opbase(), _.rmop(), ic.opsize() == 16 );
  
  if (auto _ = match( ic, opcode( "\xd9" ) /6 & RM_mem() ))
  
    return new Fstenv<ARCH>( _.opbase(), _.rmop(), ic.opsize() == 16 );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fmul : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fmul( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fmul" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fpush( arch.fpop() * f64_t( arch.template frmread<OPSIZE>( rmop ) ) ); }
};

template <class ARCH, bool P>
struct FmulReg : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FmulReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fmul" << (P ? "p " : " ") << DisasmFPR( src ) << ',' << DisasmFPR( dst ); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( dst ) * arch.fread( src ) ); if (P) arch.fpop(); }
};

template <class ARCH, class OP>
struct Fimul : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fimul( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fimul " << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) * f64_t( typename TypeFor<ARCH,OP::SIZE>::s( arch.rmread( OP(), rmop ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,FMUL> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FMUL/FMULP/FIMUL -- Multiply
  
  if (auto _ = match( ic, opcode( "\xd8" ) /1 & RM_mem() ))
  
    return new Fmul<ARCH,32>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdc" ) /1 & RM_mem() ))
  
    return new Fmul<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /1 & RM_reg() ))
  
    return new FmulReg<ARCH,false>( _.opbase(), _.ereg(), 0 );

  if (auto _ = match( ic, opcode( "\xdc" ) /1 & RM_reg() ))
  
    return new FmulReg<ARCH,false>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /1 & RM_reg() ))

    return new FmulReg<ARCH,true>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /1 & RM_mem() ))
  
    return new Fimul<ARCH,GOd>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xde" ) /1 & RM_mem() ))

    return new Fimul<ARCH,GOw>( _.opbase(), _.rmop() );

  return 0;
}};

template <class ARCH>
struct Fnop : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fnop( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fnop"; }
};

template <class ARCH> struct DC<ARCH,FNOP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xd0" ) ))
  
    return new Fnop<ARCH>( _.opbase() );
  
  return 0;
}};
 
template <class ARCH>
struct Fsin : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsin( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fsin"; }
  // void execute( ARCH& arch ) const {
  //   f64_t angle = arch.fpop();
  //   arch.fpush( sine( angle ) );
  // }
};

template <class ARCH>
struct Fcos : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fcos( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fcos"; }
  // void execute( ARCH& arch ) const {
  //   f64_t angle = arch.fpop();
  //   arch.fpush( cosine( angle ) );
  // }
};

template <class ARCH>
struct Fsincos : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsincos( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fsincos"; }
  // void execute( ARCH& arch ) const
  // {
  //   f64_t angle = arch.fpop();
  //   arch.fpush( sine( angle ) );
  //   arch.fpush( cosine( angle ) );
  // }
};

template <class ARCH>
struct Fpatan : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fpatan( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fpatan"; }
  // void execute( ARCH& arch ) const
  // {
  //   f64_t y = arch.fread( 1 );
  //   f64_t x = arch.fread( 0 );
  //   f64_t r;
  //   if (mkbool( x == f64_t( 0. ) )) {
  //     if (mkbool( y < f64_t( 0. ) ))
  //       r = f64_t( -1.57079632679489661923 );
  //     else
  //       r = f64_t( +1.57079632679489661923 );
  //   } else {
  //     r = arctan( y/x );
  //     if (mkbool( x < f64_t( 0. ) )) {
  //       if (mkbool( y < f64_t( 0. ) ))
  //         r -= f64_t( 3.14159265358979323846 );
  //       else
  //         r += f64_t( 3.14159265358979323846 );
  //     }
  //   }
  //   arch.flagwrite( ARCH::FLAG::C0, bit_t( 0 ) );
  //   arch.fwrite( 1, r );
  //   arch.fpop();
  // }
};

template <class ARCH>
struct Fptan : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fptan( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fptan"; }
  // void execute( ARCH& arch ) const
  // {
  //   arch.fwrite( 1, tangent( arch.fread( 0 ) ) );
  //   arch.fpush( f64_t( 1.0 ) );
  //   arch.flagwrite( ARCH::FLAG::C2, bit_t( 0 ) );
  // }
};

template <class ARCH>
struct Fsqrt : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsqrt( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fsqrt"; }
  // void execute( ARCH& arch ) const { arch.fwrite( 0, square_root( arch.fread( 0 ) ) ); }
};

template <class ARCH>
struct Fyl2x : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fyl2x( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fyl2x"; }
  // void execute( ARCH& arch ) const
  // {
  //   f64_t y = arch.fread( 1 );
  //   f64_t x = arch.fread( 0 );

  //   f64_t r = y*logarithm( x );

  //   arch.fwrite( 1, r );
  //   arch.fpop();
  // }
};

template <class ARCH>
struct Fyl2xp1 : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fyl2xp1( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fyl2xp1"; }
};

template <class ARCH> struct DC<ARCH,FMATH> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FSIN -- Sine
  if (auto _ = match( ic, opcode( "\xd9\xfe" ) ))
  
    return new Fsin<ARCH>( _.opbase() );
  
  // FCOS -- Opcode
  if (auto _ = match( ic, opcode( "\xd9\xff" ) ))
 
    return new Fcos<ARCH>( _.opbase() );
  
  // FSINCOS -- Sine and Cosine
  if (auto _ = match( ic, opcode( "\xd9\xfb" ) ))

    return new Fsincos<ARCH>( _.opbase() );
  
  // FPATAN -- Partial Arctangent
  if (auto _ = match( ic, opcode( "\xd9\xf3" ) ))
  
    return new Fpatan<ARCH>( _.opbase() );
  
  // FPTAN -- Partial Tangent
  if (auto _ = match( ic, opcode( "\xd9\xf2" ) ))
  
    return new Fptan<ARCH>( _.opbase() );
  
  // FSQRT -- Square Root
  if (auto _ = match( ic, opcode( "\xd9\xfa" ) ))
  
    return new Fsqrt<ARCH>( _.opbase() );
  
  // FYL2X -- Compute y ∗ log2x
  if (auto _ = match( ic, opcode( "\xd9\xf1" ) ))
  
    return new Fyl2x<ARCH>( _.opbase() );

  // FYL2XP1 -- Compute y ∗ log2(x +1)
  if (auto _ = match( ic, opcode( "\xd9\xf9" ) ))
  
    return new Fyl2xp1<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH>
struct Fprem1 : public Operation<ARCH>
{
  Fprem1( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fprem1"; }
  void execute( ARCH& arch ) const
  {
    typename ARCH::f64_t res = eval_fprem1( arch, arch.fread( 0 ), arch.fread( 1 ) );
    
    arch.fwrite( 0, res );
  }
};

template <class ARCH>
struct Fprem : public Operation<ARCH>
{
  Fprem( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fprem"; }
  void execute( ARCH& arch ) const
  {
    typename ARCH::f64_t res = eval_fprem( arch, arch.fread( 0 ), arch.fread( 1 ) );
    
    arch.fwrite( 0, res );
  }
};

template <class ARCH> struct DC<ARCH,FPREM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FPREM -- Partial Remainder
  
  if (auto _ = match( ic, opcode( "\xd9\xf8" ) ))
  
    return new Fprem<ARCH>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\xd9\xf5" ) ))
  
    return new Fprem1<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Frndint : public Operation<ARCH>
{
  Frndint( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "frndint"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::f64_t f64_t;
    
    f64_t value = arch.fread( 0 );
    value = firound( value, arch.fcwreadRC() );
    arch.fwrite( 0, value );
  }
};

template <class ARCH> struct DC<ARCH,FRNDINT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FRNDINT -- Round to Integer
  
  if (auto _ = match( ic, opcode( "\xd9\xfc" ) ))
  
    return new Frndint<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Frstor : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Frstor( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, bool _o16 ) : Operation<ARCH>( opbase ), rmop( _rmop ), o16( _o16 ) {} RMOp<ARCH> rmop; bool o16;
  void disasm( std::ostream& sink ) const { sink << "frstor" << (o16 ? "s " : " ") << DisasmM( rmop ); }
};

template <class ARCH>
struct Fsave : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsave( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, bool _o16 ) : Operation<ARCH>( opbase ), rmop( _rmop ), o16( _o16 ) {} RMOp<ARCH> rmop; bool o16;
  void disasm( std::ostream& sink ) const { sink << "fnsave" << (o16 ? "s " : " ") << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FLSSTATE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FRSTOR/FSAVE/FNSAVE  Restore/Store x87 FPU State
  
  if (auto _ = match( ic, opcode( "\xdd" ) /4 & RM_mem() ))
  
    return new  Frstor<ARCH>( _.opbase(), _.rmop(), ic.opsize() == 16 );
  
  if (auto _ = match( ic, opcode( "\xdd" ) /6 & RM_mem() ))
  
    return new  Fsave<ARCH>( _.opbase(), _.rmop(), ic.opsize() == 16 );
  
  return 0;
}};

template <class ARCH>
struct Fscale : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fscale( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fscale"; }
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) * power( f64_t( 2 ), firound( arch.fread( 1 ), intel::x87frnd_toward0 ) ) ); }
};

template <class ARCH>
struct Fxtract : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fxtract( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fxtract"; }
};

template <class ARCH> struct DC<ARCH,FSCALE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xfd" ) ))
  
    return new Fscale<ARCH>( _.opbase() );

  if (auto _ = match( ic, opcode( "\xd9\xf4" ) ))
  
    return new Fxtract<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE, bool P>
struct Fst : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fst( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fst" << (P?"p":"") << ((OPSIZE==32) ? "s " : (OPSIZE==64) ? "l " : "t ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.template frmwrite<OPSIZE>( rmop, typename TypeFor<ARCH,OPSIZE>::f( arch.fread( 0 ) ) ); if (P) arch.fpop(); }
};

template <class ARCH, bool P>
struct Fst_stn_st0 : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fst_stn_st0( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fst" << (P?"p":"") << " %st(" << unsigned(stidx) << ")"; }
  void execute( ARCH& arch ) const { arch.fwrite( stidx, arch.fread( 0 ) ); if (P) arch.fpop(); }
};

template <class ARCH> struct DC<ARCH,FST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  
  if (auto _ = match( ic, opcode( "\xd9" ) /2 & RM_mem() ))
  
    return new  Fst<ARCH,32,false>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdd" ) /2 & RM_mem() ))
  
    return new  Fst<ARCH,64,false>( _.opbase(), _.rmop() );

  if (auto _ = match( ic, opcode( "\xdd" ) /2 & RM_reg() ))
  
    return new  Fst_stn_st0<ARCH,false>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xd9" ) /3 & RM_mem() ))
  
    return new  Fst<ARCH,32,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdd" ) /3 & RM_mem() ))
  
    return new  Fst<ARCH,64,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdb" ) /7 & RM_mem() ))
  
    return new  Fst<ARCH,80,true>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdd" ) /3 & RM_reg() ))

    return new  Fst_stn_st0<ARCH,true>( _.opbase(), _.ereg() );
  
  return 0;
}};

template <class ARCH>
struct Fnstsw : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fnstsw( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fnstsw " << DisasmEd( rmop ); }
  void execute( ARCH& arch ) const { arch.rmwrite( GOw(), rmop, fswread( arch ) ); }
};

template <class ARCH>
struct Fnstsw_ax : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fnstsw_ax( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fnstsw %ax"; }
  void execute( ARCH& arch ) const { arch.regwrite( GOw(), 0, fswread( arch ) ); }
};

template <class ARCH> struct DC<ARCH,FSTSW> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdd" ) /7 & RM_mem() ))
  
    return new Fnstsw<ARCH>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdf\xe0" ) ))
  
    return new Fnstsw_ax<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fsub : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsub( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fsub" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) - f64_t( arch.template frmread<OPSIZE>( rmop ) ) ); }
};

template <class ARCH, bool P>
struct FsubReg : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FsubReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fsub" << (P ? "p " : " ") << DisasmFPR( src ) << ',' << DisasmFPR( dst ); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( dst ) - arch.fread( src ) ); if (P) arch.fpop(); }
};

template <class ARCH, class OP>
struct Fisub : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fisub( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fisub" << ((OP::SIZE==32) ? "l " : " ") << DisasmM( rmop ); }
  typedef typename TypeFor<ARCH,OP::SIZE>::s s_type;
  void execute( ARCH& arch ) const { arch.fwrite( 0, arch.fread( 0 ) - f64_t( s_type( arch.rmread( OP(), rmop ) ) ) ); }
};

template <class ARCH> struct DC<ARCH,FSUB> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  // FSUB/FSUBP/FISUB -- Subtract
  if (auto _ = match( ic, opcode( "\xd8" ) /4 & RM_mem() ))
  
    return new Fsub<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /4 & RM_mem() ))
  
    return new Fsub<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /4 & RM_reg() ))
  
    return new FsubReg<ARCH,false>( _.opbase(), _.ereg(), 0 );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /5 & RM_reg() ))
  
    return new FsubReg<ARCH,false>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /5 & RM_reg() ))
  
    return new FsubReg<ARCH,true>( _.opbase(), 0, _.ereg() );

  if (auto _ = match( ic, opcode( "\xda" ) /4 & RM_mem() ))
  
    return new Fisub<ARCH,GOd>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /4 & RM_mem() ))
  
    return new Fisub<ARCH,GOw>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH, unsigned OPSIZE>
struct Fsubr : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fsubr( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fsubr" << ((OPSIZE==32) ? "s " : "l ") << DisasmM( rmop ); }
  void execute( ARCH& arch ) const { arch.fwrite( 0, f64_t( arch.template frmread<OPSIZE>( rmop ) ) - arch.fread( 0 ) ); }
};

template <class ARCH, bool P>
struct FsubrReg : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  FsubrReg( OpBase<ARCH> const& opbase, uint8_t _src, uint8_t _dst ) : Operation<ARCH>( opbase ), src( _src ), dst( _dst ) {} uint8_t src, dst;
  void disasm( std::ostream& sink ) const { sink << "fsubr" << (P ? "p " : " ") << DisasmFPR(src) << ',' << DisasmFPR(dst); }
  void execute( ARCH& arch ) const { arch.fwrite( dst, arch.fread( src ) - arch.fread( dst ) ); if (P) arch.fpop(); }
};

template <class ARCH, unsigned OPSIZE>
struct Fisubr : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fisubr( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop ) : Operation<ARCH>( opbase ), rmop( _rmop ) {} RMOp<ARCH> rmop;
  void disasm( std::ostream& sink ) const { sink << "fisubr" << ((OPSIZE==32) ? "l " : " ") << DisasmM( rmop ); }
};

template <class ARCH> struct DC<ARCH,FSUBR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd8" ) /5 & RM_mem() ))
  
    return new Fsubr<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /5 & RM_mem() ))
  
    return new Fsubr<ARCH,64>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xd8" ) /5 & RM_reg() ))
  
    return new FsubrReg<ARCH,false>( _.opbase(), _.ereg(), 0 );
  
  if (auto _ = match( ic, opcode( "\xdc" ) /4 & RM_reg() ))
  
    return new FsubrReg<ARCH,false>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /4 & RM_reg() ))
  
    return new FsubrReg<ARCH,true>( _.opbase(), 0, _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda" ) /5 & RM_mem() ))
  
    return new Fisubr<ARCH,32>( _.opbase(), _.rmop() );
  
  if (auto _ = match( ic, opcode( "\xde" ) /5 & RM_mem() ))
 
    return new Fisubr<ARCH,16>( _.opbase(), _.rmop() );
  
  return 0;
}};

template <class ARCH>
struct Ftst : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Ftst( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "ftst"; }
};

template <class ARCH> struct DC<ARCH,FTST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xe4" ) ))
  
    return new Ftst<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH, bool P>
struct Fucom_st0_stn : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fucom_st0_stn( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fucom" << (P?"p":"") << " %st(" << unsigned(stidx) << ")"; }
  // void execute( ARCH& arch ) const {
  //   f64_t a = arch.fread( 0 );
  //   f64_t b = arch.fread( stidx );
  //   bit_t notle = not (a <= b);
  //   bit_t notge = not (a >= b);

  //   arch.flagwrite( ARCH::FLAG::C3, notge == notle );
  //   arch.flagwrite( ARCH::FLAG::C2, notge and notle );
  //   arch.flagwrite( ARCH::FLAG::C0, notge );
  //   if (P) arch.fpop();
  // }
};

template <class ARCH>
struct Fucompp : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fucompp( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fucompp"; }
  // void execute( ARCH& arch ) const {
  //   f64_t a = arch.fpop();
  //   f64_t b = arch.fpop();
  //   bit_t notle = not (a <= b);
  //   bit_t notge = not (a >= b);

  //   arch.flagwrite( ARCH::FLAG::C3, notge == notle );
  //   arch.flagwrite( ARCH::FLAG::C2, notge and notle );
  //   arch.flagwrite( ARCH::FLAG::C0, notge );
  // }
};

template <class ARCH> struct DC<ARCH,FUCOM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdd" ) /4 & RM_reg() ))
  
    return new Fucom_st0_stn<ARCH,false>( _.opbase(), _.ereg() );

  if (auto _ = match( ic, opcode( "\xdd" ) /5 & RM_reg() ))
  
    return new Fucom_st0_stn<ARCH,true>( _.opbase(), _.ereg() );
  
  if (auto _ = match( ic, opcode( "\xda\xe9" ) ))
  
    return new Fucompp<ARCH>( _.opbase() );

  return 0;
}};

template <class ARCH>
struct Fxam : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fxam( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fxam"; }
  void execute( ARCH& arch ) const { arch.fxam(); }
};

template <class ARCH> struct DC<ARCH,FXAM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9\xe5" ) ))
  
    return new Fxam<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Fxch : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fxch( OpBase<ARCH> const& opbase, uint8_t _stidx ) : Operation<ARCH>( opbase ), stidx( _stidx ) {} uint8_t stidx;
  void disasm( std::ostream& sink ) const { sink << "fxch %st(" << unsigned(stidx) << ")"; }
  void execute( ARCH& arch ) const
  {
    f64_t a = arch.fread( 0 );
    f64_t b = arch.fread( stidx );
    arch.fwrite( 0, b );
    arch.fwrite( stidx, a );
  }
};

template <class ARCH> struct DC<ARCH,FXCH> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xd9" ) /1 & RM_reg() ))
  
    return new Fxch<ARCH>( _.opbase(), _.ereg() );
  
  return 0;
}};

template <class ARCH>
struct Fwait : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fwait( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "fwait"; }
  void execute( ARCH& arch ) const {}
};

template <class ARCH> struct DC<ARCH,FWAIT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x9b" ) ))
  
    return new Fwait<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct Fobsolete : public Operation<ARCH>
{
  typedef typename ARCH::f64_t f64_t;
  Fobsolete( OpBase<ARCH> const& opbase, char const* _msg ) : Operation<ARCH>( opbase ), msg( _msg ) {} char const* msg;
  void disasm( std::ostream& sink ) const { sink << msg; }
};

template <class ARCH> struct DC<ARCH,FOBSOLETE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xdb\xe0" ) )) return new Fobsolete<ARCH>( _.opbase(), "fneni(8087 only)" );
  if (auto _ = match( ic, opcode( "\xdb\xe1" ) )) return new Fobsolete<ARCH>( _.opbase(), "fndisi(8087 only)" );
  if (auto _ = match( ic, opcode( "\xdb\xe4" ) )) return new Fobsolete<ARCH>( _.opbase(), "fnsetpm(287 only)" );
  if (auto _ = match( ic, opcode( "\xdb\xe5" ) )) return new Fobsolete<ARCH>( _.opbase(), "frstpm(287 only)" );
  return 0;
}};

