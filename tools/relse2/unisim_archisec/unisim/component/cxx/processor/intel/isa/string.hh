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

// TODO: adress size should be managed correctly. In the end, memory
// reference should, most probably, all go through the ModRM mechanism
// (to hide address size management).

template <class ARCH>
struct StringEngine
{
  virtual bool tstcounter( ARCH& arch ) const = 0;
  virtual void deccounter( ARCH& arch ) const = 0;
  
  struct StrOp : public RMOp<ARCH>
  {
    StrOp( MOp<ARCH> const* _mop ) : RMOp<ARCH>(_mop) {}
    StrOp( StrOp const& _strop ) : RMOp<ARCH>(_strop.RMOp<ARCH>::mop) {}
    ~StrOp() { RMOp<ARCH>::mop = 0; /*prevent deletion*/ }
    friend std::ostream& operator << (std::ostream& sink, StrOp const& so)
    {
      so->disasm_memory_operand( sink );
      return sink;
    }
  };
  
  virtual StrOp getdst() const = 0;
  virtual StrOp getsrc( uint8_t segment ) const = 0;
  
  virtual void addsrc( ARCH& arch, int step ) const = 0;
  virtual void adddst( ARCH& arch, int step ) const = 0;
  
  virtual ~StringEngine() {};
};

/*  According to the specification and the actual hardware, in the
 * repeated string instruction, the null counter termination test is
 * performed twice: before and after the execution of the inner linked
 * string instruction. doing the test only once (like a while loop)
 * provides the same result at the expense of sometimes having an
 * extra final step. By default, the extra counter test is skipped.
 * Declaring a StrictCounterTest type in the ARCH class sticks to the
 * specification.
 */
template < class T >
struct HasStrictCounterTest
{
  using Yes = char[2];
  using  No = char[1];

  struct Fallback { struct StrictCounterTest { }; };
  struct Derived : T, Fallback { };

  template < typename U > static No& test ( typename U::StrictCounterTest* );
  template < typename U > static Yes& test ( U* );

  enum { value = sizeof(test<Derived>(0)) == sizeof(Yes) };
};

template <class ARCH, class OP>
struct _StringEngine : public StringEngine<ARCH>
{
  typedef typename TypeFor<ARCH,OP::SIZE>::u uaddr_type;
  typedef typename TypeFor<ARCH,OP::SIZE>::s saddr_type;
  typedef typename StringEngine<ARCH>::StrOp StrOp;
  
  ModM<ARCH,OP::SIZE> dst, src[6];
  _StringEngine() : dst( ES, 7 ), src{{0, 6}, {1, 6}, {2, 6}, {3, 6}, {4, 6}, {5, 6}} {}
  
  bool tstcounter( ARCH& arch ) const { return arch.Test( arch.regread( OP(), 1 ) != uaddr_type( 0 )); }
  void deccounter( ARCH& arch ) const { arch.regwrite( OP(), 1, arch.regread( OP(), 1 ) - uaddr_type( 1 ) ); }
  
  StrOp getdst() const { return StrOp( &dst ); }
  StrOp getsrc( uint8_t segment ) const { return StrOp( &src[segment] ); }
  
  void addsrc( ARCH& arch, int step ) const { arch.regwrite( OP(), 6, arch.regread( OP(), 6 ) + uaddr_type( saddr_type( step ) ) ); }
  void adddst( ARCH& arch, int step ) const { arch.regwrite( OP(), 7, arch.regread( OP(), 7 ) + uaddr_type( saddr_type( step ) ) ); }
};

namespace {
  template <class ARCH>
  StringEngine<ARCH>*
  mkse( InputCode<ARCH> const& ic )
  {
    static _StringEngine<ARCH,GOw> se16;
    static _StringEngine<ARCH,GOd> se32;
    static _StringEngine<ARCH,GOq> se64;

    switch (ic.addrclass())
      {
      case 1: return &se16;
      case 2: return &se32;
      case 3: return &se64;
      }
    struct Bad {}; throw Bad ();
    return 0;
  }
}

template <class ARCH, class OP, bool REP>
struct Movs : public Operation<ARCH>
{
  Movs( OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), segment( _segment ), str( _str ) {} uint8_t segment; StringEngine<ARCH>* str;
  
  void disasm( std::ostream& _sink ) const {
    _sink << (REP?"rep ":"") << DisasmMnemonic( "movs", OP::SIZE ) << ' ' << str->getsrc(segment) << ',' << str->getdst();
                                                                                                
  }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    
    if (REP and not str->tstcounter( arch )) return;
    
    arch.rmwrite( OP(), str->getdst(), arch.rmread( OP(), str->getsrc( segment ) ) );
    
    int32_t step = arch.Test( arch.flagread( ARCH::FLAG::DF ) ) ? -int32_t(OP::SIZE/8) : +int32_t(OP::SIZE/8);
    str->addsrc( arch, step );
    str->adddst( arch, step );
    
    if (REP) {
      str->deccounter( arch );
      if (HasStrictCounterTest<ARCH>::value and not str->tstcounter( arch )) return;
      arch.setnip( arch.getnip() - addr_t( Operation<ARCH>::length ) );
    }
  }
};

template <class ARCH> struct DC<ARCH,MOVS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xa4" ) ))
  
    {
      if (ic.rep==0) return new Movs<ARCH,GOb,false>( _.opbase(), ic.segment, mkse( ic ) );
      else           return new Movs<ARCH,GOb, true>( _.opbase(), ic.segment, mkse( ic ) );
    }
  
  if (auto _ = match( ic, opcode( "\xa5" ) ))
  
    {
      if (ic.opsize()==16) { if (ic.rep==0) return new Movs<ARCH,GOw,false>( _.opbase(), ic.segment, mkse( ic ) ); return new Movs<ARCH,GOw, true>( _.opbase(), ic.segment, mkse( ic ) ); }
      if (ic.opsize()==32) { if (ic.rep==0) return new Movs<ARCH,GOd,false>( _.opbase(), ic.segment, mkse( ic ) ); return new Movs<ARCH,GOd, true>( _.opbase(), ic.segment, mkse( ic ) ); }
      if (ic.opsize()==64) { if (ic.rep==0) return new Movs<ARCH,GOq,false>( _.opbase(), ic.segment, mkse( ic ) ); return new Movs<ARCH,GOq, true>( _.opbase(), ic.segment, mkse( ic ) ); }
      return 0;
    }
  
  return 0;
}};

template <class ARCH, class OP, bool REP>
struct Stos : public Operation<ARCH>
{
  Stos( OpBase<ARCH> const& opbase, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), str( _str ) {} StringEngine<ARCH>* str;
  
  void disasm( std::ostream& _sink ) const { _sink << (REP?"rep ":"") << "stos " << DisasmG( OP(), 0 ) << ',' << str->getdst(); }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    
    if (REP and not str->tstcounter( arch )) return;
    
    arch.rmwrite( OP(), str->getdst(), arch.regread( OP(), 0 ) );

    int32_t step = arch.Test( arch.flagread( ARCH::FLAG::DF ) ) ? -int32_t(OP::SIZE/8) : +int32_t(OP::SIZE/8);
    str->adddst( arch, step );
    
    if (REP) {
      str->deccounter( arch );
      if (HasStrictCounterTest<ARCH>::value and not str->tstcounter( arch )) return;
      arch.setnip( arch.getnip() - addr_t( Operation<ARCH>::length ) );
    }
  }
};

template <class ARCH> struct DC<ARCH,STOS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xaa" ) ))
  
    {
      if (ic.rep==0) return new Stos<ARCH,GOb,false>( _.opbase(), mkse( ic ) );
      else           return new Stos<ARCH,GOb, true>( _.opbase(), mkse( ic ) );
    }
  
  if (auto _ = match( ic, opcode( "\xab" ) ))
  
    {
      if (ic.opsize()==16) { if (ic.rep==0) return new Stos<ARCH,GOw,false>( _.opbase(), mkse( ic ) ); return new Stos<ARCH,GOw, true>( _.opbase(), mkse( ic ) ); }
      if (ic.opsize()==32) { if (ic.rep==0) return new Stos<ARCH,GOd,false>( _.opbase(), mkse( ic ) ); return new Stos<ARCH,GOd, true>( _.opbase(), mkse( ic ) ); }
      if (ic.opsize()==64) { if (ic.rep==0) return new Stos<ARCH,GOq,false>( _.opbase(), mkse( ic ) ); return new Stos<ARCH,GOq, true>( _.opbase(), mkse( ic ) ); }
      return 0;
    }
  
  return 0;
}};

template <class ARCH, class OP, unsigned REP>
struct Cmps : public Operation<ARCH>
{
  Cmps( OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), segment( _segment ), str( _str ) {} uint8_t segment; StringEngine<ARCH>* str;
  void disasm( std::ostream& _sink ) const
  {
    _sink << ((REP==0) ? "" : (REP&1) ? "repz " : "repnz ") << "cmps" << SizeID<OP::SIZE>::iid() << ' ' << str->getdst() << ',' << str->getsrc(segment);
  }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::addr_t addr_t;
    
    if (REP and not str->tstcounter( arch )) return;
    
    eval_sub( arch, arch.rmread( OP(), str->getsrc( segment ) ), arch.rmread( OP(), str->getdst() ) );
    
    int32_t step = arch.Test( arch.flagread( ARCH::FLAG::DF ) ) ? -int32_t(OP::SIZE/8) : +int32_t(OP::SIZE/8);
    str->adddst( arch, step );
    str->addsrc( arch, step );
    
    if (REP) {
      str->deccounter( arch );
      if (HasStrictCounterTest<ARCH>::value and not str->tstcounter( arch )) return;
      if (arch.Test( bit_t( REP&1 ) ^ arch.flagread( ARCH::FLAG::ZF ) )) return;
      arch.setnip( arch.getnip() - addr_t( Operation<ARCH>::length ) );
    }
  }
};

template <class ARCH> struct DC<ARCH,CMPS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xa6" ) ))
  
    {
      if (ic.rep==0) return new Cmps<ARCH,GOb,0>( _.opbase(), ic.segment, mkse( ic ) );
      if (ic.rep==2) return new Cmps<ARCH,GOb,2>( _.opbase(), ic.segment, mkse( ic ) );
      else           return new Cmps<ARCH,GOb,3>( _.opbase(), ic.segment, mkse( ic ) );
    }

  
  if (auto _ = match( ic, opcode( "\xa7" ) ))
  
    {
      if (ic.opsize()==16) {
        if (ic.rep==0) return new Cmps<ARCH,GOw,0>( _.opbase(), ic.segment, mkse( ic ) );
        if (ic.rep==2) return new Cmps<ARCH,GOw,2>( _.opbase(), ic.segment, mkse( ic ) );
        else           return new Cmps<ARCH,GOw,3>( _.opbase(), ic.segment, mkse( ic ) );
      }
      if (ic.opsize()==32) {
        if (ic.rep==0) return new Cmps<ARCH,GOd,0>( _.opbase(), ic.segment, mkse( ic ) );
        if (ic.rep==2) return new Cmps<ARCH,GOd,2>( _.opbase(), ic.segment, mkse( ic ) );
        else           return new Cmps<ARCH,GOd,3>( _.opbase(), ic.segment, mkse( ic ) );
      }
      if (ic.opsize()==64) {
        if (ic.rep==0) return new Cmps<ARCH,GOq,0>( _.opbase(), ic.segment, mkse( ic ) );
        if (ic.rep==2) return new Cmps<ARCH,GOq,2>( _.opbase(), ic.segment, mkse( ic ) );
        else           return new Cmps<ARCH,GOq,3>( _.opbase(), ic.segment, mkse( ic ) );
      }
      return 0;
    }
  
  return 0;
}};

template <class ARCH, class OP, unsigned REP>
struct Scas : public Operation<ARCH>
{
  Scas( OpBase<ARCH> const& opbase, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), str( _str ) {} StringEngine<ARCH>* str;
  
  void disasm( std::ostream& _sink ) const
  {
    _sink << ((REP==0) ? "" : (REP&1) ? "repz " : "repnz ") << "scas " << str->getdst() << ',' << DisasmG( OP(), 0 );
  }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename ARCH::addr_t addr_t;
    
    if (REP and not str->tstcounter( arch )) return;
    
    eval_sub( arch, arch.rmread( OP(), str->getdst() ), arch.regread( OP(), 0 ) );

    int32_t step = arch.Test( arch.flagread( ARCH::FLAG::DF ) ) ? -int32_t(OP::SIZE/8) : +int32_t(OP::SIZE/8);
    str->adddst( arch, step );
    
    if (REP) {
      str->deccounter( arch );
      if (HasStrictCounterTest<ARCH>::value and not str->tstcounter( arch )) return;
      if (arch.Test( bit_t( REP&1 ) ^ arch.flagread( ARCH::FLAG::ZF ) )) return;
      arch.setnip( arch.getnip() - addr_t( Operation<ARCH>::length ) );
    }
  }
};

template <class ARCH> struct DC<ARCH,SCAS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xae" ) ))
  
    {
      if (ic.rep==0) return new Scas<ARCH,GOb,0>( _.opbase(), mkse( ic ) );
      if (ic.rep==2) return new Scas<ARCH,GOb,2>( _.opbase(), mkse( ic ) );
      else           return new Scas<ARCH,GOb,3>( _.opbase(), mkse( ic ) );
    }

  
  if (auto _ = match( ic, opcode( "\xaf" ) ))
  
    {
      if (ic.opsize()==16) {
        if (ic.rep==0) return new Scas<ARCH,GOw,0>( _.opbase(), mkse( ic ) );
        if (ic.rep==2) return new Scas<ARCH,GOw,2>( _.opbase(), mkse( ic ) );
        else           return new Scas<ARCH,GOw,3>( _.opbase(), mkse( ic ) );
      }
      if (ic.opsize()==32) {
        if (ic.rep==0) return new Scas<ARCH,GOd,0>( _.opbase(), mkse( ic ) );
        if (ic.rep==2) return new Scas<ARCH,GOd,2>( _.opbase(), mkse( ic ) );
        else           return new Scas<ARCH,GOd,3>( _.opbase(), mkse( ic ) );
      }
      if (ic.opsize()==64) {
        if (ic.rep==0) return new Scas<ARCH,GOq,0>( _.opbase(), mkse( ic ) );
        if (ic.rep==2) return new Scas<ARCH,GOq,2>( _.opbase(), mkse( ic ) );
        else           return new Scas<ARCH,GOq,3>( _.opbase(), mkse( ic ) );
      }
      return 0;
    }
  
  return 0;
}};

template <class ARCH, class OP, bool REP>
struct Lods : public Operation<ARCH>
{
  Lods( OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), segment( _segment ), str( _str ) {} uint8_t segment; StringEngine<ARCH>* str;
  
  void disasm( std::ostream& _sink ) const { _sink << (REP?"rep ":"") << "lods " << str->getsrc(segment) << ',' << DisasmG( GObLH(), 0 ); }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::addr_t addr_t;
    
    if (REP and str->tstcounter( arch )) return;
    
    arch.regwrite( OP(), 0, arch.rmread( OP(), str->getsrc( segment ) ) );
    
    int32_t step = arch.Test( arch.flagread( ARCH::FLAG::DF ) ) ? -int32_t(OP::SIZE/8) : +int32_t(OP::SIZE/8);
    str->addsrc( arch, step );
    
    if (REP) {
      str->deccounter( arch );
      if (HasStrictCounterTest<ARCH>::value and not str->tstcounter( arch )) return;
      arch.setnip( arch.getnip() - addr_t( Operation<ARCH>::length ) );
    }
  }
};

template <class ARCH> struct DC<ARCH,LODS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\xac" ) ))
    
    return newLods<GOb>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
  
  if (auto _ = match( ic, opcode( "\xad" ) ))
    {
      if (ic.opsize()==16) return newLods<GOw>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
      if (ic.opsize()==32) return newLods<GOd>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
      if (ic.opsize()==64) return newLods<GOq>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
    }
  
  return 0;
}
template <class GOP>
Operation<ARCH>* newLods( bool rep, OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str )
{
  if (rep) return new Lods<ARCH,GOP, true>( opbase, _segment, _str );
  else     return new Lods<ARCH,GOP,false>( opbase, _segment, _str );
}
};

template <class ARCH, unsigned OPSIZE, bool REP>
struct Outs : public Operation<ARCH>
{
  Outs( OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), segment( _segment ), str( _str ) {} uint8_t segment; StringEngine<ARCH>* str;
  void disasm( std::ostream& _sink ) const { _sink << (REP?"rep ":"") << DisasmMnemonic( "outs", OPSIZE ) << ' ' << str->getsrc(segment) << ",(" << DisasmG( GOw(), 2 ) << ")"; }
};

template <class ARCH> struct DC<ARCH,OUTS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x6e" ) ))
  
    return newOuts<8>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
  
  if (auto _ = match( ic, opcode( "\x6f" ) ))
    {
      if (ic.opsize()==16) return newOuts<16>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
      if (ic.opsize()==32) return newOuts<32>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
      if (ic.opsize()==64) return newOuts<64>( ic.rep, _.opbase(), ic.segment, mkse( ic ) );
    }
  
  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newOuts( bool rep, OpBase<ARCH> const& opbase, uint8_t _segment, StringEngine<ARCH>* _str )
{
  if (rep) return new Outs<ARCH,OPSIZE, true>( opbase, _segment, _str );
  else     return new Outs<ARCH,OPSIZE,false>( opbase, _segment, _str );
}
};

template <class ARCH, unsigned OPSIZE, bool REP>
struct Ins : public Operation<ARCH>
{
  Ins( OpBase<ARCH> const& opbase, StringEngine<ARCH>* _str ) : Operation<ARCH>( opbase ), str(_str) {}; StringEngine<ARCH>* str;
  void disasm( std::ostream& _sink ) const { _sink << (REP?"rep ":"") << DisasmMnemonic( "ins", OPSIZE ) << ' ' << "(" << DisasmG( GOw(), 2 ) << ")," << str->getdst(); }
};

template <class ARCH> struct DC<ARCH,INS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x6c" ) ))
  
    return newIns<8>( ic.rep, _.opbase(), mkse( ic ) );
  
  if (auto _ = match( ic, opcode( "\x6d" ) ))
    {
      if (ic.opsize()==16) return newIns<16>( ic.rep, _.opbase(), mkse( ic ) );
      if (ic.opsize()==32) return newIns<32>( ic.rep, _.opbase(), mkse( ic ) );
      if (ic.opsize()==64) return newIns<64>( ic.rep, _.opbase(), mkse( ic ) );
    }
  
  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newIns( bool rep, OpBase<ARCH> const& opbase, StringEngine<ARCH>* _str )
{
  if (rep) return new Ins<ARCH,OPSIZE, true>( opbase, _str );
  else     return new Ins<ARCH,OPSIZE,false>( opbase, _str );
}
};
