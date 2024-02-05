/*
 *  Copyright (c) 2019-2020,
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

#ifndef ARMD64DBA_ARCH_HH
#define ARMD64DBA_ARCH_HH

#include <unisim/component/cxx/processor/intel/isa/intel.hh>
#include <unisim/component/cxx/processor/intel/modrm.hh>
#include <unisim/component/cxx/processor/intel/disasm.hh>
#include <unisim/component/cxx/processor/intel/types.hh>
#include <unisim/component/cxx/processor/intel/vectorbank.hh>
#include <unisim/component/cxx/vector/vector.hh>
#include <unisim/util/symbolic/vector/vector.hh>
#include <unisim/util/symbolic/binsec/binsec.hh>
#include <unisim/util/symbolic/symbolic.hh>

// template <typename ARCH, unsigned OPSIZE> struct TypeFor {};

// template <typename ARCH> struct TypeFor<ARCH, 8> { typedef typename ARCH:: S8 S; typedef typename ARCH:: U8 U; };
// template <typename ARCH> struct TypeFor<ARCH,16> { typedef typename ARCH::S16 S; typedef typename ARCH::U16 U; };
// template <typename ARCH> struct TypeFor<ARCH,32> { typedef typename ARCH::S32 S; typedef typename ARCH::U32 U; typedef typename ARCH::F32 F; };
// template <typename ARCH> struct TypeFor<ARCH,64> { typedef typename ARCH::S64 S; typedef typename ARCH::U64 U; typedef typename ARCH::F64 F; };

void show(unsigned, unisim::util::symbolic::ExprNode const*);


struct VmmValue
{
  enum { BYTECOUNT = 32, VPREFIX='y' };
  struct value_type { char _[BYTECOUNT]; };
  VmmValue() = default;
  VmmValue(unisim::util::symbolic::Expr const& _expr) : expr(_expr) {}
  unisim::util::symbolic::Expr expr;
  static unisim::util::symbolic::ValueType const* GetType();
  //{ return unisim::util::symbolic::NoValueType(); }
};

struct ProcessorBase
{
  struct Undefined {};
  struct Unimplemented {};

  template <typename T> using SmartValue = unisim::util::symbolic::SmartValue<T>;
  template <typename T> using VectorTypeInfo = unisim::component::cxx::vector::VectorTypeInfo<T,0>;
  template <typename A, unsigned S> using TypeFor = typename unisim::component::cxx::processor::intel::TypeFor<A,S>;

  typedef SmartValue<uint8_t>     u8_t;
  typedef SmartValue<uint16_t>    u16_t;
  typedef SmartValue<uint32_t>    u32_t;
  typedef SmartValue<uint64_t>    u64_t;
  typedef void                    u128_t;
  typedef SmartValue<int8_t>      s8_t;
  typedef SmartValue<int16_t>     s16_t;
  typedef SmartValue<int32_t>     s32_t;
  typedef SmartValue<int64_t>     s64_t;
  typedef void                    s128_t;
  typedef SmartValue<bool>        bit_t;

  typedef SmartValue<float>       f32_t;
  typedef SmartValue<double>      f64_t;
  typedef SmartValue<long double> f80_t;

  typedef unisim::util::symbolic::Expr Expr;
  typedef unisim::util::symbolic::ExprNode ExprNode;
  typedef unisim::util::symbolic::ValueType ValueType;

  typedef unisim::util::symbolic::binsec::ActionNode   ActionNode;

  ProcessorBase();

  /*** MEMORY ***/
  std::set<Expr> stores;

  /*** INTEGER REGISTERS ***/

  template <typename RID>
  static Expr newRegRead( RID id ) { return new unisim::util::symbolic::binsec::RegRead<RID>( id ); }

  template <typename RID>
  static Expr newRegWrite( RID id, Expr const& value ) { return new unisim::util::symbolic::binsec::RegWrite<RID>( id, value ); }

  template <typename RID>
  static Expr newPartialRegWrite( RID id, unsigned pos, unsigned size, Expr const& value ) { return new unisim::util::symbolic::binsec::RegWrite<RID>( id, pos, size, value ); }

  /*** FLOATING POINT REGISTERS ***/

  enum {FREGCOUNT=8};

  void                        fnanchk( f64_t value ) {}

  int                         fcwreadRC() const { return 0; }
  u16_t                       fcwread() const { throw Unimplemented(); /*FCW access*/ return u16_t(); }
  void                        fcwwrite( u16_t value ) { throw Unimplemented(); /*FCW access*/}
  void                        finit() { throw Unimplemented(); /*FCW access*/ }

  void                        fxam() { throw Unimplemented(); }

  // struct FTop : public unisim::util::symbolic::ExprNode
  // {
  //   virtual FTop* Mutate() const override { return new FTop(*this); }
  //   virtual unsigned SubCount() const { return 0; }
  //   virtual int cmp(ExprNode const&) const override { return 0; }
  //   virtual ValueType const* GetType() const { return ValueType::U8; }
  //   virtual void Repr( std::ostream& sink ) const;
  // };

  // struct FTopWrite : public unisim::util::symbolic::binsec::RegWrite
  // {
  //   using unisim::util::symbolic::binsec::RegWrite;
  //   //typedef unisim::util::symbolic::binsec::RegWrite Super;
  //   FTopWrite( u8_t const& ftop ) : RegWrite( ftop.expr, 8 ) {}
  //   virtual FTopWrite* Mutate() const override { return new FTopWrite(*this); }
  //   virtual void GetRegName(std::ostream& sink) const;
  //   virtual int cmp(ExprNode const& rhs) const override { return Super::compare(dynamic_cast<Super const&>(rhs)); }
  // };

  u16_t                       ftopread() { throw Unimplemented(); /*FCW access*/; return u16_t(); }
  // unsigned                    ftop;

  Expr&                       fpaccess(unsigned r, bool w);
  bool                        fpdiff(unsigned r);

  Expr                        fpregs[8];
  void                        fpush( f64_t value ) { throw Unimplemented(); }
  void                        fwrite( unsigned idx, f64_t value ) { throw Unimplemented(); }
  f64_t                       fpop() { throw Unimplemented(); return f64_t(); }
  f64_t                       fread( unsigned idx ) { throw Unimplemented(); return f64_t(); }

  struct FRegID : public unisim::util::identifier::Identifier<FRegID>
  {
    static unisim::util::symbolic::ValueType const* GetType() { return unisim::util::symbolic::CValueType(double()); }
    enum Code { st0=0, st1, st2, st3, st4, st5, st6, st7, end } code;
    char const* c_str() const { return &"st0\0st1\0st2\0st3\0st4\0st5\0st6\0st7"[(unsigned(code) % 8)*4]; }
    FRegID() : code(end) {}
    FRegID( Code _code ) : code(_code) {}
    FRegID( char const* _code ) : code(end) { init( _code ); }
  };

  /*** VECTOR REGISTERS ***/
  struct VRegID
  {
    VRegID(unsigned _reg) : reg(_reg) {} unsigned reg;
    static unisim::util::symbolic::ValueType const* GetType() { return VmmValue::GetType(); }
    void Repr( std::ostream& ) const;
    int cmp(VRegID const& rhs) const { return int(reg) - int(rhs.reg); }
  };

  struct VClear : public unisim::util::symbolic::binsec::ASExprNode
  {
    VClear(unsigned _size) : size(_size) {} unsigned size;
    virtual VClear* Mutate() const override { return new VClear( *this ); };
    virtual unsigned SubCount() const override { return 0; };
    virtual void Repr( std::ostream& sink ) const override;
    ValueType const* GetType() const override;
    virtual int cmp( ExprNode const& rhs ) const override { return 0; }
    virtual int GenCode(unisim::util::symbolic::binsec::Label&, unisim::util::symbolic::binsec::Variables&, std::ostream& sink) const;
  };

  // VRegRead should never be a binsec::node (no dba available for it)
  // struct VRegRead : public unisim::util::symbolic::ExprNode
  // {
  //   VRegRead( unsigned _reg ) : reg(_reg) {}
  //   virtual VRegRead* Mutate() const override { return new VRegRead( *this ); }
  //   virtual ValueType const* GetType() const { return ValueType::VOID; }
  //   virtual unsigned SubCount() const override { return 0; }
  //   virtual void Repr( std::ostream& sink ) const override;
  //   virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<VRegRead const&>( rhs ) ); }
  //   int compare( VRegRead const& rhs ) const { return int(reg) - int(rhs.reg); }
  //   unsigned reg;
  // };

  struct VmmIndirectReadBase : public unisim::util::symbolic::binsec::ASExprNode
  {// Parent of VmmIndirectRead
    VmmIndirectReadBase(Expr const& _index) : index(_index) {}
    virtual void Repr( std::ostream& sink ) const override;
    virtual unsigned GetVSize() const = 0;
    virtual void GetVName( std::ostream& sink ) const = 0;
    Expr index;
  };

  /*** FLAGS ***/

  struct FLAG
    : public unisim::util::identifier::Identifier<FLAG>
    , unisim::util::symbolic::WithValueType<FLAG>
  {
    typedef bool value_type;

    enum Code { CF = 0, PF, AF, ZF, SF, DF, OF, C0, C1, C2, C3, end } code;

    char const* c_str() const
    {
      switch (code)
        {
        case CF: return "cf";
        case PF: return "pf";
        case AF: return "af";
        case ZF: return "zf";
        case SF: return "sf";
        case DF: return "df";
        case OF: return "of";
        case C0: return "c0";
        case C1: return "c1";
        case C2: return "c2";
        case C3: return "c3";
        case end: break;
        }
      return "NA";
    }

    void Repr( std::ostream& sink ) const;

    FLAG() : code(end) {}
    FLAG( Code _code ) : code(_code) {}
    FLAG( char const* _code ) : code(end) { init(_code); }
  };

  Expr                        flagvalues[FLAG::end];

  bit_t                       flagread( FLAG flag ) { return bit_t(flagvalues[flag.idx()]); }
  void                        flagwrite( FLAG flag, bit_t fval ) { flagvalues[flag.idx()] = fval.expr; }
  void                        flagwrite( FLAG flag, bit_t fval, bit_t def );

  /*** SEGMENTS ***/
  struct SegmentID : public unisim::util::identifier::Identifier<SegmentID>
  {
    enum Code { es, cs, ss, ds, fs, gs, end } code;

    char const* c_str() const
    {
      switch (code)
        {
        case  es: return "es";
        case  cs: return "cs";
        case  ss: return "ss";
        case  ds: return "ds";
        case  fs: return "fs";
        case  gs: return "gs";
        case end: break;
        }
      return "NA";
    }

    SegmentID() : code(end) {}
    SegmentID( Code _code ) : code(_code) {}
    SegmentID( char const* _code ) : code(end) { init( _code ); }
  };

  u16_t                       segregread( unsigned idx ) { throw Unimplemented(); return u16_t(); }
  void                        segregwrite( unsigned idx, u16_t value ) { throw Unimplemented(); }

  enum ipproc_t { ipjmp, ipcall, ipret };

  ActionNode*      path;
  ipproc_t         next_insn_mode;
  bool             abort;

  bool concretize( Expr cexp )
  {
    if (unisim::util::symbolic::ConstNodeBase const* cnode = cexp.ConstSimplify())
      return dynamic_cast<unisim::util::symbolic::ConstNode<bool> const&>(*cnode).value;

    bool predicate = path->proceed( cexp );
    path = path->next( predicate );
    return predicate;
  }

  template <typename T>
  bool Test( unisim::util::symbolic::SmartValue<T> const& cond )
  {
    if (not cond.expr.good())
      throw std::logic_error( "Not a valid condition" );

    return concretize( bit_t(cond).expr );
  }
};

template <class MODE>
struct Processor : public ProcessorBase
{
  typedef unisim::component::cxx::processor::intel::Operation<Processor> Operation;

  typedef unisim::component::cxx::processor::intel::GObLH GObLH;
  typedef unisim::component::cxx::processor::intel::GOb GOb;
  typedef unisim::component::cxx::processor::intel::GOw GOw;
  typedef unisim::component::cxx::processor::intel::GOd GOd;
  typedef unisim::component::cxx::processor::intel::GOq GOq;

  typedef unisim::component::cxx::processor::intel::SSE SSE;
  typedef unisim::component::cxx::processor::intel::XMM XMM;
  typedef unisim::component::cxx::processor::intel::YMM YMM;

  typedef unisim::component::cxx::processor::intel::RMOp<Processor> RMOp;

  typedef             typename MODE::IRegID  IRegID;
  typedef typename MODE::IRegID::value_type  nat_gr_type;
  typedef                 typename MODE::GR  GR;
  typedef                       nat_gr_type  nat_addr_t;
  typedef           SmartValue<nat_gr_type>  gr_type;
  typedef                           gr_type  addr_t;


  struct OpHeader { OpHeader( nat_addr_t _address ) : address( _address ) {} nat_addr_t address; };

  /*** SEGMENTS ***/
  struct SegBaseID : public SegmentID
  {
    static unisim::util::symbolic::ValueType const* GetType() { return unisim::util::symbolic::CValueType(nat_addr_t()); }
    void Repr(std::ostream& sink) const { sink << c_str() << "_base"; }
    SegBaseID() = default;
    SegBaseID( Code _code ) : SegmentID(_code) {}
    SegBaseID( char const* _code ) : SegmentID(_code) {}
  };

  Expr                        segment_bases[6];
  Expr GetSegBase( unsigned idx )
  {
    Expr& segbase = segment_bases[idx];
    if (ExprNode const* node = segbase.node)
      return node;
    return (segbase = newRegRead( SegBaseID( typename SegBaseID::Code(idx) ) ) );
  }

  /*** MEMORY ***/
  Expr PerformLoad( unsigned bytes, unsigned segment, addr_t addr )
  {
    if (segment >= 4) /*FS|GS relative addressing*/
      addr = addr_t(GetSegBase(segment)) + addr;
    return new unisim::util::symbolic::binsec::Load( addr.expr, bytes, 0, false );
  }
  void PerformStore( unsigned bytes, unsigned segment, addr_t addr, Expr const& value )
  {
    if (segment >= 4) /*FS|GS relative addressing*/
      addr = addr_t(GetSegBase(segment)) + addr;
    stores.insert( Expr( new unisim::util::symbolic::binsec::Store( addr.expr, value, bytes, 0, false ) ) );
  }

  template<unsigned OPSIZE>
  typename TypeFor<Processor,OPSIZE>::u
  memread( unsigned seg, addr_t const& addr )
  {
    typedef typename TypeFor<Processor,OPSIZE>::u u_type;
    return u_type( PerformLoad( OPSIZE/8, seg, addr.expr ) );
  }

  template <unsigned OPSIZE>
  void
  memwrite( unsigned seg, addr_t const& addr, typename TypeFor<Processor,OPSIZE>::u val )
  {
    PerformStore( OPSIZE/8, seg, addr, val.expr );
  }

  void                        fmemwrite32( unsigned seg, addr_t const& addr, f32_t val ) { PerformStore( 4, seg, addr, val.expr ); }
  void                        fmemwrite64( unsigned seg, addr_t const& addr, f64_t val ) { PerformStore( 8, seg, addr, val.expr ); }
  void                        fmemwrite80( unsigned seg, addr_t const& addr, f80_t val ) { throw Unimplemented(); }

  f32_t                       fmemread32( unsigned seg, addr_t const& addr )
  { return f32_t(PerformLoad( 4, seg, addr.expr )); }
  f64_t                       fmemread64( unsigned seg, addr_t const& addr )
  { return f64_t(PerformLoad( 8, seg, addr.expr )); }
  f80_t                       fmemread80( unsigned seg, addr_t const& addr ) { throw Unimplemented(); return f80_t(); }

  /*** CONTROL FLOW ***/

  u64_t                       tscread() { throw Unimplemented(); return u64_t( 0 ); }

  typedef std::map<unsigned,unsigned> RegMap;

  enum { GREGSIZE = MODE::GREGSIZE, GREGCOUNT = MODE::GREGCOUNT, VREGCOUNT = MODE::VREGCOUNT };

  Expr                        eregread( unsigned reg, unsigned size, unsigned pos ) const;
  void                        eregwrite( unsigned reg, unsigned size, unsigned pos, Expr const& xpr );

  Expr                        regvalues[GREGCOUNT][GREGSIZE];

  void                        eregsinks( Processor<MODE> const& ref, unsigned reg ) const;

  template <class GOP>
  typename TypeFor<Processor,GOP::SIZE>::u regread( GOP const&, unsigned idx )
  {
    return typename TypeFor<Processor,GOP::SIZE>::u( gr_type(eregread( idx, GOP::SIZE / 8, 0 )) );
  }

  u8_t regread( GObLH const&, unsigned idx ) { return u8_t( gr_type(eregread( idx%4, 1, (idx >> 2) & 1 )) ); }

  template <class GOP> void regwrite( GOP const&, unsigned idx, typename TypeFor<Processor,GOP::SIZE>::u const& val )
  {
    unsigned const size = GOP::SIZE / 8;
    if(size > MODE::GREGSIZE) throw Undefined();
    eregwrite( idx, size, 0, gr_type(val).expr );
  }

  void regwrite( GObLH const&, unsigned idx, u8_t val )  { eregwrite( idx%4, 1, (idx>>2) & 1, gr_type(val).expr ); }
  void regwrite( GOd const&,   unsigned idx, u32_t val ) { eregwrite( idx,   GREGSIZE,     0, gr_type(val).expr ); }

  addr_t                      getnip() { return next_insn_addr; }
  void                        setnip( addr_t nip, ipproc_t ipproc = ipjmp )
  {
    next_insn_addr = nip;
    next_insn_mode = ipproc;
  }

  template <unsigned OPSIZE>
  typename TypeFor<Processor,OPSIZE>::u
  pop()
  {
    // TODO: handle stack address size
    gr_type sptr = regread( GR(), 4 );
    regwrite( GR(), 4, sptr + gr_type( OPSIZE/8 ) );
    return memread<OPSIZE>( unisim::component::cxx::processor::intel::SS, addr_t(sptr) );
  }

  template <unsigned OPSIZE>
  void
  push( typename TypeFor<Processor,OPSIZE>::u const& value )
  {
    // TODO: handle stack address size
    gr_type sptr = regread( GR(), 4 ) - gr_type( OPSIZE/8 );
    memwrite<OPSIZE>( unisim::component::cxx::processor::intel::SS, addr_t(sptr), value );
    regwrite( GR(), 4, sptr );
  }

  void shrink_stack( addr_t const& offset ) { regwrite( GR(), 4, regread( GR(), 4 ) + offset ); }
  void grow_stack( addr_t const& offset ) { regwrite( GR(), 4, regread( GR(), 4 ) - offset ); }

  template <class GOP>
  typename TypeFor<Processor,GOP::SIZE>::u
  rmread( GOP const& g, RMOp const& rmop )
  {
    if (not rmop.ismem())
      return regread( g, rmop.ereg() );

    return memread<GOP::SIZE>( rmop->segment, rmop->effective_address( *this ) );
  }

  template <class GOP>
  void
  rmwrite( GOP const& g, RMOp const& rmop, typename TypeFor<Processor,GOP::SIZE>::u const& value )
  {
    if (not rmop.ismem())
      return regwrite( g, rmop.ereg(), value );

    return memwrite<GOP::SIZE>( rmop->segment, rmop->effective_address( *this ), value );
  }

  template <unsigned OPSIZE>
  typename TypeFor<Processor,OPSIZE>::f
  fpmemread( unsigned seg, addr_t const& addr )
  {
    throw Unimplemented();
    return typename TypeFor<Processor,OPSIZE>::f();
  }

  template <unsigned OPSIZE>
  typename TypeFor<Processor,OPSIZE>::f
  frmread( RMOp const& rmop )
  {
    typedef typename TypeFor<Processor,OPSIZE>::f f_type;
    if (not rmop.ismem()) return f_type( fread( rmop.ereg() ) );
    return this->fpmemread<OPSIZE>( rmop->segment, rmop->effective_address( *this ) );
  }

  template <unsigned OPSIZE>
  void
  fpmemwrite( unsigned seg, addr_t const& addr, typename TypeFor<Processor,OPSIZE>::f const& value )
  {
    throw Unimplemented();
  }

  template <unsigned OPSIZE>
  void
  frmwrite( RMOp const& rmop, typename TypeFor<Processor,OPSIZE>::f const& value )
  {
    if (not rmop.ismem()) return fwrite( rmop.ereg(), f64_t( value ) );
    fpmemwrite<OPSIZE>( rmop->segment, rmop->effective_address( *this ), value );
  }

  u32_t mxcsread() { throw Unimplemented(); /*mxcsr access*/; return u32_t(); }
  void mxcswrite( u32_t const& value ) { throw Unimplemented(); /*mxcsr access*/; }

  struct VUConfig : public unisim::util::symbolic::vector::VUConfig
  {
    static unsigned const BYTECOUNT = VmmValue::BYTECOUNT;
  };

  struct VmmBrick { char _[sizeof(u8_t)]; };
  typedef unisim::component::cxx::vector::VUnion<VUConfig> VUnion;
  VUnion umms[VREGCOUNT];
  VmmBrick vmm_storage[VREGCOUNT][VUConfig::BYTECOUNT];

  template <class VR> static unsigned vmm_wsize( VR const& vr ) { return VR::size() / 8; }
  static unsigned vmm_wsize( unisim::component::cxx::processor::intel::SSE const& ) { return VUConfig::BYTECOUNT; }

  template <class VR, class ELEM>
  struct VmmIndirectRead : public VmmIndirectReadBase
  {
    typedef unisim::util::symbolic::TypeInfo<typename ELEM::value_type> traits;
    enum { elemcount = VR::SIZE / traits::BITSIZE };

    VmmIndirectRead( ELEM const* elems, u8_t const& _index)
      : VmmIndirectReadBase(_index.expr)
    {
      for (unsigned idx = 0, end = elemcount; idx < end; ++idx)
        sources[idx] = elems[idx].expr;
    }
    typedef VmmIndirectRead<VR,ELEM> this_type;
    virtual this_type* Mutate() const override { return new this_type( *this ); }
    virtual unsigned GetVSize() const override { return VR::SIZE; }
    virtual void GetVName(std::ostream& sink) const override { return GetType()->GetName(sink); }
    virtual unsigned SubCount() const { return elemcount+1; }
    virtual Expr const& GetSub(unsigned idx) const
    {
      if (idx < elemcount) return sources[idx];
      if (idx == elemcount) return index;
      return ExprNode::GetSub(idx);
    }
    virtual ValueType const* GetType() const override { return ELEM::GetType(); }
    virtual int GenCode(unisim::util::symbolic::binsec::Label& label, unisim::util::symbolic::binsec::Variables& vars, std::ostream& sink) const override {
      for (int i = 0; i < elemcount - 1; i += 1) {
	sink << "(if";
	ASExprNode::GenerateCode( GetSub(elemcount), vars, label, sink );
	sink << " = "
	     << unisim::util::symbolic::binsec::dbx(traits::BITSIZE/8, i)
	     << " then ";
	ASExprNode::GenerateCode( GetSub(i), vars, label, sink );
	sink << " else ";
      }
      ASExprNode::GenerateCode( GetSub(elemcount - 1), vars, label, sink );
      for (int i = 0; i < elemcount - 1; i += 1) {
	sink << ')';
      }
      // sink << "((";
      // for (int i = elemcount - 1; 0 < i; i -= 1) {
      // 	ASExprNode::GenerateCode( GetSub(i), vars, label, sink );
      // 	sink << " :: ";
      // }
      // ASExprNode::GenerateCode( GetSub(0), vars, label, sink );
      // sink << ") >>u (" << traits::BITSIZE
      // 	   << '<' << GetVSize() << "> * (extu ";
      // ASExprNode::GenerateCode( GetSub(elemcount), vars, label, sink );
      // sink << ' ' << GetVSize() << "))){0," << traits::BITSIZE - 1 << '}';
      return traits::BITSIZE;
    }

    virtual int cmp( ExprNode const& brhs ) const override { return compare( dynamic_cast<this_type const&>(brhs) ); }
    int compare( this_type const& rhs ) const { return 0; }

    Expr sources[elemcount];
  };

  void vregsinks( Processor<MODE> const& ref, unsigned reg ) const;

  template <class VR, class ELEM>
  ELEM vmm_read( VR const& vr, unsigned reg, u8_t const& sub, ELEM const& e )
  {
    ELEM const* elems = umms[reg].GetConstStorage( &vmm_storage[reg][0], e, vr.size() / 8 );
    return ELEM(Expr(new VmmIndirectRead<VR, ELEM>( elems, sub.expr )));
  }

  template <class VR, class ELEM>
  ELEM vmm_read( VR const& vr, unsigned reg, unsigned sub, ELEM const& e )
  {
    ELEM const* elems = umms[reg].GetConstStorage( &vmm_storage[reg][0], e, vr.size() / 8 );
    return elems[sub];
  }

  template <class VR, class ELEM>
  void vmm_write( VR const& vr, unsigned reg, unsigned sub, ELEM const& e )
  {
    ELEM* elems = umms[reg].GetStorage( &vmm_storage[reg][0], e, vmm_wsize( vr ) );
    elems[sub] = e;
  }

  template <class VR, class ELEM>
  ELEM vmm_read( VR const& vr, RMOp const& rmop, unsigned sub, ELEM const& e )
  {
    if (not rmop.ismem()) return vmm_read( vr, rmop.ereg(), sub, e );
    return vmm_memread( rmop->segment, rmop->effective_address( *this ) + addr_t(sub*VUConfig::template TypeInfo<ELEM>::bytecount), e );
  }

  template <class VR, class ELEM>
  void vmm_write( VR const& vr, RMOp const& rmop, unsigned sub, ELEM const& e )
  {
    if (not rmop.ismem()) return vmm_write( vr, rmop.ereg(), sub, e );
    return vmm_memwrite( rmop->segment, rmop->effective_address( *this ) + addr_t(sub*VUConfig::template TypeInfo<ELEM>::bytecount), e );
  }

  // Integer case
  template <class ELEM> ELEM vmm_memread( unsigned seg, addr_t addr, ELEM const& e )
  {
    typedef unisim::component::cxx::processor::intel::atpinfo<Processor,ELEM> atpinfo;
    return ELEM(memread<atpinfo::bitsize>(seg,addr));
  }

  f32_t vmm_memread( unsigned seg, addr_t addr, f32_t const& e ) { return fmemread32( seg, addr ); }
  f64_t vmm_memread( unsigned seg, addr_t addr, f64_t const& e ) { return fmemread64( seg, addr ); }
  f80_t vmm_memread( unsigned seg, addr_t addr, f80_t const& e ) { return fmemread80( seg, addr ); }

  // Integer case
  template <class ELEM> void vmm_memwrite( unsigned seg, addr_t addr, ELEM const& e )
  {
    typedef unisim::component::cxx::processor::intel::atpinfo<Processor,ELEM> atpinfo;
    memwrite<atpinfo::bitsize>(seg,addr,typename atpinfo::utype(e));
  }

  void vmm_memwrite( unsigned seg, addr_t addr, f32_t const& e ) { return fmemwrite32( seg, addr, e ); }
  void vmm_memwrite( unsigned seg, addr_t addr, f64_t const& e ) { return fmemwrite64( seg, addr, e ); }
  void vmm_memwrite( unsigned seg, addr_t addr, f80_t const& e ) { return fmemwrite80( seg, addr, e ); }

  //   =====================================================================
  //   =                      Construction/Destruction                     =
  //   =====================================================================

private:
  Processor( Processor const& );


public:

  Processor();
  ~Processor()
  {
    for (unsigned reg = 0; reg < VREGCOUNT; ++reg)
      umms[reg].Clear(&vmm_storage[reg][0]);
  }

  bool close( Processor const& ref );

  void step( Operation const& op );

  void noexec( Operation const& op );

  void interrupt(int op, int code) { throw Unimplemented(); }

  void syscall() { throw Unimplemented(); }

  void unimplemented() { throw Unimplemented(); }

  void cpuid() { throw Unimplemented(); /*hardware*/ }

  void xgetbv() { throw Unimplemented(); /*hardware*/ }

  void stop() { throw Unimplemented(); /*hardware*/ }

  void _DE()  { abort = true; }

  void xsave(unisim::component::cxx::processor::intel::XSaveMode mode, bool is64, u64_t bv, RMOp const& rmop) { throw Unimplemented(); /*hardware*/ }
  void xrstor(unisim::component::cxx::processor::intel::XSaveMode mode, bool is64, u64_t bv, RMOp const& rmop) { throw Unimplemented(); /*hardware*/ }

  //   =====================================================================
  //   =                 Internal Instruction Control Flow                 =
  //   =====================================================================

  // bool concretize( Expr cexp )
  // {
  //   if (unisim::util::symbolic::ConstNodeBase const* cnode = cexp.ConstSimplify())
  //     return dynamic_cast<unisim::util::symbolic::ConstNode<bool> const&>(*cnode).value;

  //   bool predicate = path->proceed( cexp );
  //   path = path->next( predicate );
  //   return predicate;
  // }

  // template <typename T>
  // bool Test( unisim::util::symbolic::SmartValue<T> const& cond )
  // {
  //   if (not cond.expr.good())
  //     throw std::logic_error( "Not a valid condition" );

  //   return concretize( bit_t(cond).expr );
  // }

  static Operation* Decode(nat_addr_t address, uint8_t const* bytes);

  nat_addr_t       return_address;
  addr_t           next_insn_addr;
};

template <class MODE>
Processor<MODE>::Processor()
  : return_address()
  , next_insn_addr()
{
  for (IRegID reg; reg.next();)
    regvalues[reg.idx()][0] = newRegRead( reg );

  for (unsigned reg = 0; reg < VREGCOUNT; ++reg)
    {
      VmmValue v( newRegRead( VRegID(reg) ) );
      *(umms[reg].GetStorage( &vmm_storage[reg][0], v, VUConfig::BYTECOUNT )) = v;
    }
}

template <class MODE>
ProcessorBase::Expr
Processor<MODE>::eregread( unsigned reg, unsigned size, unsigned pos ) const
{
  using unisim::util::symbolic::ExprNode;
  using unisim::util::symbolic::make_const;

  if (not regvalues[reg][pos].node)
    {
      // requested read is in the middle of a larger value
      unsigned src = pos;
      do { src = src & (src-1); } while (not regvalues[reg][src].node);
      unsigned shift = 8*(pos - src);
      return new unisim::util::symbolic::binsec::BitFilter( regvalues[reg][src], 64, shift, 8*size, 64, false );
    }
  else if (not regvalues[reg][(pos|size)&(GREGSIZE-1)].node)
    {
      // requested read is in lower bits of a larger value
      return new unisim::util::symbolic::binsec::BitFilter( regvalues[reg][pos], 64, 0, 8*size, 64, false );
    }
  else if ((size > 1) and (regvalues[reg][pos|(size >> 1)].node))
    {
      // requested read is a concatenation of multiple source values
      Expr concat = regvalues[reg][pos];
      for (unsigned idx = 1; ++idx < size;)
        {
          if (not regvalues[reg][pos+idx].node)
            continue;
          concat = make_operation( "Or", make_operation( "Lsl", regvalues[reg][idx], make_const( uint8_t(8*idx) ) ), concat );
        }
      return concat;
    }

  // requested read is directly available
  return regvalues[reg][pos];
}

template <class MODE>
void
Processor<MODE>::eregwrite( unsigned reg, unsigned size, unsigned pos, Expr const& xpr )
{
  Expr nxt[GREGSIZE];

  for (unsigned ipos = pos, isize = size, cpos;
       (cpos = (ipos^isize) & (GREGSIZE-1)), (not regvalues[reg][ipos].node) or (not regvalues[reg][cpos].node);
       isize *= 2, ipos &= -isize
       )
    {
      nxt[cpos] = eregread( reg, isize, cpos );
    }

  for (unsigned ipos = 0; ipos < GREGSIZE; ++ipos)
    {
      if (nxt[ipos].node)
        regvalues[reg][ipos] = nxt[ipos];
    }

  regvalues[reg][pos] = xpr;

  for (unsigned rem = 1; rem < size; ++rem)
    {
      regvalues[reg][pos+rem] = 0;
    }
}

template <class MODE>
void
Processor<MODE>::vregsinks( Processor<MODE> const& ref, unsigned reg ) const
{
  struct VCorruption {};

  unsigned const vector_size = umms[reg].size;

  if (unsigned psize = 8*(VUConfig::BYTECOUNT - vector_size))
    path->add_sink( newPartialRegWrite( VRegID(reg), 8*vector_size, psize, new VClear(psize) ) );

  if (vector_size == 0)
    return;

  typename VUConfig::Byte bytes[VUConfig::BYTECOUNT];
  umms[reg].transfer( &bytes[0], const_cast<VmmBrick*>(&vmm_storage[reg][0]), vector_size, false );

  unsigned const elem_size = bytes[0].is_source();
  if (elem_size == 0 or vector_size % elem_size)
    { throw VCorruption(); }

  for (unsigned beg = 0; beg < vector_size; beg += elem_size)
    {
      if (bytes[beg].is_source() != elem_size)
        throw VCorruption();
      for (unsigned idx = 0; idx < elem_size; ++idx)
        {
          if (auto x = unisim::util::symbolic::vector::corresponding_origin(bytes[beg].get_node(), idx, beg+idx ))
            if (auto vr = dynamic_cast<unisim::util::symbolic::binsec::RegRead<VRegID> const*>( x ))
              if (vr->id.reg == reg)
                continue;
          // Found one difference !
          path->add_sink( newPartialRegWrite( VRegID(reg), 8*beg, 8*elem_size, bytes[beg].get_node() ) );
          break;
        }
    }
}

template <class MODE>
void
Processor<MODE>::eregsinks( Processor<MODE> const& ref, unsigned reg ) const
{
  // Requested read is a concatenation of multiple source values
  // Crawl register expression tree to produce sinks
  struct _
  {
    _( Processor<MODE> const& _core, Processor<MODE> const& _ref, unsigned _reg ) : core(_core), ref(_ref), reg(_reg) { Process( 0, GREGSIZE ); }
    Processor<MODE> const& core; Processor<MODE> const& ref; unsigned reg;
    void Process( unsigned pos, unsigned size )
    {
      Expr value = core.eregread(reg,size,pos);
      if (value == ref.eregread(reg,size,pos))
        return;
      value = unisim::util::symbolic::binsec::ASExprNode::Simplify( value );
      unsigned half = size / 2, mid = pos+half;
      if (value.ConstSimplify() or size <= 1 or not core.regvalues[reg][mid].node)
        {
          if (size == core.GREGSIZE)
            core.path->add_sink( newRegWrite( IRegID(reg), value ) );
          else
            {
              unisim::util::symbolic::binsec::BitFilter bf( value, 64, 0, size*8, size*8, false );
              bf.Retain(); // Not a heap-allocated object (never delete);
              value = bf.Simplify();
              if (value.node == &bf) value = new unisim::util::symbolic::binsec::BitFilter( bf );
              core.path->add_sink( newPartialRegWrite( IRegID(reg), 8*pos, 8*size, value ) );
            }
        }
      else
        {
          Process( pos, half );
          Process( mid, half );
        }
    }
  } concat( *this, ref, reg );
}

template <class MODE>
bool
Processor<MODE>::close( Processor<MODE> const& ref )
{
  bool complete = path->close();

  if (next_insn_mode == ipcall)
    path->add_sink( new unisim::util::symbolic::binsec::Call<nat_addr_t>( next_insn_addr.expr, return_address ) );
  else
    path->add_sink( new unisim::util::symbolic::binsec::Branch( next_insn_addr.expr ) );

  if (abort)
    {
      path->add_sink( new unisim::util::symbolic::binsec::AssertFalse() );
      return complete;
    }

  for (unsigned reg = GREGCOUNT; reg-- > 0;)
    eregsinks(ref, reg);

  // Flags
  for (FLAG reg; reg.next();)
    if (flagvalues[reg.idx()] != ref.flagvalues[reg.idx()])
      path->add_sink( newRegWrite( reg, flagvalues[reg.idx()] ) );

  for (unsigned reg = VREGCOUNT; reg-- > 0; )
    vregsinks(ref, reg);

  for (Expr const& store : stores)
    path->add_sink( store );

  return complete;
}

template <class MODE>
void
Processor<MODE>::step( Operation const& op )
{
  nat_addr_t insn_addr = op.address, nia = insn_addr + op.length;
  return_address = nia;
  next_insn_addr = addr_t(nia);
  op.execute( *this );
}

struct Intel64
{
  enum {GREGSIZE = 8, GREGCOUNT = 16, VREGCOUNT = 16};

  typedef unisim::component::cxx::processor::intel::GOq GR;

  struct IRegID
    : public unisim::util::identifier::Identifier<IRegID>
    , public unisim::util::symbolic::WithValueType<IRegID>
  {
    typedef uint64_t value_type;

    enum Code { rax = 0, rcx = 1, rdx = 2, rbx = 3, rsp = 4, rbp = 5, rsi = 6, rdi = 7,
                r8, r9, r10, r11, r12, r13, r14, r15,
                end } code;

    char const* c_str() const
    {
      switch (code)
        {
        case rax: return "rax";
        case rcx: return "rcx";
        case rdx: return "rdx";
        case rbx: return "rbx";
        case rsp: return "rsp";
        case rbp: return "rbp";
        case rsi: return "rsi";
        case rdi: return "rdi";
        case r8:  return "r8";
        case r9: return "r9";
        case r10: return "r10";
        case r11: return "r11";
        case r12: return "r12";
        case r13: return "r13";
        case r14: return "r14";
        case r15: return "r15";

        case end: break;
        }
      return "NA";
    }

    void Repr( std::ostream& sink ) const;

    IRegID() : code(end) {}
    IRegID( Code _code ) : code(_code) {}
    IRegID( unsigned idx ) : code(Code(idx)) {}
    IRegID( char const* _code ) : code(end) { init( _code ); }
  };

};

struct Compat32
{
  enum {GREGSIZE = 4, GREGCOUNT = 8, VREGCOUNT = 8};

  typedef unisim::component::cxx::processor::intel::GOd GR;

  struct IRegID
    : public unisim::util::identifier::Identifier<IRegID>
    , unisim::util::symbolic::WithValueType<IRegID>
  {
    typedef uint32_t value_type;

    enum Code { eax = 0, ecx = 1, edx = 2, ebx = 3, esp = 4, ebp = 5, esi = 6, edi = 7, end } code;

    char const* c_str() const
    {
      switch (code)
        {
        case eax: return "eax";
        case ecx: return "ecx";
        case edx: return "edx";
        case ebx: return "ebx";
        case esp: return "esp";
        case ebp: return "ebp";
        case esi: return "esi";
        case edi: return "edi";

        case end: break;
        }
      return "NA";
    }

    void Repr(std::ostream& sink) const;

    IRegID() : code(end) {}
    IRegID( Code _code ) : code(_code) {}
    IRegID( unsigned idx ) : code(Code(idx)) {}
    IRegID( char const* _code ) : code(end) { init( _code ); }
  };

};

#endif // ARMD64DBA_ARCH_HH
