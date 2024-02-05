/*
 *  Copyright (c) 2009-2021,
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

#include "decoder.hh"

#include <unisim/component/cxx/processor/arm/disasm.hh>
#include <unisim/component/cxx/processor/arm/psr.hh>
#include <unisim/util/symbolic/binsec/binsec.hh>
#include <unisim/util/symbolic/symbolic.hh>
#include <top_arm32.tcc>
#include <top_thumb.tcc>

#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <cstdio>

namespace armsec {

// template <typename ARCH, unsigned OPSIZE> struct TypeFor {};

// template <typename ARCH> struct TypeFor<ARCH, 8> { typedef typename ARCH:: S8 S; typedef typename ARCH:: U8 U; };
// template <typename ARCH> struct TypeFor<ARCH,16> { typedef typename ARCH::S16 S; typedef typename ARCH::U16 U; };
// template <typename ARCH> struct TypeFor<ARCH,32> { typedef typename ARCH::S32 S; typedef typename ARCH::U32 U; typedef typename ARCH::F32 F; };
// template <typename ARCH> struct TypeFor<ARCH,64> { typedef typename ARCH::S64 S; typedef typename ARCH::U64 U; typedef typename ARCH::F64 F; };

struct Processor
{
  //   =====================================================================
  //   =                           Configuration                           =
  //   =====================================================================
  struct Unimplemented {};
  struct Undefined {};

  struct Config
  {
    // Following a standard armv7-a configuration
    static uint32_t const model = unisim::component::cxx::processor::arm::ARMEMU;
    static bool const     insns4T = true;
    static bool const     insns5E = true;
    static bool const     insns5J = true;
    static bool const     insns5T = true;
    static bool const     insns6  = true;
    static bool const     insnsRM = false;
    static bool const     insnsT2 = true;
    static bool const     insns7  = true;
  };

  //   =====================================================================
  //   =                             Data Types                            =
  //   =====================================================================
  typedef unisim::util::symbolic::SmartValue<double>   F64;
  typedef unisim::util::symbolic::SmartValue<float>    F32;
  typedef unisim::util::symbolic::SmartValue<bool>     BOOL;
  typedef unisim::util::symbolic::SmartValue<uint8_t>  U8;
  typedef unisim::util::symbolic::SmartValue<uint16_t> U16;
  typedef unisim::util::symbolic::SmartValue<uint32_t> U32;
  typedef unisim::util::symbolic::SmartValue<uint64_t> U64;
  typedef unisim::util::symbolic::SmartValue<int8_t>   S8;
  typedef unisim::util::symbolic::SmartValue<int16_t>  S16;
  typedef unisim::util::symbolic::SmartValue<int32_t>  S32;
  typedef unisim::util::symbolic::SmartValue<int64_t>  S64;

  typedef unisim::util::symbolic::FP                   FP;
  typedef unisim::util::symbolic::Expr                 Expr;
  typedef unisim::util::symbolic::ValueType           ValueType;

  typedef unisim::util::symbolic::binsec::ActionNode   ActionNode;

  struct ForeignRegisterID : unisim::util::symbolic::WithValueType<ForeignRegisterID>
  {
    typedef uint32_t value_type;
    ForeignRegisterID( uint8_t _mode, unsigned _idx )
      : idx(_idx), mode(_mode == SYSTEM_MODE ? USER_MODE : _mode)
    {}

    char const* mode_ident() const
    {
      switch (mode)
        {
        case USER_MODE: return "usr";
        case FIQ_MODE: return "fiq";
        case IRQ_MODE: return "irq";
        case SUPERVISOR_MODE: return "svc";
        case MONITOR_MODE: return "mon";
        case ABORT_MODE: return "abt";
        case HYPERVISOR_MODE: return "hyp";
        case UNDEFINED_MODE: return "und";
        }
      throw 0;
      return "";
    }

    void Repr( std::ostream& sink ) const
    {
      sink << (RegID("r0") + idx).c_str() << '_' << mode_ident();
    }
    int cmp( ForeignRegisterID const& rhs ) const
    {
      if (int delta = int(mode) - int(rhs.mode)) return delta;
      return idx - rhs.idx;
    }

    unsigned idx;
    uint8_t mode;
  };

  template <typename RID>
  static Expr newRegRead( RID id ) { return new unisim::util::symbolic::binsec::RegRead<RID>( id ); }

  template <typename RID>
  static Expr newRegWrite( RID id, Expr const& value ) { return new unisim::util::symbolic::binsec::RegWrite<RID>( id, value ); }

  template <typename RID>
  static Expr newPartialRegWrite( RID id, unsigned pos, unsigned size, Expr const& value ) { return new unisim::util::symbolic::binsec::RegWrite<RID>( id, pos, size, value ); }

  struct ITCond {};

  struct Mode
  {
    Mode() {}
    bool     HasBR( unsigned index ) { return false; }
    bool     HasSPSR() { return false; }
    void     SetSPSR(U32 const& value) {}
    U32      GetSPSR() { throw Unimplemented(); return U32(); }
    void     Swap( Processor& ) {}
  };

  typedef std::map<std::pair<uint8_t,uint32_t>,Expr> ForeignRegisters;

  //   =====================================================================
  //   =                      Construction/Destruction                     =
  //   =====================================================================

  struct PSR : public StatusRegister
  {
    typedef unisim::component::cxx::processor::arm::RegisterField<31,1> NRF; /* Negative Integer Condition Flag */
    typedef unisim::component::cxx::processor::arm::RegisterField<30,1> ZRF; /* Zero     Integer Condition Flag */
    typedef unisim::component::cxx::processor::arm::RegisterField<29,1> CRF; /* Carry    Integer Condition Flag */
    typedef unisim::component::cxx::processor::arm::RegisterField<28,1> VRF; /* Overflow Integer Condition Flag */
    typedef unisim::component::cxx::processor::arm::RegisterField<27,1> QRF; /* Cumulative saturation flag */

    typedef unisim::component::cxx::processor::arm::RegisterField<28,4> NZCVRF; /* Grouped Integer Condition Flags */


    typedef unisim::component::cxx::processor::arm::RegisterField<24,1> JRF; /* Jazelle execution state bit */
    typedef unisim::component::cxx::processor::arm::RegisterField< 9,1> ERF; /* Endianness execution state */
    typedef unisim::component::cxx::processor::arm::RegisterField< 5,1> TRF; /* Thumb execution state bit */

    typedef unisim::component::cxx::processor::arm::RegisterField< 0,5> MRF; /* Mode field */

    typedef unisim::component::cxx::processor::arm::RegisterField<10,6> ITHIRF;
    typedef unisim::component::cxx::processor::arm::RegisterField<25,2> ITLORF;

    typedef unisim::component::cxx::processor::arm::RegisterField< 0,32> ALLRF;

    static uint32_t const bg_mask = 0x00ff01c0; /* 23-20, GE[3:0], A, I, F, are not handled for now */

  private:
    PSR( PSR const& );
  public:
    PSR( Processor& p, StatusRegister const& ref )
      : StatusRegister(ref)
      , proc(p)
      , n(newRegRead(Flag("n")))
      , z(newRegRead(Flag("z")))
      , c(newRegRead(Flag("c")))
      , v(newRegRead(Flag("v")))
      , q(newRegRead(Flag("q")))
      , itstate(ref.itstate >> 8 ? newRegRead(ITStateID()) : U8(ref.itstate).expr )
      , bg(newRegRead(RegID("cpsr")))
    {
    }

    bool   GetJ() const { return (iset == Jazelle) or (iset == ThumbEE); }
    bool   GetT() const { return (iset ==   Thumb) or (iset == ThumbEE); }

    template <typename RF>
    void   Set( RF const& _, U32 const& value )
    {
      unisim::util::symbolic::StaticAssert<(RF::pos > 31) or ((RF::pos + RF::size) <= 28)>::check(); // NZCV
      unisim::util::symbolic::StaticAssert<(RF::pos > 27) or ((RF::pos + RF::size) <= 27)>::check(); // Q
      unisim::util::symbolic::StaticAssert<(RF::pos > 26) or ((RF::pos + RF::size) <= 24)>::check(); // ITLO, J
      unisim::util::symbolic::StaticAssert<(RF::pos > 15) or ((RF::pos + RF::size) <=  9)>::check(); // ITHI, E
      unisim::util::symbolic::StaticAssert<(RF::pos >  5) or ((RF::pos + RF::size) <=  0)>::check(); // T, MODE

      return _.Set( bg, value );
    }

    template <typename RF>
    U32    Get( RF const& _ )
    {
      unisim::util::symbolic::StaticAssert<(RF::pos > 31) or ((RF::pos + RF::size) <= 28)>::check(); // NZCV
      unisim::util::symbolic::StaticAssert<(RF::pos > 27) or ((RF::pos + RF::size) <= 27)>::check(); // Q
      unisim::util::symbolic::StaticAssert<(RF::pos > 26) or ((RF::pos + RF::size) <= 24)>::check(); // ITLO, J
      unisim::util::symbolic::StaticAssert<(RF::pos > 15) or ((RF::pos + RF::size) <=  9)>::check(); // ITHI, E
      unisim::util::symbolic::StaticAssert<(RF::pos >  5) or ((RF::pos + RF::size) <=  0)>::check(); // T, MODE

      return _.Get( bg );
    }

    void   SetBits( U32 const& bits, uint32_t mask );
    U32    GetBits();

    void   Set( NRF const& _, BOOL const& value ) { n = value.expr; }
    void   Set( ZRF const& _, BOOL const& value ) { z = value.expr; }
    void   Set( CRF const& _, BOOL const& value ) { c = value.expr; }
    void   Set( VRF const& _, BOOL const& value ) { v = value.expr; }
    void   Set( QRF const& _, BOOL const& value ) { q = value.expr; }
    void   Set( ERF const& _, U32 const& value ) { if (proc.Test(value != U32(bigendian))) proc.UnpredictableInsnBehaviour(); }
    void   Set( NZCVRF const& _, U32 const& value );

    void   SetITState( uint8_t init_val ) { itstate = U8(init_val); }
    BOOL   InITBlock() const { return (itstate & U8(0b1111)) != U8(0); }

    U32    Get( NRF const& _ ) { return U32(BOOL(n)); }
    U32    Get( ZRF const& _ ) { return U32(BOOL(z)); }
    U32    Get( CRF const& _ ) { return U32(BOOL(c)); }
    U32    Get( VRF const& _ ) { return U32(BOOL(v)); }
    U32    Get( QRF const& _ ) { return U32(BOOL(q)); }

    /* ISetState */
    U32    Get( JRF const& _ ) { return U32(GetJ()); }
    U32    Get( TRF const& _ ) { return U32(GetT()); }

    /* Endianness */
    U32    Get( ERF const& _ ) { return U32(bigendian); }
    U32    Get( MRF const& _ ) { return U32(mode); }
    // U32 Get( ALL const& _ ) { return (U32(BOOL(n)) << 31) | (U32(BOOL(z)) << 30) | (U32(BOOL(c)) << 29) | (U32(BOOL(v)) << 28) | bg; }

    Processor& proc;
    Expr n, z, c, v, q, nthumb;
    U8 itstate;
    U32 bg;
  };

private:
  Processor( Processor const& );
public:

  Processor( StatusRegister const& ref_psr )
    : path(0)
    , reg_values()
    , next_insn_addr()
    , branch_type(B_JMP)
    , cpsr( *this, ref_psr )
    , spsr( newRegRead(RegID("spsr")) )
    , sregs()
    , FPSCR( newRegRead(RegID("fpscr")) )
    , FPEXC( newRegRead(RegID("fpexc")) )
    , stores()
    , unpredictable(false)
    , is_it_assigned(false)
    , mode()
    , foreign_registers()
    , neonregs()
  {
    // GPR regs
    for (unsigned reg = 0; reg < 15; ++reg)
      reg_values[reg] = U32( newRegRead( RegID("r0") + reg ) );

    // Special registers
    for (SRegID reg; reg.next();)
      sregs[reg.idx()] = U32( newRegRead( reg ) );

    for (unsigned reg = 0; reg < 32; ++reg)
      neonregs[reg][0] = newRegRead( NeonReg(reg) );
  }

  bool close( Processor const& ref, uint32_t linear_nia )
  {
    bool complete = path->close();
    if (branch_type == B_CALL)
      path->add_sink( new unisim::util::symbolic::binsec::Call<uint32_t>( next_insn_addr.expr, linear_nia ) );
    else
      path->add_sink( new unisim::util::symbolic::binsec::Branch( next_insn_addr.expr ) );
    if (unpredictable)
      {
        path->add_sink( new unisim::util::symbolic::binsec::AssertFalse() );
        return complete;
      }
    if (cpsr.n != ref.cpsr.n)
      path->add_sink( newRegWrite( Flag("n"), cpsr.n ) );
    if (cpsr.z != ref.cpsr.z)
      path->add_sink( newRegWrite( Flag("z"), cpsr.z ) );
    if (cpsr.c != ref.cpsr.c)
      path->add_sink( newRegWrite( Flag("c"), cpsr.c ) );
    if (cpsr.v != ref.cpsr.v)
      path->add_sink( newRegWrite( Flag("v"), cpsr.v ) );
    if (cpsr.q != ref.cpsr.q)
      path->add_sink( newRegWrite( Flag("q"), cpsr.q ) );
    if (cpsr.itstate.expr != ref.cpsr.itstate.expr)
      path->add_sink( newRegWrite( ITStateID(), cpsr.itstate.expr ) );
    if (cpsr.bg.expr != ref.cpsr.bg.expr)
      path->add_sink( newRegWrite( RegID("cpsr"), cpsr.bg.expr ) );

    if (cpsr.nthumb.good())
      {
        Expr nt( cpsr.nthumb );
        if (unisim::util::symbolic::ConstNodeBase const* ntc = nt.ConstSimplify())
          {
            if (dynamic_cast<unisim::util::symbolic::ConstNode<bool> const&>(*ntc).value ^ cpsr.GetT())
              path->add_sink( newRegWrite( Flag("t"), nt ) );
          }
        else
          path->add_sink( newRegWrite( Flag("t"), nt ) );
      }

    if (spsr.expr != ref.spsr.expr)
      path->add_sink( newRegWrite( RegID("spsr"), spsr.expr ) );

    for (SRegID reg; reg.next();)
      if (sregs[reg.idx()].expr != ref.sregs[reg.idx()].expr)
        path->add_sink( newRegWrite( reg, sregs[reg.idx()].expr ) );
    if (FPSCR.expr != ref.FPSCR.expr)
      path->add_sink( newRegWrite( RegID("fpscr"), FPSCR.expr ) );
    if (FPEXC.expr != ref.FPEXC.expr)
      path->add_sink( newRegWrite( RegID("fpexc"), FPEXC.expr ) );
    for (unsigned reg = 0; reg < 15; ++reg)
      {
        if (reg_values[reg].expr != ref.reg_values[reg].expr)
          path->add_sink( newRegWrite( RegID("r0") + reg, reg_values[reg].expr ) );
      }
    for (ForeignRegisters::iterator itr = foreign_registers.begin(), end = foreign_registers.end(); itr != end; ++itr)
      {
        unisim::util::symbolic::binsec::RegRead<ForeignRegisterID> ref(ForeignRegisterID(itr->first.first, itr->first.second));
        ref.Retain(); // Prevent deletion of this static instance
        if (itr->second == Expr(&ref)) continue;
        std::ostringstream buf;
        ref.Repr( buf );
        path->add_sink( newRegWrite( RegID(buf.str().c_str()), itr->second ) );
      }
    for (unsigned reg = 0; reg < 32; ++reg)
      GetNeonSinks(ref, reg);

    for (std::set<Expr>::const_iterator itr = stores.begin(), end = stores.end(); itr != end; ++itr)
      path->add_sink( *itr );
    return complete;
  }

  //   =====================================================================
  //   =                 Internal Instruction Control Flow                 =
  //   =====================================================================

  void UnpredictableInsnBehaviour() { unpredictable = true; }

  template <typename OP>
  void UndefinedInstruction( OP* op ) { throw Undefined(); }

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

    return concretize( BOOL(cond).expr );
  }

  void FPTrap( unsigned exc )
  {
    throw Unimplemented();
  }

  //   =====================================================================
  //   =             General Purpose Registers access methods              =
  //   =====================================================================

  U32  GetGPR( uint32_t id ) { return reg_values[id]; }

  // TODO: interworking branches are not correctly handled
  void SetGPR_mem( uint32_t id, U32 const& value )
  {
    if (id != 15)
      reg_values[id] = value;
    else
      SetNIA( value, B_JMP );
  }
  void SetGPR( uint32_t id, U32 const& value ) {
    if (id != 15)
      reg_values[id] = value;
    else
      SetNIA( value, B_JMP );
  }

  void SetGPR_usr( uint32_t id, U32 const& value ) { /* system mode */ throw Unimplemented(); }
  U32  GetGPR_usr( uint32_t id ) { /* system mode */ throw Unimplemented(); return U32(); }

  U32  GetNIA() { return next_insn_addr; }
  enum branch_type_t { B_JMP = 0, B_CALL, B_RET, B_EXC, B_DBG, B_RFE };
  void SetNIA( U32 const& nia, branch_type_t bt )
  {
    branch_type = bt;
    next_insn_addr = nia;
  }

  Expr& GetForeignRegister( uint8_t foreign_mode, uint32_t idx )
  {
    Expr& result = foreign_registers[std::make_pair( foreign_mode, idx )];
    if (not result.node)
      result = newRegRead( ForeignRegisterID( foreign_mode, idx ) );
    return result;
  }

  U32  GetBankedRegister( uint8_t foreign_mode, uint32_t idx )
  {
    if ((cpsr.mode == foreign_mode) or
        (idx < 8) or
        (idx >= 15) or
        ((foreign_mode != FIQ_MODE) and (cpsr.mode != FIQ_MODE) and (idx < 13))
        )
      return GetGPR( idx );
    return U32( GetForeignRegister( foreign_mode, idx ) );
  }

  void SetBankedRegister( uint8_t foreign_mode, uint32_t idx, U32 value )
  {
    if ((cpsr.mode == foreign_mode) or
        (idx < 8) or
        (idx >= 15) or
        ((foreign_mode != FIQ_MODE) and (cpsr.mode != FIQ_MODE) and (idx < 13))
        )
      return SetGPR( idx, value );
    GetForeignRegister( foreign_mode, idx ) = value.expr;
  }

  //   =====================================================================
  //   =              Special/System Registers access methods              =
  //   =====================================================================

  PSR& CPSR() { return cpsr; }

  U32  GetCPSR()                                 { return cpsr.GetBits(); }
  void SetCPSR( U32 const& bits, uint32_t mask ) { cpsr.SetBits( bits, mask ); }

  U32& SPSR() { throw Unimplemented(); static U32 spsr_dummy; return spsr_dummy; }

  ITCond itcond() const { return ITCond(); }
  bool itblock() { return Test(cpsr.InITBlock()); }

  void ITSetState( uint32_t cond, uint32_t mask )
  {
    cpsr.SetITState( (cond << 4) | mask );
    is_it_assigned = true;
  }

  void ITAdvance()
  {
    if (is_it_assigned)
      is_it_assigned = false;
    else if (itblock())
      {
        U8 itstate( cpsr.itstate );
        itstate = (Test((itstate & U8(7)) != U8(0))) ? ((itstate & U8(-32)) | ((itstate << 1) & U8(31))) : U8(0);
        cpsr.itstate = itstate;
      }
  }

  Mode&  CurrentMode() { /* throw Unimplemented(); */ return mode; }
  Mode&  GetMode(uint8_t) { throw Unimplemented(); return mode; }
  void RequiresPL(unsigned rpl) { /*TODO: todo*/ }

  struct CP15Reg
  {
    void CheckPermissions( uint8_t, uint8_t, uint8_t, uint8_t, Processor& cpu, bool ) const { cpu.RequiresPL(1); }
    virtual U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor&) const { throw Unimplemented(); return U32(); }
    virtual void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor&, U32 const&) const { throw Unimplemented(); }
    virtual void Describe(uint8_t crn, uint8_t op1, uint8_t crm, uint8_t op2, std::ostream& sink ) const
    {
      sink << "CR15{crn=" << crn << ", op1=" << op1 << ", crm=" << crm << ", op2=" << op2 << "}";
    }
  };

  static CP15Reg* CP15GetRegister( uint8_t crn, uint8_t opcode1, uint8_t crm, uint8_t opcode2 );

  //   ====================================================================
  //   =         Vector and Floating-point Registers access methods       =
  //   ====================================================================

  U32 RoundTowardsZeroFPSCR() const
  {
    U32 fpscr = FPSCR;
    unisim::component::cxx::processor::arm::RMode.Set( fpscr, U32(unisim::component::cxx::processor::arm::RoundTowardsZero) );
    return fpscr;
  }

  U32 RoundToNearestFPSCR() const
  {
    U32 fpscr = FPSCR;
    unisim::component::cxx::processor::arm::RMode.Set( fpscr, U32(unisim::component::cxx::processor::arm::RoundToNearest) );
    return fpscr;
  }

  // U32 StandardValuedFPSCR() const   { return AHP.Mask( FPSCR ) | 0x03000000; }

  struct NeonName
  { // Convenience class for name construction
    NeonName( unsigned idx ) : begin(&buf[sizeof(buf)]) { _('\0'); do { _('0'+idx%10); idx /= 10; } while (idx); _('d'); }
    void _(char c) { *--begin = c; } operator char const* () const { return begin; } char buf[4]; char* begin;
  };

  struct NeonReg : public unisim::util::symbolic::WithValueType<NeonReg>
  {
    typedef uint64_t value_type;
    NeonReg( unsigned _reg ) : reg(_reg) {}
    void Repr( std::ostream& sink ) const { sink << 'd' << std::dec << reg; }
    int cmp( NeonReg const& rhs ) const { return int(reg) - int(rhs.reg); }

    unsigned reg;
  };

  static unsigned const NEONSIZE = 8;

  void
  GetNeonSinks( Processor const& ref, unsigned reg )
  {
    // Requested read is a concatenation of multiple source values
    // Crawl register expression tree to produce sinks
    struct _
    {
      _( Processor& _core, Processor const& _ref,unsigned _reg ) : core(_core), ref(_ref), reg(_reg) { Process( 0, NEONSIZE ); }
      Processor& core; Processor const& ref; unsigned reg;
      void Process( unsigned pos, unsigned size )
      {
        Expr value = core.eneonread(reg,size,pos);
        if (value == ref.eneonread(reg,size,pos))
          return;
        value = unisim::util::symbolic::binsec::ASExprNode::Simplify( value );
        unsigned half = size / 2, mid = pos+half;
        if (value.ConstSimplify() or size <= 1 or not core.neonregs[reg][mid].node)
          {
            if (size == NEONSIZE)
              core.path->add_sink( newRegWrite( NeonReg(reg), value ) );
            else
              {
                unisim::util::symbolic::binsec::BitFilter bf( value, 64, 0, size*8, size*8, false );
                bf.Retain(); // Not a heap-allocated object (never delete);
                value = bf.Simplify();
                if (value.node == &bf) value = new unisim::util::symbolic::binsec::BitFilter( bf );
                core.path->add_sink( newPartialRegWrite( NeonReg(reg), 8*pos, 8*size, value ) );
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

  Expr eneonread( unsigned reg, unsigned size, unsigned pos ) const
  {
    using unisim::util::symbolic::ExprNode;
    using unisim::util::symbolic::make_const;

    // struct
    // {
    //   Expr ui( unsigned sz, Expr const& src ) const
    //   {
    //     switch (sz) {
    //     default: throw 0;
    //     case 1: return new unisim::util::symbolic::CastNode<uint8_t,uint64_t>( src );
    //     case 2: return new unisim::util::symbolic::CastNode<uint16_t,uint64_t>( src );
    //     case 4: return new unisim::util::symbolic::CastNode<uint32_t,uint64_t>( src );
    //     case 8: return new unisim::util::symbolic::CastNode<uint64_t,uint64_t>( src );
    //     }
    //     return 0;
    //   }
    // } cast;

    if (not neonregs[reg][pos].node)
      {
        // requested read is in the middle of a larger value
        unsigned src = pos;
        do { src = src & (src-1); } while (not neonregs[reg][src].node);
        unsigned shift = 8*(pos - src);
        return new unisim::util::symbolic::binsec::BitFilter( neonregs[reg][src], 64, shift, 8*size, 64, false );
      }
    else if (not neonregs[reg][(pos|size)&(NEONSIZE-1)].node)
      {
        // requested read is in lower bits of a larger value
        return new unisim::util::symbolic::binsec::BitFilter( neonregs[reg][pos], 64, 0, 8*size, 64, false );
      }
    else if ((size > 1) and (neonregs[reg][pos|(size >> 1)].node))
      {
        // requested read is a concatenation of multiple source values
        Expr concat = neonregs[reg][pos];
        for (unsigned idx = 1; ++idx < size;)
          {
            if (not neonregs[reg][pos+idx].node)
              continue;
            concat = make_operation( "Or", make_operation( "Lsl", neonregs[reg][idx], make_const( uint8_t(8*idx) ) ), concat );
          }
        return concat;
      }

    // requested read is directly available
    return neonregs[reg][pos];
  }

  void eneonwrite( unsigned reg, unsigned size, unsigned pos, Expr const& xpr )
  {
    Expr nxt[NEONSIZE];

    for (unsigned ipos = pos, isize = size, cpos;
         cpos = (ipos^isize) & (NEONSIZE-1), (not neonregs[reg][ipos].node) or (not neonregs[reg][cpos].node);
         isize *= 2, ipos &= -isize
         )
      {
        nxt[cpos] = eneonread( reg, isize, cpos );
      }

    for (unsigned ipos = 0; ipos < NEONSIZE; ++ipos)
      {
        if (nxt[ipos].node)
          neonregs[reg][ipos] = nxt[ipos];
      }

    neonregs[reg][pos] = xpr;

    for (unsigned rem = 1; rem < size; ++rem)
      {
        neonregs[reg][pos+rem] = 0;
      }
  }

  U32  GetVSU( unsigned idx ) { return U32( U64( eneonread( idx / 2, 4, (idx*4) & 4 ) ) ); }
  void SetVSU( unsigned idx, U32 val ) { eneonwrite( idx / 2, 4, (idx*4) & 4, U64(val).expr ); }
  U64  GetVDU( unsigned idx ) { return U64( eneonread( idx, 8, 0 ) ); }
  void SetVDU( unsigned idx, U64 val ) { eneonwrite( idx, 8, 0, val.expr ); }
  F32  GetVSR( unsigned idx ) { return F32(); }
  void SetVSR( unsigned idx, F32 val ) {}
  F64  GetVDR( unsigned idx ) { return F64(); }
  void SetVDR( unsigned idx, F64 val ) {}

  static unsigned tsizeof( U8 const& )  { return  1; }
  static unsigned tsizeof( U16 const& ) { return  2; }
  static unsigned tsizeof( U32 const& ) { return  4; }
  static unsigned tsizeof( U64 const& ) { return  8; }
  static unsigned tsizeof( S8 const& )  { return  1; }
  static unsigned tsizeof( S16 const& ) { return  2; }
  static unsigned tsizeof( S32 const& ) { return  4; }
  static unsigned tsizeof( S64 const& ) { return  8; }

  template <typename T> T ucast( T const& x ) { return x; }
  U8 ucast( S8 const& x ) { return U8(x); }
  U16 ucast( S16 const& x ) { return U16(x); }
  U32 ucast( S32 const& x ) { return U32(x); }
  U64 ucast( S64 const& x ) { return U64(x); }

  template <typename T> T neoncast( T const&, Expr const& x ) { return T(x); }
  S8 neoncast( S8 const&, Expr const& x ) { return S8(U8(x)); }
  S16 neoncast( S16 const&, Expr const& x ) { return S16(U16(x)); }
  S32 neoncast( S32 const&, Expr const& x ) { return S32(U32(x)); }
  S64 neoncast( S64 const&, Expr const& x ) { return S64(U64(x)); }

  // Get|Set elements
  template <class ELEMT>
  void SetVDE( unsigned reg, unsigned idx, ELEMT const& value )
  {
    using unisim::util::symbolic::binsec::BitFilter;
    auto uvalue = ucast( value );
    unsigned usz = tsizeof( uvalue );
    Expr neonval( new BitFilter( uvalue.expr, usz*8, 0, usz*8, 64, false ) );
    eneonwrite( reg, usz, usz*idx, neonval );
  }

  template <class ELEMT>
  ELEMT GetVDE( unsigned reg, unsigned idx, ELEMT const& trait )
  {
    unsigned usz = tsizeof( trait );
    return ELEMT( U64( eneonread( reg, usz, usz*idx ) ) );
  }

  U8 GetTVU8(unsigned r0, unsigned elts, unsigned regs, U8 idx, U8 oob)
  {
    struct CantDoThat {};
    throw CantDoThat();
    return U8();
    // auto r = idx/elts;
    // return Test(r < regs) ? GetVDE((r0 + r) % 32, idx % elts, U8()) : oob;
  }

  //   =====================================================================
  //   =                      Control Transfer methods                     =
  //   =====================================================================

  void BranchExchange( U32 const& target, branch_type_t branch_type )
  {
    cpsr.nthumb = new unisim::util::symbolic::binsec::BitFilter( target.expr, 32, 0, 1, 1, false );
    Branch( target, branch_type );
  }

  void Branch( U32 const& target, branch_type_t branch_type )
  {
    SetNIA( target & U32(this->cpsr.GetT() ? -2 : -4), branch_type );
  }
  // void BranchExchange( U32 const& target, branch_type_t branch_type )
  // {
  //   SetNIA( target, branch_type );
  // }
  // void Branch( U32 const& target, branch_type_t branch_type )
  // {
  //   SetNIA( target, branch_type );
  // }

  void WaitForInterrupt() { throw Unimplemented(); }
  void SWI( uint32_t imm ) { throw Unimplemented(); }
  void BKPT( uint32_t imm ) { throw Unimplemented(); }
  void CallSupervisor( uint32_t imm ) { throw Unimplemented(); }
  bool IntegerZeroDivide( BOOL const& condition ) { return false; }

  //   =====================================================================
  //   =                       Memory access methods                       =
  //   =====================================================================

  void CheckAlignment( U32 const& addr, uint32_t alignment ) { /*TODO*/ }

  U32  MemURead32( U32 const& addr ) { return U32( Expr( new unisim::util::symbolic::binsec::Load( addr.expr, 4, 0, false ) ) ); }
  U16  MemURead16( U32 const& addr ) { return U16( Expr( new unisim::util::symbolic::binsec::Load( addr.expr, 2, 0, false ) ) ); }
  U32  MemRead32( U32 const& addr ) { return U32( Expr( new unisim::util::symbolic::binsec::Load( addr.expr, 4, 2, false ) ) ); }
  U16  MemRead16( U32 const& addr ) { return U16( Expr( new unisim::util::symbolic::binsec::Load( addr.expr, 2, 1, false ) ) ); }
  U8   MemRead8( U32 const& addr ) { return U8( Expr( new unisim::util::symbolic::binsec::Load( addr.expr, 1, 0, false ) ) ); }

  void MemUWrite32( U32 const& addr, U32 const& value ) { stores.insert( new unisim::util::symbolic::binsec::Store( addr.expr, value.expr, 4, 0, false ) ); }
  void MemUWrite16( U32 const& addr, U16 const& value ) { stores.insert( new unisim::util::symbolic::binsec::Store( addr.expr, value.expr, 2, 0, false ) ); }
  void MemWrite32( U32 const& addr, U32 const& value ) { stores.insert( new unisim::util::symbolic::binsec::Store( addr.expr, value.expr, 4, 2, false ) ); }
  void MemWrite16( U32 const& addr, U16 const& value ) { stores.insert( new unisim::util::symbolic::binsec::Store( addr.expr, value.expr, 2, 1, false ) ); }
  void MemWrite8( U32 const& addr, U8 const& value ) { stores.insert( new unisim::util::symbolic::binsec::Store( addr.expr, value.expr, 1, 0, false ) ); }

  void SetExclusiveMonitors( U32 const& address, unsigned size ) { std::cerr << "SetExclusiveMonitors\n"; }
  bool ExclusiveMonitorsPass( U32 const& address, unsigned size ) { std::cerr << "ExclusiveMonitorsPass\n"; return true; }
  void ClearExclusiveLocal() { std::cerr << "ClearExclusiveMonitors\n"; }

  //   =====================================================================
  //   =                         Processor Storage                         =
  //   =====================================================================

  static const unsigned PC_reg = 15;
  static const unsigned LR_reg = 14;
  static const unsigned SP_reg = 13;

  /* masks for the different running modes */
  static uint32_t const USER_MODE = 0b10000;
  static uint32_t const FIQ_MODE = 0b10001;
  static uint32_t const IRQ_MODE = 0b10010;
  static uint32_t const SUPERVISOR_MODE = 0b10011;
  static uint32_t const MONITOR_MODE = 0b10110;
  static uint32_t const ABORT_MODE = 0b10111;
  static uint32_t const HYPERVISOR_MODE = 0b11010;
  static uint32_t const UNDEFINED_MODE = 0b11011;
  static uint32_t const SYSTEM_MODE = 0b11111;

  /* values of the different condition codes */
  // static uint32_t const COND_EQ = 0x00;
  // static uint32_t const COND_NE = 0x01;
  // static uint32_t const COND_CS_HS = 0x02;
  // static uint32_t const COND_CC_LO = 0x03;
  // static uint32_t const COND_MI = 0x04;
  // static uint32_t const COND_PL = 0x05;
  // static uint32_t const COND_VS = 0x06;
  // static uint32_t const COND_VC = 0x07;
  // static uint32_t const COND_HI = 0x08;
  // static uint32_t const COND_LS = 0x09;
  // static uint32_t const COND_GE = 0x0a;
  // static uint32_t const COND_LT = 0x0b;
  // static uint32_t const COND_GT = 0x0c;
  // static uint32_t const COND_LE = 0x0d;
  // static uint32_t const COND_AL = 0x0e;

  /* mask for valid bits in processor control and status registers */
  static uint32_t const PSR_UNALLOC_MASK = 0x00f00000;

  struct SRegID
    : public unisim::util::identifier::Identifier<SRegID>
    , public unisim::util::symbolic::WithValueType<SRegID>
  {
    typedef uint32_t value_type;
    enum Code {
      SCTLR, ACTLR,
      CTR, MPIDR,
      ID_PFR0, CCSIDR, CLIDR, CSSELR,
      CPACR, NSACR,
      TTBR0, TTBR1, TTBCR,
      DACR,
      DFSR, IFSR, DFAR, IFAR,
      ICIALLUIS, BPIALLIS,
      ICIALLU, ICIMVAU, BPIALL,
      DCIMVAC, DCISW, DCCMVAC, DCCSW, DCCMVAU, DCCIMVAC,
      TLBIALLIS, TLBIALL, TLBIASID,
      VBAR,
      CONTEXTIDR,
      DIAGCR, CFGBAR, end
    } code;

    char const* c_str() const
    {
      switch (code)
        {
        case      SCTLR: return "sctlr";
        case      ACTLR: return "actlr";
        case        CTR: return "ctr";
        case      MPIDR: return "mpidr";
        case    ID_PFR0: return "id_pfr0";
        case     CCSIDR: return "ccsidr";
        case      CLIDR: return "clidr";
        case     CSSELR: return "csselr";
        case      CPACR: return "cpacr";
        case      NSACR: return "nsacr";
        case      TTBR0: return "ttbr0";
        case      TTBR1: return "ttbr1";
        case      TTBCR: return "ttbcr";
        case       DACR: return "dacr";
        case       DFSR: return "dfsr";
        case       IFSR: return "ifsr";
        case       DFAR: return "dfar";
        case       IFAR: return "ifar";
        case  ICIALLUIS: return "icialluis";
        case   BPIALLIS: return "bpiallis";
        case    ICIALLU: return "iciallu";
        case    ICIMVAU: return "icimvau";
        case     BPIALL: return "bpiall";
        case    DCIMVAC: return "dcimvac";
        case      DCISW: return "dcisw";
        case    DCCMVAC: return "dccmvac";
        case      DCCSW: return "dccsw";
        case    DCCMVAU: return "dccmvau";
        case   DCCIMVAC: return "dccimvac";
        case  TLBIALLIS: return "tlbiallis";
        case    TLBIALL: return "tlbiall";
        case   TLBIASID: return "tlbiasid";
        case       VBAR: return "vbar";
        case CONTEXTIDR: return "contextidr";
        case     DIAGCR: return "diagcr";
        case     CFGBAR: return "cfgbar";
        case end:        break;
        }
      return "NA";
    }

    void Repr(std::ostream& sink) const { sink << c_str(); }

    SRegID() : code(end) {}
    SRegID( Code _code ) : code(_code) {}
    SRegID( char const* _code ) : code(end) { init(_code); }
  };

  U32& SReg( SRegID reg )
  {
    if (reg.code == SRegID::end)
      throw 0;
    return sregs[reg.idx()];
  }

  struct RegID
    : public unisim::util::identifier::Identifier<RegID>
    , unisim::util::symbolic::WithValueType<RegID>
  {
    typedef uint32_t value_type;

    enum Code
      {
        NA = 0,
        r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip, sp, lr,
        cpsr, spsr,
        fpscr, fpexc,
        r8_fiq,
        r9_fiq,
        sl_fiq,
        fp_fiq,
        ip_fiq,
        sp_fiq,
        lr_fiq,
        r8_usr,
        r9_usr,
        sl_usr,
        fp_usr,
        ip_usr,
        sp_usr,
        lr_usr,
        sp_irq,
        sp_svc,
        sp_abt,
        sp_hyp,
        sp_und,
        lr_irq,
        lr_svc,
        lr_abt,
        lr_hyp,
        lr_und,
        end
      } code;

    char const* c_str() const
    {
      switch (code)
        {
        case         r0: return "r0";
        case         r1: return "r1";
        case         r2: return "r2";
        case         r3: return "r3";
        case         r4: return "r4";
        case         r5: return "r5";
        case         r6: return "r6";
        case         r7: return "r7";
        case         r8: return "r8";
        case         r9: return "r9";
        case         sl: return "sl";
        case         fp: return "fp";
        case         ip: return "ip";
        case         sp: return "sp";
        case         lr: return "lr";
        case       cpsr: return "cpsr";
        case       spsr: return "spsr";
        case      fpscr: return "fpscr";
        case      fpexc: return "fpexc";
        case     r8_fiq: return "r8_fiq";
        case     r9_fiq: return "r9_fiq";
        case     sl_fiq: return "sl_fiq";
        case     fp_fiq: return "fp_fiq";
        case     ip_fiq: return "ip_fiq";
        case     sp_fiq: return "sp_fiq";
        case     lr_fiq: return "lr_fiq";
        case     r8_usr: return "r8_usr";
        case     r9_usr: return "r9_usr";
        case     sl_usr: return "sl_usr";
        case     fp_usr: return "fp_usr";
        case     ip_usr: return "ip_usr";
        case     sp_usr: return "sp_usr";
        case     lr_usr: return "lr_usr";
        case     sp_irq: return "sp_irq";
        case     sp_svc: return "sp_svc";
        case     sp_abt: return "sp_abt";
        case     sp_hyp: return "sp_hyp";
        case     sp_und: return "sp_und";
        case     lr_irq: return "lr_irq";
        case     lr_svc: return "lr_svc";
        case     lr_abt: return "lr_abt";
        case     lr_hyp: return "lr_hyp";
        case     lr_und: return "lr_und";
        case         NA:
        case        end: break;
        }
      return "NA";
    }

    void Repr(std::ostream& sink) const { sink << c_str(); }

    RegID() : code(end) {}
    RegID( Code _code ) : code(_code) {}
    RegID( char const* _code ) : code(end) { init( _code ); }
  };

  struct Flag
    : public unisim::util::identifier::Identifier<Flag>
    , public unisim::util::symbolic::WithValueType<Flag>
  {
    typedef bool value_type;

    enum Code { N, Z, C, V, Q, T, end } code;

    char const* c_str() const
    {
      static char const* names[] = {"n", "z", "c", "v", "q", "t", "NA"};
      return names[int(code)];
    }

    void Repr(std::ostream& sink) const { sink << c_str(); }
    
    Flag() : code(end) {}
    Flag( Code _code ) : code(_code) {}
    Flag( char const* _code ) : code(end) { init( _code ); }
  };

  struct ITStateID
    : public unisim::util::symbolic::WithValueType<ITStateID>
  {
    typedef uint8_t value_type;
    void Repr(std::ostream& sink) const { sink << "itstate"; }
    int cmp(ITStateID const&) const { return 0; }
  };

  ActionNode*      path;
  U32              reg_values[16];
  U32              next_insn_addr;
  branch_type_t    branch_type;
  PSR              cpsr;
  U32              spsr;
  U32              sregs[SRegID::end];
  U32              FPSCR, FPEXC;
  std::set<Expr>   stores;
  bool             unpredictable;
  bool             is_it_assigned; /* determines wether current instruction is an IT one. */
  Mode             mode;
  ForeignRegisters foreign_registers;
  Expr             neonregs[32][NEONSIZE];
};

bool CheckCondition( Processor& state, unsigned cond )
{
  Processor::BOOL N = state.cpsr.n, Z = state.cpsr.z, C = state.cpsr.c, V = state.cpsr.v, result(false);

  switch (cond) {
  case  0: result =                   Z; break; // eq; equal
  case  1: result =               not Z; break; // ne; not equal
  case  2: result =                   C; break; // cs/hs; unsigned higher or same
  case  3: result =               not C; break; // cc/lo; unsigned lower
  case  4: result =                   N; break; // mi; negative
  case  5: result =               not N; break; // pl; positive or zero
  case  6: result =                   V; break; // vs; overflow set
  case  7: result =               not V; break; // vc; overflow clear
  case  8: result =    not (not C or Z); break; // hi; unsigned higher
  case  9: result =        (not C or Z); break; // ls; unsigned lower or same
  case 10: result =       not (N xor V); break; // ge; signed greater than or equal
  case 11: result =           (N xor V); break; // lt; signed less than
  case 12: result = not(Z or (N xor V)); break; // gt; signed greater than
  case 13: result =    (Z or (N xor V)); break; // le; signed less than or equal
  case 14: return true;                         // al; always
  case 15: return true;                         // nv; never (when allowed, behaves as always)
  default:
    throw std::logic_error( "bad condition" );
  }

  return state.Test(result);
}

bool CheckCondition( Processor& state, Processor::ITCond const& cond )
{
  typedef Processor::BOOL BOOL;
  typedef Processor::U8   U8;
  BOOL N = state.cpsr.n, Z = state.cpsr.z, C = state.cpsr.c, V = state.cpsr.v;
  U8 cc = (state.cpsr.itstate >> 4);
  return state.Test(
    ((state.cpsr.itstate & U8(0b1111)) == U8(0)) or // unconditional
    ((cc == U8(0)) and (Z)) or // eq; equal
    ((cc == U8(1)) and (not Z)) or // ne; not equal
    ((cc == U8(2)) and (C)) or // cs/hs; unsigned higher or same
    ((cc == U8(3)) and (not C)) or // cc/lo; unsigned lower
    ((cc == U8(4)) and (N)) or // mi; negative
    ((cc == U8(5)) and (not N)) or // pl; positive or zero
    ((cc == U8(6)) and (V)) or // vs; overflow set
    ((cc == U8(7)) and (not V)) or // vc; overflow clear
    ((cc == U8(8)) and (not (not C or Z))) or // hi; unsigned higher
    ((cc == U8(9)) and ((not C or Z))) or // ls; unsigned lower or same
    ((cc == U8(10)) and (not (N xor V))) or // ge; signed greater than or equal
    ((cc == U8(11)) and ((N xor V))) or // lt; signed less than
    ((cc == U8(12)) and (not(Z or (N xor V)))) or // gt; signed greater than
    ((cc == U8(13)) and ((Z or (N xor V)))) or // le; signed less than or equal
    ((cc == U8(14)) and (unisim::util::symbolic::make_const( true ))));
}

}

namespace unisim { namespace util { namespace symbolic {
template <class OP>
unisim::util::symbolic::SmartValue<OP> NeonSHL( unisim::util::symbolic::SmartValue<OP> op, unisim::util::symbolic::SmartValue<int8_t> sh )
{
  struct CantDoThat {};
  throw CantDoThat();
  return unisim::util::symbolic::SmartValue<OP>();
}
}}}

namespace armsec {

void UpdateStatusSub( Processor& state, Processor::U32 const& res, Processor::U32 const& lhs, Processor::U32 const& rhs )
{
  typedef Processor::S32 S32;
  typedef Processor::U32 U32;
  Processor::BOOL neg = S32(res) < S32(0);
  state.cpsr.n = neg.expr;
  state.cpsr.z = ( res == U32(0) ).expr;
  state.cpsr.c = ( lhs >= rhs ).expr;
  state.cpsr.v = ( neg xor (S32(lhs) < S32(rhs)) ).expr;
}

void UpdateStatusSubWithBorrow( Processor& state, Processor::U32 const& res, Processor::U32 const& lhs, Processor::U32 const& rhs, Processor::U32 const& borrow )
{
  typedef Processor::S32 S32;
  typedef Processor::U32 U32;
  Processor::BOOL neg = S32(res) < S32(0);
  state.cpsr.n = neg.expr;
  state.cpsr.z = ( res == U32(0) ).expr;
  if (state.Test(borrow != U32(0)))
    {
      state.cpsr.c = ( lhs >  rhs ).expr;
      state.cpsr.v = ( neg xor (S32(lhs) <= S32(rhs)) ).expr;
    }
  else
    {
      state.cpsr.c = ( lhs >= rhs ).expr;
      state.cpsr.v = ( neg xor (S32(lhs) <  S32(rhs)) ).expr;
    }
}

void UpdateStatusAdd( Processor& state, Processor::U32 const& res, Processor::U32 const& lhs, Processor::U32 const& rhs )
{
  typedef Processor::S32 S32;
  typedef Processor::U32 U32;
  Processor::BOOL neg = S32(res) < S32(0);
  state.cpsr.n = neg.expr;
  state.cpsr.z = ( res == U32(0) ).expr;
  state.cpsr.c = ( lhs >  ~rhs ).expr;
  state.cpsr.v = ( neg xor (S32(lhs) <= S32(~rhs)) ).expr;
}

void UpdateStatusAddWithCarry( Processor& state, Processor::U32 const& res, Processor::U32 const& lhs, Processor::U32 const& rhs, Processor::U32 const& carry )
{
  typedef Processor::S32 S32;
  typedef Processor::U32 U32;
  Processor::BOOL neg = S32(res) < S32(0);
  state.cpsr.n = neg.expr;
  state.cpsr.z = ( res == U32(0) ).expr;
  if (state.Test(carry != U32(0)))
    {
      state.cpsr.c = ( lhs >= ~rhs ).expr;
      state.cpsr.v = ( neg xor (S32(lhs) <  S32(~rhs)) ).expr;
    }
  else
    {
      state.cpsr.c = ( lhs >  ~rhs ).expr;
      state.cpsr.v = ( neg xor (S32(lhs) <= S32(~rhs)) ).expr;
    }
}


struct ARMISA : public unisim::component::cxx::processor::arm::isa::arm32::Decoder<Processor>
{
  typedef unisim::component::cxx::processor::arm::isa::arm32::CodeType CodeType;
  typedef unisim::component::cxx::processor::arm::isa::arm32::Operation<Processor> Operation;
  static CodeType mkcode( uint32_t code ) { return CodeType( code ); }
  static bool const is_thumb = false;
};

struct THUMBISA : public unisim::component::cxx::processor::arm::isa::thumb::Decoder<Processor>
{
  typedef unisim::component::cxx::processor::arm::isa::thumb::CodeType CodeType;
  typedef unisim::component::cxx::processor::arm::isa::thumb::Operation<Processor> Operation;
  static CodeType mkcode( uint32_t code ) { return CodeType( code ); }
  static bool const is_thumb = true;
};

struct InstructionAddress : public unisim::util::symbolic::binsec::ASExprNode
{
  InstructionAddress() {}
  virtual void Repr( std::ostream& sink ) const { sink << "insn_addr"; }
  virtual int cmp( unisim::util::symbolic::ExprNode const& rhs ) const override { return compare( dynamic_cast<InstructionAddress const&>( rhs ) ); }
  int compare( InstructionAddress const& rhs ) const { return 0; }
};

namespace
{
  struct Translator
  {
    typedef unisim::util::symbolic::binsec::ActionNode ActionNode;

    Translator( StatusRegister const& _status, uint32_t _addr, uint32_t _code )
      : status(_status), addr(_addr), code(_code), coderoot(new ActionNode)
    {}
    ~Translator() { delete coderoot; }

    template <class ISA>
    void
    extract( std::ostream& sink, ISA& isa )
    {
      sink << "(address . " << unisim::util::symbolic::binsec::dbx(4, addr) << ")\n";

      // Instruction decoding
      struct Instruction
      {
        typedef typename ISA::Operation Operation;
        Instruction(ISA& isa, uint32_t addr, uint32_t code)
          : operation(0), bytecount(0)
        {
          operation = isa.NCDecode( addr, ISA::mkcode( code ) );
          unsigned bitlength = operation->GetLength();
          if ((bitlength != 32) and ((bitlength != 16) or not ISA::is_thumb))
            { delete operation; operation = 0; throw Processor::Undefined(); }
          bytecount = bitlength/8;
        }
        ~Instruction() { delete operation; }
        Operation* operator -> () { return operation; }
        Operation* operation;
        unsigned   bytecount;
      };

      Instruction instruction( isa, addr, code );

      {
        uint32_t encoding = instruction->GetEncoding();
        if (instruction.bytecount == 2)
          encoding &= 0xffff;

        sink << "(opcode . " << unisim::util::symbolic::binsec::dbx(instruction.bytecount, encoding) << ")\n(size . " << (instruction.bytecount) << ")\n";
      }

      Processor::U32      insn_addr = unisim::util::symbolic::make_const(addr); //< concrete instruction address
      // Processor::U32      insn_addr = Expr(new InstructionAddress()); //< symbolic instruction address
      Processor reference( status );

      // Disassemble
      sink << "(mnemonic . \"";
      try { instruction->disasm( reference, sink ); }
      catch (...) { sink << "(bad)"; }
      sink << "\")\n";

      // Get actions
      bool is_thumb = status.IsThumb();
      for (bool end = false; not end;)
        {
          Processor state( status );
          state.path = coderoot;
          // Fetch
          uint32_t insn_addr = instruction->GetAddr(), nia = insn_addr + instruction.bytecount;
          state.SetNIA( Processor::U32(nia), Processor::B_JMP );
          state.reg_values[15] = Processor::U32(insn_addr + (is_thumb ? 4 : 8) );
          // Execute
          using unisim::component::cxx::processor::arm::CheckCondition;
          if (is_thumb ? CheckCondition( state, state.itcond() ) : CheckCondition( state, instruction->GetEncoding() >> 28 ))
            instruction->execute( state );
          if (is_thumb)
            state.ITAdvance();
          end = state.close( reference, nia );
        }
      coderoot->simplify();
      coderoot->commit_stats();
    }

    void translate( std::ostream& sink )
    {
      try
        {
          if      (status.iset == status.Arm)
            {
              ARMISA armisa;
              extract( sink, armisa );
            }
          else if (status.iset == status.Thumb)
            {
              THUMBISA thumbisa;
              extract( sink, thumbisa );
            }
          else
            throw 0;
        }
      catch (Processor::Undefined const&)
        {
          sink << "(undefined)\n";
          return;
        }
      catch (...)
        {
          sink << "(unimplemented)\n";
          return;
        }

      // Translate to DBA
      unisim::util::symbolic::binsec::Program program;
      program.Generate( coderoot );
      typedef unisim::util::symbolic::binsec::Program::const_iterator Iterator;
      for (Iterator itr = program.begin(), end = program.end(); itr != end; ++itr)
        sink << "(" << unisim::util::symbolic::binsec::dbx(4, addr) << ',' << itr->first << ") " << itr->second << std::endl;
    }

    StatusRegister const& status;
    uint32_t              addr, code;
    ActionNode*           coderoot;
  };
}

void
Decoder::process( std::ostream& sink, uint32_t addr, uint32_t code )
{
  Translator actset( *this, addr, code );
  
  actset.translate( sink );
}

#define CP15ENCODE( CRN, OPC1, CRM, OPC2 ) ((OPC1 << 12) | (CRN << 8) | (CRM << 4) | (OPC2 << 0))

Processor::CP15Reg*
Processor::CP15GetRegister( uint8_t crn, uint8_t opcode1, uint8_t crm, uint8_t opcode2 )
{
  switch (CP15ENCODE( crn, opcode1, crm, opcode2 ))
    {
      /****************************
       * Identification registers *
       ****************************/
    case CP15ENCODE( 0, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CTR, Cache Type Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ctr"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 0, 0, 0, 5 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "MPIDR, Multiprocessor Affinity Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("mpidr"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 0, 0, 1, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ID_PFR0, Processor Feature Register 0"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("id_pfr0"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 0, 1, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CCSIDR, Cache Size ID Registers"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ccsidr"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 0, 1, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CLIDR, Cache Level ID Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("clidr"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 0, 2, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CSSELR, Cache Size Selection Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("csselr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("csselr") = value; }
        } x;
        return &x;
      } break;

      /****************************
       * System control registers *
       ****************************/
    case CP15ENCODE( 1, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "SCTLR, System Control Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("sctlr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("sctlr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 1, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ACTLR, Auxiliary Control Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("actlr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("actlr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 1, 0, 0, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CPACR, Coprocessor Access Control Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("cpacr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("cpacr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 1, 0, 1, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "NSACR, Non-Secure Access Control Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("nsacr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("nsacr") = value; }
        } x;
        return &x;
      } break;

      /*******************************************
       * Memory protection and control registers *
       *******************************************/
    case CP15ENCODE( 2, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TTBR0, Translation Table Base Register 0"; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("ttbr0") = value; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ttbr0"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 2, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TTBR1, Translation Table Base Register 1"; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("ttbr1") = value; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ttbr1"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 2, 0, 0, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TTBCR, Translation Table Base Control Register"; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("ttbcr") = value; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ttbcr"); }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 3, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DACR, Domain Access Control Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dacr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dacr") = value; }
        } x;
        return &x;
      } break;


      /*********************************
       * Memory system fault registers *
       *********************************/
    case CP15ENCODE( 5, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DFSR, Data Fault Status Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dfsr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dfsr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 5, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "IFSR, Instruction Fault Status Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ifsr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("ifsr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 6, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DFAR, Data Fault Status Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dfar"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dfar") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 6, 0, 0, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "IFAR, Instruction Fault Status Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("ifar"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("ifar") = value; }
        } x;
        return &x;
      } break;

      /***************************************************************
       * Cache maintenance, address translation, and other functions *
       ***************************************************************/

    case CP15ENCODE( 7, 0, 1, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ICIALLUIS, Invalidate all instruction caches to PoU Inner Shareable"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("icialluis"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("icialluis") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 1, 6 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "BPIALLIS, Invalidate all branch predictors Inner Shareable"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("bpiallis"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("bpiallis") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 5, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ICIALLU, Invalidate all instruction caches to PoU"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("iciallu"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("iciallu") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 5, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ICIMVAU, Clean data* cache line by MVA to PoU"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("icimvau"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("icimvau") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 5, 6 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "BPIALL, Invalidate all branch predictors"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("bpiall"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("bpiall") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 6, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCIMVAC, Invalidate data* cache line by MVA to PoC"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dcimvac"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dcimvac") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 6, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCISW, Invalidate data* cache line by set/way"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dcisw"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dcisw") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 10, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCCMVAC, Clean data* cache line by MVA to PoC"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dccmvac"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dccmvac") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 10, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCCSW, Clean data* cache line by set/way"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dccsw"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dccsw") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 11, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCCMVAU, Clean data* cache line by MVA to PoU"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dccmvau"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dccmvau") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 7, 0, 14, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DCCIMVAC, Clean and invalidate data* cache line by MVA to PoC"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("dccimvac"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("dccimvac") = value; }
        } x;
        return &x;
      } break;

      /******************************
       * TLB maintenance operations *
       ******************************/

    case CP15ENCODE( 8, 0, 3, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TLBIALLIS, Invalidate entire TLB Inner Shareable"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("tlbiallis"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("tlbiallis") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 8, 0, 7, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TLBIALL, invalidate unified TLB"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("tlbiall"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("tlbiall") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 8, 0, 7, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TLBIASID, invalidate unified TLB by ASID match"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("tlbiasid"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("tlbiasid") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 12, 0, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "VBAR, Vector Base Address Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("vbar"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("vbar") = value; }
        } x;
        return &x;
      } break;

      /***********************************/
      /* Context and thread ID registers */
      /***********************************/

    case CP15ENCODE( 13, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CONTEXTIDR, Context ID Register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("contextidr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("contextidr") = value; }
        } x;
        return &x;
      } break;

      /* BOARD specific */

    case CP15ENCODE( 15, 0, 0, 1 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "DIAGCR, undocumented Diagnostic Control register"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("diagcr"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("diagcr") = value; }
        } x;
        return &x;
      } break;

    case CP15ENCODE( 15, 4, 0, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CBAR, Configuration Base Address"; }
          U32 Read(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc) const override { return proc.SReg("cbar"); }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, Processor& proc, U32 const& value) const override { proc.SReg("cbar") = value; }
        } x;
        return &x;
      } break;

    }

  static CP15Reg err;
  return &err;
}

#undef CP15ENCODE

void
Processor::PSR::Set( NZCVRF const& _, U32 const& value )
{
  n = BOOL( unisim::component::cxx::processor::arm::RegisterField< 3,1>().Get( value ) ).expr;
  z = BOOL( unisim::component::cxx::processor::arm::RegisterField< 2,1>().Get( value ) ).expr;
  c = BOOL( unisim::component::cxx::processor::arm::RegisterField< 1,1>().Get( value ) ).expr;
  v = BOOL( unisim::component::cxx::processor::arm::RegisterField< 0,1>().Get( value ) ).expr;

}

Processor::U32
Processor::PSR::GetBits()
{
  return
    (U32(BOOL(n)) << 31) |
    (U32(BOOL(z)) << 30) |
    (U32(BOOL(c)) << 29) |
    (U32(BOOL(v)) << 28) |
    (U32(BOOL(q)) << 27) |
    (U32(itstate >> U8(2)) << 10) | (U32(itstate & U8(0b11)) << 25) |
    U32((uint32_t(GetJ()) << 24) | (uint32_t(GetT()) << 5) | uint32_t(mode)) |
    bg;
}

void
Processor::PSR::SetBits( U32 const& bits, uint32_t mask )
{
  if (NRF().Get(mask)) { n = BOOL( NRF().Get(bits) ).expr; NRF().Set(mask, 0u); }
  if (ZRF().Get(mask)) { z = BOOL( ZRF().Get(bits) ).expr; ZRF().Set(mask, 0u); }
  if (CRF().Get(mask)) { c = BOOL( CRF().Get(bits) ).expr; CRF().Set(mask, 0u); }
  if (VRF().Get(mask)) { v = BOOL( VRF().Get(bits) ).expr; VRF().Set(mask, 0u); }
  if (QRF().Get(mask)) { q = BOOL( QRF().Get(bits) ).expr; QRF().Set(mask, 0u); }

  if (ITHIRF().Get(mask) or ITLORF().Get(mask))
    {
      itstate = U8((ITHIRF().Get(bits) << 2) | ITLORF().Get(bits));
      uint32_t itmask = ITHIRF().getmask<uint32_t>() | ITLORF().getmask<uint32_t>();
      if ((mask & itmask) != itmask)
        throw 0;
      mask &= ~itmask;
      ITHIRF().Set(mask, 0u); ITLORF().Set(mask, 0u);
    }

  if (MRF().Get(mask))
    {
      if (MRF().Get(mask) != 0x1f)
        throw 0;
      U32       nmode = MRF().Get(bits);
      MRF().Set(mask, 0u);
      if (proc.Test(nmode != U32(mode)))
        proc.UnpredictableInsnBehaviour();
    }

  if (JRF().Get(mask)) { if (proc.Test(JRF().Get(bits) != U32(GetJ())))    { proc.UnpredictableInsnBehaviour(); } JRF().Set(mask, 0u); }
  if (TRF().Get(mask)) { if (proc.Test(TRF().Get(bits) != U32(GetT())))    { proc.UnpredictableInsnBehaviour(); } TRF().Set(mask, 0u); }
  if (ERF().Get(mask)) { if (proc.Test(ERF().Get(bits) != U32(bigendian))) { proc.UnpredictableInsnBehaviour(); } ERF().Set(mask, 0u); }

  bg = (bg & U32(~mask)) | (bits & U32(mask));
}

}
