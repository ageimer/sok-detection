/*
 *  Copyright (c) 2010-2018,
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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXECUTE_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXECUTE_HH__

#include <unisim/component/cxx/processor/arm/psr.hh>
#include <unisim/util/truth_table/truth_table.hh>
#include <unisim/util/arithmetic/arithmetic.hh>
#include <inttypes.h>
#include <stdexcept>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

  namespace CondTruthTable {
    template <uintptr_t Tbit, uintptr_t Tbits = 16>
    struct Source {
      static uintptr_t const msb = (Tbits-1);
      static uint16_t const tt = (((msb >> Tbit) & 1) ? (uint16_t(1) << msb) : uint16_t(0)) | Source<Tbit,msb>::tt;
    };

    template <uintptr_t Tbit> struct Source<Tbit,1> { static uint16_t const tt = uint16_t(0); };

    typedef Source<3> N; typedef Source<2> Z; typedef Source<1> C; typedef Source<0> V;
  };
  
  /** Check the given condition against the current CPSR status.
   * Returns true if the condition matches CPSR, false otherwise.
   *
   * @param core the core for which the CPSR will be matched
   * @param cond the condition to check
   * @return true if the condition matches CPSR, false otherwise
   */
  template <typename coreT>
  bool
  CheckCondition( coreT& core, uint32_t cond )
  {
    util::truth_table::InBit<uint16_t,3> const N;
    util::truth_table::InBit<uint16_t,2> const Z;
    util::truth_table::InBit<uint16_t,1> const C;
    util::truth_table::InBit<uint16_t,0> const V;
    
    typedef typename coreT::U8  U8;
    typedef typename coreT::U16 U16;

    static U16 const condition_truth_tables[] = {
      U16((                  Z).tt), // eq; equal
      U16((              not Z).tt), // ne; not equal
      U16((                  C).tt), // cs/hs; unsigned higher or same
      U16((              not C).tt), // cc/lo; unsigned lower
      U16((                  N).tt), // mi; negative
      U16((              not N).tt), // pl; positive or zero
      U16((                  V).tt), // vs; overflow set
      U16((              not V).tt), // vc; overflow clear
      U16((   not (not C or Z)).tt), // hi; unsigned higher
      U16((       (not C or Z)).tt), // ls; unsigned lower or same
      U16((      not (N xor V)).tt), // ge; signed greater than or equal
      U16((          (N xor V)).tt), // lt; signed less than
      U16((not(Z or (N xor V))).tt), // gt; signed greater than
      U16((   (Z or (N xor V))).tt), // le; signed less than or equal
      U16(                  0xffff), // al; always
      U16(                  0xffff), // when allowed, acts as 'al' (15)
    };
    if (cond >= 16) throw std::logic_error("invalid condition code");
    U8 nzcv( core.GetNZCV() );
    return core.Test( ((condition_truth_tables[cond] >> nzcv) & U16(1)) != U16(0) );
  }
  
  template <typename coreT>
  typename coreT::U32
  ComputeImmShift( coreT& core, typename coreT::U32 const& shift_lhs, unsigned shift, unsigned shift_rhs )
  {
    typedef typename coreT::S32 S32;
    typedef typename coreT::U32 U32;
    if (shift_rhs) {
      switch (shift) {
      case 0: return shift_lhs << shift_rhs;
      case 1: return shift_lhs >> shift_rhs;
      case 2: return U32(S32(shift_lhs) >> shift_rhs);
      case 3: return (shift_lhs >> shift_rhs) | (shift_lhs << (32 - shift_rhs));
      }
    } else {
      switch (shift) {
      case 0: return shift_lhs;
      case 1: return U32(0);
      case 2: return U32(S32(shift_lhs) >> 31);
      case 3: return ((core.CPSR().Get( C ) << 31) | (shift_lhs >> 1));
      }
    }
    
    throw std::logic_error("bad ComputeImmShift arguments");
    return U32(0);
  }
  
  template <typename coreT>
  void
  UpdateStatusImmShift( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& shift_lhs, unsigned shift, unsigned shift_rhs )
  {
    typedef typename coreT::U32 U32;
    typedef typename coreT::S32 S32;
    typedef typename coreT::BOOL BOOL;
    
    U32 carry(0);
    bool write_carry = true;

    if      ((shift_rhs == 0) and (shift == 0)) /* MOVS */
      write_carry = false;
    else if ((shift_rhs == 0) and (shift == 3)) /* RRX */
      carry = (shift_lhs & U32(1));
    else if (shift == 0)                        /* LSL */
      carry = (shift_lhs >> (32 - shift_rhs)) & U32(1);
    else                                        /* LSR, ASR, ROR */
      carry = (shift_lhs >> ((shift_rhs - 1) & 0x1f)) & U32(1);

    core.CPSR().Set( N, S32(res) < S32(0) );
    core.CPSR().Set( Z,     res == U32(0) );
    if (write_carry)
      core.CPSR().Set( C, BOOL( carry ) );
    /* CPSR.V unaltered */
  }

  template <typename coreT>
  typename coreT::U32
  ComputeRegShift( coreT& core, typename coreT::U32 const& value, unsigned shift, typename coreT::U32 const& shift_val )
  {
    typedef typename coreT::U32 U32;
    typedef typename coreT::S32 S32;
    U32 shift8 = shift_val & U32(0xff);
    U32 shift5 = shift_val & U32(0x1f);
    // shift overflow mask: all ones if shift is valid, all zeros otherwise
    U32 shof_mask = ~(U32( (S32(shift8 | (U32(31) - shift8)) >> 31) ));
    
    switch (shift) {
    case 0: return (value << shift5) & shof_mask;
    case 1: return (value >> shift5) & shof_mask;
    case 2: return (U32(S32(value) >> shift5) & shof_mask) | (U32(S32(value) >> 31) & ~shof_mask);
    case 3: return RotateRight(value, shift5);
    }
    
    return U32(0);
  }
  
  template <typename coreT>
  void
  UpdateStatusRegShift( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& value, unsigned shift, typename coreT::U32 const& shift_val )
  {
    typedef typename coreT::U32 U32;
    typedef typename coreT::S32 S32;
    typedef typename coreT::BOOL BOOL;
    
    U32 shift8 = shift_val & U32(0xff);
    // Wether output carry is input carry
    U32 select_carry = U32(shift8 == U32(0));
    U32 shvalm1 = shift8 - U32(1);
    // Wether output carry comes from a bit of input value
    U32 select_bit = U32((shvalm1 >> 5) == U32(0));
    
    U32 carry(0);
    switch (shift) {
    case 0: carry = (value >> (U32(32) - shift8)) & select_bit; break;
    case 1: carry = (value >> shvalm1) & select_bit; break;
    case 2: carry = ((value >> shvalm1) & select_bit) | (U32(S32(value) >> 31) & (select_bit ^ U32(1))); break;
    case 3: carry = (value >> (shvalm1 & U32(0x1f))) & U32(1); break;
    default: throw std::logic_error("bad UpdateStatusRegShift arguments");
    }
    
    carry = (carry & ~select_carry) | (core.CPSR().Get( C ) & select_carry);

    core.CPSR().Set( N, S32(res) < S32(0) );
    core.CPSR().Set( Z,     res == U32(0) );
    core.CPSR().Set( C, BOOL( carry ) );
    /* CPSR.V unaltered */
  }
  
  template <typename coreT>
  void
  UpdateStatusAdd( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& lhs, typename coreT::U32 const& rhs )
  {
    typedef typename coreT::U32 U32;
    core.CPSR().Set( N, (res >> 31) & U32(1) );
    core.CPSR().Set( Z, U32(res == U32(0)) );
    core.CPSR().Set( C, ((lhs & rhs) | ((~res) & (lhs | rhs))) >> 31 );
    core.CPSR().Set( V, ((lhs & rhs & (~res)) | ((~lhs) & (~rhs) & res)) >> 31 );
  }
  
  template <typename coreT>
  void
  UpdateStatusAddWithCarry( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& lhs, typename coreT::U32 const& rhs, typename coreT::U32 const& carry )
  {
    UpdateStatusAdd( core, res, lhs, rhs );
  }
  
  /* In ARM isa, the substraction carry correspond to the complementary                                                                          
   * addition's carry.                                                                                                                           
   */
  template <typename coreT>
  void
  UpdateStatusSub( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& lhs, typename coreT::U32 const& rhs )
  {
    typedef typename coreT::U32 U32;
    core.CPSR().Set( N, (res >> 31) & U32(1) );
    core.CPSR().Set( Z, U32(res == U32(0)) );
    core.CPSR().Set( C, ((lhs & (~rhs)) | ((~res) & (lhs | (~rhs)))) >> 31 );
    core.CPSR().Set( V, ((lhs & (~rhs) & (~res)) | ((~lhs) & rhs & res)) >> 31 );
  }
  
  template <typename coreT>
  void
  UpdateStatusSubWithBorrow( coreT& core, typename coreT::U32 const& res, typename coreT::U32 const& lhs, typename coreT::U32 const& rhs, typename coreT::U32 const& borrow )
  {
    UpdateStatusSub( core, res, lhs, rhs );
  }
  
  template <unsigned SIZE> struct _SWP_MSB { static uint32_t const mask = (_SWP_MSB<SIZE*2>::mask >> SIZE) | _SWP_MSB<SIZE*2>::mask; };
  template <> struct _SWP_MSB<32u> { static uint32_t const mask = 0x80000000; };
  
  template <unsigned SIZE>
  struct SWP
  {
    static unsigned const size = SIZE;
    static unsigned const msb2lsb = SIZE-1;
    static uint32_t const msbmask = _SWP_MSB<SIZE>::mask;
    static uint32_t const lsbmask = msbmask >> msb2lsb;
  };

  template <typename VT, typename CT, typename V0T, typename V1T, typename VDT>
  VT CondMove( CT c0, V0T v0, CT c1, V1T v1, VDT vd )
  {
    VT mnc0 = VT(c0) - VT(1), mnc1 = VT(c1) - VT(1);
    return (mnc0 & mnc1 & VT(vd)) | (~mnc0 & VT(v0)) | (~mnc1 & VT(v1));
  }  
  
  template <typename VT, typename CT, typename V0T, typename VDT>
  VT CondMove( CT c0, V0T v0, VDT vd )
  {
    VT mnc0 = VT(c0) - VT(1);
    return (mnc0 & VT(vd)) | (~mnc0 & VT(v0));
  }  
  
  template <typename coreT>
  void
  CPSRWriteByInstr( coreT& core, typename coreT::U32 const& psr_bits, uint32_t psr_mask )
  {
    typedef typename coreT::U32 U32;
    typedef typename coreT::BOOL BOOL;
    
    // bits <23:20> are reserved SBZP bits
    // if (core.Cond( (psr_bits & psr_mask & U32(core.PSR_UNALLOC_MASK)) != U32(0) ))
    //   core.UnpredictableInsnBehaviour();
    psr_mask &= 0xff0fffff;
    
    BOOL const is_secure( true ); // IsSecure()
    BOOL const nmfi( false ); // Non Maskable FIQ (SCTLR.NMFI == '1');
    BOOL const scr_aw( false ); // prevents Non-secure masking of asynchronous aborts that are taken to Monitor mode
    BOOL const scr_fw( false ); // prevents Non-secure masking of FIQs that are taken to Monitor mode
    BOOL const have_virt_ext( false ); // HaveVirtExt()

    BOOL privileged = core.CPSR().Get(M) != U32(PSR::USER_MODE);
    
    if (A.Get( psr_mask ) and not core.Test
        (privileged and (is_secure or  scr_aw or have_virt_ext)))
      A.Set( psr_mask, 0u );
    
    if (I.Get( psr_mask ) and not core.Test
        (privileged))
      I.Set( psr_mask, 0u );
    
    if (F.Get( psr_mask ) and not core.Test
        (privileged and (not nmfi or not BOOL(F.Get( psr_bits ))) and (is_secure or scr_fw or have_virt_ext)))
      F.Set( psr_mask, 0u );
    
    if (M.Get( psr_mask ) and not core.Test
        (privileged))
      M.Set( psr_mask, 0u );
    
    // TODO: Check for attempts to enter modes only permitted in
    // Secure state from Non-secure state. These are Monitor mode
    // ('10110'), and FIQ mode ('10001') if the Security Extensions
    // have reserved it. The definition of UNPREDICTABLE does not
    // permit the resulting behavior to be a security hole.

    core.SetCPSR( psr_bits, psr_mask );
  }
  
  template <typename coreT>
  void
  SPSRWriteByInstr( coreT& core, typename coreT::U32 const& psr_bits, uint32_t psr_mask )
  {
    typedef typename coreT::U32 U32;
    U32 spsr = core.CurrentMode().GetSPSR();
    spsr = (spsr & U32(~psr_mask)) | (psr_bits & U32(psr_mask));
    core.CurrentMode().SetSPSR( spsr );
  }

  struct LSMIter
  {
    enum mode_t { DA=0, IA=1, DB=2, IB=3 };
    LSMIter( uint32_t mode, uint32_t reglist )
      : m_reglist( reglist ), m_offset( 0 )
    {
      switch (mode_t( mode )) {
      case DA: m_dir = -1; m_reg = 16; m_incb =  0; m_inca = -4; m_offset += 4; break;
      case IA: m_dir = +1; m_reg = -1; m_incb =  0; m_inca = +4; m_offset -= 4; break;
      case DB: m_dir = -1; m_reg = 16; m_incb = -4; m_inca =  0; break;
      case IB: m_dir = +1; m_reg = -1; m_incb = +4; m_inca =  0; break;
      default: throw std::logic_error("Bad LSM mode");
      }
    
    }
    bool
    next() {
      m_offset += m_inca;
      do    { m_reg += m_dir; if (m_reg & -16) return false; }
      while (((m_reglist >> m_reg) & 1) == 0);
      m_offset += m_incb;
      return true;
    }
    uint32_t offset() const { return m_offset; }
    uint32_t reg() const { return m_reg; }

    uint32_t m_reglist, m_offset, m_inca, m_incb;
    int32_t  m_dir, m_reg;
  };

  template <typename T> struct OverShift {};
  template <> struct OverShift<int8_t>   { static int8_t const size = 8; };
  template <> struct OverShift<int16_t>  { static int8_t const size = 16; };
  template <> struct OverShift<int32_t>  { static int8_t const size = 32; };
  template <> struct OverShift<int64_t>  { static int8_t const size = 64; };
  template <> struct OverShift<uint8_t>  { static int8_t const size = 8; };
  template <> struct OverShift<uint16_t> { static int8_t const size = 16; };
  template <> struct OverShift<uint32_t> { static int8_t const size = 32; };
  template <> struct OverShift<uint64_t> { static int8_t const size = 64; };
  
  template <class OP>
  OP NeonSHL( OP op, int8_t sh )
  {
    if (sh >= OverShift<OP>::size)
      return OP(0);

    if (sh >= 0)
      return op << sh;

    if (sh <= -OverShift<OP>::size)
      {
        if (std::numeric_limits<OP>::is_signed)
          return op >> (OverShift<OP>::size-1);
        else
          return OP(0);
      }
    return op >> -sh;
  }
  
  // Min Max operations. Note: Fall back for native-like types.
  template <typename T> T const& Minimum( T const& l, T const& r ) { return std::min(l, r); }
  template <typename T> T const& Maximum( T const& l, T const& r ) { return std::max(l, r); }

  /******************/
  /* Floating Point */
  /******************/
  
  struct VFPExpandImm
  {
    uint8_t m : 4;
    uint8_t e : 3;
    uint8_t s : 1;
    
    VFPExpandImm( uint8_t neg, uint8_t exp, uint8_t man )
      : m( man ), e( exp ^ 4 ), s( neg ) {}
    
    template <typename T>
    T toFP() { return (s?-1:1) * (T( ((1 << 4) | m) << e ) / 128); }
    operator float () { return this->toFP<float>(); }
    operator double () { return this->toFP<double>(); }
    
    template <unsigned bcT>
    void toBytes( uint8_t (&bytes)[bcT] ) const
    {
      int32_t exp = (int8_t((e^4) << 5)) >> 5;
      if (bcT == 4) {
        uint32_t bits = 0;
        bits |= uint32_t( m ) << 19;                   /* inserting mantissa */
        bits |= (uint32_t((exp & 0xff) ^ 0x80) << 23);   /* inserting exponent */
        bits |= uint32_t( s ) << 31;                   /* inserting sign */
        for (unsigned byte = 0, bit = 0; byte < bcT; byte += 1, bit += 8) bytes[byte] = bits >> bit;
      } else if (bcT == 8) {
        uint64_t bits = 0;
        bits |= uint64_t( m ) << 48;                   /* inserting mantissa */
        bits |= (uint64_t((exp & 0x7ff) ^ 0x400) << 52); /* inserting exponent */
        bits |= uint64_t( s ) << 63;                   /* inserting sign */
        for (unsigned byte = 0, bit = 0; byte < bcT; byte += 1, bit += 8) bytes[byte] = bits >> bit;
      } else throw std::logic_error("unexpected FP size");
    }
  };
  
  template <class ARCH, unsigned posT, typename FPCTRL>
  void FPProcessException( ARCH& arch, RegisterField<posT,1> const& rf, FPCTRL const& fpscr_val )
  {
    RegisterField<posT+8,1> const enable;
    if (arch.Test(enable.Get( fpscr_val )))
      arch.FPTrap( posT );
    else
      rf.Set( arch.FPSCR, 1u );
  }
    
  template <typename ARCH, typename FPCTRL, typename operT>
  struct __FPProcessNaN__
  {
    typedef typename ARCH::BOOL BOOL;
    enum hasNaN_e { noNaN=0, hasQNaN, hasSNaN };
      
    __FPProcessNaN__( ARCH& _arch, FPCTRL const& _fpscr, operT& _acc )
      : arch( _arch ), fpscr_val( _fpscr ), acc( _acc ), hasNaN(noNaN)
    {
      append( acc );
    }
    
    __FPProcessNaN__&
    operator << ( operT const& op )
    {
      if (append( op ))
        acc = op;
      return *this;
    }
  
    operator bool () const
    {
      if (hasNaN == noNaN)
        return false;
      
      if (hasNaN == hasSNaN) {
        ARCH::FP::SetQuietBit( acc );
        FPProcessException( arch, IOC /*InvalidOp*/, fpscr_val );
      }
      
      if (arch.Test( DN.Get( fpscr_val ) )) {
        ARCH::FP::SetDefaultNan( acc );
      }
      
      return true;
    }
    
    void close() const { this->operator bool (); }
      
    bool append( operT const& op )
    {
      if (hasNaN == hasSNaN) return false;
      if (arch.Test( ARCH::FP::IsSNaN( op ) )) {
        hasNaN = hasSNaN;
        return true;
      }
      if (hasNaN == hasQNaN) return false;
      if (arch.Test( ARCH::FP::IsQNaN( op ) )) {
        hasNaN = hasQNaN;
        return true;
      }
      return false;
    }
    ARCH& arch;
    FPCTRL const& fpscr_val;
    operT& acc;
    hasNaN_e hasNaN;
  };

  template <typename ARCH, typename FPCTRL, typename operT>
  __FPProcessNaN__<ARCH, FPCTRL, operT>
  FPProcessNaN( ARCH& arch, FPCTRL const& fpscr_val, operT& acc )
  { return __FPProcessNaN__<ARCH, FPCTRL, operT>( arch, fpscr_val, acc ); }

  template <typename operT, typename ARCH, typename FPCTRL>
  void
  FPFlushToZero( operT& op, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( ARCH::FP::FlushToZero( op, fpscr_val ) ))
      FPProcessException( arch, IDC /* InputDenorm */, fpscr_val );
  }

  template <typename operT, typename ARCH, typename FPCTRL>
  void FPAdd( operT& acc, operT& op2, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    if (FPProcessNaN( arch, fpscr_val, acc ) << op2) return;
    
    ARCH::FP::Add( acc, op2, arch, fpscr_val );
  }
  
  template <typename operT, typename ARCH, typename FPCTRL>
  void FPSub( operT& acc, operT& op2, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    if (FPProcessNaN( arch, fpscr_val, acc ) << op2) return;
    
    ARCH::FP::Sub( acc, op2, arch, fpscr_val );
  }

  template <typename operT, typename ARCH, typename FPCTRL>
  void FPDiv( operT& acc, operT& op2, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    if (FPProcessNaN( arch, fpscr_val, acc ) << op2) return;
    
    ARCH::FP::Div( acc, op2, arch, fpscr_val );
  }
  
  template <typename operT, typename ARCH, typename FPCTRL>
  void FPMul( operT& acc, operT& op2, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    if (FPProcessNaN( arch, fpscr_val, acc ) << op2) return;
    
    ARCH::FP::Mul( acc, op2, arch, fpscr_val );
  }
  
  template <typename operT, typename ARCH, typename FPCTRL>
  void FPMulAdd( operT& acc, operT& op1, operT& op2, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
      FPFlushToZero( op1, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    // Preprocess the (QNaN + 0*inf) case because FPProcessNaN can
    // make an incoming signaling NaN silent.
    typename ARCH::BOOL doubleNaN = ARCH::FP::IsInvalidMulAdd( acc, op1, op2, fpscr_val );
    bool done = (FPProcessNaN( arch, fpscr_val, acc ) << op1 << op2);
    
    if (arch.Test( doubleNaN )) {
      ARCH::FP::SetDefaultNan( acc );
      FPProcessException( arch, IOC /* InvalidOp */, fpscr_val );
    }
                   
    if (done) return;
    
    ARCH::FP::MulAdd( acc, op1, op2, arch, fpscr_val );
  }
  
  template <typename operT, typename ARCH, typename FPCTRL>
  void FPSqrt( operT& acc, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( acc, arch, fpscr_val );
    }
    if (FPProcessNaN( arch, fpscr_val, acc )) return;
    
    ARCH::FP::Sqrt( acc, arch, fpscr_val );
  }
  
  template <typename INT, typename FPT, typename ARCH, typename FPCTRL>
  void FPToInt( INT& res, FPT& src, int fracbits, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( src, arch, fpscr_val );
    }
    
    if (arch.Test(ARCH::FP::IsSNaN( src ) or ARCH::FP::IsQNaN( src ))) {
      res = INT(0);
      FPProcessException( arch, IOC /* InvalidOp */, fpscr_val );
      return;
    }
    
    ARCH::FP::FtoI( res, src, fracbits, arch, fpscr_val );
  }
  
  template <typename FPDST, typename FPSRC, typename ARCH, typename FPCTRL>
  void FPToFP( FPDST& res, FPSRC& src, ARCH& arch, FPCTRL const& fpscr_val )
  {
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( src, arch, fpscr_val );
    }

    FPProcessNaN( arch, fpscr_val, src ).close();
    
    ARCH::FP::FtoF( res, src, arch, fpscr_val );
  }
  
  template <typename operT, typename ARCH, typename FPCTRL>
  void FPCompare( operT& op1, operT& op2, bool quiet_nan_exc, ARCH& arch, FPCTRL const& fpscr_val )
  {
    typedef typename ARCH::BOOL BOOL;
    typedef typename ARCH::S32 S32;
    typedef typename ARCH::U32 U32;
    
    if (arch.Test( FZ.Get( fpscr_val ) )) {
      FPFlushToZero( op1, arch, fpscr_val );
      FPFlushToZero( op2, arch, fpscr_val );
    }
    BOOL hasSNaN = ARCH::FP::IsSNaN( op1 ) or ARCH::FP::IsSNaN( op2 );
    BOOL hasQNaN = ARCH::FP::IsQNaN( op1 ) or ARCH::FP::IsQNaN( op2 );
    if (arch.Test(hasSNaN or hasQNaN)) {
      NZCV.Set( arch.FPSCR, U32(3) ); /* N=0,Z=0,C=1,V=1 */
      if (arch.Test(hasSNaN) or quiet_nan_exc)
        FPProcessException( arch, IOC /* InvalidOp */, fpscr_val );
    }
    else {
      S32 fc = ARCH::FP::Compare( op1, op2, fpscr_val );
      S32 const zero(0);
      
      if      (arch.Test( fc == zero ))
        NZCV.Set( arch.FPSCR, U32(6) ); /* N=0,Z=1,C=1,V=0 */
      else if (arch.Test( fc < zero ))
        NZCV.Set( arch.FPSCR, U32(8) ); /* N=1,Z=0,C=0,V=0 */
      else  /* fc > zero */
        NZCV.Set( arch.FPSCR, U32(2) ); /* N=0,Z=0,C=1,V=0 */
    }
  }

} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif /* __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_EXECUTE_HH__ */
