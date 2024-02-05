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

// /* ADDSUBPD -- Packed Single- or Double-FP Add/Subtract */
// op addsubpd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd0[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// addsubpd_vdq_wdq.disasm = { _sink << "addsubpd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op addsubps_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0xd0[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// addsubps_vdq_wdq.disasm = { _sink << "addsubps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* BLENDP -- Blend Packed Single- or Double-Precision Floating-Point Values */
// op blendps_vdq_wdq_ib( 0x0f[8]:> <:0x3a[8]:> <:0x0c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// blendps_vdq_wdq_ib.disasm = { _sink << "blendps " << DisasmI( imm ) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op blendpd_vdq_wdq_ib( 0x0f[8]:> <:0x3a[8]:> <:0x0d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// blendpd_vdq_wdq_ib.disasm = { _sink << "blendpd " << DisasmI( imm ) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* BLENDVPD -- Variable Blend Packed Double Precision Floating-Point Values */
// op blendvps_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x14[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// blendvps_vdq_wdq.disasm = { _sink << "blendvps %xmm0," << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op blendvpd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x15[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// blendvpd_vdq_wdq.disasm = { _sink << "blendvpd %xmm0," << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* COMISD -- Compare Scalar Ordered Single- or Double-Precision Floating-Point Values and Set EFLAGS */
// op comisd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x2f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// comisd_vdq_wdq.disasm = { _sink << "comisd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op comiss_vdq_wdq( 0x0f[8]:> <:0x2f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// comiss_vdq_wdq.disasm = { _sink << "comiss " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };

template <class ARCH, class VR>
struct Op3V : public Operation<ARCH>
{
  Op3V(OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, unsigned _vn, unsigned _gn) : Operation<ARCH>(opbase), rm(std::move(_rm)), vn(_vn), gn(_gn) {}
  void disasmVVW(std::ostream& sink, bool has_nds = true) const
  {
    sink          << DisasmW( VR(), rm );
    if (VR::vex() and has_nds)
      sink << ',' << DisasmV( VR(), vn );
    sink   << ',' << DisasmV( VR(), gn );
  }
  void disasmVV(std::ostream& sink) const
  {
    if (VR::vex())
      sink << ',' << DisasmV( VR(), vn );
    sink   << ',' << DisasmV( VR(), gn );
  }
  char const* vprefix() const { return &"v"[not VR::vex()]; }
  RMOp<ARCH> rm; uint8_t vn, gn;
};

/* CMP -- Compare Scalar or Packed Single- or Double-Precision Floating-Point Values */

template <class ARCH, class VR, unsigned OPSZ, bool PACKED>
struct VFPCmp : public Op3V<ARCH,VR>
{
  typedef typename TypeFor<ARCH,OPSZ>::f valtype;

  // The original Intel/AMD Coding was refactored to ease operation decode
  // 0b00000 -> 0b01011 FALSE_OQ (FALSE)	False (ordered, non-signaling)
  // 0b00001 -> 0b00000 EQ_OQ (EQ)		Equal (ordered, non-signaling)
  // 0b00010 -> 0b10001 LT_OQ			Less-than (ordered, non-signaling)
  // 0b00011 -> 0b10010 LE_OQ			Less-than-or-equal (ordered,non-signaling)
  // 0b00100 -> 0b11110 GT_OQ			Greater-than (ordered, non-signaling)
  // 0b00101 -> 0b11101 GE_OQ			Greater-than-or-equal (ordered, non-signaling)
  // 0b00110 -> 0b01100 NEQ_OQ			Not-equal (ordered, non-signaling)
  // 0b00111 -> 0b00111 ORD_Q (ORD)		Ordered (non-signaling)
  // 0b01000 -> 0b01111 TRUE_UQ(TRUE)		True (unordered, non-signaling)
  // 0b01001 -> 0b00100 NEQ_UQ (NEQ)		Not-equal (unordered, non-signaling)
  // 0b01010 -> 0b10101 NLT_UQ			Not-less-than (unordered, non-signaling)
  // 0b01011 -> 0b10110 NLE_UQ			Not-less-than-or-equal (unordered,non-signaling)
  // 0b01100 -> 0b11010 NGT_UQ			Not-greater-than (unordered, non-signaling)
  // 0b01101 -> 0b11001 NGE_UQ			Not-greater-than-or-equal (unordered, non-signaling)
  // 0b01110 -> 0b01000 EQ_UQ			Equal (unordered, non-signaling)
  // 0b01111 -> 0b00011 UNORD_Q (UNORD)		Unordered (non-signaling)
  // 0b10000 -> 0b11011 FALSE_OS	False (ordered, signaling)
  // 0b10001 -> 0b10000 EQ_OS		Equal (ordered, signaling)
  // 0b10010 -> 0b00001 LT_OS (LT)	Less-than (ordered, signaling)
  // 0b10011 -> 0b00010 LE_OS (LE)	Less-than-or-equal (ordered,signaling)
  // 0b10100 -> 0b01110 GT_OS (GT)	Greater-than (ordered, signaling)
  // 0b10101 -> 0b01101 GE_OS (GE)	Greater-than-or-equal (ordered, signaling)
  // 0b10110 -> 0b11100 NEQ_OS		Not-equal (ordered, signaling)
  // 0b10111 -> 0b10111 ORD_S		Ordered (signaling)
  // 0b11000 -> 0b11111 TRUE_US		True (unordered, signaling)
  // 0b11001 -> 0b10100 NEQ_US		Not-equal (unordered, signaling)
  // 0b11010 -> 0b00101 NLT_US (NLT)	Not-less-than (unordered, signaling)
  // 0b11011 -> 0b00110 NLE_US (NLE)	Not-less-than-or-equal (unordered,signaling)
  // 0b11100 -> 0b01010 NGT_US (NGT)	Not-greater-than (unordered, signaling)
  // 0b11101 -> 0b01001 NGE_US (NGE)	Not-greater-than-or-equal (unordered, signaling)
  // 0b11110 -> 0b11000 EQ_US		Equal (unordered, signaling)
  // 0b11111 -> 0b10011 UNORD_S		Unordered (signaling)

  VFPCmp( OpBase<ARCH> const& opbase, MOp<ARCH> const* rm, unsigned vn, unsigned gn, unsigned _op )
    : Op3V<ARCH,VR>(opbase, rm, vn, gn), op()
  {
    bool seq = ((_op >> 3) ^ ((_op >> 1) | (~_op >> 0))) & 1;
    bool slt = ((_op >> 3) ^ ((_op >> 1) | (_op >> 0))) & 1;
    bool sgt = ((_op >> 3) ^ ((_op >> 1) & (_op >> 0))) & 1;
    bool neg = sgt ^ ((_op >> 2) & 1);
    bool sig = (slt ^ sgt) ^ ((_op >> 4) & 1); // Is Signaling

    op = (seq << 0) | (slt << 1) | (sgt << 2) | (neg << 3) | (sig << 4);
  }

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const
  {
    sink << vprefix() << "cmp";

    switch (op & 7)
      {
      case 0: sink << (op & 8 ? "true" : "false"); break;
      case 1: sink << (op & 8 ? "neq" : "eq"); break;
      case 2: sink << (op & 8 ? "nlt" : "lt"); break;
      case 3: sink << (op & 8 ? "nle" : "le"); break;
      case 4: sink << (op & 8 ? "ngt" : "gt"); break;
      case 5: sink << (op & 8 ? "nge" : "ge"); break;
      case 6: sink << (op & 8 ? "eq" : "neq"); break;
      case 7: sink << (op & 8 ? "unord" : "ord"); break;
      }
    if ((((op >> 4) ^ (op >> 2) ^ (op >> 1)) & 1) or (op & 0b10111) == 0b00110)
      {
        // Not a natural comparison
        sink << '_';
        if ((op & 7) != 7)
          sink << (op & 8 ? 'u' : 'o');
        sink << (op & 16 ? 's' : 'q');
      }

    sink << (PACKED ? "p" : "s") << (OPSZ == 32 ? "s" : "d") << ' ';
    disasmVVW(sink);
  }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    typedef typename TypeFor<ARCH,OPSZ>::f f_type;
    typedef typename TypeFor<ARCH,OPSZ>::u u_type;

    bit_t seq = bit_t(op &  1); // Select Equal
    bit_t slt = bit_t(op &  2); // Select Less Than
    bit_t sgt = bit_t(op &  4); // Select Greater Than
    bit_t neg = bit_t(op &  8); // Negate result
    //bit_t sig = bit_t(op & 16); // Is Signaling

    for (unsigned idx = 0, end = PACKED ? VR::size()/OPSZ : 1; idx < end; ++idx)
      {
        f_type a = arch.vmm_read( VR(), vn, idx, f_type() );
        f_type b = arch.vmm_read( VR(), rm, idx, f_type() );
        bit_t lt = a < b;
        bit_t gt = a > b;
        bit_t eq = a == b;
        bit_t cmp = neg xor ((seq and eq) or (slt and lt) or (sgt and gt));

        arch.vmm_write( VR(), gn, idx, -u_type(cmp) );
      }

    if (gn != vn)
      for (unsigned idx = PACKED ? VR::size()/OPSZ : 1, end = VR::size()/OPSZ; idx < end; ++idx)
        arch.vmm_write( VR(), gn, idx, arch.vmm_read( VR(), vn, idx, valtype() ) );
  }
  uint8_t op;
};

template <class ARCH> struct DC<ARCH,VFPCMP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "*\x0f\xc2" ) & RM() & Imm<8>() ))
    {
      uint8_t op = _.i( uint8_t() ), gn = _.greg();
      if (not ic.vex())               return op >=  8 ? 0 : newVFPCmp<SSE>( ic, _.opbase(), gn, gn, _.rmop(), op );
      unsigned vn = ic.vreg();
      // Vex FP Scalar versions always work with XMM
      if (ic.vlen() == 128 or ic.rep) return op >= 32 ? 0 : newVFPCmp<XMM>( ic, _.opbase(), gn, vn, _.rmop(), op );
      if (ic.vlen() == 256)           return op >= 32 ? 0 : newVFPCmp<YMM>( ic, _.opbase(), gn, vn, _.rmop(), op );
      return 0;
    }

  return 0;
}
template <class VR> Operation<ARCH>*
newVFPCmp( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, unsigned gn, unsigned vn, MOp<ARCH> const* rm, uint8_t op )
{
  if (match( ic, simd__() )) return new VFPCmp<ARCH,VR,32, true>( opbase, rm, vn, gn, op );
  if (match( ic, simd66() )) return new VFPCmp<ARCH,VR,64, true>( opbase, rm, vn, gn, op );
  if (match( ic, simdF3() )) return new VFPCmp<ARCH,VR,32,false>( opbase, rm, vn, gn, op );
  if (match( ic, simdF2() )) return new VFPCmp<ARCH,VR,64,false>( opbase, rm, vn, gn, op );
  struct Bad {}; throw Bad();
  return 0;
}
};

/*********************/
/* SIMD CVT Functions*/
/*********************/

template <class ARCH, unsigned DOPSZ, unsigned SOPSZ>
struct CvtI2F : public Operation<ARCH>
{
  CvtI2F( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {}
  RMOp<ARCH> rm; uint8_t gn;
  char const* mnemonic() const { switch (DOPSZ) { case 32: return "cvtdq2ps"; case 64: return "cvtdq2pd"; } return "cvt<bad>"; }
  void disasm( std::ostream& sink ) const { sink << mnemonic() << ' ' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,DOPSZ>::f fdst_type;
    typedef typename TypeFor<ARCH,SOPSZ>::u usrc_type;
    for (unsigned idx = 0, end = 128/DOPSZ; idx < end; ++idx)
      {
        usrc_type src = arch.vmm_read( SSE(), rm, idx, usrc_type() );
        fdst_type dst = fdst_type(src);
        arch.vmm_write( SSE(), gn, idx, dst );
      }
  }
};

template <class ARCH, unsigned DOPSZ, class SOP>
struct CvtsI2F : public Operation<ARCH>
{
  CvtsI2F( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {}
  RMOp<ARCH> rm; uint8_t gn;
  char const* mnemonic() const { switch (DOPSZ) { case 32: return "cvtsi2ss"; case 64: return "cvtsi2sd"; } return "cvt<bad>"; }
  void disasm( std::ostream& sink ) const { sink << mnemonic() << ' ' << DisasmE( SOP(), rm ) << ',' << DisasmV( SSE(), gn ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,DOPSZ>::f fdst_type;
    typename TypeFor<ARCH,SOP::SIZE>::u src = arch.rmread( SOP(), rm );
    fdst_type dst = fdst_type(src);
    arch.vmm_write( SSE(), gn, 0, dst );
  }
};

template <class ARCH, unsigned DOPSZ, unsigned SOPSZ>
struct CvtsF2F : public Operation<ARCH>
{
  CvtsF2F( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const
  {
    sink << "cvts" << SizeID<SOPSZ>::fid() << "2s" << SizeID<DOPSZ>::fid() << " " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,SOPSZ>::f fsrc_type;
    typedef typename TypeFor<ARCH,DOPSZ>::f fdst_type;

    fsrc_type src = arch.vmm_read( SSE(), rm, 0, fsrc_type() );
    //FPToFP( res, op, cpu, cpu.FPSCR );
    fdst_type dst = fdst_type(src);

    arch.vmm_write( SSE(), gn, 0, dst );
  }
};

template <class ARCH, unsigned SOPSZ, class DOP>
struct CvttF2I : public Operation<ARCH>
{
  CvttF2I( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {}
  RMOp<ARCH> rm; uint8_t gn;
  char const* mnemonic() const { switch (SOPSZ) { case 32: return "cvttss2si"; case 64: return "cvttsd2si"; } return "cvt<bad>"; }
  void disasm( std::ostream& sink ) const { sink << mnemonic() << ' ' << DisasmW( SSE(), rm ) << ',' << DisasmG( DOP(), gn ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,DOP::SIZE>::u udst_type;
    typedef typename TypeFor<ARCH,SOPSZ>::f fsrc_type;
    fsrc_type src = arch.vmm_read( SSE(), rm, 0, fsrc_type() );
    udst_type dst = udst_type(src);
    arch.regwrite( DOP(), gn, dst );
  }
};

template <class ARCH> struct DC<ARCH,CVT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, simdF2() & opcode( "\x0f\x5a" ) & RM() ))

    return new CvtsF2F<ARCH,32,64>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simdF3() & opcode( "\x0f\x5a" ) & RM() ))

    return new CvtsF2F<ARCH,64,32>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simdF3() & opcode( "\x0f\xe6" ) & RM() ))

    return new CvtI2F<ARCH,64,32>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simd__() & opcode( "\x0f\x5b" ) & RM() ))

    return new CvtI2F<ARCH,32,32>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, opcode( "\x0f\x2a" ) & RM() ))
    {
      if (ic.f3())
        {
          if (ic.w()) return new CvtsI2F<ARCH,32,GOq>( _.opbase(), _.rmop(), _.greg() );
          /*else*/    return new CvtsI2F<ARCH,32,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      if (ic.f2())
        {
          if (ic.w()) return new CvtsI2F<ARCH,64,GOq>( _.opbase(), _.rmop(), _.greg() );
          /*else*/    return new CvtsI2F<ARCH,64,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      return 0;
    }

  if (auto _ = match( ic, opcode( "\x0f\x2c" ) & RM() ))
    {
      if (ic.f3())
        {
          if (ic.w()) return new CvttF2I<ARCH,32,GOq>( _.opbase(), _.rmop(), _.greg() );
          /*else*/    return new CvttF2I<ARCH,32,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      if (ic.f2())
        {
          if (ic.w()) return new CvttF2I<ARCH,64,GOq>( _.opbase(), _.rmop(), _.greg() );
          /*else*/    return new CvttF2I<ARCH,64,GOd>( _.opbase(), _.rmop(), _.greg() );
        }
      return 0;
    }

  return 0;
}};

template <class ARCH>
struct LSMxcsr : public Operation<ARCH>
{
  LSMxcsr( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, bool _st, bool _vex ) : Operation<ARCH>( opbase ), rm( _rm ), st(_st), vex(_vex) {} RMOp<ARCH> rm; bool st, vex;
  void disasm( std::ostream& sink ) const { sink << (vex ? "v" : "") << (st ? "st" : "ld") << "mxcsr " << DisasmE( GOd(), rm ); }
  void execute( ARCH& arch ) const
  {
    if (st) arch.rmwrite( GOd(), rm, arch.mxcsread() );
    else    arch.mxcswrite( arch.rmread( GOd(), rm ) );
  }
};

template <class ARCH> struct DC<ARCH,MXCSR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x0f\xae" ) & RM_mem() ))
    {
      bool vex = ic.vex();
      if (vex and (ic.vlen() != 128 or _.vreg())) return 0;
      unsigned rmopc = _.greg();
      if ((rmopc|1) != 3) return 0;
      return new LSMxcsr<ARCH>( _.opbase(), _.rmop(), rmopc&1, vex );
    }

  return 0;
}};

/* CVTDQ2PS -- Convert Packed Dword Integers to Packed Single- or Double-Precision FP Values */
// op cvtdq2ps_vdq_wdq( 0x0f[8]:> <:0x5b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtdq2ps_vdq_wdq.disasm = { _sink << "cvtdq2ps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
// op cvtdq2pd_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0xe6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtdq2pd_vdq_wdq.disasm = { _sink << "cvtdq2pd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTSI2SD -- Convert Dword Integer to Scalar Double-Precision FP Value */
// op cvtsi2sd_vdq_ed( 0xf2[8]:> <:0x0f[8]:> <:0x2a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtsi2sd_vdq_ed.disasm = { _sink << "cvtsi2sd " << DisasmEd( rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTSI2SS -- Convert Dword Integer to Scalar Single-Precision FP Value */
// op cvtsi2ss_vdq_ed( 0xf3[8]:> <:0x0f[8]:> <:0x2a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtsi2ss_vdq_ed.disasm = { _sink << "cvtsi2ss " << DisasmEd( rm ) << ',' << DisasmV( SSE(), gn ); };


/* CVTSD2SS -- Convert Scalar Double-Precision FP Value to Scalar Single-Precision FP Value */
// op cvtsd2ss_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x5a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
/* CVTPD2DQ -- Convert Packed Double-Precision FP Values to Packed Dword Integers */
// op cvtpd2dq_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0xe6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtpd2dq_vdq_wdq.disasm = { _sink << "cvtpd2dq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTPD2PI -- Convert Packed Double-Precision FP Values to Packed Dword Integers */
// op cvtpd2pi_pq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x2d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtpd2pi_pq_wdq.disasm = { _sink << "cvtpd2pi " << DisasmW( SSE(), rm ) << ',' << DisasmPq( gn ); };
/* CVTPD2PS -- Convert Packed Double-Precision FP Values to Packed Single-Precision FP Values */
// op cvtpd2ps_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x5a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtpd2ps_vdq_wdq.disasm = { _sink << "cvtpd2ps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTPI2P -- Convert Packed Dword Integers to Packed Single- or Double-Precision FP Values */
// op cvtpi2ps_vdq_qq( 0x0f[8]:> <:0x2a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtpi2ps_vdq_qq.disasm = { _sink << "cvtpi2ps " << DisasmQq( rm ) << ',' << DisasmV( SSE(), gn ); };
// op cvtpi2pd_vdq_qq( 0x66[8]:> <:0x0f[8]:> <:0x2a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtpi2pd_vdq_qq.disasm = { _sink << "cvtpi2pd " << DisasmQq( rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTPS2DQ -- Convert Packed Single-Precision FP Values to Packed Dword Integers */
// op cvtps2dq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x5b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtps2dq_vdq_wdq.disasm = { _sink << "cvtps2dq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTPS2PD -- Convert Packed Single-Precision FP Values to Packed Double-Precision FP Values */
// op cvtps2pd_vdq_wdq( 0x0f[8]:> <:0x5a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtps2pd_vdq_wdq.disasm = { _sink << "cvtps2pd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTPS2PI -- Convert Packed Single-Precision FP Values to Packed Dword Integers */
// op cvtps2pi_pq_wdq( 0x0f[8]:> <:0x2d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtps2pi_pq_wdq.disasm = { _sink << "cvtps2pi " << DisasmW( SSE(), rm ) << ',' << DisasmPq( gn ); };
/* CVTSD2SI -- Convert Scalar Double-Precision FP Value to Integer */
// op cvtsd2si_gd_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x2d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtsd2si_gd_wdq.disasm = { _sink << "cvtsd2si " << DisasmW( SSE(), rm ) << ',' << DisasmGd( gn ); };
// cvtsd2ss_vdq_wdq.disasm = { _sink << "cvtsd2ss " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTSS2SD -- Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP Value */
// op cvtss2sd_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x5a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtss2sd_vdq_wdq.disasm = { _sink << "cvtss2sd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTSS2SI -- Convert Scalar Single-Precision FP Value to Dword Integer */
// op cvtss2si_gd_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x2d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvtss2si_gd_wdq.disasm = { _sink << "cvtss2si " << DisasmW( SSE(), rm ) << ',' << DisasmGd( gn ); };
/* CVTTPD2DQ -- Convert with Truncation Packed Double-Precision FP Values to Packed Dword Integers */
// op cvttpd2dq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttpd2dq_vdq_wdq.disasm = { _sink << "cvttpd2dq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTTPD2PI -- Convert with Truncation Packed Double-Precision FP Values to Packed Dword Integers */
// op cvttpd2pi_pq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x2c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttpd2pi_pq_wdq.disasm = { _sink << "cvttpd2pi " << DisasmW( SSE(), rm ) << ',' << DisasmPq( gn ); };
/* CVTTPS2DQ -- Convert with Truncation Packed Single-Precision FP Values to Packed Dword Integers */
// op cvttps2dq_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x5b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttps2dq_vdq_wdq.disasm = { _sink << "cvttps2dq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
/* CVTTPS2PI -- Convert with Truncation Packed Single-Precision FP Values to Packed Dword Integers */
// op cvttps2pi_pq_wdq( 0x0f[8]:> <:0x2c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttps2pi_pq_wdq.disasm = { _sink << "cvttps2pi " << DisasmW( SSE(), rm ) << ',' << DisasmPq( gn ); };
/* CVTTSD2SI -- Convert with Truncation Scalar Double-Precision FP Value to Integer */
// op cvttsd2si_gd_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x2c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttsd2si_gd_wdq.disasm = { _sink << "cvttsd2si " << DisasmW( SSE(), rm ) << ',' << DisasmGd( gn ); };
/* CVTTSS2SI -- Convert with Truncation Scalar Single-Precision FP Value to Dword Integer */
// op cvttss2si_gd_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x2c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// cvttss2si_gd_wdq.disasm = { _sink << "cvttss2si " << DisasmW( SSE(), rm ) << ',' << DisasmGd( gn ); };


// /* DPPD -- Dot Product of Packed Double Precision Floating-Point Values */
// op dpps_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x40[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// dpps_vdq_wdq_ib.disasm = { _sink << "dpps " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op dppd_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x41[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// dppd_vdq_wdq_ib.disasm = { _sink << "dppd " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* EMMS -- Empty MMX Technology State */
// op emms( 0x0f[8]:> <:0x77[8] );
//
// emms.disasm = { _sink << "emms"; };
//
// /* EXTRACTPS -- Extract Packed Single Precision Floating-Point Value */
// op extractps_rd_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x17[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// extractps_rd_wdq_ib.disasm = { _sink << "extractps " << DisasmI(imm) << ',' << DisasmV( SSE(), gn ) << ',' << DisasmEd( rm ); };
//
// /* FXSAVE/FXRSTOR -- Save/Restore x87 FPU, MMX Technology, and SSE State */
// op fxrstor( 0x0f[8]:> <:0xae[8]:> <:?[2]:1[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// fxrstor.disasm = { _sink << "fxrstor " << DisasmM( rm ); };
//
// op fxsave( 0x0f[8]:> <:0xae[8]:> <:?[2]:0[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// fxsave.disasm = { _sink << "fxsave " << DisasmM( rm ); };
//
// /* HADDPD -- Packed Single- or Double-FP Horizontal Add */
// op haddps_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x7c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// haddps_vdq_wdq.disasm = { _sink << "haddps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op haddpd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x7c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// haddpd_vdq_wdq.disasm = { _sink << "haddpd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* HSUBPD -- Packed Single- or Double-FP Horizontal Substract */
// op hsubps_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x7d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// hsubps_vdq_wdq.disasm = { _sink << "hsubps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op hsubpd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x7d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// hsubpd_vdq_wdq.disasm = { _sink << "hsubpd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* INSERTPS -- Insert Packed Single Precision Floating-Point Value */
// op insertps_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x21[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// insertps_vdq_wdq_ib.disasm = { _sink << "insertps " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* LDDQU -- Load Unaligned Integer 128 Bits */
// op lddqu_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0xf0[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// lddqu_vdq_wdq.disasm = { _sink << "lddqu " << DisasmM( rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MASKMOVDQU -- Store Selected Bytes of Double Quadword */
// op maskmovdqu_vdq_vdq( 0x66[8]:> <:0x0f[8]:> <:0xf7[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// maskmovdqu_vdq_vdq.disasm = { _sink << "maskmovdqu " << DisasmV( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MASKMOVQ */
// op maskmovq_pq_nq( 0x0f[8]:> <:0xf7[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// maskmovq_pq_nq.disasm = { _sink << "maskmovq " << DisasmPq( rm ) << ',' << DisasmPq( gn ); };
//
// /* MOVD/MOVQ -- Move Doubleword/Move Quadword */
template <class ARCH, class GOP>
struct MovEP : public Operation<ARCH>
{
  MovEP( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "mov" << (GOP::SIZE==64?'q':'d') << ' ' << DisasmPq( gn ) << ',' << DisasmE( GOP(), rm ); }
};

template <class ARCH, class GOP>
struct MovPE : public Operation<ARCH>
{
  MovPE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "mov" << (GOP::SIZE==64?'q':'d') << ' ' << DisasmE( GOP(), rm ) << ',' << DisasmPq( gn ); }
};

template <class ARCH, class VR, class GOP>
struct MovEV : public Operation<ARCH>
{
  MovEV( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm(std::move(_rm)), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << (VR::vex()?"v":"") << "mov" << SizeID<GOP::SIZE>::iid() << ' ' << DisasmV( VR(), gn ) << ',' << DisasmE( GOP(), rm ); }
  void execute( ARCH& arch ) const
  {
    arch.rmwrite( GOP(), rm, arch.vmm_read( VR(), gn, 0, typename TypeFor<ARCH,GOP::SIZE>::u() ) );
  }
};

template <class ARCH, class VR, class GOP>
struct MovVE : public Operation<ARCH>
{
  MovVE( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << (VR::vex()?"v":"") << "mov" << SizeID<GOP::SIZE>::iid() << ' ' << DisasmE( GOP(), rm ) << ',' << DisasmV( VR(), gn ); }
  void execute( ARCH& arch ) const
  {
    arch.vmm_write( VR(), gn, 0, arch.rmread( GOP(), rm ) );
    for (unsigned idx = 1, end = VR::size() / GOP::SIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, typename TypeFor<ARCH,GOP::SIZE>::u(0) );
  }
};

template <class ARCH, class VR>
struct MovQ : public Operation<ARCH>
{
  MovQ( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm(std::move(_rm)), gn(_gn) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << (VR::vex()?"v":"") << "movq" << ' ' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn ); }
  void execute( ARCH& arch ) const
  {
    arch.vmm_write( VR(), gn, 0, arch.vmm_read( VR(), rm, 0, typename ARCH::u64_t() ) );
    for (unsigned idx = 1, end = VR::size() / 64; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, typename ARCH::u64_t(0) );
  }
};

template <class ARCH> struct DC<ARCH,MOVQ> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex("\xf3\x0f\x7e") & RM() ))

    return newMovQ( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex("\x66\x0f\xd6") & RM() ))

    return newMovQ( ic, false, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
Operation<ARCH>* newMovQ( InputCode<ARCH> const& ic, bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())     return newMovQ<SSE>( load, opbase, std::move(rm), gn );
  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return newMovQ<XMM>( load, opbase, std::move(rm), gn );
  if (ic.vlen() == 256) return newMovQ<YMM>( load, opbase, std::move(rm), gn );
  return 0;
}
template <class VR>
Operation<ARCH>* newMovQ( bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (load)
    return new MovQ<ARCH,VR>( opbase, std::move(rm), gn );

  return rm.ismem()
    ? static_cast<Operation<ARCH>*>( new MovEV<ARCH,VR,GOq>( opbase, std::move(rm), gn ) )
    : new MovQ<ARCH,VR>( opbase, make_rop<ARCH>(gn), rm.ereg() );
}
};

template <class ARCH> struct DC<ARCH,MOVGV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;
  bool vex_p = ic.vex(), quad_p = ic.w();
  if (not vex_p and not quad_p) return getMOVGV<SSE,GOd>( ic );
  if (not vex_p and     quad_p) return getMOVGV<SSE,GOq>( ic );
  if (    vex_p and (ic.vlen() != 128 or ic.vreg())) return 0;
  if (    vex_p and not quad_p) return getMOVGV<XMM,GOd>( ic );
  if (    vex_p and     quad_p) return getMOVGV<XMM,GOq>( ic );
  return 0;
}
template <typename VR, typename GOP> Operation<ARCH>* getMOVGV( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, simd__() & opcode( "\x0f\x6e" ) & RM() ))

    return ic.vex() ? 0 : new MovPE<ARCH,GOP>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simd__() & opcode( "\x0f\x7e" ) & RM() ))

    return ic.vex() ? 0 : new MovEP<ARCH,GOP>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6e" ) & RM() ))

    return new MovVE<ARCH,VR,GOP>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x7e" ) & RM() ))

    return new MovEV<ARCH,VR,GOP>( _.opbase(), _.rmop(), _.greg() );

  return 0;
}
};

struct   MovDQU { char const* name() { return   "movdqu"; } bool aligned() { return false; } };
struct   MovDQA { char const* name() { return   "movdqa"; } bool aligned() { return  true; } };
struct    LdDQU { char const* name() { return    "lddqu"; } bool aligned() { return false; } };
struct MovNTDQA { char const* name() { return "movntdqa"; } bool aligned() { return  true; } };
struct  MovNTDQ { char const* name() { return  "movntdq"; } bool aligned() { return  true; } };

template <class ARCH, class IMPL, class VR>
struct VLd : public Operation<ARCH>
{
  VLd( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << IMPL().name() << ' ' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn ); }
  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = VR::size() / 64; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx,  arch.vmm_read( VR(), rm, idx, typename ARCH::u64_t() ) );
  }
};

template <class ARCH, class IMPL, class VR>
struct VSt : public Operation<ARCH>
{
  VSt( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << IMPL().name() << ' ' << DisasmV( VR(), gn ) << ',' << DisasmW( VR(), rm ); }
  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = VR::size() / 64; idx < end; ++idx)
      arch.vmm_write( VR(), rm, idx, arch.vmm_read( VR(), gn, idx, typename ARCH::u64_t() ) );
  }
};

/* MOVDQA/MOVDQU -- Move Aligned Unaligned Double Quadword */
/* LDDQU -- Load Unaligned Integer 128 Bits */
/* MOVNTDQA -- Load Double Quadword Non-Temporal Aligned Hint */
/* MOVNTDQ -- Store Double Quadword Using Non-Temporal Hint */
template <class ARCH> struct DC<ARCH,MOVDQ> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\xf3\x0f\x6f" ) & RM() ))

    return newMov<MovDQU>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\xf3\x0f\x7f" ) & RM() ))

    return newMov<MovDQU>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6f" ) & RM() ))

    return newMov<MovDQA>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x7f" ) & RM() ))

    return newMov<MovDQA>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\xf2\x0f\xf0" ) & RM() ))

    return newMov<LdDQU>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x2a" ) & RM() ))

    return newMov<MovNTDQA>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xe7" ) & RM() ))

    return newMov<MovNTDQ>( ic, false, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class IMPL>
Operation<ARCH>* newMov( InputCode<ARCH> const& ic, bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())     return newMov2<IMPL,SSE>( load, opbase, std::move(rm), gn );
  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return newMov2<IMPL,XMM>( load, opbase, std::move(rm), gn );
  if (ic.vlen() == 256) return newMov2<IMPL,YMM>( load, opbase, std::move(rm), gn );
  return 0;
}
  template <class IMPL, class VR>
Operation<ARCH>* newMov2( bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (load) return new VLd<ARCH,IMPL,VR>( opbase, std::move(rm), gn );
  else      return new VSt<ARCH,IMPL,VR>( opbase, std::move(rm), gn );
}
};

template <class ARCH, class VR, class GOP>
struct Broadcast : public Operation<ARCH>
{
  Broadcast( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "vpbroadcast" << SizeID<GOP::SIZE>::iid() << ' ';
    if (rm.isreg())
      sink << DisasmW( XMM(), rm );
    else
      sink << DisasmE( GOP(), rm );
    sink << ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOP::SIZE>::u src_type;
    src_type value = arch.vmm_read( XMM(), rm, 0, src_type());
    for (unsigned idx = 0, end = VR::size() / GOP::SIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, value );
  }
};

template <class ARCH>
struct BroadcastI128 : public Operation<ARCH>
{
  BroadcastI128( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "vpbroadcasti128 " << DisasmW( XMM(), rm ) << ',' << DisasmV( YMM(), gn );}
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOq::SIZE>::u src_type;
    src_type value = arch.vmm_read( YMM(), rm, 0, src_type());
    for (unsigned idx = 0, end = YMM::size() / GOq::SIZE; idx < end; ++idx)
      arch.vmm_write( YMM(), gn, idx, value );
  }
};

template <class ARCH> struct DC<ARCH,BROADCAST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x78" ) & RM() ))

    return newBroadcast<GOb>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x79" ) & RM() ))

    return newBroadcast<GOw>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x58" ) & RM() ))

    return newBroadcast<GOd>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x59" ) & RM() ))

    return newBroadcast<GOq>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x5a" ) & RM() )) {
    if (ic.w() || ic.vlen() != 256) return 0;

    return new BroadcastI128<ARCH>( _.opbase(), _.rmop(), _.greg() );
  }

  return 0;
}
template <class GOP>
Operation<ARCH>* newBroadcast( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex() || ic.vreg() || ic.w()) return 0;
  if (ic.vlen() == 128) return new Broadcast<ARCH,XMM,GOP>( opbase, std::move(rm), gn );
  if (ic.vlen() == 256) return new Broadcast<ARCH,YMM,GOP>( opbase, std::move(rm), gn );
  return 0;
}
};


template <class ARCH, class VR, unsigned OPSIZE, class IMPL>
struct MovfpVW : public Operation<ARCH>
{
  MovfpVW( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << (VR::vex() ? "v" : "") << IMPL::name() << SizeID<OPSIZE>::fid() << ' ' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::f f_type;
    for (unsigned idx = 0, end = VR::size()/OPSIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx,  arch.vmm_read( VR(), rm, idx, f_type() ) );
  }
};

template <class ARCH, class VR, unsigned OPSIZE, class IMPL>
struct MovfpWV : public Operation<ARCH>
{
  MovfpWV( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << (VR::vex() ? "v" : "") << IMPL::name() << SizeID<OPSIZE>::fid() << ' ' << DisasmV( VR(), gn ) << ',' << DisasmW( VR(), rm ); }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::f f_type;
    for (unsigned idx = 0, end = VR::size()/OPSIZE; idx < end; ++idx)
      arch.vmm_write( VR(), rm, idx,  arch.vmm_read( VR(), gn, idx, f_type() ) );
  }
};

struct MovAFP { static char const* name() { return "movap"; } static bool aligned() { return true; } };
struct MovUFP { static char const* name() { return "movup"; } static bool aligned() { return false; } };
struct StNTFP { static char const* name() { return "movntp"; } static bool aligned() { return true; } };

/* MOVAP -- Move Aligned Packed Single- or Double-Precision Floating-Point Values */
/* MOVUP -- Move Unaligned Packed Single- or Double-Precision Floating-Point Values */
/* MOVNTPD -- Store Packed Single- or Double-Precision Floating-Point Values Using Non-Temporal Hint */
template <class ARCH> struct DC<ARCH,MOVFP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x0f\x28" ) & RM() ))

    return newMovfp<32,MovAFP>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x29" ) & RM() ))

    return newMovfp<32,MovAFP>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x28" ) & RM() ))

    return newMovfp<64,MovAFP>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x29" ) & RM() ))

    return newMovfp<64,MovAFP>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x10" ) & RM() ))

    return newMovfp<32,MovUFP>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x11" ) & RM() ))

    return newMovfp<32,MovUFP>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x10" ) & RM() ))

    return newMovfp<64,MovUFP>( ic, true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x11" ) & RM() ))

    return newMovfp<64,MovUFP>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x2b" ) & RM() ))

    return newMovfp<32,StNTFP>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x2b" ) & RM() ))

    return newMovfp<64,StNTFP>( ic, false, _.opbase(), _.rmop(), _.greg() );


  return 0;
}
template <unsigned OPSIZE, class IMPL>
Operation<ARCH>* newMovfp( InputCode<ARCH> const& ic, bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())     return newMovfp<SSE,OPSIZE,IMPL>( load, opbase, std::move(rm), gn );
  if (ic.vreg())        return 0;
  if (ic.vlen() == 128) return newMovfp<XMM,OPSIZE,IMPL>( load, opbase, std::move(rm), gn );
  if (ic.vlen() == 256) return newMovfp<YMM,OPSIZE,IMPL>( load, opbase, std::move(rm), gn );
  return 0;
}
template <class VR, unsigned OPSIZE, class IMPL>
Operation<ARCH>* newMovfp( bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (load) return new MovfpVW<ARCH,VR,OPSIZE,IMPL>( opbase, std::move(rm), gn );
  /*else*/  return new MovfpWV<ARCH,VR,OPSIZE,IMPL>( opbase, std::move(rm), gn );
}
};

template <class ARCH, class VR, unsigned OPSIZE>
struct MovfpcVW : public Op3V<ARCH,VR>
{
  MovfpcVW( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn, bool _hi ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn), hi(_hi) {} bool hi;

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << (hi ? "movhp" : "movlp") << SizeID<OPSIZE>::fid() << ' '; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::f f_type;
    for (unsigned idx = 0, end = VR::size()/2/OPSIZE, withrm = hi*end, withvn = end-withrm; idx < end; ++idx)
      {
        arch.vmm_write( VR(), gn, idx + withrm, arch.vmm_read( VR(), rm, idx, f_type() ) );
        arch.vmm_write( VR(), gn, idx + withvn, arch.vmm_read( VR(), vn, idx + withvn, f_type() ) );
      }
  }
};

template <class ARCH, class VR, unsigned OPSIZE>
struct MovfpcWV : public Operation<ARCH>
{
  MovfpcWV( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn, bool _hi ) : Operation<ARCH>(opbase), rm(std::move(_rm)), gn(_gn), hi(_hi) {} RMOp<ARCH> rm; uint8_t gn; bool hi;
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << (hi ? "movhp" : "movlp") << SizeID<OPSIZE>::fid() << ' ' << DisasmV( VR(), gn ) << ',' << DisasmW( VR(), rm );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::f f_type;
    for (unsigned idx = 0, end = VR::size()/2/OPSIZE, mux = hi*end; idx < end; ++idx)
      arch.vmm_write( VR(), rm, idx, arch.vmm_read( VR(), gn, idx + mux, f_type() ) );
  }
};

// /* MOVLPD -- Move Low Packed Double-Precision Floating-Point Value */
// /* MOVLPS -- Move Low Packed Single-Precision Floating-Point Value */
// /* MOVHPD -- Move High Packed Double-Precision Floating-Point Value */
// /* MOVHPS -- Move High Packed Single-Precision Floating-Point Value */
template <class ARCH> struct DC<ARCH,MOVFPC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x0f\x12" ) & RM_mem() ))

    return newMovFPC<32>( ic, true, _.opbase(), _.rmop(), _.greg(), 0 );

  if (auto _ = match( ic, vex( "\x0f\x13" ) & RM_mem() ))

    return newMovFPC<32>( ic, false, _.opbase(), _.rmop(), _.greg(), 0 );

  if (auto _ = match( ic, vex( "\x66\x0f\x12" ) & RM_mem() ))

    return newMovFPC<64>( ic, true, _.opbase(), _.rmop(), _.greg(), 0 );

  if (auto _ = match( ic, vex( "\x66\x0f\x13" ) & RM_mem() ))

    return newMovFPC<64>( ic, false, _.opbase(), _.rmop(), _.greg(), 0 );

  if (auto _ = match( ic, vex( "\x0f\x16" ) & RM_mem() ))

    return newMovFPC<32>( ic, true, _.opbase(), _.rmop(), _.greg(), 1 );

  if (auto _ = match( ic, vex( "\x0f\x17" ) & RM_mem() ))

    return newMovFPC<32>( ic, false, _.opbase(), _.rmop(), _.greg(), 1 );

  if (auto _ = match( ic, vex( "\x66\x0f\x16" ) & RM_mem() ))

    return newMovFPC<64>( ic, true, _.opbase(), _.rmop(), _.greg(), 1 );

  if (auto _ = match( ic, vex( "\x66\x0f\x17" ) & RM_mem() ))

    return newMovFPC<64>( ic, false, _.opbase(), _.rmop(), _.greg(), 1 );

  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newMovFPC( InputCode<ARCH> const& ic, bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn, unsigned lohi )
{
  if (not ic.vex())     return newMovFPC<SSE,OPSIZE>( load, opbase, std::move(rm), gn, gn, lohi );
  unsigned vn = ic.vreg();
  if (vn and not load) return 0;
  if (ic.vlen() == 128) return newMovFPC<XMM,OPSIZE>( load, opbase, std::move(rm), vn, gn, lohi );
  return 0;
}
template <class VR, unsigned OPSIZE>
Operation<ARCH>* newMovFPC( bool load, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn, unsigned lohi )
{
  if (load) return new MovfpcVW<ARCH,VR,OPSIZE>( opbase, std::move(rm), vn, gn, lohi );
  else      return new MovfpcWV<ARCH,VR,OPSIZE>( opbase, std::move(rm), gn, lohi );
}
};

// /* MOVDQ2Q -- Move Quadword from XMM to MMX Technology Register */
// op movdq2q_pq_vdq( 0x66[8]:> <:0x0f[8]:> <:0x2d[8]:> <:0b11[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM] );
//
// movdq2q_pq_vdq.disasm = { _sink << "movdq2q " << DisasmV( SSE(), rm ) << ',' << DisasmPq( gn ); };
//
// /* MOVHLPS -- Move Packed Single-Precision Floating-Point Values High to Low */
// op movhlps_vdq_vdq( 0x0f[8]:> <:0x12[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// movhlps_vdq_vdq.disasm = { _sink << "movhlps " << DisasmV( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MOVLHPS -- Move Packed Single-Precision Floating-Point Values Low to High */
// op movlhps_vdq_wdq( 0x0f[8]:> <:0x16[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// movlhps_vdq_wdq.disasm = { _sink << "movlhps " << DisasmV( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MOVMSKPD -- Extract Packed Single- or Double-Precision Floating-Point Sign Mask */
// op movmskpd_gd_vdq( 0x66[8]:> <:0x0f[8]:> <:0x50[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// movmskpd_gd_vdq.disasm = { _sink << "movmskpd " << DisasmV( SSE(), rm ) << ',' << DisasmGd( gn ); };
//
// op movmskps_gd_vdq( 0x0f[8]:> <:0x50[8]:> <:0b11[2]:gn[3]:rm[3] );
//
// movmskps_gd_vdq.disasm = { _sink << "movmskps " << DisasmV( SSE(), rm ) << ',' << DisasmGd( gn ); };
//
// /* MOVNTPD -- Store Packed Single- or Double-Precision Floating-Point Values Using Non-Temporal Hint */
// op movntpd_mdq_vdq( 0x66[8]:> <:0x0f[8]:> <:0x2b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movntpd_mdq_vdq.disasm = { _sink << "movntpd " << DisasmV( SSE(), gn ) << ',' << DisasmM( rm ); };
//
// op movntps_mdq_vdq( 0x0f[8]:> <:0x2b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movntps_mdq_vdq.disasm = { _sink << "movntps " << DisasmV( SSE(), gn ) << ',' << DisasmM( rm ); };
//
// /* MOVNTQ -- Store Double Quadword Using Non-Temporal Hint */
// op movntq_mq_pq( 0x0f[8]:> <:0xe7[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movntq_mq_pq.disasm = { _sink << "movntq " << DisasmPq( gn ) << ',' << DisasmM( rm ); };
//
// /* MOVQ -- Move Quadword (MMX) */
// op movq_pq_mq( 0x0f[8]:> <:0x6f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movq_pq_mq.disasm = { _sink << "movq " << DisasmM( rm ) << ',' << DisasmPq( gn ); };
//
// op movq_mq_pq( 0x0f[8]:> <:0x7f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movq_mq_pq.disasm = { _sink << "movq " << DisasmPq( gn ) << ',' << DisasmM( rm ); };
//
// op movq_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x7e[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movq_vdq_wdq.disasm = { _sink << "movq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op movq_wdq_vdq( 0x66[8]:> <:0x0f[8]:> <:0xd6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movq_wdq_vdq.disasm = { _sink << "movq " << DisasmV( SSE(), gn ) << ',' << DisasmW( SSE(), rm ); };
//
// /* MOVQ2DQ -- Move Quadword from MMX Technology to XMM Register */
// op movq2dq_vdq_pq( 0xf3[8]:> <:0x0f[8]:> <:0xd6[8]:> <:0b11[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM] );
//
// movq2dq_vdq_pq.disasm = { _sink << "movq2dq " << DisasmV( SSE(), gn ) << ',' << DisasmPq( rm ); };
//

// /* MOVSS -- Move Scalar Single-Precision Floating-Point Values */
// /* MOVSD -- Move Scalar Double-Precision Floating-Point Value */

template <class VR, unsigned OPSIZE>
struct LSMnemo
{
  typedef LSMnemo<VR,OPSIZE> this_type;
  friend std::ostream& operator << ( std::ostream& sink, this_type const& ) { sink << (VR::vex() ? "v" : "") << "movs" << SizeID<OPSIZE>::fid(); return sink; };
  this_type const& mnemonic() const { return *this; }
};

template <class ARCH, class VR, unsigned OPSIZE>
struct LSFPS : public Operation<ARCH>
{
  LSFPS( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, unsigned _gn ) : Operation<ARCH>(opbase), rm(std::move(_rm)), gn(_gn) {}
  RMOp<ARCH> rm; unsigned gn;
};

template <class ARCH, class VR, unsigned OPSIZE>
struct StoreFPS : public LSFPS<ARCH,VR,OPSIZE>, public LSMnemo<VR,OPSIZE>
{
  typedef LSFPS<ARCH,VR,OPSIZE> LSBASE; using LSBASE::LSFPS; using LSBASE::rm; using LSBASE::gn;
  void disasm( std::ostream& sink ) const { sink << this->mnemonic() << ' ' << DisasmV( VR(), gn ) << ',' << DisasmW( VR(), rm ); }
  void execute( ARCH& arch ) const
  {
    arch.vmm_write( VR(), rm, 0, arch.vmm_read( VR(), gn, 0, typename TypeFor<ARCH,OPSIZE>::f() ) );
  }
};

template <class ARCH, class VR, unsigned OPSIZE>
struct LoadFPS : public LSFPS<ARCH,VR,OPSIZE>, public LSMnemo<VR,OPSIZE>
{
  typedef LSFPS<ARCH,VR,OPSIZE> LSBASE; using LSBASE::LSFPS; using LSBASE::rm; using LSBASE::gn;
  void disasm( std::ostream& sink ) const { sink << this->mnemonic() << ' ' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn ); }
  void execute( ARCH& arch ) const
  {
    arch.vmm_write( VR(), gn, 0, arch.vmm_read( VR(), rm, 0, typename TypeFor<ARCH,OPSIZE>::f() ) );
    for (unsigned idx = 1, end = VR::size()/OPSIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, typename TypeFor<ARCH,OPSIZE>::f(0) );
  }
};

template <class ARCH, unsigned OPSIZE>
struct MergeFPS : public Operation<ARCH>, public LSMnemo<XMM,OPSIZE>
{
  MergeFPS(OpBase<ARCH> const& opbase, unsigned _dst, unsigned _src1, unsigned _src2)
    : Operation<ARCH>(opbase), dst(_dst), src1(_src1), src2(_src2)
  {}
  void disasm( std::ostream& sink ) const { sink << this->mnemonic() << ' ' << DisasmV( XMM(), src1 ) << ',' << DisasmV( XMM(), src2 ) << ',' << DisasmV( XMM(), dst ); }
  void execute( ARCH& arch ) const
  {
    arch.vmm_write( XMM(), dst, 0, arch.vmm_read( XMM(), src2, 0, typename TypeFor<ARCH,OPSIZE>::f() ) );
    for (unsigned idx = 1, end = XMM::size()/OPSIZE; idx < end; ++idx)
      arch.vmm_write( XMM(), dst, idx, arch.vmm_read( XMM(), src1, idx, typename TypeFor<ARCH,OPSIZE>::f() ) );
  }
  uint8_t dst, src1, src2;
};


template <class ARCH> struct DC<ARCH,VMOVSD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\xf3\x0f\x10" ) & RM() ))

    return newMovs<32>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\xf3\x0f\x11" ) & RM() ))

    return newMovs<32>( ic,  true, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\xf2\x0f\x10" ) & RM() ))

    return newMovs<64>( ic, false, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\xf2\x0f\x11" ) & RM() ))

    return newMovs<64>( ic,  true, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newMovs( InputCode<ARCH> const& ic, bool store, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  bool is_mem = rm.ismem();

  if (is_mem ? store : not ic.vex())
    {
      // Store
      if      (not ic.vex())  return new StoreFPS<ARCH,SSE,OPSIZE>( opbase, std::move(rm), gn );
      else if (not ic.vreg()) return new StoreFPS<ARCH,XMM,OPSIZE>( opbase, std::move(rm), gn );
      else                    return 0;
    }

  if (is_mem)
    {
      // Load
      if      (not ic.vex())  return new LoadFPS<ARCH,SSE,OPSIZE>( opbase, std::move(rm), gn );
      else if (not ic.vreg()) return new LoadFPS<ARCH,XMM,OPSIZE>( opbase, std::move(rm), gn );
      else                    return 0;
    }

  // Merger (AVX only)
  unsigned dst = gn, src1 = ic.vreg(), src2 = rm.ereg();
  if (store) std::swap(dst,src2);
  return new MergeFPS<ARCH,OPSIZE>( opbase, dst, src1, src2 );
}
};

// /* MOVSHDUP -- Move Packed Single-FP High and Duplicate */
// op movshdup_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x16[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movshdup_vdq_wdq.disasm = { _sink << "movshdup " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MOVSLDUP -- Move Packed Single-FP Low and Duplicate */
// op movsldup_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x12[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// movsldup_vdq_wdq.disasm = { _sink << "movsldup " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MPSADBW -- Compute Multiple Packed Sums of Absolute Difference */
// op mpsadbw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x42[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// mpsadbw_vdq_wdq.disasm = { _sink << "mpsadbw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };

/* SQRT -- Compute Square Roots of Packed or Scalar Single- or Double-Precision Floating-Point Values */
struct VSQRT { char const* n() { return "sqrt"; } };

template <class ARCH, class OPERATION, class VR, unsigned OPSZ, bool PACKED>
struct VFPUnaryVW : public Op3V<ARCH,VR>
{
  typedef typename TypeFor<ARCH,OPSZ>::f valtype;

  valtype eval ( VSQRT const&, valtype const& src ) const { return sqrt(src); }

  VFPUnaryVW(OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm(std::ostream& sink) const { sink << vprefix() << OPERATION().n() << (PACKED ? "p" : "s") << (OPSZ == 32 ? "s" : "d") << ' '; disasmVVW(sink, not PACKED); }

  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = PACKED ? VR::size()/OPSZ : 1; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, eval( OPERATION(), arch.vmm_read( VR(), rm, idx, valtype() ) ) );
    for (unsigned idx = PACKED ? VR::size()/OPSZ : 1, end = VR::size()/OPSZ; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, arch.vmm_read( VR(), vn, idx, valtype() ) );
  }
};

template <class ARCH> struct DC<ARCH,VFPUNARY> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "*\x0f\x51" ) & RM() ))

    return newVFPUnary<VSQRT>(ic, _.opbase(), _.greg(), _.rmop());

  return 0;
}
template <class OPERATION> Operation<ARCH>* newVFPUnary( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, unsigned gn, RMOp<ARCH>&& rm )
{
  if (not ic.vex())               return newVFPUnaryVW<OPERATION,SSE>( ic, opbase, gn, gn, std::move(rm) );
  unsigned vn = ic.vreg();
  // Vex FP Scalar versions always work with XMM
  if (ic.vlen() == 128 or ic.rep) return newVFPUnaryVW<OPERATION,XMM>( ic, opbase, gn, vn, std::move(rm) );
  if (ic.vlen() == 256)           return newVFPUnaryVW<OPERATION,YMM>( ic, opbase, gn, vn, std::move(rm) );
  return 0;
}
template <class OPERATION, class VR> Operation<ARCH>*
newVFPUnaryVW( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, unsigned gn, unsigned vn, RMOp<ARCH>&& rm )
{
  if (match( ic, simdF3() )) return new VFPUnaryVW<ARCH,OPERATION,VR,32,false>( opbase, std::move(rm), vn, gn );
  if (match( ic, simdF2() )) return new VFPUnaryVW<ARCH,OPERATION,VR,64,false>( opbase, std::move(rm), vn, gn );
  if (vn and ic.vex()) return 0; // No vreg for packed operation
  if (match( ic, simd__() )) return new VFPUnaryVW<ARCH,OPERATION,VR,32, true>( opbase, std::move(rm), vn, gn );
  if (match( ic, simd66() )) return new VFPUnaryVW<ARCH,OPERATION,VR,64, true>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

struct VADD    { char const* n() { return "add"; } };
struct VSUB    { char const* n() { return "sub"; } };
struct VMUL    { char const* n() { return "mul"; } };
struct VDIV    { char const* n() { return "div"; } };
struct VMIN    { char const* n() { return "min"; } };
struct VMAX    { char const* n() { return "max"; } };
struct VAND    { char const* n() { return "and"; } };
struct VANDN   { char const* n() { return "andn"; } };
struct VOR     { char const* n() { return "or"; } };
struct VXOR    { char const* n() { return "xor"; } };
struct VSLL    { char const* n() { return "sll"; } };
struct VSRL    { char const* n() { return "srl"; } };
struct VSRA    { char const* n() { return "sra"; } };
struct VMULL   { char const* n() { return "mull"; } };
struct VMULUDQ { char const* n() { return "muludq"; } };

struct VFPacked { enum { packed = true };  static void disasmOp(std::ostream& sink, char const* op, unsigned opsz) { sink << op << 'p' << ("ds"[opsz == 32]); } };
struct VFScalar { enum { packed = false }; static void disasmOp(std::ostream& sink, char const* op, unsigned opsz) { sink << op << 's' << ("ds"[opsz == 32]); } };
struct VIPacked { enum { packed = true };  static void disasmOp(std::ostream& sink, char const* op, unsigned opsz) { sink << 'p' << op << DisasmSize(opsz,'i'); } };
struct VBPacked { enum { packed = true };  static void disasmOp(std::ostream& sink, char const* op, unsigned opsz) { sink << 'p' << op; } };

template <class ARCH, class OPERATION, class VR, class VOP, class MODE>
struct VBinaryVVW : public Op3V<ARCH,VR>
{
  typedef VOP valtype;
  enum { opsz = atpinfo<ARCH,VOP>::bitsize };

  valtype eval ( VADD  const&, valtype const& src1, valtype const& src2 ) const { return src1 + src2; }
  valtype eval ( VDIV  const&, valtype const& src1, valtype const& src2 ) const { return src1 / src2; }
  valtype eval ( VMAX  const&, valtype const& src1, valtype const& src2 ) const { return Maximum(src1, src2); }
  valtype eval ( VMIN  const&, valtype const& src1, valtype const& src2 ) const { return Minimum(src1, src2); }
  valtype eval ( VMUL  const&, valtype const& src1, valtype const& src2 ) const { return src1 * src2; }
  valtype eval ( VMULL const&, valtype const& src1, valtype const& src2 ) const { return src1 * src2; }
  valtype eval ( VSUB  const&, valtype const& src1, valtype const& src2 ) const { return src1 - src2; }
  valtype eval ( VAND  const&, valtype const& src1, valtype const& src2 ) const { return src1 & src2; }
  valtype eval ( VANDN const&, valtype const& src1, valtype const& src2 ) const { return ~src1 & src2; }
  valtype eval ( VOR   const&, valtype const& src1, valtype const& src2 ) const { return src1 | src2; }
  valtype eval ( VXOR  const&, valtype const& src1, valtype const& src2 ) const { return src1 ^ src2; }

  VBinaryVVW( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix(); MODE::disasmOp(sink, OPERATION().n(), opsz); disasmVVW(sink << ' '); }

  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = MODE::packed ? VR::size()/opsz : 1; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, eval( OPERATION(), arch.vmm_read( VR(), vn, idx, valtype() ), arch.vmm_read( VR(), rm, idx, valtype() ) ) );
    for (unsigned idx = MODE::packed ? VR::size()/opsz : 1, end = VR::size()/opsz; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, arch.vmm_read( VR(), vn, idx, valtype() ) );
  }
};

/* ADD -- Add Scalar or Packed Single- or Double-Precision Floating-Point Values */
/* MUL -- Multiply Scalar or Packed Single- or Double-Precision Floating-Point Values */
/* SUB -- Substract Scalar or Packed Single- or Double-Precision Floating-Point Values */
/* MIN -- Return Minimum Scalar or Packed Single- or Double-Precision Floating-Point Values */
/* DIV -- Divide Scalar or Packed Single- or Double-Precision Floating-Point Values */
/* MAX -- Return Maximum Scalar or Packed Single- or Double-Precision Floating-Point Values */

template <class ARCH> struct DC<ARCH,VBINARY> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  // Floating Point Operations

  if (auto _ = match( ic, vex( "*\x0f\x58" ) & RM() ))

    return newVFPBinary<VADD>(ic, _.opbase(), _.rmop(), _.greg());

  if (auto _ = match( ic, vex( "*\x0f\x59" ) & RM() ))

    return newVFPBinary<VMUL>(ic, _.opbase(), _.rmop(), _.greg());

  if (auto _ = match( ic, vex( "*\x0f\x5c" ) & RM() ))

    return newVFPBinary<VSUB>(ic, _.opbase(), _.rmop(), _.greg());

  if (auto _ = match( ic, vex( "*\x0f\x5d" ) & RM() ))

    return newVFPBinary<VMIN>(ic, _.opbase(), _.rmop(), _.greg());

  if (auto _ = match( ic, vex( "*\x0f\x5e" ) & RM() ))

    return newVFPBinary<VDIV>(ic, _.opbase(), _.rmop(), _.greg());

  if (auto _ = match( ic, vex( "*\x0f\x5f" ) & RM() ))

    return newVFPBinary<VMAX>(ic, _.opbase(), _.rmop(), _.greg());

  // Floating Point Bitwise Logical Operations

  if (not ic.rep)
    {
      if (auto _ = match( ic, vex( "*\x0f\x54" ) & RM() ))

        return newVFLBinary<VAND>(ic, _.opbase(), _.rmop(), _.greg());

      if (auto _ = match( ic, vex( "*\x0f\x55" ) & RM() ))

        return newVFLBinary<VANDN>(ic, _.opbase(), _.rmop(), _.greg());

      if (auto _ = match( ic, vex( "*\x0f\x56" ) & RM() ))

        return newVFLBinary<VOR>(ic, _.opbase(), _.rmop(), _.greg());

      if (auto _ = match( ic, vex( "*\x0f\x57" ) & RM() ))

        return newVFLBinary<VXOR>(ic, _.opbase(), _.rmop(), _.greg());
    }

  // Integer Operations

  if (auto _ = match( ic, vex( "\x66\x0f\xfc" ) & RM() ))

    return newVBinary<VADD, typename ARCH::u8_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xfd" ) & RM() ))

    return newVBinary<VADD,typename ARCH::u16_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xfe" ) & RM() ))

    return newVBinary<VADD,typename ARCH::u32_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xd4" ) & RM() ))

    return newVBinary<VADD,typename ARCH::u64_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xf8" ) & RM() ))

    return newVBinary<VSUB, typename ARCH::u8_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xf9" ) & RM() ))

    return newVBinary<VSUB,typename ARCH::u16_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xfa" ) & RM() ))

    return newVBinary<VSUB,typename ARCH::u32_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xfb" ) & RM() ))

    return newVBinary<VSUB,typename ARCH::u64_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xd5" ) & RM() ))

    return newVBinary<VMULL,typename ARCH::u16_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x40" ) & RM() ))

    return newVBinary<VMULL,typename ARCH::u32_t, VIPacked>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class OPERATION> Operation<ARCH>* newVFPBinary( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (match( ic, simd__() )) return newVBinary<OPERATION,typename ARCH::f32_t, VFPacked>( ic, opbase, std::move(rm), gn );
  if (match( ic, simd66() )) return newVBinary<OPERATION,typename ARCH::f64_t, VFPacked>( ic, opbase, std::move(rm), gn );
  if (match( ic, simdF3() )) return newVBinary<OPERATION,typename ARCH::f32_t, VFScalar>( ic, opbase, std::move(rm), gn );
  if (match( ic, simdF2() )) return newVBinary<OPERATION,typename ARCH::f64_t, VFScalar>( ic, opbase, std::move(rm), gn );
  return 0;
}
template <class OPERATION> Operation<ARCH>* newVFLBinary( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (match( ic, simd__() )) return newVBinary<OPERATION,typename ARCH::u32_t, VFPacked>( ic, opbase, std::move(rm), gn );
  if (match( ic, simd66() )) return newVBinary<OPERATION,typename ARCH::u64_t, VFPacked>( ic, opbase, std::move(rm), gn );
  return 0;
}
template <class OPERATION, class VOP, class MODE>
Operation<ARCH>* newVBinary( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())               return new VBinaryVVW<ARCH,OPERATION,SSE,VOP,MODE>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  // Vex FP Scalar versions always work with XMM
  if (ic.vlen() == 128 or ic.rep) return new VBinaryVVW<ARCH,OPERATION,XMM,VOP,MODE>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256)           return new VBinaryVVW<ARCH,OPERATION,YMM,VOP,MODE>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

template <class ARCH, class VR, unsigned SOPSZ, unsigned DOPSZ>
struct VFPCvtp : public Operation<ARCH>
{
  typedef typename TypeFor<ARCH,SOPSZ>::f srctype;
  typedef typename TypeFor<ARCH,DOPSZ>::f dsttype;

  VFPCvtp( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, unsigned _gn ) : Operation<ARCH>(opbase), rm(std::move(_rm)), gn(_gn) {}
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "vcvt" : "cvt") << (SOPSZ == 32 ? "ps" : "pd") << '2' << (DOPSZ == 32 ? "ps" : "pd")
         << ' ' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    unsigned const dcount = VR::size()/DOPSZ;
    unsigned const scount = VR::size()/SOPSZ;

    dsttype res[dcount];
    unsigned idx = 0;
    for (unsigned end = std::min(scount,dcount); idx < end; ++idx)
      res[idx] = dsttype( arch.vmm_read( VR(), rm, idx, srctype() ) );
    for (; idx < dcount; ++ idx)
      res[idx] = dsttype(0);
    for (idx = 0; idx < dcount; ++ idx)
      arch.vmm_write( VR(), gn, idx, res[idx] );
  }
  RMOp<ARCH> rm; uint8_t gn;
};

template <class ARCH, class VR, unsigned SOPSZ, unsigned DOPSZ>
struct VFPCvts : public Op3V<ARCH,VR>
{
  typedef typename TypeFor<ARCH,SOPSZ>::f srctype;
  typedef typename TypeFor<ARCH,DOPSZ>::f dsttype;

  VFPCvts( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << "cvt" << (SOPSZ == 32 ? "ss" : "sd") << '2' << (DOPSZ == 32 ? "ss" : "sd") << ' '; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    arch.vmm_write( VR(), gn, 0, dsttype( arch.vmm_read( VR(), rm, 0, srctype() ) ) );
    for (unsigned idx = 1, end = VR::size()/DOPSZ; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, arch.vmm_read( VR(), vn, idx, dsttype() ) );
  }
};

/* FP conversions */

template <class ARCH> struct DC<ARCH,VFPCVT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "*\x0f\x5a" ) & RM() ))
    {
      unsigned gn = _.greg();
      if (not ic.vex())     return newVFPCvt<SSE>( ic, _.opbase(), _.rmop(), gn, gn );
      unsigned vn = ic.vreg();
      if (ic.vlen() == 128) return newVFPCvt<XMM>( ic, _.opbase(), _.rmop(), vn, gn );
      if (ic.vlen() == 256) return newVFPCvt<YMM>( ic, _.opbase(), _.rmop(), vn, gn );
      return 0;
    }

  return 0;
}
template <class VR>
Operation<ARCH>*
newVFPCvt( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn )
{
  if (match( ic, simdF3() )) return new VFPCvts<ARCH,VR,32,64>( opbase, std::move(rm), vn, gn );
  if (match( ic, simdF2() )) return new VFPCvts<ARCH,VR,64,32>( opbase, std::move(rm), vn, gn );
  if (vn and ic.vex()) return 0; // No vreg for packed operation
  if (match( ic, simd__() )) return new VFPCvtp<ARCH,VR,32,64>( opbase, std::move(rm), gn );
  if (match( ic, simd66() )) return new VFPCvtp<ARCH,VR,64,32>( opbase, std::move(rm), gn );
  return 0;
}
};

template <class ARCH, class VR, unsigned OPSZ, class OPERATION>
struct VShImm : public Operation<ARCH>
{
  typedef typename TypeFor<ARCH,OPSZ>::u valtype;
  typedef typename TypeFor<ARCH,OPSZ>::s svaltype;
  valtype eval ( VSLL const&, valtype const& src1, valtype const& src2 ) const { return src1 << src2; }
  valtype eval ( VSRL const&, valtype const& src1, valtype const& src2 ) const { return src1 >> src2; }
  valtype eval ( VSRA const&, valtype const& src1, valtype const& src2 ) const { return (valtype) ((svaltype) src1 >> src2); }

  VShImm( OpBase<ARCH> const& opbase, unsigned _imm, unsigned _en, unsigned _vn ) : Operation<ARCH>(opbase), vn(_vn), en(_en), imm(_imm) {}
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "vp" : "p") << OPERATION().n() << SizeID<OPSZ>::iid()
         <<                ' ' << DisasmI( imm );
    sink <<                ',' << DisasmV( VR(), en );
    if (VR::vex()) sink << ',' << DisasmV( VR(), vn );
  }
  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = VR::size()/OPSZ; idx < end; ++idx)
      arch.vmm_write( VR(), vn, idx, eval( OPERATION(), arch.vmm_read( VR(), en, idx, valtype() ), valtype( imm ) ));
  }
  unsigned vn, en; uint8_t imm;
};


template <class ARCH> struct DC<ARCH,VSHIMM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x71" ) /6 & RM_reg() & Imm<8>() ))

    return newVShImm<VSLL,16>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x72" ) /6 & RM_reg() & Imm<8>() ))

    return newVShImm<VSLL,32>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x73" ) /6 & RM_reg() & Imm<8>() ))

    return newVShImm<VSLL,64>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x71" ) /2 & RM_reg() & Imm<8>() ))

    return newVShImm<VSRL,16>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x72" ) /2 & RM_reg() & Imm<8>() ))

    return newVShImm<VSRL,32>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x73" ) /2 & RM_reg() & Imm<8>() ))

    return newVShImm<VSRL,64>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x71" ) /4 & RM_reg() & Imm<8>() ))

    return newVShImm<VSRA,16>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x72" ) /4 & RM_reg() & Imm<8>() ))

    return newVShImm<VSRA,32>( ic, _.opbase(), _.i( uint8_t() ), _.ereg() );

  return 0;
}
template <class OPERATION, unsigned OPSIZE>
Operation<ARCH>* newVShImm( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, unsigned imm, unsigned en )
{
  if (not ic.vex())     return new VShImm<ARCH,SSE,OPSIZE,OPERATION>( opbase, imm, en, en );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new VShImm<ARCH,XMM,OPSIZE,OPERATION>( opbase, imm, en, vn );
  if (ic.vlen() == 256) return new VShImm<ARCH,YMM,OPSIZE,OPERATION>( opbase, imm, en, vn );
  return 0;
}
};

template <class ARCH, class VR>
struct PMuludq : public Op3V<ARCH,VR>
{
  PMuludq( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << "pmuludq"; disasmVVW(sink << ' '); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u32_t u32;
    typedef typename ARCH::u64_t u64;

    for (unsigned idx = 0, end = VR::size()/64; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx,
		      u64(
			    u64(u32(arch.vmm_read( VR(), vn, idx, u64() ))) *
			    u64(u32(arch.vmm_read( VR(), rm, idx, u64() )))
			    ) );
  }
};


template <class ARCH> struct DC<ARCH,PMULUDQ> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\xf4" ) & RM() ))

    return newPMuludq( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
Operation<ARCH>* newPMuludq( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())     return new PMuludq<ARCH,SSE>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new PMuludq<ARCH,XMM>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new PMuludq<ARCH,YMM>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

template <class ARCH, class VR, class SOP, class DOP>
struct Vmovzx : public Operation<ARCH>
{
  typedef typename TypeFor<ARCH,SOP::SIZE>::u src_type;
  typedef typename TypeFor<ARCH,DOP::SIZE>::u dst_type;

  Vmovzx( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, unsigned _gn ) : Operation<ARCH>(opbase), rm(std::move(_rm)), gn(_gn) {}
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "vp" : "p") << "movzx"
         << SizeID<SOP::SIZE>::iid() << SizeID<DOP::SIZE>::iid()
         <<                ' ' << DisasmW( VR(), rm )
         <<                ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    src_type src[VR::size()/DOP::SIZE];
    for (unsigned idx = 0, end = VR::size()/DOP::SIZE; idx < end; ++idx)
      src[idx] = arch.vmm_read( VR(), rm, idx, src_type() );
    for (unsigned idx = 0, end = VR::size()/DOP::SIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, dst_type( src[idx] ) );
  }
  RMOp<ARCH> rm; uint8_t gn;
};


template <class ARCH> struct DC<ARCH,VMOVZX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x30" ) & RM() ))

    return newVmovzx<GOb, GOw>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x31" ) & RM() ))

    return newVmovzx<GOb, GOd>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x32" ) & RM() ))

    return newVmovzx<GOb, GOq>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x33" ) & RM() ))

    return newVmovzx<GOw, GOd>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x34" ) & RM() ))

    return newVmovzx<GOw, GOq>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x35" ) & RM() ))

    return newVmovzx<GOd, GOq>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}

  template <class SOP, class DOP>
Operation<ARCH>* newVmovzx( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())     return new Vmovzx<ARCH,SSE,SOP,DOP>( opbase, std::move(rm), gn );

  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return new Vmovzx<ARCH,XMM,SOP,DOP>( opbase, std::move(rm), gn );
  if (ic.vlen() == 256) return new Vmovzx<ARCH,YMM,SOP,DOP>( opbase, std::move(rm), gn );
  return 0;
}
};

// /* PABSB/PABSW/PABSD -- Packed Absolute Value */
// op pabsb_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x1c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsb_pq_qq.disasm = { _sink << "pabsb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pabsw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x1d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsw_pq_qq.disasm = { _sink << "pabsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pabsd_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x1e[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsd_pq_qq.disasm = { _sink << "pabsd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pabsb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x1c[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsb_vdq_wdq.disasm = { _sink << "pabsb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pabsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x1d[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsw_vdq_wdq.disasm = { _sink << "pabsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pabsd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x1e[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pabsd_vdq_wdq.disasm = { _sink << "pabsd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PACKSSWB/PACKSSDW -- Pack with Signed Saturation */
// op packsswb_pq_qq( 0x0f[8]:> <:0x63[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packsswb_pq_qq.disasm = { _sink << "packsswb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op packssdw_pq_qq( 0x0f[8]:> <:0x6b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packssdw_pq_qq.disasm = { _sink << "packssdw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op packsswb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x63[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packsswb_vdq_wdq.disasm = { _sink << "packsswb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op packssdw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x6b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packssdw_vdq_wdq.disasm = { _sink << "packssdw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PACKUSWB/PACKUSDW -- Pack with Unsigned Saturation */
// op packuswb_pq_qq( 0x0f[8]:> <:0x67[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packuswb_pq_qq.disasm = { _sink << "packuswb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op packuswb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x67[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packuswb_vdq_wdq.disasm = { _sink << "packuswb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op packusdw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x2b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// packusdw_vdq_wdq.disasm = { _sink << "packusdw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//


template <class ARCH, class VR, class OP, bool SIGN>
struct Pack_S : public Op3V<ARCH,VR>
{
  typedef typename TypeFor<ARCH,OP::SIZE>::s src_type;
  typedef typename TypeFor<ARCH,OP::SIZE/2>::s dst_type;

  const src_type lbound = SIGN
    ? src_type( - ( 1L << (OP::SIZE / 2 - 1) ) )
    : src_type( 0 );
  const src_type hbound = SIGN
    ? src_type( 1L << (OP::SIZE / 2 - 1) )
    : src_type( 1L << (OP::SIZE / 2) );

  dst_type mask ( typename ARCH::bit_t cond ) const
  {
    return dst_type( !cond ) - dst_type( 1 );
  }

  dst_type saturate ( src_type x ) const
  {
    return (mask( lbound > x ) & dst_type( lbound )) | (mask( x >= hbound ) & dst_type( hbound - src_type( 1 ) )) | (mask( lbound <= x && x < hbound ) & dst_type( x ));
  }

  Pack_S( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, unsigned gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << "pack" << (SIGN ? 's' : 'u') << 's' << SizeID<OP::SIZE>::iid() << SizeID<OP::SIZE/2>::iid() << ' '; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    src_type src[VR::size()/(OP::SIZE/2)];
    for (unsigned idx = 0, end = VR::size()/OP::SIZE; idx < end; ++idx)
      src[idx] = arch.vmm_read( VR(), vn, idx, src_type() );
    for (unsigned idx = 0, end = VR::size()/OP::SIZE; idx < end; ++idx)
      src[VR::size()/OP::SIZE+idx] = arch.vmm_read( VR(), rm, idx, src_type() );
    for (unsigned idx = 0, end = VR::size()/(OP::SIZE/2); idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, saturate( src[idx] ) );
  }
};


template <class ARCH> struct DC<ARCH,PACK_S> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x63" ) & RM() ))

    return newPack_S<GOw, true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6b" ) & RM() ))

    return newPack_S<GOd, true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x67" ) & RM() ))

    return newPack_S<GOw, false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x2b" ) & RM() ))

    return newPack_S<GOd, false>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}

  template <class OP, bool SIGN>
Operation<ARCH>* newPack_S( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())     return new Pack_S<ARCH,SSE,OP,SIGN>( opbase, std::move(rm), gn, gn );

  uint8_t vn = ic.vreg();
  if (ic.vlen() == 128) return new Pack_S<ARCH,XMM,OP,SIGN>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new Pack_S<ARCH,YMM,OP,SIGN>( opbase, std::move(rm), vn, gn );
  return 0;
}
};



// /* PADDB/PADDW/PADDD/PADDQ -- Add Packed Integers */
// op paddb_pq_qq( 0x0f[8]:> <:0xfc[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddb_pq_qq.disasm = { _sink << "paddb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddw_pq_qq( 0x0f[8]:> <:0xfd[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddw_pq_qq.disasm = { _sink << "paddw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddd_pq_qq( 0x0f[8]:> <:0xfe[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddd_pq_qq.disasm = { _sink << "paddd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddq_pq_qq( 0x0f[8]:> <:0xd4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddq_pq_qq.disasm = { _sink << "paddq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xfc[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddb_vdq_wdq.disasm = { _sink << "paddb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op paddw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xfd[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddw_vdq_wdq.disasm = { _sink << "paddw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op paddd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xfe[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddd_vdq_wdq.disasm = { _sink << "paddd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op paddq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddq_vdq_wdq.disasm = { _sink << "paddq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PADDSB/PADDSW -- Add Packed Signed Integers with Signed Saturation */
// op paddsb_pq_qq( 0x0f[8]:> <:0xec[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddsb_pq_qq.disasm = { _sink << "paddsb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddsw_pq_qq( 0x0f[8]:> <:0xed[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddsw_pq_qq.disasm = { _sink << "paddsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddsb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xec[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddsb_vdq_wdq.disasm = { _sink << "paddsb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op paddsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xed[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddsw_vdq_wdq.disasm = { _sink << "paddsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PADDUSB/PADDUSW -- Add Packed Unsigned Integers with Unsigned Saturation */
// op paddusb_pq_qq( 0x0f[8]:> <:0xdc[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddusb_pq_qq.disasm = { _sink << "paddusb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddusw_pq_qq( 0x0f[8]:> <:0xdd[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddusw_pq_qq.disasm = { _sink << "paddusw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op paddusb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xdc[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddusb_vdq_wdq.disasm = { _sink << "paddusb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op paddusw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xdd[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// paddusw_vdq_wdq.disasm = { _sink << "paddusw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PAVG -- Average Packed Integers */
// op pavgb_pq_qq( 0x0f[8]:> <:0xe0[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pavgb_pq_qq.disasm = { _sink << "pavgb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pavgw_pq_qq( 0x0f[8]:> <:0xe3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pavgw_pq_qq.disasm = { _sink << "pavgw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pavgb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe0[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pavgb_vdq_wdq.disasm = { _sink << "pavgb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pavgw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pavgw_vdq_wdq.disasm = { _sink << "pavgw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PBLENDVB -- Variable Blend Packed Bytes */
// op pblenvb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x10[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pblenvb_vdq_wdq.disasm = { _sink << "pblenvb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PBLENDW -- Blend Packed Words */
// op pblendw_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x0e[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pblendw_vdq_wdq_ib.disasm = { _sink << "pblendw " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PCLMULQDQ - Carry-Less Multiplication Quadword */
// op pclmulqdq_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x44[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pclmulqdq_vdq_wdq_ib.disasm = { _sink << "pclmulqdq " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };

namespace PCmpStrUtil
{
  template <typename ARCH, unsigned COUNT>
  void explicit_validity( typename ARCH::bit_t(&result)[COUNT], ARCH& arch, unsigned reg )
  {
    typename ARCH::gr_type count = arch.regread( typename ARCH::GR(), reg );
    if (arch.Test(count < typename ARCH::gr_type(0))) count = -count;
    for (unsigned idx = 0; idx < COUNT; ++idx)
      result[idx] = typename ARCH::gr_type(idx) < count;
  }
}

template <class ARCH, class VR, class TYPE>
struct PCmpStr : public Operation<ARCH>
{
  enum { is_signed = atpinfo<ARCH,TYPE>::is_signed, bitsize = atpinfo<ARCH,TYPE>::bitsize, count = VR::SIZE / bitsize };

  PCmpStr( OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn, uint8_t _im, bool _implicit, bool _index )
    : Operation<ARCH>( opbase ), rm(std::move(_rm)), gn(_gn), im(_im), implicit(_implicit), index(_index)
  {}

  RMOp<ARCH> rm;
  uint8_t    gn;
  uint8_t    im;
  bool       implicit;
  bool       index;

  enum Cmp { EqualAny = 0, Ranges = 0b01, EqualEach = 0b10, EqualOrdered = 0b11 }; Cmp comparison() const { return Cmp((im >> 2) & 3); }
  enum Neg { NegateNothing = 0, NegateAll = 0b01, NegateValid = 0b11 };            Neg negation()   const { return Neg((im&0x20) ? NegateValid : (im&0x10) ? NegateAll : NegateNothing); }
  enum Res { BitMask = 0, CharMask = 0b01, MaskLSB = 0b10, MaskMSB = 0b11 };       Res result()     const { return Res((index << 1) | ((im >> 6) & 1)); }

  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << "pcmp" << (implicit ? 'i' : 'e') << "str" << (index ? 'i' : 'm') << ' ' << DisasmI(im) << ',' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::bit_t bit_t;
    TYPE const null_char(0);
    bit_t gnv[count], rmv[count], intres[count];
    if (implicit)
      {
        bit_t rmv_b(true), gnv_b(true);
        for (unsigned idx = 0; idx < count; ++idx)
          {
            gnv_b = gnv[idx] = gnv_b and (arch.vmm_read( VR(), gn, idx, null_char ) != null_char);
            rmv_b = rmv[idx] = rmv_b and (arch.vmm_read( VR(), rm, idx, null_char ) != null_char);
          }
	arch.flagwrite( ARCH::FLAG::ZF, not rmv_b );
	arch.flagwrite( ARCH::FLAG::SF, not gnv_b );
      }
    else
      {
        PCmpStrUtil::explicit_validity( gnv, arch, 0 );
        PCmpStrUtil::explicit_validity( rmv, arch, 2 );
	// TODO set flags!
      }

    switch (comparison())
      {
      case EqualAny: // find characters from a set
        for (unsigned rmi = 0; rmi < count; ++rmi)
          {
            bit_t res( false );
            TYPE rmval = arch.vmm_read( VR(), rm, rmi, null_char );
            for (unsigned gni = 0; gni < count; ++gni)
              res = res or ((arch.vmm_read( VR(), gn, gni, null_char ) == rmval) and gnv[gni]);
            intres[rmi] = res and rmv[rmi];
          }
        break;

      case Ranges: // find characters from ranges
        for (unsigned rmi = 0; rmi < count; ++rmi) // Reg/Mem
          {
            bit_t res( false );
            TYPE rmval = arch.vmm_read( VR(), rm, rmi, null_char );
            for (unsigned gni = 0; gni < count; gni += 2) // Reg
              {
                bit_t lower = (arch.vmm_read( VR(), gn, gni+0, null_char ) >= rmval);
                bit_t upper = (arch.vmm_read( VR(), gn, gni+1, null_char ) <= rmval);
                res = res or (lower and gnv[gni+0] and upper and gnv[gni+1]);
              }
            intres[rmi] = res and rmv[rmi];
          }
        break;

      case EqualEach: // string compare
        for (unsigned idx = 0; idx < count; ++idx) // Reg/Mem
          intres[idx] = ((arch.vmm_read( VR(), gn, idx, null_char ) == arch.vmm_read( VR(), rm, idx, null_char )) and gnv[idx] and rmv[idx]) or (not gnv[idx] and not rmv[idx]);
        break;

      case EqualOrdered: // substring search
        for (unsigned idx = 0; idx < count; ++idx)
          {
            bit_t res( true );
            for (unsigned rmi = idx, gni = 0; rmi < count; ++rmi, ++gni)
              res = res and (((arch.vmm_read( VR(), gn, gni, null_char ) == arch.vmm_read( VR(), rm, rmi, null_char )) and gnv[gni] and rmv[rmi]) or (not gnv[idx] and not rmv[idx]));
            intres[idx] = res;
          }
        break;
      }

    switch (negation())
      {
      case NegateAll:   for (unsigned idx = 0; idx < count; ++idx) intres[idx] = not intres[idx]; break;
      case NegateValid: for (unsigned idx = 0; idx < count; ++idx) intres[idx] = intres[idx] xor rmv[idx]; break;
      case NegateNothing: break;
      }

    switch (result())
      {
      case BitMask:
        {
          typedef typename TypeFor<ARCH,count>::u bf_type;
          bf_type bf(0);
          for (unsigned idx = 0; idx < count; ++idx)
            bf |= bf_type(intres[idx]) << idx;
          arch.vmm_write( VR(), 0, 0, bf );
          for (unsigned idx = 1; idx < bitsize; ++idx)
            arch.vmm_write( VR(), 0, 0, bf_type(0) );
        }
        break;
      case CharMask:
        for (unsigned idx = 0; idx < count; ++idx)
          arch.vmm_write( VR(), 0, idx, TYPE(TYPE(not intres[idx]) - TYPE(1)) );
        break;
      case MaskLSB:
	{
	  typedef typename ARCH::gr_type res_t;
	  res_t res(0);
	  bit_t mask( true );
	  for (unsigned idx = 0; idx < count; ++idx) {
	    mask = mask and (not intres[idx]);
	    res += res_t(mask);
	  }
	  arch.regwrite( typename ARCH::GR(), 1, res );
	}
        break;
      case MaskMSB:
	{
	  typedef typename ARCH::gr_type res_t;
	  res_t res(0);
	  bit_t mask( false );
	  for (int idx = count; --idx >= 0;) {
	    mask = mask or intres[idx];
	    res += res_t(mask);
	  }
	  res = (res_t(count) & (res_t(res != res_t(0)) - res_t(1))) | res;
	  arch.regwrite( typename ARCH::GR(), 1, res );
	}
        break;
      }
    bit_t cf( false );
    for (unsigned idx = 0; idx < count; ++idx) {
      cf = cf or intres[idx];
    }
    arch.flagwrite( ARCH::FLAG::CF, cf );
    arch.flagwrite( ARCH::FLAG::OF, intres[0] );
    arch.flagwrite( ARCH::FLAG::AF, bit_t( false ) );
    arch.flagwrite( ARCH::FLAG::PF, bit_t( false ) );
  }
};

// /* PCMPESTRM -- Packed Compare Explicit Length Strings, Return Mask */
// /* PCMPESTRI -- Packed Compare Explicit Length Strings, Return Index */
// /* PCMPISTRM -- Packed Compare Implicit Length Strings, Return Mask */
// /* PCMPISTRI -- Packed Compare Implicit Length Strings, Return Index */

template <class ARCH> struct DC<ARCH,PCMPSTR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x60" ) & RM() & Imm<8>() ))

    return newPCmpStr( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()), false, false );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x61" ) & RM() & Imm<8>() ))

    return newPCmpStr( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()), false, true );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x62" ) & RM() & Imm<8>() ))

    return newPCmpStr( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()),  true, false );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x63" ) & RM() & Imm<8>() ))

    return newPCmpStr( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()),  true, true );

  return 0;
}
Operation<ARCH>* newPCmpStr( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn, uint8_t im, bool implicit, bool index )
{
  if (not ic.vex())     return newPCmpStr<SSE>( opbase, std::move(rm), gn, im, implicit, index );
  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return newPCmpStr<XMM>( opbase, std::move(rm), gn, im, implicit, index );
  return 0;
}
template <class VR>
Operation<ARCH>* newPCmpStr( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn, uint8_t im, bool implicit, bool index )
{
  switch (im&3)
    {
    case 0b00: return new PCmpStr<ARCH,VR,typename ARCH:: u8_t>( opbase, std::move(rm), gn, im, implicit, index );
    case 0b01: return new PCmpStr<ARCH,VR,typename ARCH::u16_t>( opbase, std::move(rm), gn, im, implicit, index );
    case 0b10: return new PCmpStr<ARCH,VR,typename ARCH:: s8_t>( opbase, std::move(rm), gn, im, implicit, index );
    case 0b11: return new PCmpStr<ARCH,VR,typename ARCH::s16_t>( opbase, std::move(rm), gn, im, implicit, index );
    }
  return 0;
}
};

struct PCmpEQ { static char const* name() { return "pcmpeq"; } };
struct PCmpGT { static char const* name() { return "pcmpgt"; } };

template <class ARCH, class VR, class TYPE, class OPERATION>
struct PCmpVW : public Op3V<ARCH,VR>
{
  typedef TYPE valtype;
  enum { bitsize = atpinfo<ARCH,TYPE>::bitsize };
  valtype eval( PCmpEQ const&, valtype const& a, valtype const& b ) const { return valtype(a != b) - valtype(1); }
  valtype eval( PCmpGT const&, valtype const& a, valtype const& b ) const { return valtype(a <= b) - valtype(1); }

  PCmpVW( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn ) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << OPERATION::name() << SizeID<bitsize>::iid() << ' '; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    for (unsigned sub = 0; sub < (VR::size()/bitsize); ++sub)
      arch.vmm_write( VR(), gn, sub, eval( OPERATION(), arch.vmm_read( VR(), vn, sub, valtype() ), arch.vmm_read( VR(), rm, sub, valtype() ) ) );
  }
};

/* PCMPGTB/PCMPGTW/PCMPGTD/PCMPGTQ -- Compare Packed Signed Integers for Greater Than */
/* PCMPEQB/PCMPEQW/PCMPEQD/PCMPEQQ -- Compare Packed Data for Equal */

template <class ARCH> struct DC<ARCH,PCMPEQ> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x74" ) & RM() ))

    return newPCmp<PCmpEQ,  typename ARCH::u8_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x75" ) & RM() ))

    return newPCmp<PCmpEQ, typename ARCH::u16_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x76" ) & RM() ))

    return newPCmp<PCmpEQ, typename ARCH::u32_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x29" ) & RM() ))

    return newPCmp<PCmpEQ, typename ARCH::u64_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x64" ) & RM() ))

    return newPCmp<PCmpGT,  typename ARCH::s8_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x65" ) & RM() ))

    return newPCmp<PCmpGT, typename ARCH::s16_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x66" ) & RM() ))

    return newPCmp<PCmpGT, typename ARCH::s32_t>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x37" ) & RM() ))

    return newPCmp<PCmpGT, typename ARCH::s64_t>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class OPERATION, class TYPE>
Operation<ARCH>* newPCmp( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())     return new PCmpVW<ARCH,SSE,TYPE,OPERATION>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new PCmpVW<ARCH,XMM,TYPE,OPERATION>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new PCmpVW<ARCH,YMM,TYPE,OPERATION>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

// op pcmpeqb_pq_qq( 0x0f[8]:> <:0x74[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpeqb_pq_qq.disasm = { _sink << "pcmpeqb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pcmpeqw_pq_qq( 0x0f[8]:> <:0x75[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpeqw_pq_qq.disasm = { _sink << "pcmpeqw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pcmpeqd_pq_qq( 0x0f[8]:> <:0x76[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpeqd_pq_qq.disasm = { _sink << "pcmpeqd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pcmpgtb_pq_qq( 0x0f[8]:> <:0x64[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpgtb_pq_qq.disasm = { _sink << "pcmpgtb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pcmpgtw_pq_qq( 0x0f[8]:> <:0x65[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpgtw_pq_qq.disasm = { _sink << "pcmpgtw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pcmpgtd_pq_qq( 0x0f[8]:> <:0x66[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pcmpgtd_pq_qq.disasm = { _sink << "pcmpgtd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };

// /* PEXTRB/PEXTRW/PEXTRD/PEXTRQ -- Extract Byte/Dword/Qword */
// op pextrw_rd_pq_ib( 0x0f[8]:> <:0xc5[8]:> <:0b11[2]:gn[3]:rm[3]:> <:imm[8] );
//
// pextrw_rd_pq_ib.disasm = { _sink << "pextrw " << DisasmI( imm ) << ',' << DisasmPq( rm ) << ',' << DisasmGd( gn ); };
//
// op pextrw_rd_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0xc5[8]:> <:0b11[2]:gn[3]:rm[3]:> <:imm[8] );
//
// pextrw_rd_vdq_ib.disasm = { _sink << "pextrw " << DisasmI( imm ) << ',' << DisasmV( SSE(), rm ) << ',' << DisasmGd( gn ); };
//
// op pextrb_eb_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x14[8]:> <:?[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pextrb_eb_vdq_ib.disasm = { _sink << "pextrw " << DisasmI( imm ) << ',' << DisasmV( SSE(), gn ) << ',' << DisasmEb( rm ); };
//
// op pextrw_ew_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x15[8]:> <:?[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pextrw_ew_vdq_ib.disasm = { _sink << "pextrw " << DisasmI( imm ) << ',' << DisasmV( SSE(), gn ) << ',' << DisasmEw( rm ); };
//
// op pextrd_ed_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x16[8]:> <:?[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pextrd_ed_vdq_ib.disasm = { _sink << "pextrd " << DisasmI( imm ) << ',' << DisasmV( SSE(), gn ) << ',' << DisasmEd( rm ); };
//
// // op pextrq_eb_vdq_ib( 0x66[8]:> <:0x48[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x16[8]:> <:?[2]:gn[3]:rm[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// // pextrq_eb_vdq_ib.disasm = { _sink << "pextrq " << DisasmI( imm ) << ',' << DisasmV( SSE(), gn ) << ',' << DisasmEq( rm ); };
//
// /* PHADDW/PHADDD -- Packed Horizontal Add */
// op phaddw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x01[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddw_pq_qq.disasm = { _sink << "phaddw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phaddd_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x02[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddd_pq_qq.disasm = { _sink << "phaddd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phaddw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x01[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddw_vdq_wdq.disasm = { _sink << "phaddw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op phaddd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x02[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddd_vdq_wdq.disasm = { _sink << "phaddd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PHADDSW -- Packed Horizontal Add and Saturate */
// op phaddsw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x03[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddsw_pq_qq.disasm = { _sink << "phaddsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phaddsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x03[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phaddsw_vdq_wdq.disasm = { _sink << "phaddsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PHMINPOSUW -- Packed Horizontal Word Minimum */
// op phminposuw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x41[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phminposuw_vdq_wdq.disasm = { _sink << "phminposuw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
//
// /* PHSUBW/PHSUBD -- Packed Horizontal Subtract */
// op phsubw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x05[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubw_pq_qq.disasm = { _sink << "phsubw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phsubd_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x06[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubd_pq_qq.disasm = { _sink << "phsubd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phsubw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x05[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubw_vdq_wdq.disasm = { _sink << "phsubw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op phsubd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x06[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubd_vdq_wdq.disasm = { _sink << "phsubd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PHSUBSW -- Packed Horizontal Subtract and Saturate */
// op phsubsw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x07[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubsw_pq_qq.disasm = { _sink << "phsubsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op phsubsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x07[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// phsubsw_vdq_wdq.disasm = { _sink << "phsubsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMADDUBSW --  */
// op pmaddubsw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x04[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmaddubsw_pq_qq.disasm = { _sink << "pmaddubsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmaddubsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x04[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmaddubsw_vdq_wdq.disasm = { _sink << "pmaddubsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMADDWD -- Multiply and Add Packed Integers */
// op pmaddwd_pq_qq( 0x0f[8]:> <:0xf5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmaddwd_pq_qq.disasm = { _sink << "pmaddwd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmaddwd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmaddwd_vdq_wdq.disasm = { _sink << "pmaddwd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//

template <class ARCH, class VR, class GR>
struct PInsr : public Op3V<ARCH,VR>
{
  PInsr( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn, uint8_t _im ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn), im(_im) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVV;

  void disasm( std::ostream& sink ) const
  {
    sink << vprefix() << "pinsr" << SizeID<GR::SIZE>::iid() << ' ' << DisasmI( im ) << ',';
    if (GR::SIZE < 32)
      sink << DisasmE( GOd(), rm );
    else
      sink << DisasmE( GR(), rm );
    disasmVV(sink);
  }
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GR::SIZE>::u u_type;
    for (unsigned idx = 0, end = VR::size() / GR::SIZE; idx < end; ++idx )
      {
        if (((idx ^ im) % end) == 0)
          arch.vmm_write( VR(), gn, idx, arch.rmread( GR(), rm ) );
        else if (gn != vn)
          arch.vmm_write( VR(), gn, idx, arch.vmm_read( VR(), vn, idx, u_type() ) );
      }
  }
  uint8_t im;
};

// /* PINSRB/PINSRW/PINSRD/PINSRQ -- Insert Byte/Word/Dword/Qword */
// op pinsrw_pq_ed_ib( 0x0f[8]:> <:0xc4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
// op pinsrb_vdq_ed_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x20[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
// op pinsrw_vdq_ed_ib( 0x66[8]:> <:0x0f[8]:> <:0xc4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
// op pinsrd_vdq_ed_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x22[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );

template <class ARCH> struct DC<ARCH,PINSR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\xc4" ) & RM() & Imm<8>() ))

    return newPInsr<GOw>( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x20" ) & RM() & Imm<8>() ))

    return newPInsr<GOb>( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x22" ) & RM() & Imm<8>() ))
    {
      if (ic.w()) return newPInsr<GOq>( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );
      /* else */  return newPInsr<GOd>( ic, _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );
    }

  return 0;
}
template <class GR>
Operation<ARCH>* newPInsr( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn, uint8_t im )
{
  if (not ic.vex())     return new PInsr<ARCH,SSE,GR>( opbase, std::move(rm), gn, gn, im );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new PInsr<ARCH,XMM,GR>( opbase, std::move(rm), vn, gn, im );
  return 0;
}
};

struct PMax { static char const* name() { return "pmax"; } };
struct PMin { static char const* name() { return "pmin"; } };

template <class ARCH, class VR, class VOP, class OPERATION>
struct PMinMax : public Op3V<ARCH, VR>
{
  typedef VOP valtype;
  enum { is_signed = atpinfo<ARCH,VOP>::is_signed, bitsize = atpinfo<ARCH,VOP>::bitsize };
  valtype eval( PMax const&, valtype const& a, valtype const& b ) const { return Maximum(a, b); }
  valtype eval( PMin const&, valtype const& a, valtype const& b ) const { return Minimum(a, b); }

  PMinMax( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn ) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << OPERATION::name() << (is_signed ? "s" : "u") << SizeID<bitsize>::iid() << ' '; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    for (unsigned idx = 0, end = VR::size()/bitsize; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, eval( OPERATION(), arch.vmm_read( VR(), vn, idx, valtype() ), arch.vmm_read( VR(), rm, idx, valtype() ) ) );
  }
};

// op pmaxsw_pq_qq( 0x0f[8]:> <:0xee[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// op pmaxub_pq_qq( 0x0f[8]:> <:0xde[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// op pminsw_pq_qq( 0x0f[8]:> <:0xea[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// op pminub_pq_qq( 0x0f[8]:> <:0xda[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );

// /* P{MAX|MIN}[US][BWD],  -- Maximum/Minimum of Packed Unsigned/Signed Byte/Word/DWord Integers */

template <class ARCH> struct DC<ARCH,PMINMAX> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3c" ) & RM() ))

    return newMinMax<typename ARCH::s8_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xee" ) & RM() ))

    return newMinMax<typename ARCH::s16_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3d" ) & RM() ))

    return newMinMax<typename ARCH::s32_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xde" ) & RM() ))

    return newMinMax<typename ARCH::u8_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3e" ) & RM() ))

    return newMinMax<typename ARCH::u16_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3f" ) & RM() ))

    return newMinMax<typename ARCH::u32_t,PMax>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x38" ) & RM() ))

    return newMinMax<typename ARCH::s8_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xea" ) & RM() ))

    return newMinMax<typename ARCH::s16_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x39" ) & RM() ))

    return newMinMax<typename ARCH::s32_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xda" ) & RM() ))

    return newMinMax<typename ARCH::u8_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3a" ) & RM() ))

    return newMinMax<typename ARCH::u16_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x3b" ) & RM() ))

    return newMinMax<typename ARCH::u32_t,PMin>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class VOP, class OPERATION>
Operation<ARCH>* newMinMax( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())     return new PMinMax<ARCH,SSE,VOP,OPERATION>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new PMinMax<ARCH,XMM,VOP,OPERATION>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new PMinMax<ARCH,YMM,VOP,OPERATION>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

// /* PMOVMSKB -- Move Byte Mask */
template <class ARCH>
struct PMovMskBRP : public Operation<ARCH>
{
  PMovMskBRP( OpBase<ARCH> const& opbase, uint8_t _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} uint8_t rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << "pmovmskb " << DisasmPq( rm ) << ',' << DisasmG( GOd(), gn ); }
};

template <class ARCH, class VR>
struct PMovMskBRV : public Operation<ARCH>
{
  PMovMskBRV( OpBase<ARCH> const& opbase, uint8_t _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ) {} uint8_t rm; uint8_t gn;
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << "pmovmskb " << DisasmV( VR(), rm ) << ',' << DisasmG( GOd(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u32_t u32_t;
    typedef typename ARCH::u8_t  u8_t;

    u32_t res = u32_t(0);

    for (unsigned sub = 0, end = VR::size() / 8; sub < end; ++sub)
      res |= u32_t(arch.vmm_read( VR(), rm, sub, u8_t() ) >> 7) << sub;

    arch.regwrite( GOd(), gn, res );
  }
};

template <class ARCH> struct DC<ARCH,PMOVMSKB> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, simd__() & opcode( "\x0f\xd7" ) & RM_reg() ))

    return new PMovMskBRP<ARCH>( _.opbase(), _.ereg(), _.greg() );

  if (auto _ = match( ic, vex("\x66\x0f\xd7" ) & RM_reg() ))

    return newPMovMsk( ic, _.opbase(), _.ereg(), _.greg() );

  return 0;
}
Operation<ARCH>* newPMovMsk( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, uint8_t rn, uint8_t gn )
{
  if (not ic.vex())     return new PMovMskBRV<ARCH,SSE>( opbase, rn, gn );
  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return new PMovMskBRV<ARCH,XMM>( opbase, rn, gn );
  if (ic.vlen() == 256) return new PMovMskBRV<ARCH,YMM>( opbase, rn, gn );
  return 0;
}
};

//
// /* PMOVSX -- Packed Move with Sign Extend */
// op pmovsxbw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x20[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxbw_vdq_wdq.disasm = { _sink << "pmovsxbw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovsxbd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x21[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxbd_vdq_wdq.disasm = { _sink << "pmovsxbd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovsxbq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x22[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxbq_vdq_wdq.disasm = { _sink << "pmovsxbq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovsxwd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x23[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxwd_vdq_wdq.disasm = { _sink << "pmovsxwd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovsxwq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x24[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxwq_vdq_wdq.disasm = { _sink << "pmovsxwq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovsxdq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x25[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovsxdq_vdq_wdq.disasm = { _sink << "pmovsxdq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMOVZX -- Packed Move with Sign Extend */
// op pmovzxbw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x30[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxbw_vdq_wdq.disasm = { _sink << "pmovzxbw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovzxbd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x31[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxbd_vdq_wdq.disasm = { _sink << "pmovzxbd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovzxbq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x32[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxbq_vdq_wdq.disasm = { _sink << "pmovzxbq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovzxwd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x33[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxwd_vdq_wdq.disasm = { _sink << "pmovzxwd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovzxwq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x34[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxwq_vdq_wdq.disasm = { _sink << "pmovzxwq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pmovzxdq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x35[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmovzxdq_vdq_wdq.disasm = { _sink << "pmovzxdq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULDQ -- Multiply Packed Signed Dword Integers */
// op pmuldq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x28[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmuldq_vdq_wdq.disasm = { _sink << "pmuldq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULHRSW -- Packed Multiply High with Round and Scale */
// op pmulhrsw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x0b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhrsw_pq_qq.disasm = { _sink << "pmulhrsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmulhrsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x0b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhrsw_vdq_wdq.disasm = { _sink << "pmulhrsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULHUW -- Multiply Packed Unsigned Integers and Store High Result */
// op pmulhuw_pq_qq( 0x0f[8]:> <:0xe4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhuw_pq_qq.disasm = { _sink << "pmulhuw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmulhuw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhuw_vdq_wdq.disasm = { _sink << "pmulhuw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULHW -- Multiply Packed Signed Integers and Store High Result */
// op pmulhw_pq_qq( 0x0f[8]:> <:0xe5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhw_pq_qq.disasm = { _sink << "pmulhw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmulhw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulhw_vdq_wdq.disasm = { _sink << "pmulhw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULLD -- Multiply Packed Signed Dword Integers and Store Low Result */
// op pmulld_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x40[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmulld_vdq_wdq.disasm = { _sink << "pmulld " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULLW -- Multiply Packed Signed Integers and Store Low Result */
// op pmullw_pq_qq( 0x0f[8]:> <:0xd5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmullw_pq_qq.disasm = { _sink << "pmullw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmullw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd5[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmullw_vdq_wdq.disasm = { _sink << "pmullw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PMULUDQ -- Multiply Packed Unsigned Doubleword Integers */
// op pmuludq_pq_qq( 0x0f[8]:> <:0xf4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmuludq_pq_qq.disasm = { _sink << "pmuludq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pmuludq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf4[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pmuludq_vdq_wdq.disasm = { _sink << "pmuludq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSADBW -- Compute Sum of Absolute Differences */
// op psadbw_pq_qq( 0x0f[8]:> <:0xf6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psadbw_pq_qq.disasm = { _sink << "psadbw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psadbw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psadbw_vdq_wdq.disasm = { _sink << "psadbw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//

template <class ARCH, class VR>
struct Pshufd : public Operation<ARCH>
{
  Pshufd( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn, uint8_t _oo ) : Operation<ARCH>(opbase), rm(_rm), gn(_gn), oo(_oo) {} RMOp<ARCH> rm; uint8_t gn, oo;
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << "pshufd " << DisasmI(oo) << ',' << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u32_t u32_t;


    for (unsigned chunk = 0, cend = VR::size() / 128; chunk < cend; ++ chunk)
      {
        for (unsigned idx = 0, end = 128 / 32; idx < end; ++idx)
          {
            unsigned part = (oo >> 2*idx) % 4;
            arch.vmm_write( VR(), gn, idx + chunk*end, arch.vmm_read( VR(), rm, part + chunk*end, u32_t() ) );
          }
      }
  }
};

/* PSHUFD -- Shuffle Packed Doublewords */
template <class ARCH> struct DC<ARCH,PSHUFD> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x70" ) & RM() & Imm<8>() ))
    {
      if (not ic.vex())     return new Pshufd<ARCH,SSE>( _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );
      if (ic.vreg()) return 0;
      if (ic.vlen() == 128) return new Pshufd<ARCH,XMM>( _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );
      if (ic.vlen() == 256) return new Pshufd<ARCH,YMM>( _.opbase(), _.rmop(), _.greg(), _.i(uint8_t()) );
    }

  return 0;
}};

template <class ARCH, class VR>
struct Pshufb : public Op3V<ARCH, VR>
{
  Pshufb( OpBase<ARCH> const& opbase, MOp<ARCH> const* rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,VR>(opbase, rm, vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << "pshufb "; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u8_t u8_t;
    typedef typename ARCH::s8_t s8_t;

    unsigned const size = 128 / 8;

    for (unsigned chunk = 0, cend = VR::size() / 8; chunk < cend; chunk += size)
      {
        u8_t res[size];

        for (unsigned idx = 0; idx < size; ++idx)
          {
            u8_t sidx = arch.vmm_read( VR(), rm, chunk + idx, u8_t() );
            u8_t mask = ~u8_t(s8_t(sidx) >> 7);
            sidx = (sidx & u8_t(0xf)) + u8_t(chunk);
            res[idx] = arch.vmm_read( VR(), vn, sidx, u8_t() ) & mask;
          }

        for (unsigned idx = 0; idx < size; ++idx)
          arch.vmm_write( VR(), gn, idx+chunk, res[idx] );
      }
  }
};

/* PSHUFB -- Packed Shuffle Bytes */
template <class ARCH> struct DC<ARCH,PSHUFB> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x00" ) & RM() ))
    {
      unsigned gn = _.greg();
      if (not ic.vex())     return new Pshufb<ARCH,SSE>( _.opbase(), _.rmop(), gn, gn );
      unsigned vn = ic.vreg();
      if (ic.vlen() == 128) return new Pshufb<ARCH,XMM>( _.opbase(), _.rmop(), vn, gn );
      if (ic.vlen() == 256) return new Pshufb<ARCH,YMM>( _.opbase(), _.rmop(), vn, gn );
    }

  return 0;
}};

template <class ARCH, class VR, unsigned OPSZ, class OPERATION>
struct PShiftVVW : public Op3V<ARCH,VR>
{
  typedef typename TypeFor<ARCH,OPSZ>::u valtype;
  typedef typename ARCH::u64_t counttype;

  valtype eval ( VSLL const&, valtype const& src, counttype const& count ) const { return src << count; }
  valtype eval ( VSRL const&, valtype const& src, counttype const& count ) const { return src >> count; }
  valtype eval ( VSRA const&, valtype const& src, counttype const& count ) const { return valtype(typename TypeFor<ARCH,OPSZ>::s(src) >> count); }

  PShiftVVW( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned vn, unsigned gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix(); VIPacked::disasmOp(sink,OPERATION().n(),OPSZ); disasmVVW(sink << ' '); }

  void execute( ARCH& arch ) const
  {
    // spec explicitely says that a whole XMM will be loaded
    counttype count;
    for (unsigned idx = 2; idx-- > 0;)
      count = arch.vmm_read( XMM(), rm, idx, counttype() );
    counttype bound(atpinfo<ARCH,valtype>::bitsize-1);
    if (arch.Test(count > bound))
      {
        if (not std::is_same<OPERATION,VSRA>::value)
          {
            for (unsigned idx = 0, end = VR::size()/OPSZ; idx < end; ++idx)
              arch.vmm_write( VR(), gn, idx, valtype(0) );
            return;
          }
        count = bound;
      }
    for (unsigned idx = 0, end = VR::size()/OPSZ; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, eval( OPERATION(), arch.vmm_read( VR(), vn, idx, valtype() ), count ) );
  }
};

template <class ARCH> struct DC<ARCH,PSHIFT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\xd1" ) & RM() ))

    return newPShift<VSRL,16>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xd2" ) & RM() ))

    return newPShift<VSRL,32>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xd3" ) & RM() ))

    return newPShift<VSRL,64>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xe1" ) & RM() ))

    return newPShift<VSRA,16>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xe2" ) & RM() ))

    return newPShift<VSRA,32>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xf1" ) & RM() ))

    return newPShift<VSLL,16>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xf2" ) & RM() ))

    return newPShift<VSLL,32>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xf3" ) & RM() ))

    return newPShift<VSLL,64>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class OPERATION, unsigned OPSIZE>
Operation<ARCH>* newPShift( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, unsigned gn )
{
  if (not ic.vex())     return new PShiftVVW<ARCH,SSE,OPSIZE,OPERATION>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new PShiftVVW<ARCH,XMM,OPSIZE,OPERATION>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new PShiftVVW<ARCH,YMM,OPSIZE,OPERATION>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

template <class ARCH, class VR>
struct Pshdq : public Operation<ARCH>
{
  Pshdq( OpBase<ARCH> const& opbase, uint8_t _rn, uint8_t _vn, uint8_t _im, bool _sr ) : Operation<ARCH>(opbase), rn(_rn), vn(_vn), im(_im), sr(_sr) {} uint8_t rn, vn, im; bool sr;
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << (sr ? "psrldq" : "pslldq")
         <<                ' ' << DisasmI( im )
         <<                ',' << DisasmV( VR(), rn );
    if (VR::vex()) sink << ',' << DisasmV( VR(), vn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u8_t u8_t;

    unsigned const size = 128 / 8, delta = (sr ? im : -im);
    for (unsigned chunk = 0, cend = VR::size() / 128; chunk < cend; ++chunk )
      {
        u8_t res[size];
        for (unsigned idx = 0; idx < size; ++idx)
          {
            unsigned sidx = idx + delta;
            res [idx] = sidx < size ? arch.vmm_read( VR(), rn, sidx + chunk*size, u8_t() ) : u8_t(0);
          }
        for (unsigned idx = 0; idx < size; ++idx)
          arch.vmm_write( VR(), vn, idx + chunk*size, res[idx] );
      }
  }
};

/* PSLLDQ/PSRLDQ -- Shift Double Quadword Left/Right Logical */
template <class ARCH> struct DC<ARCH,PSHDQ> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x73" ) /7 & RM_reg() & Imm<8>() ))

    return newPshdq( ic, false, _.opbase(), _.ereg(), _.i(uint8_t()) );

  if (auto _ = match( ic, vex( "\x66\x0f\x73" ) /3 & RM_reg() & Imm<8>() ))

    return newPshdq( ic, true, _.opbase(), _.ereg(), _.i(uint8_t()) );

  return 0;
}
Operation<ARCH>* newPshdq( InputCode<ARCH> const& ic, bool right, OpBase<ARCH> const& opbase, uint8_t rn, uint8_t im )
{
  if (not ic.vex())     return new Pshdq<ARCH,SSE>( opbase, rn, rn, im, right );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new Pshdq<ARCH,XMM>( opbase, rn, vn, im, right );
  if (ic.vlen() == 256) return new Pshdq<ARCH,YMM>( opbase, rn, vn, im, right );
  return 0;
}
};

// /* PSHUFHW -- Shuffle Packed High Words */
// op pshufhw_vdq_wdq_ib( 0xf3[8]:> <:0x0f[8]:> <:0x70[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pshufhw_vdq_wdq_ib.disasm = { _sink << "pshufhw " << DisasmI(imm) << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSHUFLW -- Shuffle Packed Low Words */
// op pshuflw_vdq_wdq_ib( 0xf2[8]:> <:0x0f[8]:> <:0x70[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// pshuflw_vdq_wdq_ib.disasm = { _sink << "pshuflw " << DisasmI(imm) << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSHUFW -- Shuffle Packed Words */
// op pshufw_pq_qq( 0x0f[8]:> <:0x70[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pshufw_pq_qq.disasm = { _sink << "pshufw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// /* PSIGNB/PSIGNW/PSIGND -- Packed SIGN */
// op psignb_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x08[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignb_pq_qq.disasm = { _sink << "psignb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psignw_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x09[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignw_pq_qq.disasm = { _sink << "psignw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psignd_pq_qq( 0x0f[8]:> <:0x38[8]:> <:0x0a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignd_pq_qq.disasm = { _sink << "psignd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psignb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x08[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignb_vdq_wdq.disasm = { _sink << "psignb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psignw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x09[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignw_vdq_wdq.disasm = { _sink << "psignw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psignd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0x38[8]:> <:0x0a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psignd_vdq_wdq.disasm = { _sink << "psignd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSLLW/PSLLD/PSLLQ -- Shift Packed Data Left Logical */
// op psllw_pq_qq( 0x0f[8]:> <:0xf1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psllw_pq_qq.disasm = { _sink << "psllw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psllw_pq_ib( 0x0f[8]:> <:0x71[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// psllw_pq_ib.disasm = { _sink << "psllw " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op pslld_pq_qq( 0x0f[8]:> <:0xf2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pslld_pq_qq.disasm = { _sink << "pslld " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op pslld_pq_ib( 0x0f[8]:> <:0x72[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// pslld_pq_ib.disasm = { _sink << "pslld " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psllq_pq_qq( 0x0f[8]:> <:0xf3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psllq_pq_qq.disasm = { _sink << "psllq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psllq_pq_ib( 0x0f[8]:> <:0x73[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// psllq_pq_ib.disasm = { _sink << "psllq " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psllw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psllw_vdq_wdq.disasm = { _sink << "psllw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psllw_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x71[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// psllw_vdq_ib.disasm = { _sink << "psllw " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// op pslld_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// pslld_vdq_wdq.disasm = { _sink << "pslld " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op pslld_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x72[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// pslld_vdq_ib.disasm = { _sink << "pslld " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// op psllq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psllq_vdq_wdq.disasm = { _sink << "psllq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psllq_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x73[8]:> <:0b11[2]:6[3]:rm[3]:> <:imm[8] );
//
// psllq_vdq_ib.disasm = { _sink << "psllq " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// /* PSRAW/PSRAD -- Shift Packed Data Right Arithmetic */
// op psraw_pq_qq( 0x0f[8]:> <:0xe1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psraw_pq_qq.disasm = { _sink << "psraw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psraw_pq_ib( 0x0f[8]:> <:0x71[8]:> <:0b11[2]:4[3]:rm[3]:> <:imm[8] );
//
// psraw_pq_ib.disasm = { _sink << "psraw " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psrad_pq_qq( 0x0f[8]:> <:0xe2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrad_pq_qq.disasm = { _sink << "psrad " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psrad_pq_ib( 0x0f[8]:> <:0x72[8]:> <:0b11[2]:4[3]:rm[3]:> <:imm[8] );
//
// psrad_pq_ib.disasm = { _sink << "psrad " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psraw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psraw_vdq_wdq.disasm = { _sink << "psraw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psraw_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x71[8]:> <:0b11[2]:4[3]:rm[3]:> <:imm[8] );
//
// psraw_vdq_ib.disasm = { _sink << "psraw " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// op psrad_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrad_vdq_wdq.disasm = { _sink << "psrad " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psrad_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x72[8]:> <:0b11[2]:4[3]:rm[3]:> <:imm[8] );
//
// psrad_vdq_ib.disasm = { _sink << "psrad " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// /* PSRLW/PSRLD/PSRLQ -- Shift Packed Data Right Logical */
// op psrlw_pq_qq( 0x0f[8]:> <:0xd1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrlw_pq_qq.disasm = { _sink << "psrlw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psrlw_pq_ib( 0x0f[8]:> <:0x71[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrlw_pq_ib.disasm = { _sink << "psrlw " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psrld_pq_qq( 0x0f[8]:> <:0xd2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrld_pq_qq.disasm = { _sink << "psrld " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psrld_pq_ib( 0x0f[8]:> <:0x72[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrld_pq_ib.disasm = { _sink << "psrld " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psrlq_pq_qq( 0x0f[8]:> <:0xd3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrlq_pq_qq.disasm = { _sink << "psrlq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psrlq_pq_ib( 0x0f[8]:> <:0x73[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrlq_pq_ib.disasm = { _sink << "psrlq " << DisasmI(imm) << ',' << DisasmPq( rm ); };
//
// op psrlw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd1[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrlw_vdq_wdq.disasm = { _sink << "psrlw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psrlw_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x71[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrlw_vdq_ib.disasm = { _sink << "psrlw " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// op psrld_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd2[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrld_vdq_wdq.disasm = { _sink << "psrld " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psrld_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x72[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrld_vdq_ib.disasm = { _sink << "psrld " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// op psrlq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd3[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psrlq_vdq_wdq.disasm = { _sink << "psrlq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psrlq_vdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x73[8]:> <:0b11[2]:2[3]:rm[3]:> <:imm[8] );
//
// psrlq_vdq_ib.disasm = { _sink << "psrlq " << DisasmI(imm) << ',' << DisasmV( SSE(), rm ); };
//
// /* PSUBB/PSUBW/PSUBD/PSUBQ -- Subtract Packed Integers */
// op psubb_pq_qq( 0x0f[8]:> <:0xf8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubb_pq_qq.disasm = { _sink << "psubb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubw_pq_qq( 0x0f[8]:> <:0xf9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubw_pq_qq.disasm = { _sink << "psubw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubd_pq_qq( 0x0f[8]:> <:0xfa[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubd_pq_qq.disasm = { _sink << "psubd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubq_pq_qq( 0x0f[8]:> <:0xfb[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubq_pq_qq.disasm = { _sink << "psubq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubb_vdq_wdq.disasm = { _sink << "psubb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psubw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xf9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubw_vdq_wdq.disasm = { _sink << "psubw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psubd_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xfa[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubd_vdq_wdq.disasm = { _sink << "psubd " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psubq_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xfb[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubq_vdq_wdq.disasm = { _sink << "psubq " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSUBSB/PSUBSW -- Subtract Packed Signed Integers with Signed Saturation */
// op psubsb_pq_qq( 0x0f[8]:> <:0xe8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubsb_pq_qq.disasm = { _sink << "psubsb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubsw_pq_qq( 0x0f[8]:> <:0xe9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubsw_pq_qq.disasm = { _sink << "psubsw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubsb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubsb_vdq_wdq.disasm = { _sink << "psubsb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psubsw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xe9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubsw_vdq_wdq.disasm = { _sink << "psubsw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* PSUBUSB/PSUBUSW -- Subtract Packed Unsigned Integers with Unsigned Saturation */
// op psubusb_pq_qq( 0x0f[8]:> <:0xd8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubusb_pq_qq.disasm = { _sink << "psubusb " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubusw_pq_qq( 0x0f[8]:> <:0xd9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubusw_pq_qq.disasm = { _sink << "psubusw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
//
// op psubusb_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd8[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubusb_vdq_wdq.disasm = { _sink << "psubusb " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// op psubusw_vdq_wdq( 0x66[8]:> <:0x0f[8]:> <:0xd9[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// psubusw_vdq_wdq.disasm = { _sink << "psubusw " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//

template <class ARCH, class VR>
struct PTest : public Operation<ARCH>
{
  PTest( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, unsigned _gn ) : Operation<ARCH>(opbase), rm(_rm), gn(_gn) {}
  void disasm( std::ostream& sink ) const
  {
    sink << (VR::vex() ? "v" : "") << "ptest " << DisasmW( VR(), rm ) << ',' << DisasmV( VR(), gn );
  }
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u64_t u64_t;
    typedef typename ARCH::bit_t bit_t;
    bit_t zf(true), cf( true );
    for (unsigned idx = 0, end = VR::size()/64; idx < end; ++idx)
      {
        u64_t lhs = arch.vmm_read( VR(), rm, idx, u64_t() );
        u64_t rhs = arch.vmm_read( VR(), gn, idx, u64_t() );
        zf &= (lhs &  rhs) == u64_t(0);
        cf &= (lhs & ~rhs) == u64_t(0);
      }
    arch.flagwrite( ARCH::FLAG::ZF, zf );
    arch.flagwrite( ARCH::FLAG::CF, cf );
    arch.flagwrite( ARCH::FLAG::PF, bit_t(false) );
    arch.flagwrite( ARCH::FLAG::OF, bit_t(false) );
    arch.flagwrite( ARCH::FLAG::SF, bit_t(false) );
    arch.flagwrite( ARCH::FLAG::AF, bit_t(false) );
  }
  RMOp<ARCH> rm; uint8_t gn;
};

template <class ARCH> struct DC<ARCH,PTEST> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x38\x17" ) & RM() ))
    {
      if (not ic.vex())     return new PTest<ARCH,SSE>( _.opbase(), _.rmop(), _.greg() );
      if (ic.vreg()) return 0;
      if (ic.vlen() == 128) return new PTest<ARCH,XMM>( _.opbase(), _.rmop(), _.greg() );
      if (ic.vlen() == 256) return new PTest<ARCH,YMM>( _.opbase(), _.rmop(), _.greg() );
    }

  return 0;
}};
// op punpckhbw_pq_qq( 0x0f[8]:> <:0x68[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpckhbw_pq_qq.disasm = { _sink << "punpckhbw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
// op punpckhwd_pq_qq( 0x0f[8]:> <:0x69[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpckhwd_pq_qq.disasm = { _sink << "punpckhwd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
// op punpckhdq_pq_qq( 0x0f[8]:> <:0x6a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpckhdq_pq_qq.disasm = { _sink << "punpckhdq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
// op punpcklbw_pq_qq( 0x0f[8]:> <:0x60[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpcklbw_pq_qq.disasm = { _sink << "punpcklbw " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
// op punpcklwd_pq_qq( 0x0f[8]:> <:0x61[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpcklwd_pq_qq.disasm = { _sink << "punpcklwd " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };
// op punpckldq_pq_qq( 0x0f[8]:> <:0x62[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// punpckldq_pq_qq.disasm = { _sink << "punpckldq " << DisasmQq( rm ) << ',' << DisasmPq( gn ); };

template <class ARCH, class VR, class TYPE, bool HI>
struct Unpack : public Op3V<ARCH,VR>
{
  typedef TYPE val_type;
  typedef atpinfo<ARCH,TYPE> CFG;

  Unpack( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  template <typename T, typename std::enable_if<T::is_integral == 1, int>::type = 0>
  std::ostream& mnemonic( T const&, std::ostream& sink ) const { sink << 'p' << "unpck" << "lh"[HI] << SizeID<T::bitsize>::iid() << SizeID<2*T::bitsize>::iid(); return sink; }
  template <typename T, typename std::enable_if<T::is_integral == 0, int>::type = 0>
  std::ostream& mnemonic( T const&, std::ostream& sink ) const { sink << "unpck" << "lh"[HI] << 'p' << SizeID<T::bitsize>::fid(); return sink; }

  void disasm( std::ostream& sink ) const { this->mnemonic(CFG(), sink << vprefix()); disasmVVW(sink << ' '); }

  void execute( ARCH& arch ) const
  {
    unsigned const chunk_items = 128/CFG::bitsize;
    unsigned const srcoffset = HI ? chunk_items/2 : 0;

    for (unsigned chunk_offset = 0, cend = VR::size()/CFG::bitsize; chunk_offset < cend; chunk_offset += chunk_items)
      {
        val_type res[chunk_items];
        for (unsigned idx = 0; idx < chunk_items; idx+=2)
          {
            unsigned sidx = chunk_offset + srcoffset + idx/2;
            res[idx+0] = arch.vmm_read( VR(), vn, sidx, val_type() );
            res[idx+1] = arch.vmm_read( VR(), rm, sidx, val_type() );
          }
        for (unsigned idx = 0; idx < chunk_items; ++idx)
          arch.vmm_write( VR(), gn, chunk_offset + idx, res[idx] );
      }
  }
};

/* PUNPCKHBW/PUNPCKHWD/PUNPCKHDQ/PUNPCKHQDQ/PUNPCKLBW/PUNPCKLWD/PUNPCKLDQ/PUNPCKLQDQ/UNPCKHPS/UNPCKHPD/UNPCKLPS/UNPCKLPD -- Unpack and Interleave Data */
template <class ARCH> struct DC<ARCH,PUNPCK> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x60" ) & RM() ))

    return newUnpack<typename ARCH::u8_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x61" ) & RM() ))

    return newUnpack<typename ARCH::u16_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x62" ) & RM() ))

    return newUnpack<typename ARCH::u32_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6c" ) & RM() ))

    return newUnpack<typename ARCH::u64_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x68" ) & RM() ))

    return newUnpack<typename ARCH::u8_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x69" ) & RM() ))

    return newUnpack<typename ARCH::u16_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6a" ) & RM() ))

    return newUnpack<typename ARCH::u32_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x6d" ) & RM() ))

    return newUnpack<typename ARCH::u64_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x14" ) & RM() ))

    return newUnpack<typename ARCH::f32_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x14" ) & RM() ))

    return newUnpack<typename ARCH::f64_t,false>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x0f\x15" ) & RM() ))

    return newUnpack<typename ARCH::f32_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x15" ) & RM() ))

    return newUnpack<typename ARCH::f64_t,true>( ic, _.opbase(), _.rmop(), _.greg() );

  return 0;
}
template <class TYPE,bool LOHI>
Operation<ARCH>* newUnpack( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())     return new Unpack<ARCH,SSE,TYPE,LOHI>( opbase, std::move(rm), gn, gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new Unpack<ARCH,XMM,TYPE,LOHI>( opbase, std::move(rm), vn, gn );
  if (ic.vlen() == 256) return new Unpack<ARCH,YMM,TYPE,LOHI>( opbase, std::move(rm), vn, gn );
  return 0;
}
};

template <class ARCH, class VR, unsigned OPSIZE>
struct Palignr : public Op3V<ARCH,VR>
{
  Palignr( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn, uint8_t _im ) : Op3V<ARCH,VR>(opbase, std::move(rm), vn, gn), im(_im) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm(std::ostream& sink) const { sink << vprefix() << "palignr" << ' ' << DisasmI(im); disasmVVW(sink << ' '); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::u uint_t;
    unsigned const size =  128 / OPSIZE;

    for (unsigned step = 0, end = VR::size() / 128; step < end; ++step)
      {
        uint_t res[size];

        {
          unsigned sidx, ridx = 0;
          // SRC2 part
          sidx = im*8/OPSIZE;
          for (; sidx < size; ++sidx, ++ridx)
            res[ridx] = arch.vmm_read( VR(), rm, sidx+step*size, uint_t() );
          // SRC1 part
          sidx -= size;
          for (unsigned end = size - (ridx > sidx ? ridx - sidx : 0); sidx < end; ++sidx, ++ridx)
            res[ridx] = arch.vmm_read( VR(), vn, sidx+step*size, uint_t() );
          // Zero part
          for (; ridx < size; ++ridx)
            res[ridx] = uint_t(0u);
        }

        for (unsigned idx = 0; idx < size; ++idx)
          arch.vmm_write( VR(), gn, idx+step*size, res[idx] );
      }
  }
  uint8_t im;
};

// op palignr_pq_qq_ib( 0x0f[8]:> <:0x3a[8]:> <:0x0f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
// op palignr_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x0f[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );

/* PALIGNR -- Packed Align Right */
template <class ARCH> struct DC<ARCH,PALIGNR> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x0f" ) & RM() & Imm<8>() ))
    {
      uint8_t imm = _.i(int8_t());
      switch ((imm^(imm-1)) & 15)
        {
        case 1:  return newPalignr <8>( ic, _.opbase(), _.rmop(), _.greg(), imm );
        case 3:  return newPalignr<16>( ic, _.opbase(), _.rmop(), _.greg(), imm );
        case 7:  return newPalignr<32>( ic, _.opbase(), _.rmop(), _.greg(), imm );
        case 15: return newPalignr<64>( ic, _.opbase(), _.rmop(), _.greg(), imm );
        }
    }

  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newPalignr( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t gn, uint8_t im )
{
  if (not ic.vex())     return new Palignr<ARCH,SSE,OPSIZE>( opbase, std::move(rm), gn, gn, im );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new Palignr<ARCH,XMM,OPSIZE>( opbase, std::move(rm), vn, gn, im );
  if (ic.vlen() == 256) return new Palignr<ARCH,YMM,OPSIZE>( opbase, std::move(rm), vn, gn, im );
  return 0;
}
};

template <class ARCH, class OPERATION>
struct MMXBitManip : public Operation<ARCH>
{
  MMXBitManip( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>(opbase), rm(_rm), gn(_gn) {} RMOp<ARCH> rm; uint8_t gn;
  void disasm( std::ostream& sink ) const { sink << 'p' << OPERATION().n() << DisasmQq( rm ) << ',' << DisasmPq( gn ); }
};

/**** Packed Bit Manipulations ****/
/* PAND -- Bitwise Logical AND */
/* PANDN -- Bitwise Logical AND NOT */
/* POR -- Bitwise Logical OR */
/* PXOR -- Logical Exclusive OR */
template <class ARCH> struct DC<ARCH,PBM> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  /* MMX */

  if (auto _ = match( ic, simd__() & opcode( "\x0f\xeb" ) & RM() ))

    return new MMXBitManip<ARCH,VOR>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simd__() & opcode( "\x0f\xdb" ) & RM() ))

    return new MMXBitManip<ARCH,VAND>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simd__() & opcode( "\x0f\xdb" ) & RM() ))

    return new MMXBitManip<ARCH,VANDN>( _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, simd__() & opcode( "\x0f\xef" ) & RM() ))

    return new MMXBitManip<ARCH,VXOR>( _.opbase(), _.rmop(), _.greg() );

  /* SSE/AVX Integer */

  if (auto _ = match( ic, vex( "\x66\x0f\xdb" ) & RM() ))

    return newPBitManipVVW<VAND>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xdf" ) & RM() ))

    return newPBitManipVVW<VANDN>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xeb" ) & RM() ))

    return newPBitManipVVW<VOR>( ic, _.opbase(), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xef" ) & RM() ))

    return newPBitManipVVW<VXOR>( ic, _.opbase(), _.rmop(), _.greg() );

  /* SSE/AVX Floating Point */

  return 0;
}
template <class OPERATION>
Operation<ARCH>* newPBitManipVVW( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, RMOp<ARCH>&& _rm, uint8_t _gn )
{
  /* TODO: this operation will always blow the vector typing, but is this avoidable ? */
  typedef typename ARCH::u64_t BMOP;
  if (not ic.vex())     return new VBinaryVVW<ARCH,OPERATION,SSE,BMOP,VBPacked>( opbase, std::move(_rm), _gn, _gn );
  unsigned vn = ic.vreg();
  if (ic.vlen() == 128) return new VBinaryVVW<ARCH,OPERATION,XMM,BMOP,VBPacked>( opbase, std::move(_rm),  vn, _gn );
  if (ic.vlen() == 256) return new VBinaryVVW<ARCH,OPERATION,YMM,BMOP,VBPacked>( opbase, std::move(_rm),  vn, _gn );
  return 0;
}
};

template <class ARCH, unsigned OPSZ>
struct Ucomis : public Operation<ARCH>
{
  Ucomis( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rm, uint8_t _gn, bool _v, bool _o )
    : Operation<ARCH>(opbase), rm(_rm), gn(_gn), v(_v), o(_o) {}
  RMOp<ARCH> rm; uint8_t gn; bool v; bool o;
  void disasm( std::ostream& sink ) const { sink << (v?"v":"") << (o?"":"u") << "comis" << SizeID<OPSZ>::fid() << ' ' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); }

  void execute( ARCH& arch ) const
  {
    // TODO: handle ordered case
    typedef typename TypeFor<ARCH,OPSZ>::f f_type;
    typedef typename ARCH::bit_t bit_t;

    f_type a = arch.vmm_read( SSE(), gn, 0, f_type() );
    f_type b = arch.vmm_read( SSE(), rm, 0, f_type() );
    bit_t notle = not (a <= b);
    bit_t notge = not (a >= b);

    arch.flagwrite( ARCH::FLAG::ZF, notge == notle );
    arch.flagwrite( ARCH::FLAG::PF, notge and notle );
    arch.flagwrite( ARCH::FLAG::CF, notge );
    arch.flagwrite( ARCH::FLAG::OF, bit_t(false) );
    arch.flagwrite( ARCH::FLAG::SF, bit_t(false) );
    arch.flagwrite( ARCH::FLAG::AF, bit_t(false) );
  }
};

/* UCOMISD -- Unordered Compare Scalar Double-Precision Floating-Point Values and Set EFLAGS */
/* UCOMISS -- Unordered Compare Scalar Single-Precision Floating-Point Values and Set EFLAGS */
template <class ARCH> struct DC<ARCH,UCOMIS> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, (vex( "*\x0f\x2e" ) + Var<1>()) & RM() ))
    {
      if (ic.vex() and ic.vreg()) return 0;
      if (match( ic, simd__() )) return new Ucomis<ARCH,32>( _.opbase(), _.rmop(), _.greg(), ic.vex(), _.var() );
      if (match( ic, simd66() )) return new Ucomis<ARCH,64>( _.opbase(), _.rmop(), _.greg(), ic.vex(), _.var() );
    }

  return 0;
}};

// /* RCPPS -- Compute Reciprocals of Packed Single-Precision Floating-Point Values */
// op rcpps_vdq_wdq( 0x0f[8]:> <:0x53[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// rcpps_vdq_wdq.disasm = { _sink << "rcpps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* RCPSS -- Compute Reciprocal of Scalar Single-Precision Floating-Point Values */
// op rcpss_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x53[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// rcpss_vdq_wdq.disasm = { _sink << "rcpss " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* ROUNDPS -- Round Packed Single-Precision Floating-Point Values */
// op roundps_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x08[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// roundps_vdq_wdq_ib.disasm = { _sink << "roundps " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* ROUNDPD -- Round Packed Double-Precision Floating-Point Values */
// op roundpd_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x09[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// roundpd_vdq_wdq_ib.disasm = { _sink << "roundpd " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* ROUNDSS -- Round Scalar Single-Precision Floating-Point Values */
// op roundss_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x0a[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// roundss_vdq_wdq_ib.disasm = { _sink << "roundss " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* ROUNDSD -- Round Scalar Double-Precision Floating-Point Values */
// op roundsd_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0x3a[8]:> <:0x0b[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// roundsd_vdq_wdq_ib.disasm = { _sink << "roundsd " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* RSQRTPS -- Compute Reciprocals of Square Roots of Packed Single-Precision Floating-Point Values */
// op rsqrtps_vdq_wdq( 0x0f[8]:> <:0x52[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// rsqrtps_vdq_wdq.disasm = { _sink << "rsqrtps " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* RSQRTSS -- Compute Reciprocal of Square Root of Scalar Single-Precision Floating-Point Value */
// op rsqrtss_vdq_wdq( 0xf3[8]:> <:0x0f[8]:> <:0x52[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
//
// rsqrtss_vdq_wdq.disasm = { _sink << "rsqrtss " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* SHUFPS -- Shuffle Packed Single-Precision Floating-Point Values */
// op shufps_vdq_wdq_ib( 0x0f[8]:> <:0xc6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//
// shufps_vdq_wdq_ib.disasm = { _sink << "shufps " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* SHUFPD -- Shuffle Packed Double-Precision Floating-Point Values */
// op shufpd_vdq_wdq_ib( 0x66[8]:> <:0x0f[8]:> <:0xc6[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM]:> <:imm[8] );
//

template <class ARCH, class VR, unsigned OPSIZE>
struct Shufp : public Op3V<ARCH,VR>
{
  Shufp( OpBase<ARCH> const& opbase, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn, uint8_t _imm ) : Op3V<ARCH,VR>( opbase, std::move(rm), vn, gn ), imm( _imm ) {}

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::vprefix; using Op3V<ARCH,VR>::disasmVVW;

  void disasm( std::ostream& sink ) const { sink << vprefix() << "shufp" << SizeID<OPSIZE>::fid() << ' ' << DisasmI( imm ) << ','; disasmVVW(sink); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,OPSIZE>::f src_type;

    enum {
	  N = 128 / OPSIZE,
	  BITSHIFT = meta::BitScan<128 / OPSIZE>::forward,
	  MASK = 128 / OPSIZE - 1
    };

    src_type value[VR::SIZE/OPSIZE];

    for (unsigned idx = 0, end = VR::SIZE / 128; idx < end; ++idx) {
      for (unsigned idy = 0; idy < N / 2; ++idy) {
	unsigned idz = N * idx + idy;
	value[idz] = arch.vmm_read( VR(), vn, N * idx + ((imm >> (BITSHIFT * idz)) & MASK), src_type() );
      }
      for (unsigned idy = 0; idy < N / 2; ++idy) {
	unsigned idz = N * idx + N / 2 + idy;
	value[idz] = arch.vmm_read( VR(), rm, N * idx + ((imm >> (BITSHIFT * idz)) & MASK), src_type() );
      }
    }

    for (unsigned idx = 0, end = VR::size() / OPSIZE; idx < end; ++idx)
      arch.vmm_write( VR(), gn, idx, value[idx] );
  }

  uint8_t imm;
};

template <class ARCH> struct DC<ARCH,SHUFP> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x0f\xc6" ) & RM() & Imm<8>() ))

    return newShufp<32>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xc6" ) & RM() & Imm<8>() ))

    return newShufp<64>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  return 0;
}
template <unsigned OPSIZE>
Operation<ARCH>* newShufp( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, uint8_t imm, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())
    return new Shufp<ARCH,SSE,OPSIZE>( opbase, std::move(rm), gn, gn, imm );

  uint8_t vn = ic.vreg();
  if (ic.vlen() == 128)
    return new Shufp<ARCH,XMM,OPSIZE>( opbase, std::move(rm), vn, gn, imm );
  if (ic.vlen() == 256)
    return new Shufp<ARCH,YMM,OPSIZE>( opbase, std::move(rm), vn, gn, imm );

  return 0;
}
};

// shufpd_vdq_wdq_ib.disasm = { _sink << "shufpd " << DisasmI(imm) << ',' << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };
//
// /* MOVDDUP -- Move One Double-FP and Duplicate */
// op movddup_vdq_wdq( 0xf2[8]:> <:0x0f[8]:> <:0x12[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// movddup_vdq_wdq.disasm = { _sink << "movddup " << DisasmW( SSE(), rm ) << ',' << DisasmV( SSE(), gn ); };

template <class ARCH, class VR>
struct VZeroUpper : public Operation<ARCH>
{
  VZeroUpper( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {};

  void disasm( std::ostream& sink ) const { sink << "vzeroupper"; }
  void execute( ARCH& arch ) const
  {
    for (unsigned gn = 0; gn < ARCH::VREGCOUNT; gn += 1)
      for (unsigned idx = 2, end = VR::size() / 64; idx < end; ++idx)
	arch.vmm_write( VR(), gn, idx, typename ARCH::u64_t(0) );
  }
};

template <class ARCH> struct DC<ARCH,VZEROUPPER> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex("\x0f\x77") ))
    if (ic.vex() and ic.vlen() == 128 and ic.vreg() == 0x0)
      return new VZeroUpper<ARCH,YMM>( _.opbase() );

  return 0;
}
};



template <class ARCH, class VR, class GOP, class DOP>
struct Extr : public Operation<ARCH>
{
  Extr( OpBase<ARCH> const& opbase, uint8_t _imm, RMOp<ARCH>&& _rm, uint8_t _gn )
    : Operation<ARCH>( opbase ), rm( std::move(_rm) ), gn( _gn ), imm( _imm )
  {}

  void disasm( std::ostream& sink ) const { sink << (VR::vex() ? "vp" : "p") << "extr" << SizeID<GOP::SIZE>::iid() << ' ' << DisasmI( imm ) << ',' << DisasmV( VR(), gn ) << ',' << DisasmE( DOP(), rm );
  }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOP::SIZE>::u src_type;
    typedef typename TypeFor<ARCH,DOP::SIZE>::u dst_type;
    src_type value = arch.vmm_read( VR(), gn, imm & ((VR::SIZE / GOP::SIZE) - 1), src_type() );
    if (rm.isreg())
      arch.rmwrite( DOP(), rm, dst_type( value ) );
    else
      arch.rmwrite( GOP(), rm, value );
  }

  RMOp<ARCH> rm; uint8_t gn, imm;
};

template <class ARCH>
struct VExtractI128 : public Operation<ARCH>
{
  VExtractI128( OpBase<ARCH> const& opbase, uint8_t _imm, MOp<ARCH> const* _rm, uint8_t _gn ) : Operation<ARCH>( opbase ), rm( _rm ), gn( _gn ), imm( _imm ) {} RMOp<ARCH> rm; uint8_t gn, imm;
  void disasm( std::ostream& sink ) const { sink << "vextracti128 " << DisasmI( imm ) << ',' << DisasmV( YMM(), gn ) << ',' << DisasmW( XMM(), rm );}
  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOq::SIZE>::u src_type;
    arch.vmm_write( XMM(), rm, 0, arch.vmm_read( YMM(), gn, 2 * (imm & 1), src_type()) );
    arch.vmm_write( XMM(), rm, 1, arch.vmm_read( YMM(), gn, 2 * (imm & 1) + 1, src_type()) );
  }
};

template <class ARCH> struct DC<ARCH,EXTRACT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x14" ) & RM() & Imm<8>() ))

    return newExtr<GOb>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xc5" ) & RM_reg() & Imm<8>() ))

    return newExtr<GOw>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x15" ) & RM() & Imm<8>() ))

    return newExtr<GOw>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x16" ) & RM() & Imm<8>() )) {

    if (ic.w())
      return newExtr<GOq>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );
    else
      return newExtr<GOd>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  }

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x39" ) & RM() & Imm<8>() )) {
    if (ic.w() || ic.vlen() != 256) return 0;

    return new VExtractI128<ARCH>( _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );
  }

  return 0;
}
template <class GOP>
Operation<ARCH>* newExtr( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, uint8_t imm, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex()) return newExtr2<SSE,GOP>( ic, opbase, imm, std::move(rm), gn );
  if (ic.vreg()) return 0;
  if (ic.vlen() == 128) return newExtr2<XMM,GOP>( ic, opbase, imm, std::move(rm), gn );
  if (ic.vlen() == 256) return newExtr2<YMM,GOP>( ic, opbase, imm, std::move(rm), gn );
  return 0;
}
template <class VR, class GOP>
Operation<ARCH>* newExtr2( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, uint8_t imm, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (ic.mode64()) return new Extr<ARCH,VR,GOP,GOq>( opbase, imm, std::move(rm), gn );
  else return new Extr<ARCH,VR,GOP,GOd>( opbase, imm, std::move(rm), gn );
}
};

template <class ARCH, class VR, class GOP>
struct Insr : public Op3V<ARCH,VR>
{
  Insr( OpBase<ARCH> const& opbase, uint8_t _imm, RMOp<ARCH>&& rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,VR>( opbase, std::move(rm), vn, gn ), imm( _imm ) {} uint8_t imm;

  using Op3V<ARCH,VR>::rm; using Op3V<ARCH,VR>::vn; using Op3V<ARCH,VR>::gn; using Op3V<ARCH,VR>::disasmVV; using Op3V<ARCH,VR>::vprefix;

  void disasm( std::ostream& sink ) const
  {
    sink << vprefix() << "pinsr" << SizeID<GOP::SIZE>::iid() << ' ' << DisasmI( imm ) << ',';
    if (GOP::SIZE < 32)
      sink << DisasmE( GOd(), rm );
    else
      sink << DisasmE( GOP(), rm );
    disasmVV(sink);
  }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOP::SIZE>::u src_type;
    unsigned pos = imm & ((VR::SIZE / GOP::SIZE) - 1);
    for (unsigned idx = 0, end = VR::size() / GOP::SIZE; idx < end; ++idx) {
      src_type value;
      if (idx == pos) value = arch.rmread( GOP(), rm );
      else value = arch.vmm_read( VR(), vn, idx, src_type() );
      arch.vmm_write( VR(), gn, idx, value );
    }
  }
};

template <class ARCH>
struct VInsertI128 : public Op3V<ARCH,YMM>
{
  VInsertI128( OpBase<ARCH> const& opbase, uint8_t _imm, MOp<ARCH> const* rm, uint8_t vn, uint8_t gn ) : Op3V<ARCH,YMM>( opbase, rm, vn, gn ), imm( _imm ) {} uint8_t imm;

  using Op3V<ARCH,YMM>::rm; using Op3V<ARCH,YMM>::vn; using Op3V<ARCH,YMM>::gn; using Op3V<ARCH,YMM>::disasmVV;

  void disasm( std::ostream& sink ) const { sink << "vinserti128 " << DisasmI( imm ) << ',' << DisasmW( XMM(), rm ); disasmVV(sink); }

  void execute( ARCH& arch ) const
  {
    typedef typename TypeFor<ARCH,GOq::SIZE>::u src_type;
    uint8_t pos = imm & 1;
    arch.vmm_write( YMM(), gn, 2 * pos, arch.vmm_read( XMM(), rm, 0, src_type() ) );
    arch.vmm_write( YMM(), gn, 2 * pos + 1, arch.vmm_read( XMM(), rm, 1, src_type() ) );
    arch.vmm_write( YMM(), gn, 2 * (1 - pos), arch.vmm_read( YMM(), vn, 2 * (1 - pos), src_type() ) );
    arch.vmm_write( YMM(), gn, 2 * (1 - pos) + 1, arch.vmm_read( YMM(), vn, 2 * (1 - pos) + 1, src_type() ) );
  }
};

template <class ARCH> struct DC<ARCH,INSERT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.f0()) return 0;

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x20" ) & RM() & Imm<8>() ))

    return newInsr<GOb>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  if (auto _ = match( ic, vex( "\x66\x0f\xc4" ) & RM() & Imm<8>() )) {
    if (ic.vex() && ic.w()) return 0;

    return newInsr<GOw>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );
  }

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x22" ) & RM() & Imm<8>() )) {

    if (ic.w())
      return newInsr<GOq>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );
    else
      return newInsr<GOd>( ic, _.opbase(), _.i( uint8_t() ), _.rmop(), _.greg() );

  }

  if (auto _ = match( ic, vex( "\x66\x0f\x3a\x38" ) & RM() & Imm<8>() )) {
    if (ic.w() || ic.vlen() != 256) return 0;

    return new VInsertI128<ARCH>( _.opbase(), _.i( uint8_t() ), _.rmop(), _.vreg(), _.greg() );
  }

  return 0;
}
template <class GOP>
Operation<ARCH>* newInsr( InputCode<ARCH> const& ic, OpBase<ARCH> const& opbase, uint8_t imm, RMOp<ARCH>&& rm, uint8_t gn )
{
  if (not ic.vex())
    return new Insr<ARCH,SSE,GOP>( opbase, imm, std::move(rm), gn, gn );

  if (ic.vlen() != 128) return 0;

  return  new Insr<ARCH,XMM,GOP>( opbase, imm, std::move(rm), ic.vreg(), gn );
}
};
