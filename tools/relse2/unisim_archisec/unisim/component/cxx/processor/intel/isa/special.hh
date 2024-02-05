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
struct CpuID : public Operation<ARCH>
{
  CpuID( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "cpuid"; }
  void execute( ARCH& arch ) const { arch.cpuid(); }
};

template <class ARCH> struct DC<ARCH,CPUID> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.lock_f0) return 0;
  
  if (auto _ = match( ic, opcode( "\x0f\xa2" ) )) return new CpuID<ARCH>( _.opbase() );
  
  return 0;
}};

template <class ARCH>
struct RdTSC : public Operation<ARCH>
{
  RdTSC( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  
  void disasm( std::ostream& sink ) const { sink << "rdtsc"; }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u64_t u64_t;
    typedef typename ARCH::u32_t u32_t;
    
    u64_t tsc = arch.tscread();
    arch.regwrite( GOd(), 0, u32_t( tsc >> 0 ) );
    arch.regwrite( GOd(), 2, u32_t( tsc >> 32 ) );
  }
};

template <class ARCH> struct DC<ARCH,RDTSC> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.lock_f0) return 0;
  
  if (auto _ = match( ic, opcode( "\x0f\x31" ) )) return new RdTSC<ARCH>( _.opbase() );
  
  return 0;
}};

// op xgetbv( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b010[3]:0b000[3]:> rewind <:*modrm[ModRM] );
// 
// xgetbv.disasm = { _sink << "xgetbv "; };
// 
// op xsetbv( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b010[3]:0b001[3]:> rewind <:*modrm[ModRM] );
// 
// xsetbv.disasm = { _sink << "xsetbv "; };
// 

template <class ARCH>
struct XGetBV : public Operation<ARCH>
{
  XGetBV( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "xgetbv"; }
  void execute( ARCH& arch ) const { arch.xgetbv(); }
};

template <class ARCH>
struct XSetBV : public Operation<ARCH>
{
  XSetBV( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}
  void disasm( std::ostream& sink ) const { sink << "xsetbv"; }
};

template <class ARCH> struct DC<ARCH,XBV> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\x01\xd0" ) ))

    return new XGetBV<ARCH>( _.opbase() );
  
  if (auto _ = match( ic, opcode( "\x0f\x01\xd1" ) ))

    return new XSetBV<ARCH>( _.opbase() );
  
  return 0;
}};

// 
// op wrmsr( 0x0f[8]:> <:0x30[8] );
// 
// wrmsr.disasm = { _sink << "wrmsr"; };
// 
// 
// 
// op rdtscp( 0x0f[8]:> <:0x01[8]:> <:0xf9[8] );
// 
// rdtscp.disasm = { _sink << "rdtscp"; };
// 
// op rdmsr( 0x0f[8]:> <:0x32[8] );
// 
// rdmsr.disasm = { _sink << "rdmsr"; };
// 
// op rdpmc( 0x0f[8]:> <:0x33[8] );
// 
// rdpmc.disasm = { _sink << "rdpmc"; };
// 

template <class ARCH>
struct Hlt : public Operation<ARCH>
{
  Hlt( OpBase<ARCH> const& opbase ) : Operation<ARCH>( opbase ) {}

  void disasm( std::ostream& sink ) const { sink << "hlt"; }

  void execute( ARCH& arch ) const { arch.stop(); }
};

template <class ARCH> struct DC<ARCH,HLT> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (ic.lock_f0) return 0;

  if (auto _ = match( ic, opcode( "\xf4" ) )) return new Hlt<ARCH>( _.opbase() );

  return 0;
}};


// op in_al_ib( 0xe4[8]:> <:port[8] );
// 
// in_al_ib.disasm = { _sink << "in " << DisasmI( port ) << ',' << DisasmGb( 0 ); };
// 
// op in_ax_ib( 0x66[8]:> <:0xe5[8]:> <:port[8] );
// 
// in_ax_ib.disasm = { _sink << "in " << DisasmI( port ) << ',' << DisasmGw( 0 ); };
// 
// op in_eax_ib( 0xe5[8]:> <:port[8] );
// 
// in_eax_ib.disasm = { _sink << "in " << DisasmI( port ) << ',' << DisasmGd( 0 ); };
// 
// op out_ib_al( 0xe6[8]:> <:port[8] );
// 
// out_ib_al.disasm = { _sink << "out " << DisasmGb( 0 ) << ',' << DisasmI( port ); };
// 
// op out_ib_ax( 0x66[8]:> <:0xe7[8]:> <:port[8] );
// 
// out_ib_ax.disasm = { _sink << "out " << DisasmGw( 0 ) << ',' << DisasmI( port ); };
// 
// op out_ib_eax( 0xe7[8]:> <:port[8] );
// 
// out_ib_eax.disasm = { _sink << "out " << DisasmGd( 0 ) << ',' << DisasmI( port ); };
// 
// op in_al_dx( 0xec[8] );
// 
// in_al_dx.disasm = { _sink << "in (" << DisasmGw( 2 ) << ")," << DisasmGb( 0 ); };
// 
// op in_ax_dx( 0x66[8]:> <:0xed[8] );
// 
// in_ax_dx.disasm = { _sink << "in (" << DisasmGw( 2 ) << ")," << DisasmGw( 0 ); };
// 
// op in_eax_dx( 0xed[8] );
// 
// in_eax_dx.disasm = { _sink << "in (" << DisasmGw( 2 ) << ")," << DisasmGd( 0 ); };
// 
// op out_dx_al( 0xee[8] );
// 
// out_dx_al.disasm = { _sink << "out " << DisasmGb( 0 ) << ",(" << DisasmGw( 2 ) << ")"; };
// 
// op out_dx_ax( 0x66[8]:> <:0xef[8] );
// 
// out_dx_ax.disasm = { _sink << "out " << DisasmGw( 0 ) << ",(" << DisasmGw( 2 ) << ")"; };
// 
// op out_dx_eax( 0xef[8] );
// 
// out_dx_eax.disasm = { _sink << "out " << DisasmGd( 0 ) << ",(" << DisasmGw( 2 ) << ")"; };
// 
// op clc( 0xf8[8] );
// 
// clc.disasm = { _sink << "clc"; };
// 
// op stc( 0xf9[8] );
// 
// stc.disasm = { _sink << "stc"; };
// 
// op cli( 0xfa[8] );
// 
// cli.disasm = { _sink << "cli"; };
// 
// op sti( 0xfb[8] );
// 
// sti.disasm = { _sink << "sti"; };
// 
// op pause( 0xf3[8]:> <:0x90[8] );
// 
// pause.disasm = { _sink << "pause"; };
// 
// op rsm( 0x0f[8]:> <:0xaa[8] );
// 
// rsm.disasm = { _sink << "rsm"; };
// 
// op ud1( 0x0f[8]:> <:0xb9[8]:> <:*modrm[ModRM] );
// 
// ud1.disasm = { _sink << "ud1"; };
// 
// op ud2( 0x0f[8]:> <:0x0b[8] );
// 
// ud2.disasm = { _sink << "ud2"; };
// 
// op rdrand_rw( 0x66[8]:> <:0x0f[8]:> <:0xc7[8]:> <:0b11[2]:110[3]:reg[3] );
// 
// rdrand_rw.disasm = { _sink << "rdrand " << DisasmGw( reg ); };
// 
// op rdrand_rd( 0x0f[8]:> <:0xc7[8]:> <:0b11[2]:0b110[3]:reg[3] );
// 
// rdrand_rd.disasm = { _sink << "rdrand " << DisasmGd( reg ); };
// 
// op rdseed_rw( 0x66[8]:> <:0x0f[8]:> <:0xc7[8]:> <:0b11[2]:111[3]:reg[3] );
// 
// rdseed_rw.disasm = { _sink << "rdseed " << DisasmGw( reg ); };
// 
// op rdseed_rd( 0x0f[8]:> <:0xc7[8]:> <:0b11[2]:0b111[3]:reg[3] );
// 
// rdseed_rd.disasm = { _sink << "rdseed " << DisasmGd( reg ); };
// 
// op icebp( 0xf1[8] );
// 
// icebp.disasm = { _sink << "icebp"; };
// 
// op xabort( 0xc6[8]:> <:0xf8[8]:> <:imm[8] );
// 
// xabort.disasm = { _sink << "xabort " << DisasmI( imm ); };
// 
// op xbegin_jd( 0xc7[8]:> <:0xf8[8]:> <:offset[32] );
// 
// xbegin_jd.disasm = { _sink << "xbegin 0x" << std::hex << (this->addr + this->size + offset); };
// 
// op xend( 0x0f[8]:> <:0x01[8]:> <:0xd5[8] );
// 
// xend.disasm = { _sink << "xend"; };
// 
// op xtest( 0x0f[8]:> <:0x01[8]:> <:0xd6[8] );
// 
// xtest.disasm = { _sink << "xtest"; };
// 
// op invd( 0x0f[8]:> <:0x08[8] );
// 
// invd.disasm = { _sink << "invd"; };
// 
// op wbinvd( 0x0f[8]:> <:0x09[8] );
// 
// wbinvd.disasm = { _sink << "wbinvd"; };
// 
// op syscall( 0x0f[8]:> <:0x05[8] );
// 
// syscall.disasm = { _sink << "syscall"; };
// 
// op sysret( 0x0f[8]:> <:0x07[8] );
// 
// sysret.disasm = { _sink << "sysret"; };
// 
// op sysenter( 0x0f[8]:> <:0x34[8] );
// 
// sysenter.disasm = { _sink << "sysenter"; };
// 
// op sysexit( 0x0f[8]:> <:0x35[8] );
// 
// sysexit.disasm = { _sink << "sysexit"; };
// 
// op clts( 0x0f[8]:> <:0x06[8] );
// 
// clts.disasm = { _sink << "clts"; };
// 
// op lar_gd_ew( 0x0f[8]:> <:0x02[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lar_gd_ew.disasm = { _sink << "lar " << DisasmEw( modrm, segment ) << ',' << DisasmGd( gn ); };
// 
// op lsl_gd_ew( 0x0f[8]:> <:0x03[8]:> <:?[2]:gn[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lsl_gd_ew.disasm = { _sink << "lsl " << DisasmEw( modrm, segment ) << ',' << DisasmGd( gn ); };
// 
// op mov_rd_cd( 0x0f[8]:> <:0x20[8]:> <:0b11[2]:gn[3]:rm[3] );
// 
// mov_rd_cd.disasm = { _sink << "mov " << DisasmCd( gn ) << ',' << DisasmGd( rm ); };
// 
// op mov_rd_dd( 0x0f[8]:> <:0x21[8]:> <:0b11[2]:gn[3]:rm[3] );
// 
// mov_rd_dd.disasm = { _sink << "mov " << DisasmDd( gn ) << ',' << DisasmGd( rm ); };
// 
// op mov_cd_rd( 0x0f[8]:> <:0x22[8]:> <:0b11[2]:gn[3]:rm[3] );
// 
// mov_cd_rd.disasm = { _sink << "mov " << DisasmGd( rm ) << ',' << DisasmCd( gn ); };
// 
// op mov_dd_rd( 0x0f[8]:> <:0x23[8]:> <:0b11[2]:gn[3]:rm[3] );
// 
// mov_dd_rd.disasm = { _sink << "mov " << DisasmGd( rm ) << ',' << DisasmDd( gn ); };
// 
// op sgdt_ms( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b000[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// sgdt_ms.disasm = { _sink << "sgdtl " << DisasmM( modrm, segment ); };
// 
// op vmcall( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b000[3]:0b001[3]:> rewind <:*modrm[ModRM] );
// 
// vmcall.disasm = { _sink << "vmcall"; };
// 
// op vmlaunch( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b000[3]:0b010[3]:> rewind <:*modrm[ModRM] );
// 
// vmlaunch.disasm = { _sink << "vmlaunch "; };
// 
// op vmresume( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b000[3]:0b011[3]:> rewind <:*modrm[ModRM] );
// 
// vmresume.disasm = { _sink << "vmresume "; };
// 
// op vmxoff( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b000[3]:0b100[3]:> rewind <:*modrm[ModRM] );
// 
// vmxoff.disasm = { _sink << "vmxoff "; };
// 
// op sidt_ms( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b001[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// sidt_ms.disasm = { _sink << "sidtl " << DisasmM( modrm, segment ); };
// 
// op monitor( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b001[3]:0b000[3]:> rewind <:*modrm[ModRM] );
// 
// monitor.disasm = { _sink << "monitor "; };
// 
// op mwait( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b001[3]:0b001[3]:> rewind <:*modrm[ModRM] );
// 
// mwait.disasm = { _sink << "mwait "; };
// 
// op clac( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b001[3]:0b010[3]:> rewind <:*modrm[ModRM] );
// 
// clac.disasm = { _sink << "clac "; };
// 
// op stac( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b001[3]:0b011[3]:> rewind <:*modrm[ModRM] );
// 
// stac.disasm = { _sink << "stac "; };
// 
// op lgdt_ms( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b010[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lgdt_ms.disasm = { _sink << "lgdtl " << DisasmM( modrm, segment ); };
// 
// op vmfunc( 0x0f[8]:> <:0x01[8]:> <:0b11[2]:0b010[3]:0b100[3]:> rewind <:*modrm[ModRM] );
// 
// vmfunc.disasm = { _sink << "vmfunc "; };
// 
// op lidt_ms( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b011[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lidt_ms.disasm = { _sink << "lidtl " << DisasmM( modrm, segment ); };
// 
// op smsw_ed( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b100[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// smsw_ed.disasm = { _sink << "smsw " << DisasmEd( modrm, segment ); };
// 
// op lmsw_ed( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b110[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lmsw_ed.disasm = { _sink << "lmsw " << DisasmEd( modrm, segment ); };
// 
// op invlpg_mb( 0x0f[8]:> <:0x01[8]:> <:?[2]:0b111[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// invlpg_mb.disasm = { _sink << "invlpg " << DisasmM( modrm, segment ); };
// 
// op prefetch( 0x0f[8]:> <:0x0d[8]:> <:?[2]:0b000[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// prefetch.disasm = { _sink << "prefetch " << DisasmM( modrm, segment ); };
// 
// op prefetchw( 0x0f[8]:> <:0x0d[8]:> <:?[2]:0b001[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// prefetchw.disasm = { _sink << "prefetchw " << DisasmM( modrm, segment ); };
// 
// op prefetchwt1( 0x0f[8]:> <:0x0d[8]:> <:?[2]:0b010[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// prefetchwt1.disasm = { _sink << "prefetchwt1 " << DisasmM( modrm, segment ); };
// 
// op sldt( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b000[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// sldt.disasm = { _sink << "sldt " << DisasmEd( modrm, segment ); };
// 
// op str( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b001[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// str.disasm = { _sink << "str " << DisasmEd( modrm, segment ); };
// 
// op lldt( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b010[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// lldt.disasm = { _sink << "lldt " << DisasmEw( modrm, segment ); };
// 
// op ltr( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b011[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// ltr.disasm = { _sink << "ltr " << DisasmEw( modrm, segment ); };
// 
// op verr( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b100[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// verr.disasm = { _sink << "verr " << DisasmEw( modrm, segment ); };
// 
// op verw( 0x0f[8]:> <:0x0[8]:> <:?[2]:0b101[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// verw.disasm = { _sink << "verw " << DisasmEw( modrm, segment ); };
// 

template <class ARCH>
struct XSave : public Operation<ARCH>
{
  XSave( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, XSaveMode _mode, bool _is64 ) : Operation<ARCH>( opbase ), rmop(_rmop), mode(_mode), is64(_is64) {}
  
  void disasm( std::ostream& sink ) const
  {
    sink << "xsave";
    if      (mode.code == mode.BASE) sink << "";
    else if (mode.code == mode.OPT)  sink << "opt";
    else if (mode.code == mode.C)    sink << "c";
    else if (mode.code == mode.S)    sink << "s";
    else throw 0;
    if (is64) sink << "64";
  }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u64_t u64_t;
    arch.xsave( mode, is64, (u64_t(arch.regread( GOd(), 2 )) << 32) | (u64_t(arch.regread( GOd(), 0 )) << 0), rmop );
  }

  RMOp<ARCH> rmop;
  XSaveMode mode;
  bool is64;
};

template <class ARCH>
struct XRstor : public Operation<ARCH>
{
  XRstor( OpBase<ARCH> const& opbase, MOp<ARCH> const* _rmop, XSaveMode _mode, bool _is64 ) : Operation<ARCH>( opbase ), rmop(_rmop), mode(_mode), is64(_is64) {}
  
  void disasm( std::ostream& sink ) const
  {
    sink << "xrstor";
    if      (mode.code == mode.BASE) sink << "";
    else if (mode.code == mode.S)    sink << "s";
    else throw 0;
    if (is64) sink << "64";
  }
  
  void execute( ARCH& arch ) const
  {
    typedef typename ARCH::u64_t u64_t;
    arch.xrstor( mode, is64, (u64_t(arch.regread( GOd(), 2 )) << 32) | (u64_t(arch.regread( GOd(), 0 )) << 0), rmop );
  }

  RMOp<ARCH> rmop;
  XSaveMode mode;
  bool is64;
};

template <class ARCH> struct DC<ARCH,XSAVE>
{ Operation<ARCH>* get( InputCode<ARCH> const& ic ) {
  if (ic.lock_f0) return 0;

  if (auto _ = match( ic, opcode( "\x0f\xae" ) /4 & RM_mem() )) return new XSave<ARCH>( _.opbase(), _.rmop(), XSaveMode::BASE, ic.rex_w );

  if (auto _ = match( ic, opcode( "\x0f\xae" ) /5 & RM_mem() )) return new XRstor<ARCH>( _.opbase(), _.rmop(), XSaveMode::BASE, ic.rex_w );

  if (auto _ = match( ic, opcode( "\x0f\xae" ) /6 & RM_mem() )) return new XSave<ARCH>( _.opbase(), _.rmop(), XSaveMode::OPT, ic.rex_w );

  if (auto _ = match( ic, opcode( "\x0f\xc7" ) /4 & RM_mem() )) return new XSave<ARCH>( _.opbase(), _.rmop(), XSaveMode::C, ic.rex_w );

  if (auto _ = match( ic, opcode( "\x0f\xc7" ) /5 & RM_mem() )) return new XSave<ARCH>( _.opbase(), _.rmop(), XSaveMode::S, ic.rex_w );

  if (auto _ = match( ic, opcode( "\x0f\xc7" ) /3 & RM_mem() )) return new XRstor<ARCH>( _.opbase(), _.rmop(), XSaveMode::S, ic.rex_w );

  return 0;
}};

// op xrstor( 0x0f[8]:> <:0xae[8]:> <:?[2]:0b101[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// xrstor.disasm = { _sink << "xrstor " << DisasmM( modrm, segment ); };
// 
// op clflush( 0x0f[8]:> <:0xae[8]:> <:?[2]:0b111[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// clflush.disasm = { _sink << "clflush " << DisasmM( modrm, segment ); };
// 
// op vmptrld( 0x0f[8]:> <:0xc7[8]:> <:?[2]:0b110[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// vmptrld.disasm = { _sink << "vmptrld " << DisasmM( modrm, segment ); };
// 
// op vmclear( 0x66[8]:> <:0x0f[8]:> <:0xc7[8]:> <:?[2]:0b110[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// vmclear.disasm = { _sink << "vmclear " << DisasmM( modrm, segment ); };
// 
// op vmxon( 0xf3[8]:> <:0x0f[8]:> <:0xc7[8]:> <:?[2]:0b110[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// vmxon.disasm = { _sink << "vmxon " << DisasmM( modrm, segment ); };
// 
// op vmptrst1( 0x0f[8]:> <:0xc7[8]:> <:?[2]:0b111[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// vmptrst1.disasm = { _sink << "vmptrst " << DisasmM( modrm, segment ); };
// 
// op vmptrst2( 0xf3[8]:> <:0x0f[8]:> <:0xc7[8]:> <:?[2]:0b111[3]:?[3]:> rewind <:*modrm[ModRM] );
// 
// vmptrst2.disasm = { _sink << "vmptrst " << DisasmM( modrm, segment ); };
// 

template <class ARCH>
struct Fence : public Operation<ARCH>
{
  Fence( OpBase<ARCH> const& opbase, char const* _mnemo ) : Operation<ARCH>( opbase ), mnemo(_mnemo) {}
  void disasm( std::ostream& sink ) const { sink << mnemo; }
  void execute( ARCH& arch ) const { /*arch.fence();*/ }
  char const* mnemo;
};

template <class ARCH> struct DC<ARCH,FENCE> { Operation<ARCH>* get( InputCode<ARCH> const& ic )
{
  if (auto _ = match( ic, opcode( "\x0f\xae\xe8" ) ))

    return new Fence<ARCH>( _.opbase(), "lfence" );
  
  if (auto _ = match( ic, opcode( "\x0f\xae\xf0" ) ))

    return new Fence<ARCH>( _.opbase(), "mfence" );
  
  if (auto _ = match( ic, opcode( "\x0f\xae\xf8" ) ))

    return new Fence<ARCH>( _.opbase(), "sfence" );
  
  return 0;
}};

