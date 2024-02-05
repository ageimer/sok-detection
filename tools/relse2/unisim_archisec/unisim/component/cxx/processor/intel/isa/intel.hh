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

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_HH__

//#include <typeinfo>
#include <inttypes.h>

#include <iosfwd>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace intel {

  struct Mode
  {
    // TODO: should handle non protected mode (where cs_l, cs_d and ss_b are ignored)
    uint8_t cs_l     : 1; // 64-bit modes
    uint8_t cs_d     : 1; // default size
    uint8_t ss_b     : 1; // stack address size
    uint8_t pad      : 5;
    
    Mode() : cs_l( 0 ), cs_d( 0 ), ss_b( 0 ), pad( 0 ) {}
    Mode( uint8_t _csl, uint8_t _csd, uint8_t _ssb ) : cs_l( _csl ), cs_d( _csd ), ss_b( _ssb ), pad(0) {}

    int cmp( Mode const& rhs ) const
    {
      if (int delta = int(cs_l) - int(rhs.cs_l)) return delta;
      if (int delta = int(cs_d) - int(rhs.cs_d)) return delta;
      return int(ss_b) - int(rhs.ss_b);
    }
    
    bool operator == ( Mode const& m ) const { return cmp(m) == 0; }
    bool operator != ( Mode const& m ) const { return cmp(m) != 0; }
  };
  
  template <class ARCH>
  struct OpBase : public ARCH::OpHeader
  {
    typedef typename ARCH::OpHeader Header;
    
    Mode     mode;
    uint8_t  length;
    
    OpBase( Header const& _header, Mode _mode, uint8_t _length ) : Header( _header ), mode( _mode ), length( _length ) {}
  };
  
  template <class ARCH>
  struct Operation : public OpBase<ARCH>
  {
    Operation( OpBase<ARCH> const& _opbase ) : OpBase<ARCH>( _opbase ) {}
    virtual ~Operation() {}
    virtual void disasm( std::ostream& _sink ) const = 0;
    virtual void execute( ARCH& arch ) const;
  };

  struct CodeBase
  {
    uint8_t const* bytes;
    Mode           mode;
    
    enum {ES=0, CS=1, SS=2, DS=3, FS=4, GS=5};
    
    /*** PreDecoded ***/
    uint32_t adsz_67        : 1; /* grp4 */
    uint32_t opsz_66        : 1; /* grp3 */
    uint32_t lock_f0        : 1; /* grp1.lock */
    uint32_t segment        : 3; /* grp2 */
    uint32_t rep            : 2; /* grp1.rep {0: None, 2: F2, 3: F3} */
    uint32_t opcode_offset  : 4; /* opcode offset from starting byte (prefix length). */
    uint32_t rex_b          : 1;
    uint32_t rex_x          : 1;
    uint32_t rex_r          : 1;
    uint32_t rex_w          : 1;
    uint32_t rex_p          : 1; /* rex present */

    struct PrefixError { PrefixError(unsigned _len) : len(_len) {} unsigned len; };

    uint8_t const* opcode() const { return &bytes[opcode_offset]; }
    
    bool set_vex_bits( uint8_t nrex, uint8_t pp )
    {
      if (opsz_66 or rep or rex_p)
        return false;
      
      pp &= 3;
      if (pp == 1) opsz_66 = 1;
      else if (pp != 0) rep = pp ^ 1;

      rex_r = ~nrex >> 7;
      rex_x = ~nrex >> 6;
      rex_b = ~nrex >> 5;
      
      return true;
    }
    
    CodeBase( Mode _mode, uint8_t const* bptr )
      : bytes( bptr ), mode( _mode )
      , adsz_67( 0 ), opsz_66( 0 ), lock_f0( 0 ), segment( DS ), rep( 0 ), opcode_offset( 0 )
      , rex_b(0), rex_x(0), rex_r(0), rex_w(0), rex_p(0)
    {
      for (unsigned bcnt = 0; bcnt < 15; ++bptr, ++bcnt)
        {
          switch (*bptr)
            {
              // OpCode
            default:
              if (mode64() and (*bptr & 0xf0) == 0x40)
                {
                  /* REX prefix */
                  if (rex_p) throw PrefixError(opcode_offset+1);
                  rex_p = 1; rex_w = bptr[0] >> 3; rex_r = bptr[0] >> 2; rex_x = bptr[0] >> 1; rex_b = bptr[0] >> 0;
                  opcode_offset = bptr - bytes + 1;
                  /* REX should be the last prefix, go check */
                  continue;
                }
              /* VEX prefixes */
              if (bptr[0] == 0xc5 and (mode64() or (bptr[1] >> 6) == 3))
                {
                  /* Two-bytes VEX prefix */
                  if (bcnt > 13 or not set_vex_bits( bptr[1] | 0x60, bptr[1] ))
                    throw PrefixError(bptr - bytes + 1);
                }
              else if (bptr[0] == 0xc4 and (mode64() or (bptr[1] >> 6) == 3))
                {
                  /* Three-bytes VEX prefix */
                  if (bcnt > 12 or not set_vex_bits( bptr[1], bptr[2] ))
                    throw PrefixError(bptr - bytes + 1);
                  rex_w = bptr[2] >> 7;
                }
              if (rex_p and (bptr[-1] & 0xf0) != 0x40)
                throw PrefixError(opcode_offset + 1);
              opcode_offset = bptr - bytes;
              return;
              // Group1::lock
            case 0xf0: lock_f0 = true; break;
              // Group1::repeat
            case 0xf2: rep = 2; break;
            case 0xf3: rep = 3; break;
              // Group2 (segments)
              // In 64-bit the CS, SS, DS and ES segment overrides are ignored.
            case /*046*/ 0x26: if (not mode64()) segment = ES; break;
            case /*056*/ 0x2e: if (not mode64()) segment = CS; break;
            case /*066*/ 0x36: if (not mode64()) segment = SS; break;
            case /*076*/ 0x3e: if (not mode64()) segment = DS; break;
            case /*144*/ 0x64: segment = FS; break;
            case /*145*/ 0x65: segment = GS; break;
              // Group3 (alternative operand size)
            case 0x66: opsz_66 = true; break;
              // Group4 (alternative address size)
            case 0x67: adsz_67 = true; break;
            }
        }
      throw PrefixError(15);
    }
    unsigned w() const { return rex_w; }
    unsigned opclass() const { return rex_w ? 3 : (mode.cs_l ^ mode.cs_d ^ opsz_66) ? 2 : 1; }
    unsigned opsize() const { return 8 << opclass(); }
    unsigned addrclass() const { return mode64() ? (adsz_67 ? 2 : 3 ) : (mode.cs_d ^ adsz_67) ? 2 : 1; }
    unsigned addrsize() const { return 8 << addrclass(); }
    bool f0() const { return lock_f0 == 1; }
    bool f3() const { return rep == 3; }
    bool f2() const { return rep == 2; }
    bool _66() const { return opsz_66; }
    bool mode64() const { return mode.cs_l != 0; }
    bool vex() const { return (*opcode() | 1) == 0xc5; }
    unsigned vlen() const { uint8_t const* v = opcode(); return (v[2 - (v[0] & 1)] & 4) ? 256 : 128; }
    unsigned vreg() const { uint8_t const* v = opcode(); return ~(v[2 - (v[0] & 1)] >> 3) & 15; }
  };
  
  template <class ARCH>
  struct InputCode : public CodeBase
  {
    typedef typename ARCH::OpHeader OpHeader;
    OpHeader       header;
    
    InputCode( Mode _mode, uint8_t const* _bytes, OpHeader const& _header )
      : CodeBase( _mode, _bytes ), header( _header )
    {}
  };
  
} // end of namespace intel
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_INTEL_ISA_INTEL_HH__
