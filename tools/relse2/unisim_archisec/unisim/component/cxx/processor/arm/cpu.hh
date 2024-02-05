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
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr), Daniel Gracia Perez (daniel.gracia-perez@cea.fr)
 */

#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_HH__

#include <unisim/component/cxx/vector/vector.hh>
#include <unisim/component/cxx/processor/arm/exception.hh>
#include <unisim/component/cxx/processor/arm/psr.hh>
#include <unisim/component/cxx/processor/arm/cp15.hh>
#include <unisim/kernel/logger/logger.hh>
#include <unisim/util/endian/endian.hh>
#include <unisim/util/inlining/inlining.hh>
#include <unisim/service/interfaces/registers.hh>
#include <unisim/service/interfaces/register.hh>
#include <map>
#include <set>
#include <stdexcept>
#include <inttypes.h>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

/** Base class for the ARM family.
 *
 * This class is the base for all the cpu's of the ARM processor
 * family, for that purpose it defines the basic registers and
 * different methods to handle them.
 */

template <typename FP_IMPL, typename CPU_IMPL>
struct CPU
  : public virtual unisim::kernel::Object
  , public unisim::kernel::Service<unisim::service::interfaces::Registers>
{
  typedef FP_IMPL FP;
  typedef typename FP::F64  F64;
  typedef typename FP::F32  F32;
  typedef uint8_t  U8;
  typedef uint16_t U16;
  typedef uint32_t U32;
  typedef uint64_t U64;
  typedef int8_t   S8;
  typedef int16_t  S16;
  typedef int32_t  S32;
  typedef int64_t  S64;
  typedef bool     BOOL;
  
  /*
   * ARM architecture constants
   */
    
  /* values of the different condition codes */
  static uint32_t const COND_EQ = 0x00;
  static uint32_t const COND_NE = 0x01;
  static uint32_t const COND_CS_HS = 0x02;
  static uint32_t const COND_CC_LO = 0x03;
  static uint32_t const COND_MI = 0x04;
  static uint32_t const COND_PL = 0x05;
  static uint32_t const COND_VS = 0x06;
  static uint32_t const COND_VC = 0x07;
  static uint32_t const COND_HI = 0x08;
  static uint32_t const COND_LS = 0x09;
  static uint32_t const COND_GE = 0x0a;
  static uint32_t const COND_LT = 0x0b;
  static uint32_t const COND_GT = 0x0c;
  static uint32_t const COND_LE = 0x0d;
  static uint32_t const COND_AL = 0x0e;

  /* mask for valid bits in processor control and status registers */
  static uint32_t const PSR_UNALLOC_MASK = 0x00f00000;
  /* Number of logic registers */
  static unsigned const num_log_gprs = 16;
  
  /** Base class for the ARM Modes
   *
   * This class is the base for all ARM Modes specifying the interface
   * of Mode related operation. Basically it specifies accessors for
   * banked registers and SPSR. It also introduce an internal swaping
   * mechanism to save/restore bancked registers.
   */
  
  struct Mode
  {
    Mode( char const* _suffix ) : suffix( _suffix ) {} char const* suffix;
    virtual ~Mode() {}
    virtual bool     HasBR( unsigned index ) { return false; }
    virtual bool     HasSPSR() { return false; }
    virtual void     SetSPSR(uint32_t value ) { throw std::logic_error("No SPSR for this mode"); };
    virtual uint32_t GetSPSR() { throw std::logic_error("No SPSR for this mode"); return 0; };
    virtual void     Swap( CPU& cpu ) {};
  };
  
  //=====================================================================
  //=                       Logger                                      =
  //=====================================================================
  
  /** Unisim logging services. */
  unisim::kernel::logger::Logger logger;
  /** Verbosity of the CPU implementation */
  bool verbose;
  
  //=====================================================================
  //=                  public service imports/exports                   =
  //=====================================================================
		
  //=====================================================================
  //=                    Constructor/Destructor                         =
  //=====================================================================
	
  CPU(const char* name, Object* parent);
  ~CPU();
  
  /********************************************/
  /* General Purpose Registers access methods */
  /********************************************/
		
  /* GPR access functions */
  /** Get the value contained by a GPR.
   *
   * @param id the register index
   * @return the value contained by the register
   */
  uint32_t GetGPR(uint32_t id) const
  {
    return gpr[id];
  }

  /** Assign a GPR with a value coming from the Execute stage (See
   * ARM's ALUWritePC).  In ARMv7 architectures this is interworking
   * except in thumb state.
   *
   * @param id the register index
   * @param val the value to set
   */
  void SetGPR(uint32_t id, uint32_t val)
  {
    if (id != 15) gpr[id] = val;
    else if (cpsr.Get( T )) this->Branch( val, B_JMP );
    else this->BranchExchange( val, B_JMP );
  }
	
  /** Assign a GPR with a value coming from the Memory stage.  From
   * ARMv5T architectures, this is always interworking (exchanging
   * branch when destination register is PC).
   *
   * @param id the register index
   * @param val the value to set
   */
  void SetGPR_mem(uint32_t id, uint32_t val)
  {
    if (id != 15) gpr[id] = val;
    else this->BranchExchange( val, B_JMP );
  }
  
  enum branch_type_t { B_JMP = 0, B_CALL, B_RET, B_EXC, B_DBG, B_RFE };
  /** Sets the PC (and potentially exchanges mode ARM<->Thumb)
   *
   * @param val the value to set PC
   */
  void BranchExchange(uint32_t target, branch_type_t branch_type)
  {
    this->cpsr.Set( T, target & 1 );
    this->Branch( target, branch_type );
  }
	
  /** Sets the PC (fixing alignment and preserving mode)
   *
   * @param val the value to set PC
   */
  void Branch(uint32_t target, branch_type_t branch_type)
  {
    this->next_insn_addr = target & (this->cpsr.Get( T ) ? -2 : -4);
  }
	
  /** Gets the current instruction address
   *
   */
  uint32_t GetCIA()
  { return this->current_insn_addr; }
	
  /** Gets the next instruction address (as currently computed)
   *
   */
  uint32_t GetNIA()
  { return this->next_insn_addr; }
	
  /******************************************/
  /* Program Status Register access methods */
  /******************************************/
  
  /** Get the CPSR register.
   *
   * @return the CPSR structured register.
   */
  PSR&     CPSR() { return cpsr; };
  
  void     SetCPSR( uint32_t bits, uint32_t mask );
  
  uint32_t GetCPSR() const { return cpsr.Get(ALL32); }
  uint32_t GetNZCV() const { return cpsr.Get(NZCV); }
  
  /** Get the endian configuration of the processor.
   *
   * @return the endian being used
   */
  unisim::util::endian::endian_type
  GetEndianness() const
  {
    return (this->cpsr.Get( E ) == 0) ? unisim::util::endian::E_LITTLE_ENDIAN : unisim::util::endian::E_BIG_ENDIAN;
  }

  /** Determine wether the processor instruction stream is inside an
   * IT block.
   */
  bool itblock() const { return CPU_IMPL::Config::insnsT2 ? cpsr.InITBlock() : false; }
  
  /** Return the current condition associated to the IT state of the
   * processor.
   */
  uint32_t itcond() const { return CPU_IMPL::Config::insnsT2 ? cpsr.ITGetCondition() : COND_AL; }
  
  bool m_isit; /* determines wether current instruction is an IT one. */
  void ITSetState( uint32_t cond, uint32_t mask )
  {
    this->cpsr.ITSetState( cond, mask );
    m_isit = true;
  }
  void ITAdvance()
  {
    if (m_isit)
      this->m_isit = false;
    else if (this->itblock())
      this->cpsr.ITAdvance();
  }

  /*********************************************/
  /* Modes and Banked Registers access methods */
  /*********************************************/
  
  Mode& GetMode(uint8_t mode)
  {
    typename ModeMap::iterator itr = modes.find(mode);
    if (itr == modes.end()) UnpredictableInsnBehaviour();
    return *(itr->second);
  }
  
  unsigned GetPL();
  void RequiresPL(unsigned rpl);
  
  Mode& CurrentMode() { return GetMode(cpsr.Get(M)); }
  
  /** Get the value contained by a banked register GPR.
   *
   * Returns the value contained by a banked register.  It is the same
   * than GetGPR but mode can be different from the running mode.
   *
   * @param mode the mode of banked register
   * @param idx the register index
   * @return the value contained by the register
   */
  uint32_t GetBankedRegister( uint8_t foreign_mode, uint32_t idx )
  {
    uint8_t running_mode = cpsr.Get( M );
    if (running_mode == foreign_mode) return GetGPR( idx );
    GetMode(running_mode).Swap(*this); // OUT
    GetMode(foreign_mode).Swap(*this); // IN
    uint32_t value = GetGPR( idx );
    GetMode(foreign_mode).Swap(*this); // OUT
    GetMode(running_mode).Swap(*this); // IN
    return value;
  }
  
  /** Set the value contained by a user GPR.
   *
   * Sets the value contained by a user GPR. It is the same than
   * SetGPR but mode can be different from the running mode.
   *
   * @param mode the mode of banked register
   * @param idx the register index
   * @param val the value to set
   */
  void SetBankedRegister( uint8_t foreign_mode, uint32_t idx, uint32_t value )
  {
    uint8_t running_mode = cpsr.Get( M );
    if (running_mode == foreign_mode) return SetGPR( idx, value );
    GetMode(running_mode).Swap(*this); // OUT
    GetMode(foreign_mode).Swap(*this); // IN
    SetGPR( idx, value );
    GetMode(foreign_mode).Swap(*this); // OUT
    GetMode(running_mode).Swap(*this); // IN
  }
  
  /************************************************************************/
  /* Exception handling                                             START */
  /************************************************************************/

public:
  bool     Test( bool cond ) { return cond; }
  virtual void UnpredictableInsnBehaviour();
  void     CallSupervisor( uint32_t imm );
  bool     IntegerZeroDivide( bool zero_div ) { return zero_div; }
  virtual void WaitForInterrupt() {}; // Implementation-defined
  
protected:
  uint32_t     HandleAsynchronousException( uint32_t );
  uint32_t     ExcVectorBase();
  void         TakeReset();
  void         TakePhysicalFIQorIRQException( bool isIRQ );
  virtual void BranchToFIQorIRQvector( bool isIRQ );
  void         TakeSVCException();
  void         TakeDataOrPrefetchAbortException( bool isdata );
  void         TakeUndefInstrException();

  /************************************************************************/
  /* Exception handling                                               END */
  /************************************************************************/

  /**************************/
  /* CP15 Interface   START */
  /**************************/

public:
  struct CP15Reg
  {
    virtual         ~CP15Reg() {}
    virtual void     CheckPermissions(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, bool) const { cpu.RequiresPL(1); }
    virtual void     Write(uint8_t crn, uint8_t op1, uint8_t crm, uint8_t op2, CPU_IMPL& cpu, uint32_t value) const
    {
      cpu.logger << unisim::kernel::logger::DebugError << "Writing " << Description(crn, op1, crm, op2)
                 << " (pc=" << std::hex << cpu.current_insn_addr << std::dec << ")" << unisim::kernel::logger::EndDebugError;
      cpu.UnpredictableInsnBehaviour();
    }
    virtual uint32_t Read(uint8_t crn, uint8_t op1, uint8_t crm, uint8_t op2, CPU_IMPL& cpu) const
    {
      cpu.logger << unisim::kernel::logger::DebugError << "Reading " << Description(crn, op1, crm, op2)
                 << " (pc=" << std::hex << cpu.current_insn_addr << std::dec << ")" << unisim::kernel::logger::EndDebugError;
      cpu.UnpredictableInsnBehaviour();
      return 0;
    }
    virtual void Describe(uint8_t crn, uint8_t op1, uint8_t crm, uint8_t op2, std::ostream& sink) const
    {
      sink << Description(crn, op1, crm, op2);
    }
    struct Description
    {
      Description(uint8_t _crn, uint8_t _op1, uint8_t _crm, uint8_t _op2) : crn(_crn), op1(_op1), crm(_crm), op2(_op2) {}
      friend std::ostream& operator << (std::ostream& sink, Description const& d)
      { return sink << "CR15{crn=" << int(d.crn) << ", op1=" << int(d.op1) << ", crm=" << int(d.crm) << ", op2=" << int(d.op2) << "}"; }
      uint8_t crn; uint8_t op1; uint8_t crm; uint8_t op2;
    };
  };
  
  static CP15Reg* CP15GetRegister(uint8_t crn, uint8_t op1, uint8_t crm, uint8_t op2);
  void            CP15ResetRegisters();
    
  /**************************/
  /* CP15 Interface     END */
  /**************************/

protected:
  /*
   * Memory access variables
   */
  
  /* Storage for Modes and banked registers */
  typedef std::map<uint8_t, Mode*> ModeMap;
  ModeMap modes;
  
  /** Storage for the logical registers */
  uint32_t gpr[num_log_gprs];
  uint32_t current_insn_addr, next_insn_addr;
  
  /** PSR registers */
  PSR      cpsr;
  
  /***********************************/
  /* System control registers  START */
  /***********************************/

  uint32_t SCTLR; //< System Control Register
  uint32_t CPACR; //< CPACR, Coprocessor Access Control Register
  
  /***********************************/
  /* System control registers   END  */
  /***********************************/
  
  /****************************************************/
  /* Process, context and thread ID registers   START */
  /****************************************************/
  
  uint32_t CONTEXTIDR; //< Context ID Register
  uint32_t TPIDRURW; //< User Read/Write Thread ID Register
  uint32_t TPIDRURO; //< User Read-Only Thread ID Register
  uint32_t TPIDRPRW; //< PL1 only Thread ID Register
  
  /****************************************************/
  /* Process, context and thread ID registers    END  */
  /****************************************************/

public:
  // VFP/NEON registers
  virtual void FPTrap( unsigned fpx ) { throw std::logic_error("unimplemented FP trap"); }
  
  U32 FPSCR, FPEXC;

  U32 RoundTowardsZeroFPSCR() const { U32 fpscr = FPSCR; RMode.Set( fpscr, U32(RoundTowardsZero) ); return fpscr; }
  U32 RoundToNearestFPSCR() const   { U32 fpscr = FPSCR; RMode.Set( fpscr, U32(RoundToNearest) ); return fpscr; }
  U32 StandardValuedFPSCR() const   { return AHP.Mask( FPSCR ) | 0x03000000; }
  
  static unsigned const VECTORCOUNT = 32;

  struct VUConfig
  {
    static unsigned const BYTECOUNT = 8;
    template <typename T> using TypeInfo = unisim::component::cxx::vector::VectorTypeInfo<T,0>;
    typedef U8 Byte;
  };
  unisim::component::cxx::vector::VUnion<VUConfig> vector_views[VECTORCOUNT];

  uint8_t vector_data[VECTORCOUNT][VUConfig::BYTECOUNT];

  //====================================================================
  //=                 Special  Registers access methods
  //====================================================================

  template <typename T>
  T vector_read(unsigned reg, unsigned sub)
  {
    return (vector_views[reg].GetConstStorage(&vector_data[reg], T(), VUConfig::BYTECOUNT))[sub];
  }

  U32 GetVSU( unsigned reg )                 { return vector_read<U32> (reg/2, reg%2); }
  U64 GetVDU( unsigned reg )                 { return vector_read<U64> (reg, 0); }
  F32 GetVSR( unsigned reg )                 { return vector_read<F32> (reg/2, reg%2); }
  F64 GetVDR( unsigned reg )                 { return vector_read<F64> (reg, 0); }

  template <class ELEMT>
  ELEMT GetVDE( unsigned reg, unsigned idx, ELEMT const& trait )
  {
    return ELEMT( vector_read<ELEMT>(reg, idx) );
  }

  U8 GetTVU8(unsigned r0, unsigned elts, unsigned regs, U8 idx, U8 oob)
  {
    auto r = idx/elts;
    return r < regs ? GetVDE((r0 + r) % 32, idx % elts, U8()) : oob;
  }
  
  template <typename T>
  void vector_write(unsigned reg, unsigned sub, T value )
  {
    (vector_views[reg].GetStorage(&vector_data[reg], value, VUConfig::BYTECOUNT))[sub] = value;
  }

  void SetVSU( unsigned reg, U32 const& val ) { vector_write( reg/2, reg%2, val ); }
  void SetVDU( unsigned reg, U64 const& val ) { vector_write( reg, 0, val ); }
  void SetVSR( unsigned reg, F32 const& val ) { vector_write( reg/2, reg%2, val ); }
  void SetVDR( unsigned reg, F64 const& val ) { vector_write( reg, 0, val ); }

  template <class ELEMT>
  void SetVDE( unsigned reg, unsigned idx, ELEMT const& value )
  {
    vector_write(reg, idx, value);
  }

  /*************************************/
  /* Debug Registers             START */
  /*************************************/
  
public:

  virtual unisim::service::interfaces::Register* GetRegister( const char* name );
  virtual void ScanRegisters( unisim::service::interfaces::RegisterScanner& scanner );
		
  unisim::kernel::ServiceExport<unisim::service::interfaces::Registers> registers_export;
  
protected:
  /** The registers interface for debugging purpose */
  typedef std::map<std::string, unisim::service::interfaces::Register*> RegistersRegistry;
  RegistersRegistry registers_registry;
  
  typedef std::set<unisim::kernel::VariableBase*> VariableRegisterPool;
  VariableRegisterPool variable_register_pool;
  
  /*************************************/
  /* Debug Registers              END  */
  /*************************************/
  
  virtual void Sync() = 0;
};
	
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_HH__
