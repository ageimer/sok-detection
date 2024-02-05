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
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES;LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 *  SUCH DAMAGE.
 *
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr), Daniel Gracia Perez (daniel.gracia-perez@cea.fr)
 */

 
#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_TCC__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_TCC__

#include <unisim/component/cxx/processor/arm/disasm.hh>
#include <unisim/component/cxx/processor/arm/cpu.hh>
#include <unisim/component/cxx/processor/arm/exception.hh>
#include <unisim/component/cxx/processor/arm/models.hh>
#include <unisim/component/cxx/processor/arm/cp15.hh>
#include <unisim/kernel/variable/variable.hh>
#include <unisim/util/likely/likely.hh>
#include <unisim/util/arithmetic/arithmetic.hh>
#include <unisim/util/endian/endian.hh>
#include <unisim/util/debug/simple_register.hh>
#include <unisim/util/backtrace/backtrace.hh>


namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

using unisim::kernel::logger::DebugInfo;
using unisim::kernel::logger::EndDebugInfo;
using unisim::kernel::logger::DebugWarning;
using unisim::kernel::logger::EndDebugWarning;
using unisim::kernel::logger::DebugError;
using unisim::kernel::logger::EndDebugError;

/** ModeInfo: compile time generation for parameters of ARM modes with banked registers
 *
 * This meta class generates at compile-time parameters and structure
 * of Banked Registers for ARM Modes.
 */

template <uint32_t MAPPED>
struct ModeInfo
{
  static uint32_t const next = MAPPED & (MAPPED-1);
  static uint32_t const count = 1 + ModeInfo<next>::count;
};

template <> struct ModeInfo<0> { static uint32_t const count = 0; };

template <class CORE, uint32_t MAPPED>
struct BankedMode : public CORE::Mode
{
  BankedMode( char const* _suffix )
    : CORE::Mode( _suffix ), banked_regs(), spsr()
  {
  }
  uint32_t banked_regs[ModeInfo<MAPPED>::count];
  uint32_t spsr;

  virtual bool     HasBR( unsigned idx ) { return (MAPPED >> idx) & 1; }
  virtual bool     HasSPSR() { return true; }
  virtual void     SetSPSR(uint32_t value ) { spsr = value; };
  virtual uint32_t GetSPSR() { return spsr; };
  virtual void     Swap( CORE& cpu )
  {
    for (unsigned idx = 0, bidx = 0; idx < cpu.num_log_gprs; ++idx)
      if ((MAPPED >> idx) & 1) {
        uint32_t regval = cpu.GetGPR(idx);
        cpu.SetGPR( idx, banked_regs[bidx] );
        banked_regs[bidx] = regval;
        bidx += 1;
      }
  }
};

/** Constructor.
 * Initializes CPU
 *
 * @param name the name that will be used by the UNISIM service 
 *   infrastructure and will identify this object
 * @param parent the parent object of this object
 */
template <class FP_IMPL, class CPU_IMPL>
CPU<FP_IMPL,CPU_IMPL>::CPU(const char *name, Object *parent)
  : unisim::kernel::Object(name, parent)
  , Service<Registers>(name, parent)
  , logger(*this)
  , verbose(false)
  , m_isit(false)
  , SCTLR()
  , CPACR()
  , TPIDRURW()
  , TPIDRURO()
  , FPSCR( 0x03000000 )
  , FPEXC( 0 )
  , registers_export("registers-export", this)
{
  // Initialize general purpose registers
  for (unsigned idx = 0; idx < num_log_gprs; idx++)
    gpr[idx] = 0;
  this->current_insn_addr = 0;
  this->next_insn_addr = 0;
  
  /* ARM modes (Banked Registers)
   * At any given running mode only 16 registers are accessible.
   * The following list indicates the mapping per running modes.
   * - user:           0-14 (R0-R14),                  15 (PC)
   * - system:         0-14 (R0-R14),                  15 (PC)
   * - supervisor:     0-12 (R0-R12), 16-17 (R13-R14), 15 (PC)
   * - abort:          0-12 (R0-R12), 18-19 (R13-R14), 15 (PC)
   * - undefined:      0-12 (R0-R12), 20-21 (R13-R14), 15 (PC)
   * - interrupt:      0-12 (R0-R12), 22-23 (R13-R14), 15 (PC)
   * - fast interrupt: 0-7 (R0-R7),   24-30 (R8-R14),  15 (PC)
   */
  // Initialize ARM Modes (TODO: modes should be conditionnaly selected based on CONFIG)
  modes[0b10000] = new Mode( "usr" ); // User mode (No banked regs, using main regs)
  modes[0b10001] = new BankedMode<CPU,0b0111111100000000>( "fiq" ); // FIQ mode
  modes[0b10010] = new BankedMode<CPU,0b0110000000000000>( "irq" ); // IRQ mode
  modes[0b10011] = new BankedMode<CPU,0b0110000000000000>( "svc" ); // Supervisor mode
  modes[0b10110] = new BankedMode<CPU,0b0110000000000000>( "mon" ); // Monitor mode
  modes[0b10111] = new BankedMode<CPU,0b0110000000000000>( "abt" ); // Abort mode
  modes[0b11010] = new BankedMode<CPU,0b0110000000000000>( "hyp" ); // Hyp mode
  modes[0b11011] = new BankedMode<CPU,0b0110000000000000>( "und" ); // Undefined mode
  modes[0b11111] = new Mode( "sys" ); // System mode (No banked regs, using main regs)
  
  // Initialize NEON/VFP registers
  for (unsigned idx = 0; idx < 32; ++idx)
    SetVDU( idx, U64(0) );

  /*************************************/
  /* Registers Debug Accessors   START */
  /*************************************/
  
  {
    unisim::service::interfaces::Register* dbg_reg = 0;
    unisim::kernel::variable::Register<uint32_t>* var_reg = 0;
  
    /** Specific Banked Register Debugging Accessor */
    struct BankedRegister : public unisim::service::interfaces::Register
    {
      BankedRegister(CPU& _cpu, std::string _name, uint8_t _mode, uint8_t _idx ) : cpu(_cpu), name(_name), mode(_mode), idx(_idx) {}
      virtual const char *GetName() const { return name.c_str(); }
      virtual void GetValue( void* buffer ) const { *((uint32_t*)buffer) = cpu.GetBankedRegister( mode, idx ); }
      virtual void SetValue( void const* buffer ) { cpu.SetBankedRegister( mode, idx, *((uint32_t*)buffer ) ); }
      virtual int  GetSize() const { return 4; }
      CPU&        cpu;
      std::string name;
      uint8_t     mode, idx;
    };
  
    // initialize the registers debugging interface for the first 15 registers
    for (unsigned idx = 0; idx < 15; idx++) {
      std::string name, pretty_name, description;
      { std::stringstream ss; ss << "r" << idx; name = ss.str(); }
      { std::stringstream ss; ss << DisasmRegister( idx ); pretty_name = ss.str(); }
      { std::stringstream ss; ss << "Logical register #" << idx << ": " << pretty_name; description = ss.str(); }
      dbg_reg = new unisim::util::debug::SimpleRegister<uint32_t>( pretty_name, &gpr[idx] );
      registers_registry[pretty_name] = dbg_reg;
      if (name != pretty_name) {
        registers_registry[name] = dbg_reg;
        description =  description + ", " + name;
      }
      var_reg = new unisim::kernel::variable::Register<uint32_t>( pretty_name.c_str(), this, gpr[idx], description.c_str() );
      variable_register_pool.insert( var_reg );
      bool is_banked = false;
      for (typename ModeMap::const_iterator itr = modes.begin(), end = modes.end(); itr != end; ++itr) {
        if (not itr->second->HasBR( idx )) continue;
        is_banked = true;
        std::string br_name = name + '_' + itr->second->suffix;
        std::string br_pretty_name = pretty_name + '_' + itr->second->suffix;
        dbg_reg = new BankedRegister( *this, br_pretty_name, itr->first, idx );
        registers_registry[br_pretty_name] = dbg_reg;
        if (br_name != br_pretty_name)
          registers_registry[br_name] = dbg_reg;
      }
      if (is_banked) {
        std::string br_name = name + "_usr";
        std::string br_pretty_name = pretty_name + "_usr";
        dbg_reg = new BankedRegister( *this, br_pretty_name, PSR::USER_MODE, idx );
        registers_registry[br_pretty_name] = dbg_reg;
        if (br_name != br_pretty_name)
          registers_registry[br_name] = dbg_reg;
      }
    }
  
    /** Specific Program Counter Register Debugging Accessor */
    struct ProgramCounterRegister : public unisim::service::interfaces::Register
    {
      ProgramCounterRegister( CPU& _cpu ) : cpu(_cpu) {}
      virtual const char *GetName() const { return "pc"; }
      virtual void GetValue( void* buffer ) const { *((uint32_t*)buffer) = cpu.next_insn_addr; }
      virtual void SetValue( void const* buffer ) { uint32_t address = *((uint32_t*)buffer); cpu.BranchExchange( address, CPU::B_DBG ); }
      virtual int  GetSize() const { return 4; }
      virtual void Clear() { /* Clear is meaningless for PC */ }
      CPU&        cpu;
    };

    dbg_reg = new ProgramCounterRegister( *this );
    registers_registry["pc"] = registers_registry["r15"] = dbg_reg;
    var_reg = new unisim::kernel::variable::Register<uint32_t>( "pc", this, this->next_insn_addr, "Logical Register #15: pc, r15" );
    variable_register_pool.insert( var_reg );
    
    // Handling the CPSR register
    dbg_reg = new unisim::util::debug::SimpleRegister<uint32_t>( "cpsr", &cpsr.m_value );
    registers_registry["cpsr"] = dbg_reg;
    var_reg = new unisim::kernel::variable::Register<uint32_t>( "cpsr", this, this->cpsr.m_value, "Current Program Status Register" );
    variable_register_pool.insert( var_reg );
    
    /** SPSRs */
    struct SavedProgramStatusRegisterWithMode : public unisim::service::interfaces::Register
    {
      SavedProgramStatusRegisterWithMode( CPU& _cpu, std::string _name, uint8_t _mode ) : cpu(_cpu), name(_name), mode(_mode) {}
      virtual ~SavedProgramStatusRegisterWithMode() {}
      virtual const char *GetName() const { return name.c_str(); }
      virtual void GetValue( void* buffer ) const { *((uint32_t*)buffer) = cpu.GetMode(mode).GetSPSR(); }
      virtual void SetValue( void const* buffer ) { cpu.GetMode(mode).SetSPSR( *((uint32_t*)buffer) ); }
      virtual int  GetSize() const { return 4; }
      CPU&        cpu;
      std::string name;
      uint8_t     mode;
    };
    
    for (typename ModeMap::const_iterator itr = modes.begin(), end = modes.end(); itr != end; ++itr) {
      if (not itr->second->HasSPSR()) continue;
      
      std::string name = std::string( "spsr_" ) + itr->second->suffix;
      dbg_reg = new SavedProgramStatusRegisterWithMode( *this, name, itr->first );
      registers_registry[name] = dbg_reg;
    }
    struct SavedProgramStatusRegister : public unisim::service::interfaces::Register
    {
      SavedProgramStatusRegister( CPU& _cpu ) : cpu(_cpu) {} CPU& cpu;
      virtual ~SavedProgramStatusRegister() {}
      virtual const char *GetName() const { return "spsr"; }
      virtual void GetValue( void* buffer ) const
      {
        try { *((uint32_t*)buffer) = cpu.CurrentMode().GetSPSR(); }
        catch (std::logic_error const&)
          {
            /* Do not produce an error because dwarf says this register always exists */
            *((uint32_t*)buffer) = 0;
            //cpu.logger << DebugError << "No SPSR in " << cpu.CurrentMode().suffix << " mode" << EndDebugError;
          }
      }
      virtual void SetValue( void const* buffer )
      {
        try { cpu.CurrentMode().SetSPSR( *((uint32_t*)buffer) ); }
        catch (std::logic_error const&)
          { cpu.logger << DebugError << "No SPSR in " << cpu.CurrentMode().suffix << " mode" << EndDebugError; }
      }
      virtual int  GetSize() const { return 4; }
    };
    registers_registry["spsr"] = new SavedProgramStatusRegister( *this );
    
    /* SCTLR */
    dbg_reg = new unisim::util::debug::SimpleRegister<uint32_t>( "sctlr", &SCTLR );
    registers_registry["sctlr"] = dbg_reg;
    /* CPACR */
    dbg_reg = new unisim::util::debug::SimpleRegister<uint32_t>( "cpacr", &CPACR );
    registers_registry["cpacr"] = dbg_reg;
    
    // Advanced SIMD and VFP register
    struct VFPDouble : public unisim::service::interfaces::Register
    {
      VFPDouble( CPU& _cpu, std::string _name, unsigned _reg ) : cpu(_cpu), name(_name), reg(_reg) {}
      
      virtual ~VFPDouble() {}
      virtual const char *GetName() const { return name.c_str(); };
      virtual void GetValue( void* buffer ) const { *((uint64_t*)buffer) = cpu.GetVDU( reg ); }
      virtual void SetValue( void const* buffer ) { cpu.SetVDU( reg, *((uint64_t*)buffer) ); }
      virtual int  GetSize() const { return 8; }

      CPU& cpu; std::string name; unsigned reg;
    };
    
    for (unsigned idx = 0; idx < 32; ++idx)
      {
        std::stringstream regname; regname << 'd' << idx;
        dbg_reg = new VFPDouble( *this, regname.str(), idx );
        registers_registry[regname.str()] = dbg_reg;
      }
    
    struct VFPSingle : public unisim::service::interfaces::Register
    {
      VFPSingle( CPU& _cpu, std::string _name, unsigned _reg ) : cpu(_cpu), name(_name), reg(_reg) {}

      virtual ~VFPSingle() {}
      virtual const char *GetName() const { return name.c_str(); };
      virtual void GetValue( void* buffer ) const { *((uint32_t*)buffer) = cpu.GetVSU( reg ); }
      virtual void SetValue( void const* buffer ) { cpu.SetVSU( reg, *((uint32_t*)buffer) ); }
      virtual int  GetSize() const { return 8; }

      CPU& cpu; std::string name; unsigned reg;
    };

    for (unsigned idx = 0; idx < 32; ++idx)
      {
        std::stringstream regname; regname << 's' << idx;
        dbg_reg = new VFPSingle( *this, regname.str(), idx );
        registers_registry[regname.str()] = dbg_reg;
      }
    
    // Handling the FPSCR register
    dbg_reg = new unisim::util::debug::SimpleRegister<uint32_t>( "fpscr", &this->FPSCR );
    registers_registry["fpscr"] = dbg_reg;
    var_reg = new unisim::kernel::variable::Register<uint32_t>( "fpscr", this, this->FPSCR, "Current Program Status Register" );
    variable_register_pool.insert( var_reg );
  }
    
  CP15ResetRegisters();
}

/** Destructor.
 *
 * Takes care of releasing:
 *  - Debug Registers
 */
template <class FP_IMPL, class CPU_IMPL>
CPU<FP_IMPL,CPU_IMPL>::~CPU()
{
  /* Debug registers may be referenced more than once (by different
   * names).  Thus we must keep track of deleted registers in order
   * not to delete them multiple times. */
  { std::set<unisim::service::interfaces::Register*> deleted_regs;
    for (typename RegistersRegistry::iterator itr = registers_registry.begin(),
           end = registers_registry.end(); itr != end; ++itr)
      {
        if (deleted_regs.insert( itr->second ).second)
          delete itr->second;
      }
  }
  
  for (typename VariableRegisterPool::iterator itr = variable_register_pool.begin(),
         end = variable_register_pool.end(); itr != end; ++itr)
    delete *itr;
  for (typename ModeMap::iterator itr = modes.begin(), end = modes.end(); itr != end; ++itr)
    delete itr->second;

  for (unsigned reg = 0; reg < VECTORCOUNT; ++reg)
    vector_views[reg].Clear( &vector_data[reg][0] );
}

/** Modify CPSR internal value with proper side effects
 *
 * @param bits the value of the modified bits
 * @param mask the location of the modified bits
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::SetCPSR( uint32_t bits, uint32_t mask )
{
  uint32_t old_psr = cpsr.m_value;
  uint32_t new_psr = (old_psr & ~mask) | (bits & mask);

  if (M.Get(old_psr ^ new_psr))
    {
      CurrentMode().Swap(*this); // OUT
      cpsr.m_value = new_psr;
      CurrentMode().Swap(*this); // IN
    }
  else
    cpsr.m_value = new_psr;
}

/** Get a register by its name.
 * Gets a register interface to the register specified by name.
 *
 * @param name the name of the requested register
 *
 * @return a pointer to the RegisterInterface corresponding to name
 */
template <class FP_IMPL, class CPU_IMPL>
unisim::service::interfaces::Register*
CPU<FP_IMPL,CPU_IMPL>::GetRegister(const char *name)
{
  RegistersRegistry::iterator itr = registers_registry.find( name );
  if (itr != registers_registry.end())
    return itr->second;
  else
    return 0;
}

/** Get current privilege level
 *
 * Returns the current privilege level according to the running mode.
 */
template <class FP_IMPL, class CPU_IMPL>
unsigned
CPU<FP_IMPL,CPU_IMPL>::GetPL()
{
  /* NOTE: in non-secure mode (TrustZone), there are more privilege levels. */
  switch (cpsr.Get(M))
    {
    case PSR::USER_MODE:
      return 0;
      break;
    case PSR::FIQ_MODE:
    case PSR::IRQ_MODE:
    case PSR::SUPERVISOR_MODE:
    case PSR::MONITOR_MODE:
    case PSR::ABORT_MODE:
    case PSR::HYPERVISOR_MODE:
    case PSR::UNDEFINED_MODE:
    case PSR::SYSTEM_MODE:
      return 1;
      break;
    default:
      throw std::logic_error("undefined mode");
    }
  return 0;
}
  
/** Assert privilege level
 *
 * Throws if the current privilege level according to the running mode
 * is not sufficient.
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::RequiresPL(unsigned rpl)
{
  if (GetPL() < rpl)
    UnpredictableInsnBehaviour();
}

/** Scan available registers for the Registers interface
 * 
 *  Allows clients of the Registers interface to scan available
 * register by providing a suitable RegisterScanner interface.
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::ScanRegisters( unisim::service::interfaces::RegisterScanner& scanner )
{
  scanner.Append( this->GetRegister( "r0" ) );
  scanner.Append( this->GetRegister( "r1" ) );
  scanner.Append( this->GetRegister( "r2" ) );
  scanner.Append( this->GetRegister( "r3" ) );
  scanner.Append( this->GetRegister( "r4" ) );
  scanner.Append( this->GetRegister( "r5" ) );
  scanner.Append( this->GetRegister( "r6" ) );
  scanner.Append( this->GetRegister( "r7" ) );
  scanner.Append( this->GetRegister( "r8" ) );
  scanner.Append( this->GetRegister( "r9" ) );
  scanner.Append( this->GetRegister( "r10" ) );
  scanner.Append( this->GetRegister( "r11" ) );
  scanner.Append( this->GetRegister( "r12" ) );
  scanner.Append( this->GetRegister( "sp" ) );
  scanner.Append( this->GetRegister( "lr" ) );
  scanner.Append( this->GetRegister( "pc" ) );
  // TODO: should expose CPSR (and most probably the APSR view)
  // scanner.Append( this->GetRegister( "cpsr" ) );
}


/** Software Interrupt
 *  This method is called by SWI instructions to handle software interrupts.
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::CallSupervisor( uint32_t imm )
{
  throw SVCException();
}

/** Process Asynchronous Exceptions
 *
 * Processes pending asynchronous exceptions and return processed
 * exception (at most one). Note 1: this is designed to be called just
 * before PC update; next_insn_addr should point at the next instruction to
 * execute whereas current_insn_addr is ignored (but should point to a
 * finished instruction, except PC update).
 *
 * @param exception the A|I|F exception vector (as in CPSR)
 * @return the exception vector corresponding to the processed esception
 */
template <class FP_IMPL, class CPU_IMPL>
uint32_t
CPU<FP_IMPL,CPU_IMPL>::HandleAsynchronousException( uint32_t exceptions )
{
  // Asynchronous exceptions
  // - Asynchronous Abort
  // - FIQ
  // - IRQ
  
  // If we reached this point at least one exception is pending (but maybe masked).
  exceptions &= ~GetCPSR();
  
  if (A.Get( exceptions ))
    {
      logger << DebugError << "Exception not handled (Asynchronous Abort)" << EndDebugError;
      
      unisim::kernel::Simulator::Instance()->Stop(this, __LINE__);
      
      return A.Mask( exceptions );
    }
  
  if (I.Get( exceptions ) or F.Get( exceptions ))
    {
      // FIQs have higher priority
      bool isIRQ = not F.Get( exceptions );
      if (this->verbose)
        logger << DebugInfo << "Received " << (isIRQ ? "IRQ" : "FIQ") << " interrupt, handling it." << EndDebugInfo;
      
      TakePhysicalFIQorIRQException( isIRQ );
      
      return isIRQ ? I.Mask( exceptions ) : F.Mask( exceptions );
    }
  
  return 0;
}

template <class FP_IMPL, class CPU_IMPL>
uint32_t
CPU<FP_IMPL,CPU_IMPL>::ExcVectorBase()
{
  return sctlr::V.Get( SCTLR ) ? 0xffff0000 : 0x00000000;
}

/** Take Reset Exception
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::TakeReset()
{
  //   Enter Supervisor mode and (if relevant) Secure state, and reset
  // CP15.  This affects the Banked versions and values of various
  // registers accessed later in the code.  Also reset other system
  // components.
  
  cpsr.Set( M, PSR::SUPERVISOR_MODE );
  //if HaveSecurityExt() then SCR.NS = '0';

  CP15ResetRegisters();
  
  //if HaveAdvSIMDorVFP() then FPEXC.EN = '0'; SUBARCHITECTURE_DEFINED further resetting;
  //if HaveThumbEE() then TEECR.XED = '0';
  //if HaveJazelle() then JMCR.JE = '0'; SUBARCHITECTURE_DEFINED further resetting;
  // Further CPSR changes: all interrupts disabled, IT state reset, instruction set
  // and endianness according to the SCTLR values produced by the above call to
  // ResetControlRegisters().
  cpsr.Set( I, 1 );
  cpsr.Set( F, 1 );
  cpsr.Set( A, 1 );
  cpsr.ITSetState( 0b0000, 0b0000 ); // IT state reset
  cpsr.Set( J, 0 );
  cpsr.Set( T, sctlr::TE.Get( SCTLR ) );
  cpsr.Set( E, sctlr::EE.Get( SCTLR ) );
  // All registers, bits and fields not reset by the above pseudocode or by the
  // BranchTo() call below are UNKNOWN bitstrings after reset. In particular, the
  // return information registers R14_svc and SPSR_svc have UNKNOWN values, so that
  // it is impossible to return from a reset in an architecturally defined way.
  // Branch to Reset vector.
  Branch(ExcVectorBase() + 0, B_EXC);
}


/** Take Undefined Exception
 *  Implements how the processor takes the undefined exception
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::CP15ResetRegisters()
{
  // Base default values for SCTLR (may be overwritten by memory architectures)
  SCTLR = 0x00c50058; // SBO mask
  sctlr::TE.Set(      SCTLR, 0 ); // Thumb Exception enable
  sctlr::NMFI.Set(    SCTLR, 0 ); // Non-maskable FIQ (NMFI) support
  sctlr::EE.Set(      SCTLR, 0 ); // Exception Endianness.
  sctlr::VE.Set(      SCTLR, 0 ); // Interrupt Vectors Enable
  sctlr::U.Set(       SCTLR, 1 ); // Alignment Model (0 before ARMv6, 0 or 1 in ARMv6, 1 in armv7)
  sctlr::FI.Set(      SCTLR, 0 ); // Fast interrupts configuration enable
  sctlr::RR.Set(      SCTLR, 0 ); // Round Robin select
  sctlr::V.Set(       SCTLR, 0 ); // Vectors bit
  sctlr::I.Set(       SCTLR, 0 ); // Instruction cache enable
  sctlr::Z.Set(       SCTLR, 0 ); // Branch prediction enable.
  sctlr::SW.Set(      SCTLR, 0 ); // SWP and SWPB enable. This bit enables the use of SWP and SWPB instructions.
  sctlr::B.Set(       SCTLR, 0 ); // Endianness model (up to ARMv6)
  sctlr::CP15BEN.Set( SCTLR, 1 ); // CP15 barrier enable.
  sctlr::C.Set(       SCTLR, 0 ); // Cache enable. This is a global enable bit for data and unified caches.
  sctlr::A.Set(       SCTLR, 0 ); // Alignment check enable
  sctlr::M.Set(       SCTLR, 0 ); // MMU enable.
  
  CPACR = 0x0;
}

/** Take Undefined Exception
 *  Implements how the processor takes the undefined exception
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::TakeUndefInstrException()
{
  //   Determine return information.  SPSR is to be the current CPSR,
  // and LR is to be the current instruction address +4 for ARM or +2
  // for THUMB.

  uint32_t new_lr_value = GetCIA() + (cpsr.Get( T ) ? 2 : 4);
  uint32_t new_spsr_value = cpsr.Get( ALL32 );
  uint32_t vect_offset = 0x4;

  // Check whether to take exception to Hyp mode
  // if in Hyp mode then stay in Hyp mode
  // take_to_hyp = HaveVirtExt() && HaveSecurityExt() && SCR.NS == '1' && CPSR.M == '11010';
  // if HCR.TGE is set, take to Hyp mode through Hyp Trap vector
  // route_to_hyp = (HaveVirtExt() && HaveSecurityExt() && !IsSecure() && HCR.TGE == '1'
  //                && CPSR.M == '10000'); // User mode
  // if HCR.TGE == '1' and in a Non-secure PL1 mode, the effect is UNPREDICTABLE
  // return_offset = if CPSR.T == '1' then 2 else 4;
  // preferred_exceptn_return = new_lr_value - return_offset;
  // if take_to_hyp then
  //     Note that whatever called TakeUndefInstrException() will have set the HSR
  //     EnterHypMode(new_spsr_value, preferred_exceptn_return, vect_offset);
  // elsif route_to_hyp then
  //     Note that whatever called TakeUndefInstrException() will have set the HSR
  //     EnterHypMode(new_spsr_value, preferred_exceptn_return, 20);
  // else

  // Enter Undefined ('11011') mode, and ensure Secure state if initially in Monitor
  // ('10110') mode. This affects the Banked versions of various registers accessed later
  // in the code.

  // if CPSR.M == '10110' then SCR.NS = '0';
  CurrentMode().Swap( *this ); // OUT
  cpsr.Set( M, PSR::UNDEFINED_MODE ); // CPSR.M = '11011';
  Mode& newmode = CurrentMode();
  newmode.Swap( *this ); // IN
  
  // Write return information to registers, and make further CPSR changes: IRQs disabled,
  // IT state reset, instruction set and endianness set to SCTLR-configured values.
  newmode.SetSPSR( new_spsr_value );
  SetGPR( 14, new_lr_value );
  cpsr.Set( I, 1 );
  cpsr.ITSetState( 0b0000, 0b0000 );
  cpsr.Set( J, 0 );
  cpsr.Set( T, sctlr::TE.Get( SCTLR ) ); // TE=0: ARM, TE=1: Thumb
  cpsr.Set( E, sctlr::EE.Get( SCTLR ) ); // EE=0: little-endian, EE=1: big-endian
  // Branch to Undefined Instruction vector.
  Branch(ExcVectorBase() + vect_offset, B_EXC);
}

/** Take Data Abort Exception
 *
 * Implements how the processor takes the data abort exception
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::TakeDataOrPrefetchAbortException( bool isdata )
{
  //   Determine return information.  SPSR is to be the current CPSR,
  // and LR is to be the current instruction address +8 for data abort
  // or +4 for prefetch abort.  Thus exception should preferably
  // return to LR-8 for data aborts or LR-4 for prefetch abort.

  uint32_t preferred_exceptn_return = GetCIA();
  uint32_t new_lr_value = preferred_exceptn_return + (isdata ? 8 : 4);
  uint32_t new_spsr_value = GetCPSR();
  uint32_t vect_offset = isdata ? 16 : 12;
  
  // preferred_exceptn_return = new_lr_value - 8;
  // // Determine whether this is an external abort to be routed to Monitor mode.
  // route_to_monitor = HaveSecurityExt() && SCR.EA == '1' && IsExternalAbort();
  // // Check whether to take exception to Hyp mode
  // // if in Hyp mode then stay in Hyp mode
  // take_to_hyp = HaveVirtExt() && HaveSecurityExt() && SCR.NS == '1' && CPSR.M == '11010';
  // // otherwise, check whether to take to Hyp mode through Hyp Trap vector
  // route_to_hyp = (HaveVirtExt() && HaveSecurityExt() && !IsSecure() &&
  //                 (SecondStageAbort() ||
  //                  (CPSR.M != HYPERVISOR_MODE && DebugException() && HDCR.TDE == '1') ||
  //                  (CPSR.M != HYPERVISOR_MODE && (IsExternalAbort() && IsAsyncAbort() && HCR.AMO == '1')) ||
  //                  (CPSR.M == USER_MODE && HCR.TGE == '1' && ((IsExternalAbort() && !IsAsyncAbort()) || IsAlignmentFault()))
  //                 )
  //                );
  // // if HCR.TGE == '1' and in a Non-secure PL1 mode, the effect is UNPREDICTABLE
  // if (route_to_monitor) {
  //   // Ensure Secure state if initially in Monitor mode. This affects the Banked
  //   // versions of various registers accessed later in the code
  //   if (CPSR.M == '10110') SCR.NS = '0';
  //   EnterMonitorMode(new_spsr_value, new_lr_value, vect_offset);
  // } else if (take_to_hyp) {
  //   EnterHypMode(new_spsr_value, preferred_exceptn_return, vect_offset);
  // } else if (route_to_hyp) {
  //   EnterHypMode(new_spsr_value, preferred_exceptn_return, 20);
  //   else
      
  // Handle in Abort mode. Ensure Secure state if initially in Monitor mode. This
  // affects the Banked versions of various registers accessed later in the code
  // if HaveSecurityExt() && CPSR.M == '10110' then SCR.NS = '0';
  
  CurrentMode().Swap( *this ); // OUT
  cpsr.Set( M, PSR::ABORT_MODE ); // CPSR.M = '10111';
  Mode& newmode = CurrentMode();
  newmode.Swap( *this ); // IN
  
  // Abort mode
  // Write return information to registers, and make further CPSR changes:
  // IRQs disabled, other interrupts disabled if appropriate,
  // IT state reset, instruction set and endianness set to SCTLR-configured values.
  
  newmode.SetSPSR( new_spsr_value );
  SetGPR( 14, new_lr_value );

  cpsr.Set( I, 1 );
  // if !HaveSecurityExt() || HaveVirtExt() || SCR.NS == '0' || SCR.AW == '1' then
  //    CPSR.A = '1';
  cpsr.ITSetState( 0b0000, 0b0000 );
  cpsr.Set( J, 0 );
  cpsr.Set( T, sctlr::TE.Get( SCTLR ) ); // TE=0: ARM, TE=1: Thumb
  cpsr.Set( E, sctlr::EE.Get( SCTLR ) ); // EE=0: little-endian, EE=1: big-endian
  // Branch to Abort vector.
  Branch(ExcVectorBase() + vect_offset, B_EXC);
}

/** Take Reset Exception
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::TakeSVCException()
{
  //   Determine return information.  SPSR is to be the current CPSR,
  // after changing the IT[] bits to give them the correct values for
  // the following instruction, and LR is to be the next instruction
  // address.  Thus exception should preferably return to LR.
  
  ITAdvance(); //< Finalize SVC instruction
  
  uint32_t new_lr_value = GetNIA();
  uint32_t new_spsr_value = cpsr.Get( ALL32 );
  uint32_t vect_offset = 0x8;
  
  // Check whether to take exception to Hyp mode
  // if in Hyp mode then stay in Hyp mode
  // take_to_hyp = (HaveVirtExt() && HaveSecurityExt() && SCR.NS == '1' && CPSR.M == '11010');
  // if HCR.TGE is set to 1, take to Hyp mode through Hyp Trap vector
  // route_to_hyp = (HaveVirtExt() && HaveSecurityExt() && !IsSecure() && HCR.TGE == '1'
  //                && CPSR.M == '10000'); // User mode
  // if HCR.TGE == '1' and in a Non-secure PL1 mode, the effect is UNPREDICTABLE
  // preferred_exceptn_return = new_lr_value;
  // if take_to_hyp then
  //     EnterHypMode(new_spsr_value, preferred_exceptn_return, vect_offset);
  // elsif route_to_hyp then
  //     EnterHypMode(new_spsr_value, preferred_exceptn_return, 20);
  // else
  
  // Enter Supervisor ('10011') mode, and ensure Secure state if initially in Monitor
  // ('10110') mode. This affects the Banked versions of various registers accessed later
  // in the code.
  
  // if CPSR.M == '10110' then SCR.NS = '0';
  CurrentMode().Swap( *this ); // OUT
  cpsr.Set( M, PSR::SUPERVISOR_MODE ); // CPSR.M = '10011';
  Mode& newmode = CurrentMode();
  newmode.Swap( *this ); // IN
  
  // Write return information to registers, and make further CPSR changes: IRQs disabled,
  // IT state reset, instruction set and endianness set to SCTLR-configured values.
  newmode.SetSPSR( new_spsr_value );
  SetGPR( 14, new_lr_value );
  cpsr.Set( I, 1 );
  cpsr.ITSetState( 0b0000, 0b0000 );
  cpsr.Set( J, 0 );
  cpsr.Set( T, sctlr::TE.Get( SCTLR ) ); // TE=0: ARM, TE=1: Thumb
  cpsr.Set( E, sctlr::EE.Get( SCTLR ) ); // EE=0: little-endian, EE=1: big-endian
  // Branch to SVC vector.
  Branch(ExcVectorBase() + vect_offset, B_EXC);
}

/** Take Physical FIQ or IRQ Exception
 *
 * @param isIRQ   whether the Exception is an IRQ (true) or an FIQ (false)
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::TakePhysicalFIQorIRQException( bool isIRQ )
{
  //   Determine return information.  SPSR is to be the current CPSR,
  // and LR is to be the aborted instruction address + 4.  Thus
  // exception should preferably return to LR-4.
  
  uint32_t new_lr_value = GetNIA() + 4;
  uint32_t new_spsr_value = cpsr.Get( ALL32 );
      
  // TODO: [IRQ|FIQ]s may be routed to monitor (if
  // HaveSecurityExt() and SCR.[IRQ|FIQ]) or to Hypervisor (if
  // (HaveVirtExt() && HaveSecurityExt() && SCR.[IRQ|FIQ] == '0'
  // && HCR.[IMO|FMO] == '1' && !IsSecure()) || CPSR.M ==
  // '11010');
      
  // Handle in [IRQ|FIQ] mode. TODO: Ensure Secure state if
  // initially in Monitor mode. This affects the Banked versions
  // of various registers accessed later in the code.
  CurrentMode().Swap( *this ); // OUT
  cpsr.Set( M, isIRQ ? PSR::IRQ_MODE : PSR::FIQ_MODE );
  Mode& newmode = CurrentMode();
  newmode.Swap( *this ); // IN
  // Write return information to registers, and make further CPSR
  // changes: IRQs disabled, other interrupts disabled if
  // appropriate, IT state reset, instruction set and endianness
  // set to SCTLR-configured values.
  newmode.SetSPSR( new_spsr_value );
  SetGPR( 14, new_lr_value );
  // IRQs disabled
  cpsr.Set( I, 1 );
  // When taking FIQ, FIQs masked (if !HaveSecurityExt() || HaveVirtExt() || SCR.NS == '0' || SCR.FW == '1')
  if (not isIRQ)
    cpsr.Set( F, 1 );
  // Async Abort disabled (if !HaveSecurityExt() || HaveVirtExt() || SCR.NS == '0' || SCR.AW == '1')
  cpsr.Set( A, 1 );
  cpsr.ITSetState( 0b0000, 0b0000 ); // IT state reset
  cpsr.Set( J, 0 );
  cpsr.Set( T, sctlr::TE.Get( SCTLR ) );
  cpsr.Set( E, sctlr::EE.Get( SCTLR ) );
  // Branch to correct [IRQ|FIQ] vector
  if (sctlr::VE.Get( SCTLR ))
    BranchToFIQorIRQvector( isIRQ );              //< Virtual method, Implementation defined
  else
    CPU<FP_IMPL,CPU_IMPL>::BranchToFIQorIRQvector( isIRQ ); //< Static method, default behavior
}

/** Branch to Physical FIQ or IRQ vector
 * This method provides default behavior when branching to physical FIQ or IRQ vector
 * @param isIRQ   whether the Exception is an IRQ (true) or an FIQ (false)
 */
template <class FP_IMPL, class CPU_IMPL>
void
CPU<FP_IMPL,CPU_IMPL>::BranchToFIQorIRQvector( bool isIRQ )
{
  uint32_t vect_offset = isIRQ ? 0x18 : 0x1c;
  Branch(ExcVectorBase() + vect_offset, B_EXC);
}

#define CP15ENCODE( CRN, OPC1, CRM, OPC2 ) ((OPC1 << 12) | (CRN << 8) | (CRM << 4) | (OPC2 << 0))

/** Get the Internal representation of the CP15 Register
 * 
 * @param crn     the "crn" field of the instruction code
 * @param opcode1 the "opcode1" field of the instruction code
 * @param crm     the "crm" field of the instruction code
 * @param opcode2 the "opcode2" field of the instruction code
 * @return        an internal CP15Reg
 */
template <class FP_IMPL, class CPU_IMPL>
typename CPU<FP_IMPL,CPU_IMPL>::CP15Reg*
CPU<FP_IMPL,CPU_IMPL>::CP15GetRegister( uint8_t crn, uint8_t opcode1, uint8_t crm, uint8_t opcode2 )
{
  switch (CP15ENCODE( crn, opcode1, crm, opcode2 ))
    {
      /****************************
       * Identification registers *
       ****************************/
    case CP15ENCODE( 0, 0, 1, 0 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "ID_PFR0, Processor Feature Register 0"; }
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override {
            /*        ARM              Thumb2         Jazelle         ThumbEE   */
            return (0b0001 << 0) | (0b0011 << 4) | (0b0000 << 8) | (0b0000 << 12);
          }
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
          /* TODO: handle SBO(DGP=0x00050078U) and SBZ(DGP=0xfffa0c00U)... */
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.SCTLR; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t value) const override {
            uint32_t old_ctlr = cpu.SCTLR;
            cpu.SCTLR = value;
            uint32_t diff = old_ctlr ^ value;
            if (cpu.verbose) {
              if      (sctlr::C.Get( diff ))
                cpu.logger << DebugInfo << "DCache " << (sctlr::C.Get( value ) ? "enabled" : "disabled") << EndDebugInfo;
              if (sctlr::M.Get( diff )) {
                cpu.logger << DebugInfo << "MMU " << (sctlr::M.Get( value ) ? "enabled" : "disabled") << EndDebugInfo;
              }
            }
          }
        } x;
        return &x;
      } break;
      
    case CP15ENCODE( 1, 0, 0, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "CPACR, Coprocessor Access Control Register"; }
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.CPACR; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t value) const override {
            // bit 29 is Reserved, UNK/SBZP
            // cp0-cp9 and cp12-cp13 are not implemented
            value &= ~0x2f0fffffU;
            uint32_t neon = ((value >> 20)) & 0b1111;
            if ((neon != 0b0000) and (neon != 0b0101) and (neon != 0b1111))
              cpu.UnpredictableInsnBehaviour();
            cpu.CPACR = value;
          }
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
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.CONTEXTIDR; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t value) const override { cpu.CONTEXTIDR = value; }
        } x;
        return &x;
      } break;
      
    case CP15ENCODE( 13, 0, 0, 2 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TPIDRURW, User Read/Write Thread ID Register"; }
          unsigned RequiredPL() { return 0; /* Doesn't requires priviledges */ }
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.TPIDRURW; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t value) const override { cpu.TPIDRURW = value; }
        } x;
        return &x;
      } break;
      
    case CP15ENCODE( 13, 0, 0, 3 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TPIDRURO, User Read-Only Thread ID Register"; }
          void CheckPermissions(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, bool w) const override { return cpu.RequiresPL(w ? 1 : 0); }
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.TPIDRURO; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t val) const override { cpu.TPIDRURO = val; }
        } x;
        return &x;
      } break;
      
    case CP15ENCODE( 13, 0, 0, 4 ):
      {
        static struct : public CP15Reg
        {
          void Describe(uint8_t, uint8_t, uint8_t, uint8_t, std::ostream& sink) const override { sink << "TPIDRPRW, PL1 only Thread ID Register"; }
          uint32_t Read(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu) const override { return cpu.TPIDRPRW; }
          void Write(uint8_t, uint8_t, uint8_t, uint8_t, CPU_IMPL& cpu, uint32_t val) const override { cpu.TPIDRPRW = val; }
        } x;
        return &x;
      } break;
      
    }

  static CP15Reg err;
  return &err;
}

#undef CP15ENCODE

/** Unpredictable Instruction Behaviour.
 * This method is just called when an unpredictable behaviour is detected to
 *   notifiy the processor.
 */
template <class FP_IMPL, class CPU_IMPL>
void 
CPU<FP_IMPL,CPU_IMPL>::UnpredictableInsnBehaviour()
{
  logger << DebugWarning
         << unisim::util::backtrace::BackTrace()
         << "Trying to execute unpredictable behavior instruction."
         << " PC: " << std::hex << current_insn_addr << std::dec
         << ", CPSR: " << std::hex << GetCPSR() << std::dec
         << " (" << cpsr << ")"
         << EndDebugWarning;
  this->Stop( -1 );
}


    
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#endif // __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_CPU_TCC__
