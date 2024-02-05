/*
 *  Copyright (c) 2009-2020,
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
#include <arch.hh>
#include <unisim/util/symbolic/binsec/binsec.hh>
#include <unisim/util/symbolic/symbolic.hh>
#include <iostream>
#include <cstdint>

namespace intel {

struct InstructionAddress : public unisim::util::symbolic::binsec::ASExprNode
{
  InstructionAddress() {}
  virtual void Repr( std::ostream& sink ) const { sink << "insn_addr"; }
  virtual int cmp( unisim::util::symbolic::ExprNode const& rhs ) const override { return compare( dynamic_cast<InstructionAddress const&>( rhs ) ); }
  int compare( InstructionAddress const& rhs ) const { return 0; }
};

struct Translator
{
  typedef unisim::util::symbolic::binsec::ActionNode ActionNode;
  typedef unisim::util::symbolic::binsec::dbx print_dbx;

  Translator(uint64_t _addr, std::vector<uint8_t>&& _code)
    : code(std::move(_code)), addr(_addr), coderoot(new ActionNode)
  {}
  ~Translator() { delete coderoot; }

  template <class MODE>
  void
  extract( MODE const&, std::ostream& sink )
  {
    typedef Processor<MODE> Proc;
    typedef typename Proc::nat_addr_t addr_t;
    typedef unisim::component::cxx::processor::intel::Operation<Proc> Operation;

    sink << "(address . " << print_dbx(MODE::GREGSIZE, addr) << ")\n";

    // Instruction decoding
    struct Instruction
    {
      Instruction(addr_t address, uint8_t* bytes) : operation()
      {
        operation = Proc::Decode(address, bytes);
        if (not operation) throw typename Proc::Undefined();
      }
      ~Instruction() { delete operation; }
      Operation* operator -> () { return operation; }
      Operation& operator * () { return *operation; }
      Operation* operation;
    };
    Instruction instruction( addr, &code[0] );

    if (instruction->length > code.size()) { struct LengthError {}; throw LengthError(); }
    code.resize(instruction->length);

    sink << "(opcode . \"";
    char const* sep = "";
    for (auto byte : code) { sink << sep; sep = " "; for (int n = 0; n < 2; n++, byte <<=4) sink << "0123456789abcdef"[byte>>4&15]; }
    sink << "\")\n(size . " << code.size() << ")\n";

    typename Proc::addr_t insn_addr = unisim::util::symbolic::make_const(addr); //< concrete instruction address
    // Proc::U32      insn_addr = Expr(new InstructionAddress()); //< symbolic instruction address
    Proc reference;

    // Disassemble
    sink << "(mnemonic . \"";
    try { instruction->disasm( sink ); }
    catch (...) { sink << "(bad)"; }
    sink << "\")\n";

    // Get actions
    for (bool end = false; not end;)
      {
        Proc state;
        state.path = coderoot;
        state.step(*instruction);
        end = state.close(reference);
      }
    coderoot->simplify();
    coderoot->commit_stats();
  }

  void translate( bool mode64, std::ostream& sink )
  {
    try
      {
        if (mode64)
          extract( Intel64(), sink );
        else
          extract( Compat32(), sink );

        // Translate to DBA
        unisim::util::symbolic::binsec::Program program;
        program.Generate( coderoot );
        for (auto stmt : program)
          sink << "(" << print_dbx(mode64 ? 8 : 4, addr) << ',' << stmt.first << ") " << stmt.second << std::endl;
      }
    catch (ProcessorBase::Undefined const&)
      {
        sink << "(undefined)\n";
        return;
      }
    catch (...)
      {
        sink << "(unimplemented)\n";
        return;
      }
  }

  std::vector<uint8_t> code;
  uint64_t addr;
  ActionNode* coderoot;
};

void
Decoder::process( std::ostream& sink, uint64_t addr, std::vector<uint8_t>&& code )
{
  Translator actset( addr, std::move(code) );

  actset.translate( mode64, sink );
}

}
