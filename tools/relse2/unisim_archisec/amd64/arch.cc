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

#include <arch.hh>
#include <iostream>

ProcessorBase::ProcessorBase()
  : path(0)
  , next_insn_mode(ipjmp)
  , abort(false)
{
  for (FLAG reg; reg.next();)
    flagvalues[reg.idx()] = newRegRead( reg );
}

// void
// ProcessorBase::FTop::Repr( std::ostream& sink ) const
// {
//   sink << "FpuStackTop";
// }

unisim::util::symbolic::Expr&
ProcessorBase::fpaccess( unsigned reg, bool write )
{
  throw Unimplemented();
}

void
Compat32::IRegID::Repr(std::ostream& sink) const
{
  sink << c_str();
}

void
Intel64::IRegID::Repr(std::ostream& sink) const
{
  sink << c_str();
}

void
ProcessorBase::FLAG::Repr( std::ostream& sink ) const
{
  sink << c_str();
}

void
ProcessorBase::VClear::Repr( std::ostream& sink ) const
{
  sink << "VClear(" << std::dec << size << ")";
}

int
ProcessorBase::VClear::GenCode(unisim::util::symbolic::binsec::Label&, unisim::util::symbolic::binsec::Variables&, std::ostream& sink) const
{
  if (size % 8) throw 0;
  sink << unisim::util::symbolic::binsec::dbx(size / 8, 0);
  return size;
}

unisim::util::symbolic::ValueType const*
ProcessorBase::VClear::GetType() const
{
  struct VCT : public unisim::util::symbolic::ValueType
  {
    VCT(unsigned _bitsize) : unisim::util::symbolic::ValueType(unisim::util::symbolic::ValueType::NA), bitsize(_bitsize) {} unsigned bitsize;
    virtual unsigned GetBitSize() const override { return bitsize; }
    virtual void GetName(std::ostream& sink) const override { sink << "VClear" << std::dec << bitsize; }
    bool operator < (VCT const& rhs) const { return bitsize < rhs.bitsize; }
  };

  static std::set<VCT> type_descriptors;
  auto tp = type_descriptors.insert(this->size).first;

  return &*tp;
}

void
ProcessorBase::VRegID::Repr(std::ostream& sink) const
{
  sink << char(VmmValue::VPREFIX) << "mm" << std::dec << reg;
}

unisim::util::symbolic::ValueType const*
VmmValue::GetType()
{
  static struct Type : unisim::util::symbolic::ValueType
  {
    Type() : ValueType(unisim::util::symbolic::ValueType::NA) {}
    virtual unsigned GetBitSize() const override { return 8*VmmValue::BYTECOUNT; }
    virtual void GetName(std::ostream& sink) const override { sink << "VmmValue"; }
  } _;
  return &_;
}

void
ProcessorBase::VmmIndirectReadBase::Repr( std::ostream& sink ) const
{
  GetVName(sink << "VmmIndirectReadRead<" << GetVSize() << ",");
  sink << ">(";
  for (unsigned idx = 0, end = SubCount()-1; idx < end; ++idx)
    sink << GetSub(idx) << ", ";
  sink << index << ")";
}

void
ProcessorBase::flagwrite( FLAG flag, bit_t fval, bit_t def )
{
  if (unisim::util::symbolic::ConstNodeBase const* cnode = def.expr.ConstSimplify())
    {
      flagvalues[flag.idx()] = dynamic_cast<unisim::util::symbolic::ConstNode<bool> const&>(*cnode).value ? fval.expr : new unisim::util::symbolic::binsec::UndefinedValue<bool>();
    }
  else
    {
      flagvalues[flag.idx()] = ((def and fval) or ((not def) and bit_t(new unisim::util::symbolic::binsec::UndefinedValue<bool>()))).expr;
    }
}

namespace
{
  template <class OP>
  void
  noexec_error( OP const& op )
  {
    // std::cerr << "error: no execute method in `" << typeid(op).name() << "'\n" << std::hex << op.address << ":\t";
    // op.disasm( std::cerr );
    // std::cerr << '\n';
    throw ProcessorBase::Unimplemented();
  }
}

template <> void Processor<Compat32>::noexec( Processor<Compat32>::Operation const& op ) { noexec_error(op); }
template <> void Processor <Intel64>::noexec( Processor<Intel64>::Operation const& op ) { noexec_error(op); }

void show(unsigned idx, unisim::util::symbolic::ExprNode const* node)
{
  std::cerr << "[" << idx << "]: ";
  if (node)
    node->Repr(std::cerr);
  std::cerr << "\n";
}

