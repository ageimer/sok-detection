/*
 *  Copyright (c) 2007-2017,
 *  Commissariat a l'Energie Atomique (CEA),
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

#include <unisim/util/symbolic/binsec/binsec.hh>
#include <ostream>
#include <sstream>
#include <iomanip>

namespace unisim {
namespace util {
namespace symbolic {
namespace binsec {

  std::ostream&
  operator << ( std::ostream& sink, dbx const& _ )
  {
    sink << "0x" << std::hex << std::setw(_.bytes*2) << std::setfill('0') << _.value << std::dec;
    return sink;
  }

  bool
  Label::subst_next( std::string& s, int next )
  {
    uintptr_t pos = s.find( "<next>" );
    if (pos == std::string::npos)
      return false;
    { std::ostringstream buf; buf << next; s.replace(pos, 6, buf.str()); }
    return true;
  }

  Expr
  ASExprNode::Simplify( Expr const& ixpr )
  {
    unsigned subcount = ixpr->SubCount();
    Expr subs[subcount];

    struct Simplified
    {
      Simplified(ExprNode const* _e, Expr* _subs, unsigned _subc)
        : e(_e), subs(_subs), subc(_subc), diff(false)
      {
        for (unsigned idx = 0; idx < subc; ++idx)
          {
            Expr const& sub = e->GetSub(idx);
            if (sub != (subs[idx] = ASExprNode::Simplify( sub )))
              diff = true;
          }
      }
      ExprNode const* base()
      {
        if (ExprNode* r = diff ? e->Mutate() : 0)
          {
            for (unsigned idx = 0; idx < subc; ++idx)
              const_cast<Expr&>(r->GetSub(idx)) = subs[idx];
            return r;
          }
        return e;
      }
      ExprNode const* e;
      Expr* subs;
      unsigned subc;
      bool diff;
    } simplified(ixpr.node,&subs[0],subcount);

    if (OpNodeBase const* node = simplified.e->AsOpNode())
      {
        switch (node->op.code)
          {
          default: break;

            //          case Op::Lsl:
          case Op::Asr:
          case Op::Lsr:
            if (subcount == 2)
              {
                if (ConstNodeBase const* cnb = subs[1].Eval(EvalSpace()))
                  {
                    unsigned sh = dynamic_cast<ConstNode<shift_type> const&>(*cnb).value;
                    unsigned bitsize = subs[0]->GetType()->GetBitSize();
                    if (sh >= bitsize) { struct Bad {}; throw Bad(); }

                    unsigned rshift, sxtend;
                    switch (node->op.code)
                      {
                      case Op::Lsr: rshift = sh; sxtend = false; break;
                      case Op::Asr: rshift = sh; sxtend = true; break;
                      default:  { struct Bad {}; throw Bad(); }
                      }

                    return BitFilter( subs[0], bitsize, rshift, bitsize - sh, bitsize, sxtend ).mksimple();
                  }

              }
            break;


          case Op::And:
            if (subcount == 2)
              {
                for (unsigned idx = 0; idx < 2; ++idx)
                  if (ConstNodeBase const* node = subs[idx].Eval(EvalSpace()))
                    {
                      Expr dispose(node);
                      unsigned bitsize = node->GetType()->GetBitSize();
                      if (bitsize > 64)
                        continue;
                      uint64_t v = node->GetBits(0);
                      if (v & (v+1))
                        continue;
                      if (v == 0)
                        return subs[idx];
                      unsigned select = arithmetic::BitScanReverse(v)+1;
                      if (select >= bitsize)
                        return subs[idx^1];
                      return BitFilter( subs[idx^1], bitsize, 0, select, bitsize, false ).mksimple();
                    }
              }
            break;

          case Op::Cast:
            if (subcount == 1)
              {
                CastNodeBase const& cnb = dynamic_cast<CastNodeBase const&>( *ixpr.node );
                auto src = cnb.GetSrcType(), dst = cnb.GetType();
                if ((dst->encoding != dst->UNSIGNED and dst->encoding != dst->SIGNED) or
                    (src->encoding != src->UNSIGNED and src->encoding != src->SIGNED and src->encoding != src->BOOL))
                  return simplified.base(); // Complex casts

                unsigned src_bit_size = src->GetBitSize(), dst_bit_size = dst->GetBitSize();

                if (src_bit_size == dst_bit_size)
                  return subs[0];

                return BitFilter( subs[0], src_bit_size, 0, std::min(src_bit_size, dst_bit_size), dst_bit_size, dst_bit_size > src_bit_size and src->encoding == src->SIGNED ).mksimple();
              }
            break;
          }
      }
    else if (dynamic_cast<ASExprNode const*>( ixpr.node ))
      {
        return dynamic_cast<ASExprNode const*>( simplified.base() )->Simplify();
      }

    return simplified.base();
  }

  int
  ASExprNode::GenerateCode( Expr const& expr, Variables& vars, Label& label, std::ostream& sink )
  {
    /*** Pre expression process ***/
    Variables::iterator itr = vars.find( expr );
    if (itr != vars.end())
      {
        sink << itr->second.first;
        return itr->second.second;
      }

    /*** Sub expression process ***/
    if (ConstNodeBase const* node = expr.Eval(EvalSpace()))
      {
        Expr dispose( node );
        auto tp = node->GetType();
        switch (tp->encoding)
          {
          default: break;
          case ValueType::BOOL: sink << node->GetBits(0) << "<1>";  return 1;
          case ValueType::SIGNED: case ValueType::UNSIGNED:
            {
              unsigned bitsize = tp->GetBitSize();
              if (bitsize > 64)
                throw 0;
              sink << dbx(bitsize / 8, node->GetBits(0));
              return bitsize;
            }
          }
        throw std::logic_error("can't encode type");
      }
    else if (OpNodeBase const* node = expr->AsOpNode())
      {
        switch (node->SubCount())
          {
          case 2: {
            auto infix = [&] (char const* op) -> int {
              int lhs_size = GenerateCode( node->GetSub(0), vars, label, sink << '(' );
              sink << ' ' << op << ' ' << GetCode( node->GetSub(1), vars, label ) << ')';
              return lhs_size;
            };

            auto prefix = [&] (char const* op) -> int {
              int lhs_size = GenerateCode( node->GetSub(0), vars, label, sink << op << '(' );
              sink << ", " << GetCode( node->GetSub(1), vars, label ) << ')';
              return lhs_size;
            };

            auto test = [&] (char const* op) -> int {
              sink << '(' << GetCode( node->GetSub(0), vars, label ) << ' ' << op << ' ' << GetCode( node->GetSub(1), vars, label ) << ')';
              return 1;
            };

            auto shift = [&] (char const* op) -> int {
              int lhs_size = GenerateCode( node->GetSub(0), vars, label, sink << '(' );
              Expr rhs = node->GetSub(1);
              switch (lhs_size)
                {
                case 16: rhs = Simplify( U16(U8(rhs)).expr ); break;
                case 32: rhs = Simplify( U32(U8(rhs)).expr ); break;
                case 64: rhs = Simplify( U64(U8(rhs)).expr ); break;
                }
              sink << ' ' << op << ' ' << GetCode( rhs, vars, label ) << ')';
              return lhs_size;
            };
        
            switch (node->op.code)
              {
              default:          break;
              case Op::Add:     return infix("+");
              case Op::Sub:     return infix("-");
              case Op::Mul:     return infix("*");
              case Op::Mod:     return infix("mods");
              case Op::Modu:    return infix("modu");
              case Op::Div:     return infix("/s");
              case Op::Divu:    return infix("/u");

              case Op::Xor:     return infix("xor");
              case Op::Or:      return infix("or");
              case Op::And:     return infix("and");

              case Op::Teq:     return test("=");
              case Op::Tne:     return test("<>");

              case Op::Tle:     return test("<=s");
              case Op::Tleu:    return test("<=u");

              case Op::Tge:     return test(">=s");
              case Op::Tgeu:    return test(">=u");

              case Op::Tlt:     return test("<s");
              case Op::Tltu:    return test("<u");

              case Op::Tgt:     return test(">s");
              case Op::Tgtu:    return test(">u");


              case Op::Lsl:     return shift("lshift");
              case Op::Asr:     return shift("rshifts");
              case Op::Lsr:     return shift("rshiftu");
              case Op::Ror:     return shift("rrotate");

              case Op::Min:     return prefix("min");
              case Op::Max:     return prefix("max");
              }

            std::ostringstream buf;
            buf << "[" << node->op.c_str() << "]";
            return infix(buf.str().c_str());
          }

          case 1: {
            char const* operation = 0;

            switch (node->op.code)
              {
              default:              operation = node->op.c_str(); break;

              case Op::Not:    operation = "not "; break;
              case Op::Neg:    operation = "- "; break;

                // case Op::BSwp:  break;
              case Op::BSF:
                {
                  unsigned bitsize = node->GetType()->GetBitSize();
                  Label head(label);
                  int exit = label.allocate(), loop;

                  std::ostringstream buffer;
                  buffer << "bsf_in<" << bitsize << "> := " << GetCode(node->GetSub(0), vars, head) << " ; goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "bsf_out<" << bitsize << "> := 0<" << bitsize << "> ; goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "if (bsf_in<" << bitsize << "> = 0<" << bitsize << ">) goto " << exit << " else goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "if ((bsf_in<" << bitsize << "> rshiftu bsf_out<" << bitsize << ">){0,0}) goto " << exit << " else goto <next>";
                  loop = head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "bsf_out<" << bitsize << "> := bsf_out<" << bitsize << "> + 1<" << bitsize << "> ; goto " << loop;
                  head.write( buffer.str()  );

                  sink << "bsf_out<" << bitsize << ">";

                  return bitsize;
                }

              case Op::BSR:
                {
                  unsigned bitsize = node->GetType()->GetBitSize();
                  Label head(label);
                  int exit = label.allocate(), loop;

                  std::ostringstream buffer;
                  buffer << "bsr_in<" << bitsize << "> := " << GetCode(node->GetSub(0), vars, head) << " ; goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "bsr_out<" << bitsize << "> := " << bitsize << "<" << bitsize << "> ; goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "if (bsr_in<" << bitsize << "> = 0<" << bitsize << ">) goto " << exit << " else goto <next>";
                  head.write( buffer.str() );

                  buffer = std::ostringstream();
                  buffer << "bsr_out<" << bitsize << "> := bsr_out<" << bitsize << "> - 1<" << bitsize << "> ; goto <next>";
                  loop = head.write( buffer.str()  );

                  buffer = std::ostringstream();
                  buffer << "if ((bsr_in<" << bitsize << "> rshiftu bsr_out<" << bitsize << ">){0,0}) goto " << exit << " else goto " << loop;
                  head.write( buffer.str() );

                  sink << "bsr_out<" << bitsize << ">";

                  return bitsize;
                }
              case Op::Cast:
                {
                  CastNodeBase const& cnb = dynamic_cast<CastNodeBase const&>( *expr.node );
                  auto src = cnb.GetSrcType(), dst = cnb.GetType();

                  /* At this point, only boolean casts should remain */
                  if (dst->encoding == dst->BOOL)
                    {
                      sink << "(" << GetCode(cnb.src, vars, label) << " <> " << dbx(src->GetBitSize()/8,0) << ")";
                    }
                  else
                    {
                      throw std::logic_error("Unexpected cast");
                      /* TODO: What to do with FP casts ? */
                      dst->GetName(sink);
                      sink << "( " << GetCode(cnb.src, vars, label) << " )";
                    }

                  return dst->GetBitSize();
                }
              }

            sink << '(' << operation << ' ';
            int retsz = GenerateCode( node->GetSub(0), vars, label, sink );
            sink << ')';
            return retsz;
          }
          default:
            break;
          }
      }
    else if (auto vt = dynamic_cast<vector::VTransBase const*>( expr.node ))
      {
        unsigned srcsize = 8*vt->srcsize, dstsize = vt->GetType()->GetBitSize(), srcpos = 8*vt->srcpos;
        
        if (dstsize < srcsize)
          sink << "(" << GetCode(vt->src, vars, label) << " {" << std::dec << srcpos << ", " << (srcpos+dstsize-1) << "})";
        else
          sink << GetCode(vt->src, vars, label);
        return dstsize;
      }
    else if (auto mix = dynamic_cast<vector::VMix const*>( expr.node ))
      {
        decltype(mix) prev;
        sink << "(";
        int retsize = 0;
        do
          {
            prev = mix;
            retsize += GenerateCode( mix->l, vars, label, sink );
            sink << " :: ";
            mix = dynamic_cast<vector::VMix const*>( mix->r.node );
          }
        while (mix);
        retsize += GenerateCode(prev->r, vars, label, sink);
        sink << ")";
        return retsize;
      }
    else if (ASExprNode const* node = dynamic_cast<ASExprNode const*>( expr.node ))
      {
        return node->GenCode( label, vars, sink );
      }

    throw std::logic_error("No GenCode method");
    return 0;
  }

  Expr
  BitFilter::mksimple()
  {
    // Prevent deletion of this stack-allocated object
    if (ExprNode::refs != 0) throw 0;
    this->Retain();
    Expr bf = this->Simplify();
    return (bf.node == this) ? new BitFilter( *this ) : bf.node;
  }

  Expr
  BitFilter::Simplify() const
  {
    if (rshift == 0 and source == select and select == extend) return input;

    if (OpNodeBase const* onb = input->AsOpNode())
      {
        if (onb->op.code != onb->op.Lsl) return this;
        ConstNodeBase const* cnb = onb->GetSub(1).Eval(EvalSpace());
        if (not cnb) return this;
        unsigned lshift = dynamic_cast<ConstNode<shift_type> const&>(*cnb).value;
        if (lshift > rshift) return this;
        BitFilter bf( *this );
        bf.rshift -= lshift;
        bf.input = onb->GetSub(0);
        return bf.mksimple();
      }

    if (BitFilter const* bf = dynamic_cast<BitFilter const*>( input.node ))
      {
        struct Bad {};

        if (source != bf->extend)
          throw Bad ();

        if (rshift >= bf->select) // TODO: maybe this can be optimized
          return this;

        unsigned new_rshift = bf->rshift + rshift;

        if ((rshift + select) <= bf->select)
          return BitFilter( bf->input, bf->source, new_rshift, select, extend, sxtend ).mksimple();

        // (rshift + select) > bf->select
        if (not sxtend and bf->sxtend)
          return this;

        return BitFilter( bf->input, bf->source, new_rshift, bf->select - rshift, extend, bf->sxtend ).mksimple();
      }

    return this;
  }

  int
  BitFilter::compare( BitFilter const& rhs ) const
  {
    if (int delta = int(source) - int(rhs.source)) return delta;
    if (int delta = int(rshift) - int(rhs.rshift)) return delta;
    if (int delta = int(select) - int(rhs.select)) return delta;
    if (int delta = int(extend) - int(rhs.extend)) return delta;
    return int(sxtend) - int(rhs.sxtend);
  }

  ConstNodeBase const*
  BitFilter::Eval( unisim::util::symbolic::EvalSpace const& evs, ConstNodeBase const** cnbs ) const
  {
    ConstNodeBase const* args[2] = {cnbs[0], 0};
    Expr dispose;
    if (rshift)
      {
        ConstNode<shift_type> rsh(rshift);
        rsh.Retain(); // Prevent deletion of this stack-allocated object
        args[1] = &rsh;
        args[0] = args[0]->apply("Lsr", args);
        dispose = args[0];
      }
    // TODO: avoid usage of actual value
    uint64_t value = args[0]->GetBits(0);
    unsigned ext = 64 - select;
    value <<= ext;
    value = sxtend ? (int64_t(value) >> ext) : value >> ext;

    switch (extend)
      {
      case 64: return new ConstNode<uint64_t>( value );
      case 32: return new ConstNode<uint32_t>( value );
      case 16: return new ConstNode<uint16_t>( value );
      case  8: return new ConstNode<uint8_t>( value );
      case  1: return new ConstNode<bool>( value );
      }

    // struct Bad {};
    // throw Bad ();
    return 0;
  }

  int
  BitFilter::GenCode( Label& label, Variables& vars, std::ostream& sink ) const
  {
    bool selection = source > select;
    if (extend == source and selection)
      {
        bool done = true;
        if      (not rshift and not sxtend and select < 64)
          sink << "(" << GetCode(input, vars, label, source) << " and " << dbx(source/8, (1ull << select)-1) << ")";
        else if ((rshift + select) == extend)
          sink << "(" << GetCode(input, vars, label, source) << " rshift" << (sxtend?"s ":"u ") << dbx(source/8, rshift) << ")";
        else
          done = false;

        if (done)
          return extend;
      }

    bool extension = extend > select;
    if (extension)
      sink << '(' << (sxtend ? "exts " : "extu ");
    if (selection)
      sink << '(';

    int chksize = ASExprNode::GenerateCode( input, vars, label, sink );
    if (chksize != source) throw 0;

    if (selection)
      sink << " {" << (rshift) << "," << (rshift+select-1) << "})";
    if (extension)
      sink << ' ' << extend << ')';

    return extend;
  }

  void
  BitFilter::Repr( std::ostream& sink ) const
  {
    sink << "BitFilter(" << input
         << ", " << source
         << ", " << rshift
         << ", " << select
         << ", " << extend
         << ", " << (sxtend ? "signed" : "unsigned")
         << ")";
  }

  int
  RegReadBase::GenCode( Label& label, Variables& vars, std::ostream& sink ) const
  {
    unsigned bitsize = GetType()->GetBitSize();
    GetRegName( sink );
    sink << "<" << bitsize << ">";
    return bitsize;
  }

  void
  RegReadBase::Repr( std::ostream& sink ) const
  {
    sink << "RegRead( ";
    GetRegName( sink );
    sink << " )";
  }

  int
  RegWriteBase::GenerateCode( Label& label, Variables& vars, std::ostream& sink ) const
  {
    /* Name of the assigned register */
    int lhsize = size, rhsize;
    GetRegName( sink );
    sink << '<' << size << '>';
    if (rsize != size)
      {
        sink << '{' << rbase << ',' << (rbase + rsize - 1) << '}';
        lhsize = rsize;
      }
    sink << " := ";
    if (value->AsConstNode())
      rhsize = ASExprNode::GenerateCode( value, vars, label, sink );
    else
      {
        auto const& var = vars[value];
        if (var.first.empty())
          throw std::logic_error( "corrupted sink" );
        sink << var.first;
        rhsize = var.second;
      }
    if (lhsize != rhsize)
      throw std::logic_error( "none matching size in register assignment" );
    return rsize;
  }

  void RegWriteBase::Repr( std::ostream& sink ) const
  {
    sink << "RegWrite( ";
    GetRegName( sink );
    sink << ", " << size << ", " << rbase << ", " << rsize << ", ";
    value->Repr( sink );
    sink << " )";
  }

  void
  Branch::Repr( std::ostream& sink ) const
  {
    sink << "Branch(";
    value->Repr( sink );
    sink << ")";
  }

  int
  Load::GenCode( Label& label, Variables& vars, std::ostream& sink ) const
  {
    /* TODO: exploit alignment info */
    sink << "@[" << GetCode(addr, vars, label) << ',' << (bigendian?"->":"<-") << ',' << bytecount() << "]";
    return 8*bytecount();
  }

  int
  Store::GenCode( Label& label, Variables& vars, std::ostream& sink ) const
  {
    /* TODO: exploit alignment info */
    sink << "@[" << GetCode(addr, vars, label) << ',' << (bigendian?"->":"<-") << ',' << bytecount() << "] := " << GetCode(value, vars, label);
    return 0;
  }

  void
  MemAccess::Repr( std::ostream& sink ) const
  {
    sink << "[" << addr << ',' << bytecount() << ",^" << alignment << ',' << (bigendian ? "be" : "le") << "]";
  }

  void
  Store::Repr( std::ostream& sink ) const
  {
    MemAccess::Repr( sink );
    sink << " := " << value;
  }

  namespace {
    struct SinksMerger { void operator () ( std::set<Expr>& sinks, Expr const& l, Expr const& r ) { sinks.insert( l ); } };
  }

  void
  ActionNode::simplify()
  {
    while (cond.good())
      {
        cond = ASExprNode::Simplify( cond );
        if (ConstNodeBase const* c = cond.ConstSimplify())
          {
            //            std::cerr << "warning: post simplification of if-then-else condition\n";
            bool eval = dynamic_cast<ConstNode<bool> const&>(*c).value;
            ActionNode* always = nexts[eval];
            ActionNode* never = nexts[not eval];
            delete never;
            // Import always branch
            for (unsigned idx = 0; idx < 2; ++idx)
              {
                nexts[idx] = always->nexts[idx];
                always->nexts[idx] = 0;
              }
            cond = always->cond;
            sinks.insert(always->sinks.begin(), always->sinks.end());
            delete always;
          }
        else
          break;
      }

    {
      std::set<Expr> nsinks;
      for (std::set<Expr>::const_iterator itr = sinks.begin(), end = sinks.end(); itr != end; ++itr)
        {
          Expr x = ASExprNode::Simplify( *itr );
          x.ConstSimplify();
          nsinks.insert( x );
        }
      std::swap(nsinks, sinks);
    }

    if (not cond.good())
      return;

    for (unsigned choice = 0; choice < 2; ++choice)
      if (ActionNode* next = nexts[choice])
        next->simplify();

    factorize( sinks, nexts[0]->sinks, nexts[1]->sinks, SinksMerger() );

    bool leaf = true;
    for (unsigned choice = 0; choice < 2; ++choice)
      if (ActionNode* next = nexts[choice])
        {
          if (next->cond.good() or next->sinks.size()) leaf = false;
          else { delete next; nexts[choice] = 0; }
        }

    if (leaf)
      cond = Expr();
    else if (OpNodeBase const* onb = cond->AsOpNode())
      if (onb->op.code == onb->op.Not)
        {
          // If condition begins with a logical not, remove the not and
          //   swap if then else branches
          cond = onb->GetSub(0);
          std::swap( nexts[false], nexts[true] );
        }

  }

  void
  ActionNode::commit_stats()
  {
    struct Sec
    {
      void Flood( Expr const& e )
      {
        for (unsigned idx = 0, end = e->SubCount(); idx < end; ++idx)
          this->Process( e->GetSub(idx) );
      }
      void Process( Expr const& e )
      {
        if (not e->SubCount())
          return;
        bool cont = true;
        for (Sec* sec = this; sec; sec = sec->up)
          cont &= (sec->stats[e]++ == 0);
        if (cont)
          this->Flood( e );
      }
      Sec( ActionNode* node, Sec* _up )
        : stats(node->sestats), up(_up)
      {
        // First level of expression is not functionnal (architectual side effect)
        for (std::set<Expr>::const_iterator itr = node->sinks.begin(), end = node->sinks.end(); itr != end; ++itr)
          this->Flood( *itr );
        for (unsigned choice = 0; choice < 2; ++choice)
          if (ActionNode* next = node->nexts[choice])
            { Sec sub(next,this); }
      }
      std::map<Expr,unsigned>& stats; Sec* up;
    } sec(this,0);
  }

  void
  Program::Generate( ActionNode const* action_tree )
  {
    struct Context
    {
      Context() : upper(0) {}
      Context( Context* _up ) : upper(_up)
      {
        if (_up) next_tmp = _up->next_tmp;
        if (_up) vars = _up->vars;
      }

      void add_pending( RegWriteBase const* e ) { pendings.push_back(e); }
      bool has_pending() const { return pendings.size() > 0; }

      std::string const& mktemp(Expr const& expr, unsigned size, Assignment const* assignment)
      {
        auto itr = vars.lower_bound(expr);
        if (itr != vars.end() and itr->first == expr)
          throw std::logic_error( "multiple temporary definitions" );
        
        std::string name;
        {
          std::ostringstream buf;
          buf << "%%" << vars.size() << "<" << size << ">";
          name = buf.str();
        }
        
        itr = vars.emplace_hint(itr, std::piecewise_construct, std::forward_as_tuple(expr), std::forward_as_tuple(std::move(name), size) );
        return itr->second.first;
      }
      
      void GenCode( ActionNode const* action_tree, Label const& start, Label const& after )
      {
        Branch const* nia = 0;

        // Using a delayed writing mechanism so that the last code line
        // produced is linked to the next code line given by the upper
        // context instead of a fresh new one
        struct Head
        {
          Head( Label const& _start, int _after ) : cur(_start), after(_after) {}
          ~Head()
          {
            if (not pending.size()) return;
            Label::subst_next(pending, after);
            cur.write( pending );
            pending.clear();
          }

          Label& current() { flush(); return cur; }
          void write( std::string const& s )
          {
            flush();
            if (s.size()==0) throw std::runtime_error("xxx");
            pending = s;
          }
          void flush()
          {
            if (not pending.size()) return;
            cur.write( pending );
            pending.clear();
          }
          int GenCode(Expr const& expr, Context& context, Assignment const* rw)
          {
            std::string tmp_src, tmp_dst;
            int retsize;
            {
              std::ostringstream buffer;
              retsize = ASExprNode::GenerateCode( expr, context.vars, this->current(), buffer );
              tmp_src = buffer.str();
            }
            std::ostringstream buffer;
            buffer << context.mktemp( expr, retsize, rw ) << " := " << tmp_src << "; goto <next>";
            this->write( buffer.str() );
            return retsize;
          }
      
          Label cur;
          int after;
          std::string pending;
        } head( start, after.GetID() );

        {
          // Ordering Sub Expressions by size of expressions (so that
          // smaller expressions are factorized in larger ones)
          struct CSE : public std::multimap<unsigned,Expr>
          {
            void Process( Expr const& expr )
            {
              insert( std::make_pair( CountSubs( expr ), expr ) );
            }
            unsigned CountSubs( Expr const& expr )
            {
              unsigned sum = 1;
              for (unsigned idx = 0, end = expr->SubCount(); idx < end; ++idx)
                sum += CountSubs( expr->GetSub(idx) );
              return sum;
            }
          } cse;

          for (std::map<Expr,unsigned>::const_iterator itr = action_tree->sestats.begin(), end = action_tree->sestats.end(); itr != end; ++itr)
            {
              if (itr->second >= 2 and not this->vars.count(itr->first))
                cse.Process(itr->first);
            }

          // Keeping track of expressions involved in register
          // assignment (Clobbers). They require temporaries (which names
          // may differ from conventional pure CSE temporaries)
          std::map<Expr,Assignment const*> rtmps;
          for (std::set<Expr>::const_iterator itr = action_tree->sinks.begin(), end = action_tree->sinks.end(); itr != end; ++itr)
            {
              if (Assignment const* rw = dynamic_cast<Assignment const*>( itr->node ))
                if (not rw->value->AsConstNode() and not this->vars.count(rw->value))
                  rtmps[rw->value] = rw;
            }
          
          for (std::multimap<unsigned,Expr>::const_iterator itr = cse.begin(), end = cse.end(); itr != end; ++itr)
            {
              std::map<Expr,Assignment const*>::const_iterator rtmp = rtmps.find(itr->second);
              head.GenCode(itr->second, *this, rtmp != rtmps.end() ? rtmp->second : 0);
            }
        }

        for (std::set<Expr>::const_iterator itr = action_tree->sinks.begin(), end = action_tree->sinks.end(); itr != end; ++itr)
          {
            if (Assignment const* assignment = dynamic_cast<Assignment const*>( itr->node ))
              {
                Expr const  value = assignment->value;

                if (not value->AsConstNode() and not this->vars.count(value))
                  head.GenCode(value, *this, assignment);

                if (Branch const* branch = dynamic_cast<Branch const*>( assignment ))
                  { nia = branch; }
                else if (RegWriteBase const* rw = dynamic_cast<RegWriteBase const*>( assignment ))
                  { this->add_pending( rw ); }
                else
                  throw std::logic_error( "unknown assignment" );
              }
            else
              {
                std::ostringstream buffer;
                if (ASExprNode::GenerateCode( *itr, this->vars, head.current(), buffer ))
                  throw std::logic_error( "corrupted sink" );

                buffer << "; goto <next>";
                head.write( buffer.str() );
              }
          }

        if (not action_tree->cond.good())
          {
            if (action_tree->sinks.size() == 0)
              throw std::logic_error( "empty leaf" );
          }
        else
          {
            std::ostringstream buffer;
            Label ifinsn(head.current());
            buffer << "if " << GetCode(action_tree->cond, this->vars, ifinsn) << " ";

            // Preparing room for if then else code
            Label endif( after );
            if (nia or (after.valid() and (this->has_pending())))
              endif.allocate();

            if (not action_tree->nexts[0]) {
              Label ifthen(ifinsn);
              buffer << " goto " << ifthen.allocate() << " else goto " << endif.GetID();
              ifinsn.write( buffer.str() );
              Context nxt(this);
              nxt.GenCode( action_tree->nexts[1], ifthen, endif );
            } else if (not action_tree->nexts[1]) {
              Label ifelse(ifinsn);
              buffer << " goto " << endif.GetID() << " else goto " << ifelse.allocate();
              ifinsn.write( buffer.str() );
              Context nxt(this);
              nxt.GenCode( action_tree->nexts[0], ifelse, endif );
            } else {
              Label ifthen(ifinsn), ifelse(ifinsn);
              buffer << " goto " << ifthen.allocate() << " else goto " << ifelse.allocate();
              ifinsn.write( buffer.str() );
              {
                Context nxt(this);
                nxt.GenCode( action_tree->nexts[1], ifthen, endif );
              }
              {
                Context nxt(this);
                nxt.GenCode( action_tree->nexts[0], ifelse, endif );
              }
            }

            head.current() = endif;
          }

        if (not nia and not after.valid())
          return;

        for (RegWriteBase const* rw : this->pendings)
          {
            std::ostringstream buffer;
            rw->GenerateCode(head.current(), this->vars, buffer);
            buffer << "; goto <next>";
            head.write( buffer.str() );
          }

        if (not nia)
          return;

        Label current( head.current() );

        for (Context* uc = this->upper; uc; uc = uc->upper)
          {
            for (RegWriteBase const* rw : uc->pendings)
              {
                std::ostringstream buffer;
                rw->GenerateCode(current, this->vars, buffer);
                buffer << "; goto <next>";
                current.write( buffer.str() );
              }
          }

        std::ostringstream buffer;
        Expr const& target = nia->value;
        buffer << "goto (" << GetCode(target, this->vars, current) << (target->AsConstNode() ? ",0" : "") << ")";
        nia->annotate( buffer );
        current.write( buffer.str() );
      }

      Context* upper;
      typedef std::vector<RegWriteBase const*> Pendings;
      Pendings pendings;
      Variables vars;
      std::map<unsigned,unsigned> next_tmp;
    };

    Label beglabel(*this), endlabel(*this);
    beglabel.allocate();
    Context ctx;
    ctx.GenCode( action_tree, beglabel, endlabel );
  }

  void
  UndefinedValueBase::Repr( std::ostream& sink ) const
  {
    sink << "UndefinedValue<";
    GetType()->GetName(sink);
    sink << ">()";
  }

  int
  UndefinedValueBase::GenCode(Label&, Variables&, std::ostream& sink) const
  {
    sink << "\\undef";
    return GetType()->GetBitSize();
  }

} /* end of namespace binsec */
} /* end of namespace symbolic */
} /* end of namespace util */
} /* end of namespace unisim */

