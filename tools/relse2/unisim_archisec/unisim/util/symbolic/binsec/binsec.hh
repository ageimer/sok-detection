/*
 *  Copyright (c) 20017-2018,
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
 
#ifndef __UNISIM_UTIL_SYMBOLIC_BINSEC_BINSEC_HH__
#define __UNISIM_UTIL_SYMBOLIC_BINSEC_BINSEC_HH__

#include <unisim/util/symbolic/vector/vector.hh>
#include <unisim/util/symbolic/symbolic.hh>
#include <map>
#include <set>
#include <vector>

namespace unisim {
namespace util {
namespace symbolic {

  struct Unimplemented {};

  template <typename VALUE_TYPE>
  struct FpSmartValue : SmartValue<VALUE_TYPE>
  {

    typedef VALUE_TYPE value_type;
    typedef SmartValue<value_type> this_type;
    static ValueType const* GetType() { return CValueType(value_type()); }

    Expr expr;

    FpSmartValue() : SmartValue<value_type>() {}

    FpSmartValue( Expr const& _expr ) : SmartValue<value_type>( _expr ) {}

    explicit FpSmartValue( value_type value ) :
      FpSmartValue( make_const( value ) ) {}

    template <typename SRC_VALUE_TYPE>
    explicit FpSmartValue( SmartValue<SRC_VALUE_TYPE> const& other )
    {
      if (CmpTypes<SRC_VALUE_TYPE,VALUE_TYPE>::same) {
        expr = other.expr;
      } else {
        expr = new CastNode<VALUE_TYPE,SRC_VALUE_TYPE>( other.expr );
        expr.ConstSimplify();
      }
    }

    static bool const is_signed = std::numeric_limits<value_type>::is_signed;

    this_type& operator = ( this_type const& other ) { expr = other.expr; return *this; }

    template <typename SHT>
    this_type operator << ( SHT sh ) const { throw Unimplemented(); return FpSmartValue(); }
    template <typename SHT>
    this_type operator >> ( SHT sh ) const { throw Unimplemented(); return FpSmartValue(); }
    template <typename SHT>
    this_type& operator <<= ( SHT sh ) { throw Unimplemented(); return *this; }
    template <typename SHT>
    this_type& operator >>= ( SHT sh ) { throw Unimplemented(); return *this; }

    template <typename SHT>
    this_type operator << ( SmartValue<SHT> const& sh ) const { throw Unimplemented(); return FpSmartValue(); }
    template <typename SHT>
    this_type operator >> ( SmartValue<SHT> const& sh ) const { throw Unimplemented(); return FpSmartValue(); }

    this_type operator - () const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator ~ () const { throw Unimplemented(); return FpSmartValue(); }

    this_type& operator += ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator -= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator *= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator /= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator %= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator ^= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator &= ( this_type const& other ) { throw Unimplemented(); return *this; }
    this_type& operator |= ( this_type const& other ) { throw Unimplemented(); return *this; }

    this_type operator + ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator - ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator * ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator / ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator % ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator ^ ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator & ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }
    this_type operator | ( this_type const& other ) const { throw Unimplemented(); return FpSmartValue(); }

    SmartValue<bool> operator == ( this_type const& other ) const { return SmartValue<bool>( make_operation( "Teq", expr, other.expr ) ); }
    SmartValue<bool> operator != ( this_type const& other ) const { return SmartValue<bool>( make_operation( "Tne", expr, other.expr ) ); }
    SmartValue<bool> operator <= ( this_type const& other ) const { throw Unimplemented(); return SmartValue<bool>(); }
    SmartValue<bool> operator >= ( this_type const& other ) const { throw Unimplemented(); return SmartValue<bool>(); }
    SmartValue<bool> operator < ( this_type const& other ) const  { throw Unimplemented(); return SmartValue<bool>(); }
    SmartValue<bool> operator > ( this_type const& other ) const  { throw Unimplemented(); return SmartValue<bool>(); }

  };

namespace binsec {
  
  typedef FpSmartValue<double> F64;
  typedef FpSmartValue<float>  F32;
  typedef SmartValue<bool>     BOOL;
  typedef SmartValue<uint8_t>  U8;
  typedef SmartValue<uint16_t> U16;
  typedef SmartValue<uint32_t> U32;
  typedef SmartValue<uint64_t> U64;
  typedef SmartValue<int8_t>   S8;
  typedef SmartValue<int16_t>  S16;
  typedef SmartValue<int32_t>  S32;
  typedef SmartValue<int64_t>  S64;

  struct dbx
  {
    dbx( unsigned _bytes, uint64_t _value ) : value(_value << (64 - 8 * _bytes) >> (64 - 8 * _bytes)), bytes(_bytes) {} uint64_t value; unsigned bytes;
    friend std::ostream& operator << ( std::ostream& sink, dbx const& _ );
  };
  
  struct ActionNode : public Conditional<ActionNode>
  {
    ActionNode() : Conditional<ActionNode>(), sinks(), sestats() {}

    void                    add_sink( Expr expr ) { expr.ConstSimplify(); sinks.insert( expr ); }
    void                    simplify();
    void                    commit_stats();
    
    std::set<Expr>          sinks;
    std::map<Expr,unsigned> sestats;
  };

  struct Program : public std::map<int,std::string>
  {
    typedef std::map<int,std::string> MapType;
    typedef MapType::iterator iterator;
    typedef MapType::const_iterator const_iterator;
    
    Program() : insn_count(0) {}
    
    void        Generate( ActionNode const* action_tree );
    
    int         next_insn() const { return insn_count; }
    int         allocate() { return insn_count++; }
    iterator    write(int idx, std::string const& s)
    {
      iterator itr = lower_bound(idx);
      if (itr != end() and itr->first == idx)
        throw std::runtime_error("overwriting statement");
      return insert( itr, std::make_pair(idx,s) );
    }
    
    int insn_count;
  };
  
  struct Label
  {
    Label( Program& _program ) : program(_program), id(-1) {}
    
    Label& operator= (Label const& l)
    {
      if (&program != &l.program) throw std::runtime_error("label programs must aggree");
      id = l.id;
      return *this;
    }
    
    int allocate() { return (id = program.allocate()); }
    
    bool valid() const { return id >= 0; }
    
    static bool subst_next( std::string& s, int next );
    
    int write( std::string const& src )
    {
      Program::iterator insn = program.write( id, src );
      if (subst_next(insn->second, program.next_insn()))
        id = program.allocate();
      return insn->first;
    }
    
    int GetID() const { return id; }
    
  private:
    Program& program;
    int id;
  };
  
  typedef std::map<Expr,std::pair<std::string,int>> Variables;
  
  struct ASExprNode : public ExprNode
  {
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const = 0;
    static  int GenerateCode( Expr const& expr, Variables& vars, Label& label, std::ostream& sink );
    virtual Expr Simplify() const { return this; }
    static  Expr Simplify( Expr const& );
  };

  struct BitFilter : public ASExprNode
  {
    BitFilter( Expr const& _input, unsigned _source, unsigned _rshift, unsigned _select, unsigned _extend, bool _sxtend )
      : input(_input), source(_source), pad0(), rshift(_rshift), pad1(), select(_select), pad2(), extend(_extend), sxtend(_sxtend)
    {}

    Expr mksimple();
    virtual BitFilter* Mutate() const override { return new BitFilter( *this ); }
    virtual Expr Simplify() const override;
    virtual ValueType const* GetType() const { return CValueType(ValueType::UNSIGNED, extend); }
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const;
    virtual void Repr( std::ostream& sink ) const;
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<BitFilter const&>( rhs ) ); }
    int compare( BitFilter const& rhs ) const;
    virtual unsigned SubCount() const { return 1; }
    virtual Expr const& GetSub(unsigned idx) const { if (idx != 0) return ExprNode::GetSub(idx); return input; }

    virtual ConstNodeBase const* Eval( unisim::util::symbolic::EvalSpace const& evs, ConstNodeBase const** cnbs ) const;
    
    Expr     input;
    uint64_t source   : 15;
    uint64_t pad0     :  1;
    uint64_t rshift   : 15;
    uint64_t pad1     :  1;
    uint64_t select   : 15;
    uint64_t pad2     :  1;
    uint64_t extend   : 15;
    uint64_t sxtend   :  1;
  };

  struct GetCode
  {
    GetCode(Expr const& _expr, Variables& _vars, Label& _label)
      : expr(_expr), vars(_vars), label(_label), expected(-1)
    {}
    GetCode(Expr const& _expr, Variables& _vars, Label& _label, int _expected)
      : expr(_expr), vars(_vars), label(_label), expected(_expected)
    {}
    
    friend std::ostream& operator << ( std::ostream& sink, GetCode const& gc )
    {
      int size = ASExprNode::GenerateCode( gc.expr, gc.vars, gc.label, sink );
      if (gc.expected >= 0 and gc.expected != size) { struct TypeSizeMisMatch {}; throw TypeSizeMisMatch(); }
      return sink;
    }
    Expr const& expr; Variables& vars; Label& label;
    int expected;
  };

  struct RegReadBase : public ASExprNode
  {
    virtual void GetRegName( std::ostream& ) const = 0;
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const;
    virtual void Repr( std::ostream& sink ) const;
    virtual unsigned SubCount() const { return 0; }
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<RegReadBase const&>( rhs ) ); }
    int compare( RegReadBase const& rhs ) const { return 0; }
  };

  template <typename RID>
  struct RegRead : public RegReadBase
  {
    typedef RegRead<RID> this_type;
    typedef RegReadBase Super;
    RegRead( RID _id ) : Super(), id(_id) {}
    virtual this_type* Mutate() const override { return new this_type( *this ); }
    virtual ValueType const* GetType() const override { return RID::GetType(); }
    virtual void GetRegName( std::ostream& sink ) const override { id.Repr(sink); }
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<RegRead const&>( rhs ) ); }
    int compare( RegRead const& rhs ) const { if (int delta = Super::compare(rhs)) return delta; return id.cmp( rhs.id ); }

    RID id;
  };

  struct Assignment : public ExprNode
  {
    Assignment( Expr const& _value ) : value(_value) {}
    
    virtual ValueType const* GetType() const { return NoValueType(); }
    virtual unsigned SubCount() const { return 1; }
    virtual Expr const& GetSub(unsigned idx) const { if (idx != 0) return ExprNode::GetSub(idx); return value; }
    
    Expr value;
  };
  
  struct RegWriteBase : public Assignment
  {
    RegWriteBase( Expr const& _value, int _size ) : Assignment(_value), size(_size), rbase(0), rsize(_size) {}
    RegWriteBase( Expr const& _value, int _size, int _rbase, int _rsize ) : Assignment(_value), size(_size), rbase(_rbase), rsize(_rsize) {}
    
    virtual void GetRegName( std::ostream& ) const = 0;
    
    int GenerateCode( Label& label, Variables& vars, std::ostream& sink ) const;
    virtual void Repr( std::ostream& sink ) const;
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<RegWriteBase const&>( rhs ) ); }
    int compare( RegWriteBase const& rhs ) const
    {
      if (int delta = size - rhs.size) return delta;
      if (int delta = rbase - rhs.rbase) return delta;
      return rsize - rhs.rsize;
    }
    
    int size, rbase, rsize;
  };

  template <typename RID>
  struct RegWrite : public RegWriteBase
  {
    typedef RegWrite<RID> this_type;
    typedef RegWriteBase Super;
    RegWrite( RID _id, Expr const& _value ) : Super(_value, TypeInfo<typename RID::value_type>::BITSIZE), id(_id) {}
    RegWrite( RID _id, int rbase, int rsize, Expr const& _value ) : Super(_value, RID::GetType()->GetBitSize(), rbase, rsize), id(_id) {}
    virtual this_type* Mutate() const override { return new this_type( *this ); }
    virtual void GetRegName( std::ostream& sink ) const override { id.Repr(sink); }
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<RegWrite const&>( rhs ) ); }
    int compare( RegWrite const& rhs ) const { if (int delta = id.cmp( rhs.id )) return delta; return Super::compare( rhs ); }

    RID id;
  };

  struct Branch : public Assignment
  {
    Branch( Expr const& value ) : Assignment( value ) {}
    virtual Branch* Mutate() const override { return new Branch( *this ); }
    virtual void annotate(std::ostream& sink) const {};
    virtual int cmp( ExprNode const& rhs ) const override { return 0; }
    virtual void Repr( std::ostream& sink ) const;
  };

  template <typename T>
  struct Call : public Branch
  {
    typedef Call<T> this_type;
    Call( Expr const& target, T ra ) : Branch(target), return_address(ra) {}
    virtual this_type* Mutate() const override { return new this_type( *this ); }
    virtual void annotate(std::ostream& sink) const override
    {
      sink << " // call (" << binsec::dbx(sizeof(T), return_address) << ",0)";
    }
    virtual void Repr( std::ostream& sink ) const
    {
      sink << "Call(";
      Branch::Repr(sink);
      sink << ", " << binsec::dbx(sizeof(T), return_address) << ")";
    }
    virtual int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<this_type const&>( rhs ) ); }
    int compare( this_type const& rhs ) const
    {
      if (return_address < rhs.return_address) return -1;
      return int(return_address > rhs.return_address);
    }

    T return_address;
  };
  
  struct AssertFalse : public ASExprNode
  {
    AssertFalse() {}
    virtual AssertFalse* Mutate() const override { return new AssertFalse( *this ); }
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const override
    {
      sink << "assert (false)";
      return 0;
    }
    virtual ValueType const* GetType() const override{ return NoValueType(); }

    virtual int cmp( ExprNode const& brhs ) const override { return 0; }
    virtual unsigned SubCount() const override { return 0; }
    virtual void Repr( std::ostream& sink ) const override { sink << "assert (false)"; }
  };

  struct MemAccess : public ASExprNode
  {
    MemAccess(Expr const& _addr, unsigned _size, unsigned _alignment, bool _bigendian)
      : addr(_addr), lastbyte(_size-1), alignment(_alignment), bigendian(_bigendian)
    {}
    unsigned bytecount() const { return lastbyte+1; }
    virtual void Repr( std::ostream& sink ) const;
    int cmp( ExprNode const& rhs ) const override { return compare( dynamic_cast<MemAccess const&>( rhs ) ); }
    int compare( MemAccess const& rhs ) const
    {
      if (int delta = int(lastbyte) - int(rhs.lastbyte)) return delta;
      if (int delta = int(alignment) - int(rhs.alignment)) return delta;
      return (int(bigendian) - int(rhs.bigendian));
    }
    
    Expr addr;
    uint32_t lastbyte  : 16; // size in bytes [1,..;65536]
    uint32_t alignment :  4; // (log2) [1,2,4,8,...,32768] bytes
    uint32_t bigendian :  1; // 0=little-endian
    uint32_t reserved  : 11; // reserved
  };
    
  struct Load : public MemAccess
  {
    Load( Expr const& _addr, unsigned _size, unsigned _alignment, bool _bigendian )
      : MemAccess(_addr, _size, _alignment, _bigendian)
    {}
    virtual Load* Mutate() const override { return new Load(*this); }
    virtual ValueType const* GetType() const override { return CValueType(ValueType::UNSIGNED, 8*bytecount()); }
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const override;
    virtual void Repr( std::ostream& sink ) const override { MemAccess::Repr(sink); }
    virtual unsigned SubCount() const override { return 1; }
    virtual Expr const& GetSub(unsigned idx) const override { if (idx != 0) return ExprNode::GetSub(idx); return addr; }
  };

  struct Store : public MemAccess
  {
    Store( Expr const& _addr, Expr const& _value, unsigned _size, unsigned _alignment, bool _bigendian )
      : MemAccess(_addr, _size, _alignment, _bigendian), value(_value)
    {}
    virtual ValueType const* GetType() const override { return NoValueType(); }
    virtual Store* Mutate() const override { return new Store(*this); }
    virtual int GenCode( Label& label, Variables& vars, std::ostream& sink ) const override;
    virtual void Repr( std::ostream& sink ) const override;
    virtual unsigned SubCount() const override { return 2; }
    virtual Expr const& GetSub(unsigned idx) const override { switch (idx) { case 0: return addr; case 1: return value; } return ExprNode::GetSub(idx); }
      
    Expr value;
  };
    
  struct UndefinedValueBase : public unisim::util::symbolic::binsec::ASExprNode
  {
    UndefinedValueBase() {}
    virtual unsigned SubCount() const override { return 0; };
    virtual void Repr( std::ostream& sink ) const override;
    virtual int cmp( ExprNode const& rhs ) const override { return 0; }
    virtual int GenCode(Label&, Variables&, std::ostream& sink) const;
  };

  template <typename T>
  struct UndefinedValue : public UndefinedValueBase
  {
    typedef UndefinedValue<T> this_type;

    virtual this_type* Mutate() const override { return new this_type( *this ); }
    virtual ValueType const* GetType() const override { return unisim::util::symbolic::CValueType(T()); }
  };

} /* end of namespace binsec */
} /* end of namespace symbolic */
} /* end of namespace util */
} /* end of namespace unisim */

#endif // __UNISIM_UTIL_SYMBOLIC_BINSEC_BINSEC_HH__
