/*
 *  Copyright (c) 2007-2016,
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
 
#ifndef __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_FLOATING_HH__
#define __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_FLOATING_HH__

#include <unisim/util/simfloat/floating.hh>
#include <unisim/component/cxx/processor/arm/psr.hh>
#include <unisim/kernel/variable/variable.hh>
#include <unisim/service/interfaces/register.hh>

#include <limits>
#include <inttypes.h>
#include <string>

namespace unisim {
namespace component {
namespace cxx {
namespace processor {
namespace arm {

  struct VFPExpandImm;

namespace simfloat {
  struct SoftFloat;
  struct SoftDouble;
  
  struct Flags
  {
    Flags()
      : fRoundToEven(true), fUpApproximateInfty(false), rmRound(RMNearest)
      , fKeepSignalingConversion(true), aApproximation(AExact), rrReadResult(RRTotal)
      , fEffectiveRoundToEven(false), fSNaNOperand(false), qnrQNaNResult(QNNRUndefined)
      , feExcept(FENoException), fDivisionByZero(false)
    {}
    Flags(const Flags& rpSource)
      : fRoundToEven(rpSource.fRoundToEven), fUpApproximateInfty(rpSource.fUpApproximateInfty)
      , rmRound(rpSource.rmRound), fKeepSignalingConversion(rpSource.fKeepSignalingConversion)
      , aApproximation(rpSource.aApproximation), rrReadResult(rpSource.rrReadResult)
      , fEffectiveRoundToEven(rpSource.fEffectiveRoundToEven), fSNaNOperand(rpSource.fSNaNOperand)
      , qnrQNaNResult(rpSource.qnrQNaNResult), feExcept(rpSource.feExcept)
      , fDivisionByZero(rpSource.fDivisionByZero)
    {}

    Flags& operator=(const Flags& rpSource)
    {
      aApproximation = rpSource.aApproximation;
      rrReadResult = rpSource.rrReadResult;
      fEffectiveRoundToEven = rpSource.fEffectiveRoundToEven;
      fSNaNOperand = rpSource.fSNaNOperand;
      qnrQNaNResult = rpSource.qnrQNaNResult;
      feExcept = rpSource.feExcept;
      fDivisionByZero = rpSource.fDivisionByZero;
      return *this;
    }
    bool isRoundToEven() const { return fRoundToEven && isNearestRound(); }
    bool isPositiveZeroMAdd() { return true; }
    bool isInftyAvoided() const { return true; }
    bool isAllInftyAvoided() const { return false; }
    bool doesAvoidInfty(bool fNegative) const {  return fNegative ? (rmRound >= RMHighest) : (rmRound & RMLowest); }
    bool isDenormalizedAvoided() const { return false; }
    bool keepNaNSign() const { return true; }
    bool produceMultNaNPositive() const { return true; }
    bool produceDivNaNPositive() const { return true; }
    bool produceAddNaNPositive() const { return true; }
    bool produceSubNaNPositive() const { return true; }
    bool upApproximateInfty() const { return fUpApproximateInfty; }
    bool upApproximateInversionForNear() const { return true; }
    bool chooseNaNAddBeforeMult() const { return true; }
    bool isConvertNaNNegative() const { return true; }
    bool acceptMinusZero() const { return true; }

    void setRoundToEven() { fRoundToEven = true; }
    void clearRoundToEven() { fRoundToEven = false; }
    void setUpApproximateInfty() { fUpApproximateInfty = true; }
    void clearUpApproximateInfty() { fUpApproximateInfty = false; }

    // dynamic read parameters
    Flags& setNearestRound()   { rmRound = RMNearest; return *this; }
    Flags& setHighestRound()   { rmRound = RMHighest; return *this; }
    Flags& setLowestRound()    { rmRound = RMLowest; return *this; }
    Flags& setZeroRound()      { rmRound = RMZero; return *this; }

    bool isLowestRound() const { return rmRound == RMLowest; }
    bool isNearestRound() const { return rmRound == RMNearest; }
    bool isHighestRound() const { return rmRound == RMHighest; }
    bool isZeroRound() const { return rmRound == RMZero; }

    Flags& setKeepSignalingConversion() { fKeepSignalingConversion = true; return *this; }
    Flags& clearKeepSignalingConversion() { fKeepSignalingConversion = false; return *this; }
    bool keepSignalingConversion() const { return fKeepSignalingConversion; }

    // dynamic write parameters
    bool isApproximate() const { return aApproximation != AExact; }
    bool isDownApproximate() const { return aApproximation == ADownApproximate; }
    bool isUpApproximate() const { return aApproximation == AUpApproximate; }
    void setDownApproximate() { aApproximation = ADownApproximate; }
    void setUpApproximate() { aApproximation = AUpApproximate; }
    void clearApproximate() { aApproximation = AExact; }
    enum Direction { Down, Up };
    void setApproximate(Direction dDirection)
    {  aApproximation = ((dDirection == Down) ? ADownApproximate : AUpApproximate); }
    bool isApproximate(Direction dDirection) const
    {  return aApproximation == ((dDirection == Down) ? ADownApproximate : AUpApproximate); }
    bool hasSameApproximation(const Flags& rpSource) const
    {  return aApproximation == rpSource.aApproximation; }
    bool hasIncrementFraction(bool fNegative) const
    {  return fNegative ? isDownApproximate() : isUpApproximate(); }

    void setEffectiveRoundToEven() { fEffectiveRoundToEven = true; }
    void clearEffectiveRoundToEven() { fEffectiveRoundToEven = false; }
    bool hasEffectiveRoundToEven() { return fEffectiveRoundToEven; }

    void setPartialRead() { rrReadResult = RRPartial; }
    void setTotalRead() { rrReadResult = RRTotal; }
    bool isPartialRead() const { return rrReadResult == RRPartial; }
    bool isTotalRead() const { return rrReadResult == RRTotal; }
    bool hasPartialRead() const { return rrReadResult != RRTotal; }

    void setSNaNOperand() { fSNaNOperand = true; }
    bool hasSNaNOperand() const { return fSNaNOperand; }
      
    void setInftyMinusInfty() { assert(!qnrQNaNResult); qnrQNaNResult = QNNRInftyMinusInfty; }
    void setInftyOnInfty() { assert(!qnrQNaNResult); qnrQNaNResult = QNNRInftyOnInfty; }
    void setZeroOnZero() { assert(!qnrQNaNResult); qnrQNaNResult = QNNRZeroOnZero; }
    void setInftyMultZero() { assert(!qnrQNaNResult); qnrQNaNResult = QNNRInftyMultZero; }
    bool hasQNaNResult() const { return qnrQNaNResult; }
    bool isInftyMinusInfty() const { return qnrQNaNResult == QNNRInftyMinusInfty; }
    bool isInftyOnInfty() const { return qnrQNaNResult == QNNRInftyOnInfty; }
    bool isZeroOnZero() const { return qnrQNaNResult == QNNRZeroOnZero; }
    bool isInftyMultZero() const { return qnrQNaNResult == QNNRInftyMultZero; }

    void clear()
    {
      aApproximation = AExact;
      rrReadResult = RRTotal;
      fEffectiveRoundToEven = false;
      fSNaNOperand = false;
      qnrQNaNResult = QNNRUndefined;
      feExcept = FENoException;
      fDivisionByZero = false;
    }

    bool isDivisionByZero() const { return fDivisionByZero; }
    void setDivisionByZero() { fDivisionByZero = true; }
    void clearFlowException() { feExcept = FENoException; }
    void setOverflow() { feExcept = FEOverflow; }
    void setUnderflow() { feExcept = FEUnderflow; }
    bool isOverflow() const { return feExcept == FEOverflow; }
    bool isUnderflow() const { return feExcept == FEUnderflow; }
      
    void setRoundingMode(unsigned int rn_mode)
    {
      switch(rn_mode)
        {
        case 0b00: /* Round to Nearest (RN) mode */
          setNearestRound();
          break;
        case 0b01: /* Round towards Plus Infinity (RP) mode */
          setHighestRound();
          break;
        case 0b10: /* Round towards Minus Infinity (RM) mode */
          setLowestRound();
          break;
        case 0b11: /* Round towards Zero (RZ) mode. */
          setZeroRound();
          break;
        }
    }
  protected:
    enum RoundMode { RMNearest, RMLowest, RMHighest, RMZero };
    enum Approximation { AExact, ADownApproximate, AUpApproximate };
    enum ReadResult { RRTotal, RRPartial };
    enum QNaNResult
      {  QNNRUndefined, QNNRInftyMinusInfty, QNNRInftyOnInfty, QNNRZeroOnZero,
         QNNRInftyMultZero
      };
    enum FlowException { FENoException, FEOverflow, FEUnderflow, FEEnd };
      
  private:
    bool fRoundToEven;
    bool fUpApproximateInfty;
      
    RoundMode rmRound;
    bool fKeepSignalingConversion;

    Approximation aApproximation;
    ReadResult rrReadResult;
    bool fEffectiveRoundToEven;
    bool fSNaNOperand;
    QNaNResult qnrQNaNResult;
    FlowException feExcept;
    bool fDivisionByZero;

  };
  
  template <int BitSizeMantissa, int BitSizeExponent>
  struct SoftFPTraits
    : public unisim::util::simfloat::Numerics::Double::BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>
  {
    static const int UBitSizeMantissa = BitSizeMantissa;
    static const int UBitSizeExponent = BitSizeExponent;
    typedef Flags StatusAndControlFlags;
    
    struct MultExtension
      : public unisim::util::simfloat::Numerics::Double::BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::MultExtension
    {
      typedef Flags StatusAndControlFlags;
    };
  };
  
  template <class FPTraits>
  void Sqrt( unisim::util::simfloat::Numerics::Double::TBuiltDouble<FPTraits>& acc, Flags& flags )
  {
    typedef unisim::util::simfloat::Numerics::Double::TBuiltDouble<FPTraits> SOFTDBL;
    static int const bitSizeMantissa = FPTraits::UBitSizeMantissa;
    static int const bitSizeExponent = FPTraits::UBitSizeExponent;
    static int const bitSizeExtMantissa = bitSizeMantissa + 5;
    static int const bitSizeExtExponent = bitSizeExponent + 2;
    typedef SoftFPTraits<bitSizeExtMantissa,bitSizeExtExponent> SQRTFPTraits;
    typedef unisim::util::simfloat::Numerics::Double::TBuiltDouble<SQRTFPTraits> WorkFP;
      
    Flags xflags;
    typename WorkFP::FloatConversion xconv;
    xconv.setSizeMantissa(bitSizeMantissa).setSizeExponent(bitSizeExponent);
    //xconv.setNegative(acc.isNegative());
    {
      typename SOFTDBL::Exponent const& exp = acc.queryBasicExponent();
      for (int idx = exp.queryCellSize(); --idx >= 0; )
        xconv.exponent()[idx] = exp[idx];
    }
    {
      typename SOFTDBL::Mantissa const& man = acc.queryMantissa();
      for (int idx = man.queryCellSize(); --idx >= 0; )
        xconv.mantissa()[idx] = man[idx];
    }
      
    WorkFP input_value( xconv, xflags );
    WorkFP series_value( input_value );
    // Initial guess by halving exponent
    series_value.querySBasicExponent() >>= 1;
    series_value.querySBasicExponent().plusAssign(series_value.getZeroExponent() >>= 1);
    
    WorkFP half;
    half.querySBasicExponent() = half.getMinusOneExponent();
    
    for (int ttl = 3; ttl >= 0;)
      {
        WorkFP next( input_value );
        xflags.clear();
        // We need to use Round Towards Zero (default would be round
        // to nearest) because we need to have exact values of
        // mantissa bits rather than good quality approximation
        xflags.setZeroRound();
        next.divAssign( series_value, xflags );
        next.plusAssign( series_value, xflags );
        next.multAssign( half, xflags );
          
        WorkFP last( series_value );
        series_value = next;
          
        if (next.queryBasicExponent() != last.queryBasicExponent())
          { ttl = 3; continue; }
        typename WorkFP::Mantissa
          lm( last.queryMantissa() ),
          nm( next.queryMantissa() );
        {
          bool strong_diff = false;
          for (int idx = lm.queryCellSize(); --idx > 0;)
            if (lm[idx] != nm[idx])
              { strong_diff = true; break; }
          if (strong_diff) { ttl = 3; continue; }
        }
        unsigned lm0 = lm[0], nm0 = nm[0], diff = lm0 > nm0 ? (lm0 - nm0) : (nm0 - lm0);
        if (diff >= 4) { ttl = 3; continue; }
        if (diff == 0) break;
        ttl -= 1;
      }
    
      
    typename SOFTDBL::FloatConversion fconv;
    fconv.setSizeMantissa(bitSizeExtMantissa).setSizeExponent(bitSizeExtExponent);
    {
      typename WorkFP::Exponent const& exp = series_value.queryBasicExponent();
      for (int idx = exp.queryCellSize(); --idx >= 0; )
        fconv.exponent()[idx] = exp[idx];
    }
    {
      typename WorkFP::Mantissa const& man = series_value.queryMantissa();
      for (int idx = man.queryCellSize(); --idx >= 0; )
        fconv.mantissa()[idx] = man[idx];
    }
    
    if (xflags.isApproximate())
      fconv.mantissa()[0] |= 1;
    
    acc.setFloat(fconv, flags);
  }
    
  typedef SoftFPTraits<52,11> SoftDoubleTraits;

  struct SoftDouble : public unisim::util::simfloat::Numerics::Double::TBuiltDouble<SoftDoubleTraits>
  {
    SoftDouble() : inherited() {}
    SoftDouble(const SoftFloat& sfFloat, Flags& rpParams);
    SoftDouble(const uint64_t& uDouble) { setChunk((void *) &uDouble, unisim::util::endian::IsHostLittleEndian()); }
    SoftDouble(VFPExpandImm const& imm);
    SoftDouble& operator=(const SoftDouble& sdSource) { return (SoftDouble&) inherited::operator=(sdSource); }
    SoftDouble& assign(const SoftDouble& sdSource) { return (SoftDouble&) inherited::operator=(sdSource); }
    SoftDouble& assign(const SoftDouble& sdSource, Flags& rpParams) { return (SoftDouble&) inherited::operator=(sdSource); }
    SoftDouble& assign(const SoftFloat& sfSource, Flags& rpParams);
    uint64_t queryValue() const
    { uint64_t uResult; fillChunk(&uResult, unisim::util::endian::IsHostLittleEndian()); return uResult; }
    void ToBytes( uint8_t* bytes ) const;
    void FromBytes( uint8_t const* bytes );
    void SquareRoot( Flags& rpParams );
    ComparisonResult compare( SoftDouble const& sdSource ) const;
    
  private:
    typedef unisim::util::simfloat::Numerics::Double::TBuiltDouble<SoftDoubleTraits> inherited;
  };

  typedef SoftFPTraits<23,8> SoftFloatTraits;
  
  struct SoftFloat : public unisim::util::simfloat::Numerics::Double::TBuiltDouble<SoftFloatTraits>
  {
    SoftFloat() : inherited() {}
    SoftFloat(const SoftDouble& sdDouble, Flags& rpParams);
    SoftFloat(const uint32_t& uFloat) { setChunk((void *) &uFloat, unisim::util::endian::IsHostLittleEndian()); }
    SoftFloat(VFPExpandImm const& imm);

    SoftFloat& operator=(const SoftFloat& sfSource)
    {  return (SoftFloat&) inherited::operator=(sfSource); }
    SoftFloat& assign(const SoftFloat& sfSource)
    {  return (SoftFloat&) inherited::operator=(sfSource); }
    SoftFloat& assign(const SoftDouble& sdDouble, Flags& rpParams);
    uint32_t queryValue() const
    {  uint32_t uResult; fillChunk(&uResult, unisim::util::endian::IsHostLittleEndian()); return uResult; }
    void ToBytes( uint8_t* bytes ) const;
    void FromBytes( uint8_t const* bytes ); 
    void SquareRoot( Flags& rpParams );
    ComparisonResult compare( SoftFloat const& sfSource ) const;
    
  private:
    typedef unisim::util::simfloat::Numerics::Double::TBuiltDouble<SoftFloatTraits> inherited;
  };

  inline SoftDouble&
  SoftDouble::assign(const SoftFloat& sfFloat, Flags& rpParams) {
    FloatConversion fcConversion;
    fcConversion.setSizeMantissa(23).setSizeExponent(8);
    fcConversion.setNegative(sfFloat.isNegative());
    fcConversion.exponent()[0] = sfFloat.queryBasicExponent()[0];
    fcConversion.mantissa()[0] = sfFloat.queryMantissa()[0];
    inherited source(fcConversion, rpParams);
    return (SoftDouble&) inherited::operator=(source);
  }

  inline
  SoftDouble::SoftDouble(const SoftFloat& sfFloat, Flags& rpParams)
  { assign(sfFloat, rpParams); }

  inline SoftFloat&
  SoftFloat::assign(const SoftDouble& sdDouble, Flags& rpParams) {
    FloatConversion fcConversion;
    fcConversion.setSizeMantissa(52).setSizeExponent(11);
    fcConversion.setNegative(sdDouble.isNegative());
    fcConversion.exponent()[0] = sdDouble.queryBasicExponent()[0];
    fcConversion.mantissa()[0] = sdDouble.queryMantissa()[0];
    fcConversion.mantissa()[1] = sdDouble.queryMantissa()[1];
    return (SoftFloat&) inherited::operator=(inherited(fcConversion, rpParams));
  }

  inline
  SoftFloat::SoftFloat(const SoftDouble& sdDouble, Flags& rpParams)
  { assign(sdDouble, rpParams); }

  class FloatingPointRegisterInterface : public unisim::service::interfaces::Register
  {
  public:
    FloatingPointRegisterInterface(const char *name, SoftDouble *value);
    virtual ~FloatingPointRegisterInterface();
    virtual const char *GetName() const;
    virtual void GetValue(void *buffer) const;
    virtual void SetValue(const void *buffer);
    virtual int GetSize() const;
  private:
    std::string name;
    SoftDouble *value;
  };

  class FloatingPointRegisterView : public unisim::kernel::VariableBase
  {
  public:
    FloatingPointRegisterView(const char *name, unisim::kernel::Object *owner, SoftDouble& storage, const char *description);
    virtual ~FloatingPointRegisterView();
    virtual const char *GetDataTypeName() const;
    virtual operator bool () const;
    virtual operator long long () const;
    virtual operator unsigned long long () const;
    virtual operator double () const;
    virtual operator std::string () const;
    virtual unisim::kernel::VariableBase& operator = (bool value);
    virtual unisim::kernel::VariableBase& operator = (long long value);
    virtual unisim::kernel::VariableBase& operator = (unsigned long long value);
    virtual unisim::kernel::VariableBase& operator = (double value);
    virtual unisim::kernel::VariableBase& operator = (const char * value);
  private:
    SoftDouble& storage;
  };
  
  struct FP
  {
    typedef SoftDouble F64;
    typedef SoftFloat  F32;
    
    template <typename SOFTDBL> static
    void Abs( SOFTDBL& acc )
    {
      acc.setNegative(false);
    }
    
    template <typename SOFTDBL> static
    void Neg( SOFTDBL& acc )
    {
      acc.opposite();
    }

    template <typename SOFTDBL> static
    void SetDefaultNan( SOFTDBL& result )
    {
      result.setNegative(false);
      result.querySBasicExponent() = result.getInftyExponent();
      result.querySMantissa().clear();
      result.querySMantissa().setTrueBitArray(result.bitSizeMantissa()-1);
    }
    
    template <typename SOFTDBL> static
    void SetQuietBit( SOFTDBL& op )
    {
      op.querySMantissa().setTrueBitArray(op.bitSizeMantissa()-1);
    } 

    template <class SOFTDBL, class ARCH> static
    void Sqrt( SOFTDBL& acc, ARCH& arch, uint32_t fpscr_val )
    {
      bool negative = acc.isNegative();
      if (acc.isZero() or (acc.isInfty() and not negative))
        return;
      if (negative) {
        SetDefaultNan( acc );
        FPProcessException( arch, IOC, fpscr_val );
        return;
      }
      
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      //flags.setRoundingMode( arm::RoundTowardsZero );
      acc.SquareRoot( flags );
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
      
    }

    template <typename SOFTDBL> static
    int Compare( SOFTDBL const& op1, SOFTDBL const& op2, uint32_t fpscr_val )
    {
      typename SOFTDBL::ComparisonResult cmp = op1.compare( op2 );
      if      (cmp == SOFTDBL::CRLess)    return -1;
      else if (cmp == SOFTDBL::CRGreater) return +1;
      return 0;
    }
    
    template <typename SOFTDBL> static
    bool IsSNaN( SOFTDBL const& op )
    {
      return op.isSNaN();
    }

    template <typename SOFTDBL> static
    bool IsQNaN( SOFTDBL const& op )
    {
      return op.isQNaN();
    }

    template <typename SOFTDBL> static
    bool FlushToZero( SOFTDBL& op, uint32_t fpscr_val )
    {
      if (op.isDenormalized()) {
        op.querySMantissa().clear();
        return true;
      }
      return false;
    }

    template <typename SOFTDBL, class ARCH> static
    void Add( SOFTDBL& acc, SOFTDBL const& op2, ARCH& arch, uint32_t fpscr_val )
    {
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      acc.plusAssign(op2, flags);
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
    }
    
    template <typename SOFTDBL, class ARCH> static
    void Sub( SOFTDBL& acc, SOFTDBL const& op2, ARCH& arch, uint32_t fpscr_val )
    {
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      acc.minusAssign(op2, flags);
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
    }

    template <typename SOFTDBL, class ARCH> static
    void Div( SOFTDBL& acc, SOFTDBL const& op2, ARCH& arch, uint32_t fpscr_val )
    {
      bool divide_by_zero = not acc.isInfty() and not acc.isZero() and op2.isZero();
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      acc.divAssign(op2, flags);
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
      if (divide_by_zero)
        FPProcessException( arch, DZC, fpscr_val );
    }

    template <typename SOFTDBL, class ARCH> static
    void Mul( SOFTDBL& acc, SOFTDBL const& op2, ARCH& arch, uint32_t fpscr_val )
    {
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      acc.multAssign(op2, flags);
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
    }
    
    template <typename SOFTDBL> static
    bool IsInvalidMulAdd( SOFTDBL& acc, SOFTDBL const& op1, SOFTDBL const& op2, uint32_t fpscr_val )
    {
      return acc.isQNaN() and ((op1.isZero() and op2.isInfty()) or (op1.isInfty() and op2.isZero()));
    }

    template <typename SOFTDBL, class ARCH> static
    void MulAdd( SOFTDBL& acc, SOFTDBL const& op1, SOFTDBL const& op2, ARCH& arch, uint32_t fpscr_val )
    {
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      
      SOFTDBL res( op1 );
      res.multAndAddAssign(op2, acc, flags);
      acc = res;
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( acc, fpscr_val ) or (acc.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
    }
    
    template <class FPDST, class FPSRC, class ARCH> static
    void FtoF( FPDST& dst, FPSRC const& src, ARCH& arch, uint32_t fpscr_val )
    {
      Flags flags;
      flags.setRoundingMode( RMode.Get( fpscr_val ) );
      flags.clearKeepSignalingConversion();
      flags.setUpApproximateInfty();
      
      dst.assign(src, flags);
      // Process exceptions (Underflow, Overflow, InvalidOp, Inexact)
      if (FZ.Get( fpscr_val ) and (FlushToZero( dst, fpscr_val ) or (dst.isZero() and flags.isApproximate()))) {
        FPProcessException( arch, UFC, 0 );
        return;
      }
      if (flags.hasQNaNResult())
        FPProcessException( arch, IOC, fpscr_val );
      if (flags.isApproximate()) {
        if      (flags.isOverflow())     FPProcessException( arch, OFC, fpscr_val );
        else if (flags.isUnderflow())    FPProcessException( arch, UFC, fpscr_val );
        FPProcessException( arch, IXC, fpscr_val );
      }
    }
    
    template <typename INT, typename SOFTDBL, class ARCH> static
    void FtoI( INT& dst, SOFTDBL const& src, int fracbits, ARCH& arch, uint32_t fpscr_val )
    {
      // At this point "src" should not be any NaN, and Inf are
      // treated as if the were normalized since their normalized
      // equivalent is way beyond what any Integer can encode
      int32_t exp = 0;
      int64_t res = 0;
      
      {
        typename SOFTDBL::Exponent biExp = src.queryExponent();
        for (unsigned pos = src.bitSizeExponent(); pos-- > 0;)
          exp = (exp << 1) | int32_t(biExp.cbitArray(pos));
      }
      
      if (src.hasNegativeExponent())
        exp = -exp;
      
      if (src.queryBasicExponent().isZero()) {
        exp += 1;
      } else {
        res = 1;
      }
      
      {
        typename SOFTDBL::Mantissa biMan = src.queryMantissa();
        for (unsigned pos = src.bitSizeMantissa(); pos-- > 0;) {
          res = (res << 1) | int64_t(biMan.cbitArray(pos));
          exp -= 1;
        }
      }
      
      if (src.isNegative())
        res = -res;
      
      // getting fraction bits of requested fixed point
      exp += fracbits;
      // position of the integer part is given by -exp
      // Computing integer part and the error 
      bool error_msb = false, error_tail = false, overflow = false;
      
      if (exp <= 0) {
        for (;exp < 0;exp+=1)
          {
            error_tail |= error_msb;
            error_msb = res & 1;
            res >>= 1;
          }
      } else {
        for (;exp > 0;exp-=1)
          {
            int64_t nres = res << 1;
            if ((nres ^ res) >> 63) {
              overflow = true;
              res = ~((res >> 63) ^ (int64_t(1) << 63));
              break;
            }
            res = nres;
          }
      }
      enum {zero = 0, close_to_zero, halfway, close_to_one }
      error = error_msb ? error_tail ? close_to_one : halfway : error_tail ? close_to_zero : zero;
      
      int64_t round_up = 0;
      switch (RMode.Get( fpscr_val )) {
      case 0b00: // Round to Nearest (rounding to even if exactly halfway)
        round_up = ((error > halfway) or (error == halfway and (res & 1)));
        break;
      case 0b01: // Round towards Plus Infinity
        round_up = (error != 0);
        break;
      case 0b10: // Round towards Minus Infinity
        round_up = 0;
        break;
      case 0b11: // Round towards Zero
        round_up = ((error != 0) and (res < 0));
        break;
      }
      res += round_up;
      
      int64_t const int_max = std::numeric_limits<INT>::max();
      int64_t const int_min = std::numeric_limits<INT>::min();
      if (res < int_min) { overflow = true; res = int_min; }
      if (res > int_max) { overflow = true; res = int_max; }
      dst = res;
      
      if (overflow)
        FPProcessException( arch, IOC, fpscr_val );
      else if (error)
        FPProcessException( arch, IXC, fpscr_val );
    }

    template <typename SOFTDBL, class ARCH> static
    void ItoF( SOFTDBL& dst, int64_t src, int fracbits, ARCH& arch, uint32_t fpscr_val )
    {
      SoftDouble tmp;
      tmp.clear();
      
      if (src == 0)
        return;
      
      bool negative = (src < 0);
      if (negative)
        src = -src;
      
      SoftDouble two( VFPExpandImm( 0, 0, 0 ) );
      Flags flags;
      
      for (SoftDouble bit( VFPExpandImm( 0, 7, 0 ) ); src; )
        {
          if (src & 1)
            tmp.plusAssign( bit, flags );
          bit.multAssign( two, flags );
          src >>= 1;
        }
      
      while (fracbits)
        {
          tmp.divAssign( two, flags );
          fracbits -= 1;
        }
      
      tmp.setNegative(negative);
      
      FtoF( dst, tmp, arch, fpscr_val );
    }
  };

} // end of namespace simfloat
  
} // end of namespace arm
} // end of namespace processor
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim

#include <unisim/component/cxx/vector/vector.hh>

namespace unisim {
namespace component {
namespace cxx {
namespace vector {
  template <unsigned E> struct VectorTypeInfo<processor::arm::simfloat::SoftFloat,E>
  {
    typedef processor::arm::simfloat::SoftFloat float_type;
    enum bytecount_t { bytecount = 4 };
    // TODO: what about endianness E ?
    static void ToBytes( uint8_t* dst, float_type const& src ) { src.ToBytes( dst ); }
    static void FromBytes( float_type& dst, uint8_t const* src ) { dst.FromBytes( src ); }
    static void Destroy( float_type& obj ) { obj.~float_type(); }
    static void Allocate( float_type& obj ) { new (&obj) float_type(); }
  };

  template <unsigned E> struct VectorTypeInfo<processor::arm::simfloat::SoftDouble,E>
  {
    typedef processor::arm::simfloat::SoftDouble float_type;
    enum bytecount_t { bytecount = 8 };
    static void ToBytes( uint8_t* dst, float_type const& src ) { src.ToBytes( dst ); }
    static void FromBytes( float_type& dst, uint8_t const* src ) { dst.FromBytes( src ); }
    static void Destroy( float_type& obj ) { obj.~float_type(); }
    static void Allocate( float_type& obj ) { new (&obj) float_type(); }
  };
  // template <> struct ExtTypeInfo<simfloat::SoftFloat>
  // {
  // };

  // template <> struct ExtTypeInfo<simfloat::SoftDouble>
  // {
  // };
} // end of namespace vector
} // end of namespace cxx
} // end of namespace component
} // end of namespace unisim
  

#endif /*  __UNISIM_COMPONENT_CXX_PROCESSOR_ARM_FLOATING_HH__ */
