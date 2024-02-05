/***************************************************************************
  Floating.hh  -  Template for various types of floating point computations
 ***************************************************************************/

/*
 *  Copyright (c) 2005-2008,
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
 * Authors:
 *   Franck Vedrine (Franck.Vedrine@cea.fr)
 *   Bruno Marre (Bruno.Marre@cea.fr)
 *   Benjamin Blanc (benjamin.blanc@cea.fr)
 *   Gilles Mouchard (gilles.mouchard@cea.fr)
 */

#ifndef Numerics_Double_FloatingH
#define Numerics_Double_FloatingH

#include <unisim/util/endian/endian.hh>
#include <iosfwd>
#include <climits>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cassert>
#if defined(__GNUC__)
#ifdef __SUN__
#include <ieeefp.h>
#else
#ifndef __CYGWIN__
#include <fenv.h>
#endif
#endif
#endif
#include <unisim/util/simfloat/integer.hh>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Double {

namespace Details { namespace DTDoubleElement {

class Access : public Integer::Details::Access {
  public:
   class StatusAndControlFlags {
     protected:
      enum RoundMode { RMNearest, RMLowest, RMHighest, RMZero };
      enum Approximation { AExact, ADownApproximate, AUpApproximate };
      enum ReadResult { RRTotal, RRPartial };
      enum QNaNResult
         {  QNNRUndefined, QNNRInftyMinusInfty, QNNRInftyOnInfty, QNNRZeroOnZero,
            QNNRInftyMultZero
         };
      enum FlowException { FENoException, FEOverflow, FEUnderflow, FEEnd };
      enum Context { CMinDown, CMaxDown, CMinUp, CMaxUp };
      
     private:
      bool fAvoidInfty;
      bool fAvoidAllInfty;
      bool fAvoidDenormalized;
      bool fKeepNaNSign;
      bool fProduceDivNaNPositive;
      bool fRoundToEven;
      bool fPositiveZeroMAdd;
      bool fUpApproximateInfty;
      bool fUpApproximateInversionForNear;
      bool fChooseNaNAddBeforeMult;
      bool fConvertNaNNegative;
      bool fRefuseMinusZero;
      Context cContext;
      bool fInverseContext;

      RoundMode rmRound;
      bool fKeepSignalingConversion;

      Approximation aApproximation;
      ReadResult rrReadResult;
      bool fEffectiveRoundToEven;
      bool fSNaNOperand;
      QNaNResult qnrQNaNResult;
      FlowException feExcept;
      bool fDivisionByZero;

     public:
      StatusAndControlFlags()
         :  fAvoidInfty(false), fAvoidAllInfty(false), fAvoidDenormalized(false),
            fKeepNaNSign(false), fProduceDivNaNPositive(false),
            fRoundToEven(true), fPositiveZeroMAdd(false), fUpApproximateInfty(false),
            fUpApproximateInversionForNear(false), fChooseNaNAddBeforeMult(false),
            fConvertNaNNegative(false), fRefuseMinusZero(false), cContext(CMinDown),
            fInverseContext(false), rmRound(RMNearest), fKeepSignalingConversion(false),
            aApproximation(AExact), rrReadResult(RRTotal), fEffectiveRoundToEven(false),
            fSNaNOperand(false), qnrQNaNResult(QNNRUndefined), feExcept(FENoException),
            fDivisionByZero(false) {}
      StatusAndControlFlags(const StatusAndControlFlags& rpSource)
         :  fAvoidInfty(rpSource.fAvoidInfty), fAvoidAllInfty(rpSource.fAvoidAllInfty), fAvoidDenormalized(rpSource.fAvoidDenormalized),
            fKeepNaNSign(rpSource.fKeepNaNSign), fProduceDivNaNPositive(rpSource.fProduceDivNaNPositive),
            fRoundToEven(rpSource.fRoundToEven), fPositiveZeroMAdd(rpSource.fPositiveZeroMAdd),
            fUpApproximateInfty(rpSource.fUpApproximateInfty), fUpApproximateInversionForNear(rpSource.fUpApproximateInversionForNear),
            fChooseNaNAddBeforeMult(rpSource.fChooseNaNAddBeforeMult), fConvertNaNNegative(rpSource.fConvertNaNNegative),
            fRefuseMinusZero(rpSource.fRefuseMinusZero), cContext(rpSource.cContext),
            fInverseContext(rpSource.fInverseContext), rmRound(rpSource.rmRound),
            fKeepSignalingConversion(rpSource.fKeepSignalingConversion),
            aApproximation(rpSource.aApproximation), rrReadResult(rpSource.rrReadResult),
            fEffectiveRoundToEven(rpSource.fEffectiveRoundToEven), fSNaNOperand(rpSource.fSNaNOperand), qnrQNaNResult(rpSource.qnrQNaNResult),
            feExcept(rpSource.feExcept), fDivisionByZero(rpSource.fDivisionByZero) {}

      StatusAndControlFlags& operator=(const StatusAndControlFlags& rpSource)
         {  aApproximation = rpSource.aApproximation;
            rrReadResult = rpSource.rrReadResult;
            fEffectiveRoundToEven = rpSource.fEffectiveRoundToEven;
            fSNaNOperand = rpSource.fSNaNOperand;
            qnrQNaNResult = rpSource.qnrQNaNResult;
            feExcept = rpSource.feExcept;
            fDivisionByZero = rpSource.fDivisionByZero;
            return *this;
         }

      // Static parameters
      StatusAndControlFlags& setRoundToEven()
         {  rmRound = RMNearest; fRoundToEven = true; return *this; }
      StatusAndControlFlags& clearRoundToEven() { fRoundToEven = false; return *this; }
      StatusAndControlFlags& setPositiveZeroMAdd() { fPositiveZeroMAdd = true; return *this; }
      StatusAndControlFlags& avoidInfty()      { fAvoidInfty = true; return *this; }
      StatusAndControlFlags& clearAvoidInfty() { fAvoidInfty = false; return *this; }
      StatusAndControlFlags& avoidAllInfty()   { fAvoidAllInfty = true; return *this; }
      StatusAndControlFlags& clearAvoidAllInfty() { fAvoidAllInfty = false; return *this; }
      StatusAndControlFlags& avoidDenormalized() { fAvoidDenormalized = true; return *this; }
      StatusAndControlFlags& clearAvoidDenormalized() { fAvoidDenormalized = false; return *this; }
      StatusAndControlFlags& setKeepNaNSign()  { fKeepNaNSign = true; return *this; }
      StatusAndControlFlags& setProduceDivNaNPositive() { fProduceDivNaNPositive = true; return *this; }
      StatusAndControlFlags& setUpApproximateInfty() { fUpApproximateInfty = true; return *this; }
      StatusAndControlFlags& setUpApproximateInversionForNear() { fUpApproximateInversionForNear = true; return *this; }
      StatusAndControlFlags& setChooseNaNAddBeforeMult() { fChooseNaNAddBeforeMult = true; return *this; }
      StatusAndControlFlags& setConvertNaNNegative() { fConvertNaNNegative= true; return *this; }
      StatusAndControlFlags& setAcceptMinusZero() { fRefuseMinusZero = false; return *this; }
      StatusAndControlFlags& setRefuseMinusZero() { fRefuseMinusZero = true; return *this; }
      StatusAndControlFlags& setMinDown() { cContext = CMinDown; return *this; }
      StatusAndControlFlags& setMinUp() { cContext = CMinUp; return *this; }
      StatusAndControlFlags& setMaxDown() { cContext = CMaxDown; return *this; }
      StatusAndControlFlags& setMaxUp() { cContext = CMaxUp; return *this; }
      StatusAndControlFlags& setInverseContext() { fInverseContext = true; return *this; }
      StatusAndControlFlags& clearInverseContext() { fInverseContext = false; return *this; }

      bool isRoundToEven() const { return fRoundToEven && isNearestRound(); }
      bool isPositiveZeroMAdd() { return fPositiveZeroMAdd; }
      bool isInftyAvoided() const { return fAvoidInfty; }
      bool isAllInftyAvoided() const { return fAvoidAllInfty; }
      bool doesAvoidInfty(bool fNegative) const
         {  assert(fAvoidInfty);
            return fAvoidAllInfty || (fNegative ? (rmRound >= RMHighest) : (rmRound & RMLowest));
         }
      bool isDenormalizedAvoided() const { return fAvoidDenormalized; }
      bool keepNaNSign() const { return fKeepNaNSign; }
      bool produceDivNaNPositive() const { return fProduceDivNaNPositive; }
      bool upApproximateInfty() const { return fUpApproximateInfty; }
      bool upApproximateInversionForNear() const { return fUpApproximateInversionForNear; }
      bool chooseNaNAddBeforeMult() const { return fChooseNaNAddBeforeMult; }
      bool isConvertNaNNegative() const { return fConvertNaNNegative; }
      bool acceptMinusZero() const { return !fRefuseMinusZero; }
      bool isContextUp() const { return cContext & CMinUp; }
      bool isContextMax() const { return cContext & CMaxDown; }
      bool doesInverseContext() const { return fInverseContext; }

      // dynamic read parameters
      StatusAndControlFlags& setNearestRound()   { rmRound = RMNearest; return *this; }
      StatusAndControlFlags& setHighestRound()   { rmRound = RMHighest; return *this; }
      StatusAndControlFlags& setLowestRound()    { rmRound = RMLowest; return *this; }
      StatusAndControlFlags& setZeroRound()      { rmRound = RMZero; return *this; }

      bool isLowestRound() const { return rmRound == RMLowest; }
      bool isNearestRound() const { return rmRound == RMNearest; }
      bool isHighestRound() const { return rmRound == RMHighest; }
      bool isZeroRound() const { return rmRound == RMZero; }

      StatusAndControlFlags& setKeepSignalingConversion() { fKeepSignalingConversion = true; return *this; }
      StatusAndControlFlags& clearKeepSignalingConversion() { fKeepSignalingConversion = false; return *this; }
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
      bool hasSameApproximation(const StatusAndControlFlags& rpSource) const
         {  return aApproximation == rpSource.aApproximation; }
      bool hasIncrementFraction(bool fNegative) const
         {  return fNegative ? isDownApproximate() : isUpApproximate(); }

      void setEffectiveRoundToEven() { fEffectiveRoundToEven = true; }
      void clearEffectiveRoundToEven() { fEffectiveRoundToEven = false; }
      bool hasEffectiveRoundToEven() const { return fEffectiveRoundToEven; }

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
         {  aApproximation = AExact;
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
   };
   class WriteParameters {
     private:
      enum Type { TDecimal, TBinary };
      Type tType;
         
     public:
      WriteParameters() : tType(TDecimal) {}

      WriteParameters& setDecimal() { tType = TDecimal; return *this; }
      WriteParameters& setBinary() { tType = TBinary; return *this; }

      bool isDecimal() const { return tType == TDecimal; }
      bool isBinary() const { return tType == TBinary; }
   };

   class Carry {
     private:
      bool fCarry;

     public:
      Carry() : fCarry(false) {}
      Carry(const Carry& cSource) : fCarry(cSource.fCarry) {}
      bool& carry() { return fCarry; }
      const bool& carry() const { return fCarry; }
      bool hasCarry() const { return fCarry; }
   };
   
   template <class TypeMantissa, class TypeStatusAndControlFlags>
   static Carry trightShift(TypeMantissa& mMantissa, int uShift,
         unsigned int uValue, TypeStatusAndControlFlags& scfFlags, bool fNegative, int uBitSizeMantissa);
   
   static bool isBigEndian()
      {
#if defined(__GNUC__) && defined(__LINUX__)
#if BYTE_ORDER == BIG_ENDIAN
         return true;
#else
         return false;
#endif
#else
         int dummy = 0x1234;
         unsigned char chDummy[4];
         memcpy((unsigned char*) chDummy, &dummy, 4);
         return *chDummy == 0x12;
#endif
      }
};

} // end of namespace DTDoubleElement

namespace DBuiltDoubleTraits {

class Access {
  public:
   template <int USizeMantissa, int USizeExponent>
   class TFloatConversion {
     public:
      typedef Integer::TBigCellInt<Integer::Details::TCellIntegerTraits<USizeMantissa> > Mantissa;
      typedef Integer::TBigCellInt<Integer::Details::TCellIntegerTraits<USizeExponent> > Exponent;

     private:
      typedef TFloatConversion<USizeMantissa, USizeExponent> thisType;

      Mantissa bciMantissa;
      int uBitsMantissa;
      Exponent bciExponent;
      int uBitsExponent;
      bool fNegative;

     public:
      TFloatConversion() : bciMantissa(), uBitsMantissa(0), bciExponent(), uBitsExponent(0), fNegative(false) {}
      TFloatConversion(const thisType& fcSource)
         :  bciMantissa(fcSource.bciMantissa), uBitsMantissa(fcSource.uBitsMantissa),
            bciExponent(fcSource.bciExponent), uBitsExponent(fcSource.uBitsExponent),
            fNegative(fcSource.fNegative) {}

      bool isPositive() const { return !fNegative; }
      bool isNegative() const { return fNegative; }
      bool isInftyExponent() const
         { return Exponent(bciExponent).neg(uBitsExponent).hasZero(uBitsExponent); }
      bool isZeroExponent() const { return bciExponent.hasZero(uBitsExponent); }
      bool isZeroMantissa() const { return bciMantissa.hasZero(uBitsMantissa); }
      const int& querySizeMantissa() const { return uBitsMantissa; }
      const int& querySizeExponent() const { return uBitsExponent; }

      thisType& setSizeMantissa(int uSize) { uBitsMantissa = uSize; return *this; }
      thisType& setSizeExponent(int uSize) { uBitsExponent = uSize; return *this; }

      void setPositive(bool fPositive) { fNegative = !fPositive; }
      void setNegative(bool fNegativeSource) { fNegative = fNegativeSource; }
      const Mantissa& mantissa() const { return bciMantissa; }
      Mantissa& mantissa() { return bciMantissa; }
      const Exponent& exponent() const { return bciExponent; }
      Exponent& exponent() { return bciExponent; }
   };
};

}} // end of namespace Details::DBuiltDoubleTraits

template <int BitSizeMantissa, int BitSizeExponent>
class BuiltDoubleTraits : public Details::DBuiltDoubleTraits::Access {
  private:
   typedef Details::DBuiltDoubleTraits::Access inherited;

  public:
   static const int UBitSizeMantissa = BitSizeMantissa;
   static const int UBitSizeExponent = BitSizeExponent;
   typedef unsigned char CharChunk[BitSizeMantissa+BitSizeExponent+1];
   void setChunkSize(int uChunkSize) const { assert(uChunkSize == (BitSizeMantissa+BitSizeExponent+1+7)/8); }
   void copyChunk(CharChunk& ccChunk, void const* pChunk, int uChunkSize) const
      {  assert(uChunkSize == (BitSizeMantissa+BitSizeExponent+1+7)/8);
         memcpy((unsigned char*) ccChunk, pChunk, uChunkSize);
      }
   void retrieveChunk(void* pChunk, const CharChunk& ccChunk, int uChunkSize) const
      {  assert(uChunkSize == (BitSizeMantissa+BitSizeExponent+1+7)/8);
         memcpy(pChunk, (unsigned char*) ccChunk, uChunkSize);
      }
   void clearChunk(CharChunk& ccChunk, int uChunkSize) const
      {  assert(uChunkSize == (BitSizeMantissa+BitSizeExponent+1+7)/8);
         memset((unsigned char*) ccChunk, 0, uChunkSize);
      }

   class ExtendedMantissa;
   class Mantissa : public Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeMantissa> > {
     private:
      typedef Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeMantissa> > inherited;

     public:
      Mantissa() {}
      Mantissa(const Mantissa& mSource) : inherited(mSource) {}
      Mantissa(const ExtendedMantissa& emSource)
         {  for (int uIndex = 0; uIndex < inherited::uCellSize; ++uIndex)
               inherited::array(uIndex) = emSource[uIndex];
         }
      void normalizeLastCell() { inherited::normalizeLastCell(); }

      Mantissa& operator=(unsigned int uValue) { return (Mantissa&) inherited::operator=(uValue); }
      Mantissa& operator=(const Mantissa& mSource)
         {  return (Mantissa&) inherited::operator=(mSource); }
      Mantissa& operator=(const ExtendedMantissa& emSource)
         {  for (int uIndex = 0; uIndex <= inherited::lastCellIndex(); ++uIndex)
               inherited::array(uIndex) = emSource[uIndex];
            inherited::normalize();
            return *this;
         }
   };
   
   class Exponent : public Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeExponent> > {
     private:
      typedef Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeExponent> > inherited;
      
     public:
      class Min { public : Min() {} };
      class Zero { public : Zero() {} };
      class One { public : One() {} };
      class MinusOne { public : MinusOne() {} };
      class Max { public : Max() {} };
      class Basic { public : Basic() {} };
      
      Exponent() {}
      Exponent(Basic, unsigned int uBasicValue) : inherited(uBasicValue) {}
      Exponent(Min)  {}
      Exponent(Max)  { inherited::neg(); }
      Exponent(Zero) { inherited::neg(); inherited::bitArray(UBitSizeExponent-1) = false; }
      Exponent(MinusOne)
         {  inherited::neg();
            inherited::bitArray(UBitSizeExponent-1) = false;
            inherited::bitArray(0) = false;
         }
      Exponent(One)  { inherited::bitArray(UBitSizeExponent-1) = true; }
      Exponent(const Exponent& eSource) : inherited(eSource) {}

      Exponent& operator=(const Exponent& eSource) { return (Exponent&) inherited::operator=(eSource); }
      Exponent& operator=(unsigned int uSource) { return (Exponent&) inherited::operator=(uSource); }
      Exponent& operator-=(const Exponent& eSource) { return (Exponent&) inherited::operator-=(eSource); }
      Exponent& operator+=(const Exponent& eSource) { return (Exponent&) inherited::operator+=(eSource); }
      Exponent& operator--() { return (Exponent&) inherited::operator--(); }
      Exponent& operator++() { return (Exponent&) inherited::operator++(); }
   };
   static int bitSizeMantissa(const Mantissa&) { return BitSizeMantissa; }
   static int bitSizeExponent(const Exponent&) { return BitSizeExponent; }

   static Exponent eZeroExponent;
   static Exponent eOneExponent;
   static Exponent eMinusOneExponent;
   static Exponent eInftyExponent;
   
   static const Exponent& getZeroExponent(const Exponent&) { return eZeroExponent; }
   Exponent getBasicExponent(const Exponent&, unsigned int uExponent) const
#ifndef __BORLANDC__
      {  return Exponent(typename Exponent::Basic(), uExponent); }
#else
      {  return Exponent(Exponent::Basic(), uExponent); }
#endif
   static const Exponent& getOneExponent(const Exponent&) { return eOneExponent; }
   static const Exponent& getMinusOneExponent(const Exponent&) { return eMinusOneExponent; }
   static const Exponent& getInftyExponent(const Exponent&) { return eInftyExponent; }

   class ExtendedMantissa : public Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeMantissa+1> > {
     private:
      typedef Integer::TBigInt<Integer::Details::TIntegerTraits<BitSizeMantissa+1> > inherited;

     public:
      ExtendedMantissa(const ExtendedMantissa& emSource) : inherited(emSource) {}
      ExtendedMantissa(const Mantissa& mSource)
         {  int uIndex = 0;
            for (; uIndex <= mSource.lastCellIndex(); ++uIndex)
               inherited::array(uIndex) = mSource[uIndex];
            inherited::bitArray(UBitSizeMantissa) = true;
         }
      typedef Integer::TBigInt<typename inherited::MultResult> EnhancedMultResult;
      typedef Integer::TBigInt<typename inherited::RemainderResult> EnhancedRemainderResult;
      int queryMultResultCellSize(const EnhancedMultResult& emrResult) const
         {  return emrResult.queryCellSize(); }
   };
   
   class IntConversion {
     private:
      unsigned int uResult;
      bool fUnsigned;

     public:
      IntConversion() : uResult(0U), fUnsigned(false) {}
      IntConversion(const IntConversion& iSource) : uResult(iSource.uResult), fUnsigned(iSource.fUnsigned) {}

      IntConversion& setSigned() { fUnsigned = false; return *this; }
      IntConversion& setUnsigned() { fUnsigned = true; return *this; }
      IntConversion& assign(int uValue) { assert(!fUnsigned); uResult = uValue; return *this; }
      IntConversion& assign(unsigned int uValue) { assert(fUnsigned); uResult = uValue; return *this; }

      int querySize() const   { return sizeof(unsigned int)*8; }
      int queryMaxDigits() const
         { return fUnsigned ? sizeof(unsigned int)*8 : (sizeof(unsigned int)*8-1); }
      bool isUnsigned() const { return fUnsigned; }
      bool isSigned() const   { return !fUnsigned; }
      int queryInt() const { assert(!fUnsigned); return (int) uResult; }
      unsigned int queryUnsignedInt() const { assert(fUnsigned); return uResult; }
      unsigned int& sresult() { return uResult; }
      void opposite() { assert(!fUnsigned); uResult = (~uResult + 1); }
      bool isPositive() const { return fUnsigned || ((int) uResult >= 0); }
      bool isNegative() const { return !fUnsigned && ((int) uResult < 0); }
      bool isDifferentZero() const { return uResult != 0; }
      int log_base_2() const { return Integer::Details::Access::log_base_2(uResult); }
      bool hasZero(int uDigits) const { return !(uResult & ~(~0U << uDigits)); }
      bool cbitArray(int uLocalIndex) const { return uResult & (1U << uLocalIndex); }
      IntConversion& operator>>=(int uShift) { uResult >>= uShift; return *this; }
      IntConversion& operator<<=(int uShift) { uResult <<= uShift; return *this; }
      IntConversion& operator&=(const IntConversion& icSource) { uResult &= icSource.uResult; return *this; }
      IntConversion& neg() { uResult = ~uResult; return *this; }
      IntConversion& inc() { ++uResult; return *this; }

      IntConversion& operator=(const IntConversion& icSource)
         {  uResult = icSource.uResult;
            fUnsigned = icSource.fUnsigned;
            return *this;
         }
      IntConversion& operator=(int uValue)
         {  if (fUnsigned) {
               assert(uValue >= 0);
               uResult = (unsigned int) uValue;
            }
            else
               uResult = (unsigned int) uValue;
            return *this;
         }
      class BitArray {
        private:
         unsigned int* puResult;
         int uIndex;

        public:
         BitArray(IntConversion& icThis, int uIndexSource)
            : puResult(&icThis.uResult), uIndex(uIndexSource) {}
         BitArray(const BitArray& baSource) : puResult(baSource.puResult), uIndex(baSource.uIndex) {}
         BitArray& operator=(const BitArray& baSource)
            {  puResult = baSource.puResult;
               uIndex = baSource.uIndex;
               return *this;
            }
         BitArray& operator=(bool fValue)
            {  if (fValue)
                  *puResult |= (1U << (uIndex%(sizeof(unsigned int)*8)));
               else
                  *puResult &= ~(1U << (uIndex%(sizeof(unsigned int)*8)));
               return *this;
            }
         operator bool() const
            {  return (*puResult & (1U << (uIndex%(sizeof(unsigned int)*8))))
                  ? true : false;
            }
      };
      friend class BitArray;
      BitArray bitArray(int uIndex) {  return BitArray(*this, uIndex); }
      void setBitArray(int uIndex, bool fValue)
         {  if (fValue)
               uResult |= (1U << (uIndex%(sizeof(unsigned int)*8)));
            else
               uResult &= ~(1U << (uIndex%(sizeof(unsigned int)*8)));
         }
      void setTrueBitArray(int uIndex)
         {  uResult |= (1U << (uIndex%(sizeof(unsigned int)*8))); }
      void setFalseBitArray(int uIndex)
         {  uResult &= ~(1U << (uIndex%(sizeof(unsigned int)*8))); }

      void setMin() { uResult = fUnsigned ? 0U : (1U << (8*sizeof(unsigned int)-1)); }
      void setMax() { uResult = fUnsigned ? ~0U : ~(1U << (8*sizeof(unsigned int)-1)); }
      unsigned int& operator[](int uIndex) { assert(uIndex == 0); return uResult; }
      const unsigned int& operator[](int uIndex) const { assert(uIndex == 0); return uResult; }
   };

   typedef typename inherited::TFloatConversion<2, 1> FloatConversion;

   typedef Integer::TBigInt<Numerics::Integer::Details::TIntegerTraits<BitSizeMantissa+BitSizeExponent+1> >
      DiffDouble;
   typedef BuiltDoubleTraits<2*BitSizeMantissa+1, BitSizeExponent+1> MultExtension;
   typedef Details::DTDoubleElement::Access::StatusAndControlFlags StatusAndControlFlags;
   typedef Details::DTDoubleElement::Access::WriteParameters WriteParameters;
};

template <class TypeTraits>
class TBuiltDouble : protected Details::DTDoubleElement::Access, protected TypeTraits {
  private:
   typedef TBuiltDouble<TypeTraits> thisType;

  public:
   typedef thisType BuiltDouble;
   typedef typename TypeTraits::StatusAndControlFlags StatusAndControlFlags;
   typedef typename TypeTraits::WriteParameters WriteParameters;
   class MultParameters {
     private:
      enum Operation { OPlusPlus=0, OPlusMinus=1, OMinusPlus=2, OMinusMinus=3 };
      StatusAndControlFlags& scfFlags;
      const thisType* pbdAdd;
      Operation oOperation;

     public:
      MultParameters(StatusAndControlFlags& scfFlagsSource)
         :  scfFlags(scfFlagsSource), pbdAdd(NULL), oOperation(OPlusPlus) {}
      MultParameters(const MultParameters& mpSource)
         :  scfFlags(mpSource.scfFlags), pbdAdd(mpSource.pbdAdd), oOperation(mpSource.oOperation) {}

      MultParameters& setAdd(const thisType& bdAdd) { pbdAdd = &bdAdd; return *this; }
      void clear() { pbdAdd = NULL; oOperation = OPlusPlus; }
      MultParameters& setPositiveMult()
         { oOperation = (Operation) ((int) oOperation & (int) OPlusMinus); return *this; }
      MultParameters& setNegativeMult()
         {  oOperation = (Operation) ((int) oOperation | (int) OMinusPlus); return *this; }
      MultParameters& setPositiveAdditive()
         {  oOperation = (Operation) ((int) oOperation & (int) OMinusPlus); return *this; }
      MultParameters& setNegativeAdditive()
         { oOperation = (Operation) ((int) oOperation | (int) OPlusMinus); return *this; }
      bool hasAdd() const { return pbdAdd != NULL; }
      StatusAndControlFlags& readParams() const { return scfFlags; }
      const thisType& queryAddSource() const { assert(pbdAdd); return *pbdAdd; }
      bool isPositiveAdditive() const { return !(oOperation & OPlusMinus); }
      bool isNegativeAdditive() const { return (oOperation & OPlusMinus); }
      bool isPositiveMult() const { return !(oOperation & OMinusPlus); }
      bool isNegativeMult() const { return (oOperation & OMinusPlus); }
      bool hasSameSign(bool fNegative) const
         {  assert(pbdAdd);
            bool fResult = pbdAdd->fNegative == fNegative;
            return ((oOperation == OPlusPlus) || (oOperation == OMinusMinus)) ? fResult : !fResult;
         }
   };
   friend class MultParameters;
   
  public:
   int bitSizeMantissa() const { return TypeTraits::bitSizeMantissa(biMantissa); }
   int bitSizeExponent() const { return TypeTraits::bitSizeExponent(biExponent); }

  private:
   typename TypeTraits::Mantissa biMantissa;
   typename TypeTraits::Exponent biExponent;
   bool fNegative;

   void addExtension(const thisType& bdSource,
         typename TypeTraits::ExtendedMantissa::EnhancedMultResult& mprResult,
         StatusAndControlFlags& scfFlags, bool fPositiveAdd, int& uLogResult,
         bool& fExponentHasCarry, bool& fResultPositiveExponent, bool& fAddExponent);

  public:
   thisType& plusAssignSureNN(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& plusAssignSureND(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& plusAssignSureDN(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& plusAssignSureDD(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& minusAssignSureNN(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& minusAssignSureND(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& minusAssignSureDD(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& multAssignNN(const thisType& bdSource, const MultParameters& mpFlags);
   thisType& multAssignND(const thisType& bdSource, const MultParameters& mpFlags);
   thisType& multAssignDN(const thisType& bdSource, const MultParameters& mpFlags);
   thisType& multAssignDD(const thisType& bdSource, const MultParameters& mpFlags);
   thisType& divAssignNN(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& divAssignND(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& divAssignDN(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& divAssignDD(const thisType& bdSource, StatusAndControlFlags& scfFlags);

  public:
   TBuiltDouble() : biMantissa(), biExponent(), fNegative(false) {}
   TBuiltDouble(unsigned int uValue);
   typedef typename TypeTraits::IntConversion IntConversion;
   typedef typename TypeTraits::FloatConversion FloatConversion;
   TBuiltDouble(const IntConversion& icValue, StatusAndControlFlags& scfFlags)
      :  biMantissa(), biExponent(), fNegative(false)
      {  setInteger(icValue, scfFlags); }
   TBuiltDouble(const FloatConversion& fcValue, StatusAndControlFlags& scfFlags)
      :  biMantissa(), biExponent(), fNegative(false)
      {  setFloat(fcValue, scfFlags); }
   TBuiltDouble(const thisType& bdSource)
      :  biMantissa(bdSource.biMantissa), biExponent(bdSource.biExponent),
         fNegative(bdSource.fNegative) {}
   thisType& operator=(const thisType& bdSource)
      {  biMantissa = bdSource.biMantissa;
         biExponent = bdSource.biExponent;
         fNegative = bdSource.fNegative;
         return *this;
      }

   void setChunk(void const* pChunk) { setChunk(pChunk, !Details::DTDoubleElement::Access::isBigEndian()); }
   void fillChunk(void* pChunk) const { fillChunk(pChunk, !Details::DTDoubleElement::Access::isBigEndian()); }
   void setChunk(void const* pChunk, bool fLittleEndian); // size(pChunk) = UByteSizeImplantation
   void fillChunk(void* pChunk, bool fLittleEndian) const;

   void setFloat(const FloatConversion& fcValue, StatusAndControlFlags& scfFlags);
   void setInteger(const IntConversion& icValue, StatusAndControlFlags& scfFlags);
   void retrieveInteger(IntConversion& icResult, StatusAndControlFlags& scfFlags, unsigned fbits=0) const;
   enum ComparisonResult { CRNaN=0, CRLess=1, CREqual=2, CRGreater=3 };
   ComparisonResult compare(const thisType& bdSource) const
      {  ComparisonResult crResult = CRNaN;
         if (!isNaN() && !bdSource.isNaN()) {
            if (fNegative != bdSource.fNegative) {
               crResult = fNegative ? CRLess : CRGreater;
               if (isZero() && bdSource.isZero())
                  crResult = CREqual;
            }
            else {
               typename Exponent::ComparisonResult crExponentResult = biExponent.compare(bdSource.biExponent);
               crResult = (crExponentResult != Exponent::CREqual)
                  ? ((ComparisonResult) (1+crExponentResult))
                  : ((ComparisonResult) (1+biMantissa.compare(bdSource.biMantissa)));
               if (fNegative)
                  crResult = (ComparisonResult) (CRGreater+1-crResult);
            };
         };
         return crResult;
      }
   ComparisonResult compareValue(const thisType& bdSource) const
      {  ComparisonResult crResult;
         if (fNegative != bdSource.fNegative) {
            if (!isZero() || !bdSource.isZero())
               crResult = fNegative ? CRLess : CRGreater;
            else
               crResult = CREqual;
         }
         else {
            typename Exponent::ComparisonResult crExponentResult = biExponent.compare(bdSource.biExponent);
            crResult = (crExponentResult != Exponent::CREqual)
               ? ((ComparisonResult) (1+crExponentResult))
               : ((ComparisonResult) (1+biMantissa.compare(bdSource.biMantissa)));
               if (fNegative)
                  crResult = (ComparisonResult) (CRGreater+1-crResult);
         };
         return crResult;
      }
   bool operator==(const thisType& bdSource) const { return compare(bdSource) == CREqual; }
   bool operator!=(const thisType& bdSource) const
      {  ComparisonResult crResult = compare(bdSource);
         return (crResult == CRLess) || (crResult == CRGreater);
      }
   bool operator<(const thisType& bdSource) const { return compare(bdSource) == CRLess; }
   bool operator>(const thisType& bdSource) const { return compare(bdSource) == CRGreater; }
   bool operator<=(const thisType& bdSource) const
      {  ComparisonResult crResult = compare(bdSource);
         return (crResult == CRLess) || (crResult == CREqual);
      }
   bool operator>=(const thisType& bdSource) const
      {  ComparisonResult crResult = compare(bdSource);
         return (crResult == CRGreater) || (crResult == CREqual);
      }

   typename TypeTraits::Exponent getZeroExponent() const { return TypeTraits::getZeroExponent(biExponent); }
   typename TypeTraits::Exponent getBasicExponent(unsigned int uExponent) const
      {  return TypeTraits::getBasicExponent(biExponent, uExponent); }
   typename TypeTraits::Exponent getOneExponent() const { return TypeTraits::getOneExponent(biExponent); }
   typename TypeTraits::Exponent getMinusOneExponent() const { return TypeTraits::getMinusOneExponent(biExponent); }
   typename TypeTraits::Exponent getInftyExponent() const { return TypeTraits::getInftyExponent(biExponent); }

   const typename TypeTraits::Exponent& queryBasicExponent() const { return biExponent; }
   typename TypeTraits::Exponent& querySBasicExponent() { return biExponent; }
   bool hasPositiveExponent() const { return biExponent > TypeTraits::getZeroExponent(biExponent); }
   bool hasPositiveOrNullExponent() const { return biExponent >= TypeTraits::getZeroExponent(biExponent); }
   bool hasNullExponent() const { return biExponent == TypeTraits::getZeroExponent(biExponent); }
   bool hasNegativeExponent() const { return biExponent < TypeTraits::getZeroExponent(biExponent); }
   bool hasNegativeOrNullExponent() const { return biExponent <= TypeTraits::getZeroExponent(biExponent); }
   
   typename TypeTraits::Exponent queryExponent() const
      {  typename TypeTraits::Exponent biResult = TypeTraits::getZeroExponent(biExponent);
         if (biExponent >= biResult) {
            biResult = biExponent;
            biResult -= TypeTraits::getZeroExponent(biExponent);
         }
         else
            biResult -= biExponent;
         return biResult;
      }
   int queryExponentValue() const { return queryBasicExponent().queryValue() - getZeroExponent().queryValue(); }
   void setBasicExponent(const typename TypeTraits::Exponent& biExponentSource) { biExponent = biExponentSource; }
   void setInfty(bool negative=false) { fNegative = negative; biExponent = TypeTraits::getInftyExponent(biExponent); biMantissa = 0U; }
   void setZero(bool negative=false) { fNegative = negative; biExponent = 0U; biMantissa = 0U; }
   void setOne() { fNegative = false; biExponent = TypeTraits::getZeroExponent(biExponent); biMantissa = 0U; }
   void setExponent(const typename TypeTraits::Exponent& biExponentSource, bool fNegative = false)
      {  if (!fNegative) {
            biExponent = biExponentSource;
            biExponent += TypeTraits::getZeroExponent(biExponent);
         }
         else {
            biExponent = TypeTraits::getZeroExponent(biExponent);
            biExponent -= biExponentSource;
         };
      }
   bool isPositive() const {  return !fNegative; }
   bool isNegative() const {  return fNegative; }
   void setSign(bool fPositive) {  fNegative = !fPositive; }
   thisType& opposite() { fNegative = !fNegative; return *this; }
   void setPositive() { fNegative = false; }
   void setNegative(bool fNegativeSource=true) { fNegative = fNegativeSource; }

   bool isInfty() const
      {  return (biExponent == TypeTraits::getInftyExponent(biExponent)) && biMantissa.isZero(); }
   bool isNaN() const
      {  return (biExponent == TypeTraits::getInftyExponent(biExponent)) && !biMantissa.isZero(); }
   bool isSNaN() const
      {  return (biExponent == TypeTraits::getInftyExponent(biExponent)) && !biMantissa.isZero()
            && !biMantissa.cbitArray(bitSizeMantissa()-1);
      }
   bool isQNaN() const
      {  return (biExponent == TypeTraits::getInftyExponent(biExponent))
            && biMantissa.cbitArray(bitSizeMantissa()-1);
      }
   bool hasInftyExponent() const
      {  return biExponent == TypeTraits::getInftyExponent(biExponent); }
   bool isNormalized() const
      {  return (!biExponent.isZero()) && (biExponent != TypeTraits::getInftyExponent(biExponent)); }
   bool isDenormalized() const { return biExponent.isZero() && !biMantissa.isZero(); }
   bool isZero() const { return biExponent.isZero() && biMantissa.isZero(); }

   void setToEpsilon()
      {  if (biExponent > bitSizeMantissa()) {
            Exponent biSub(biExponent);
            biSub.clear();
            biSub[0] = bitSizeMantissa();
            biExponent.sub(biSub);
            biMantissa = 0U;
         }
         else if (biExponent.isZero())
            biMantissa = 1U;
         else {
            biMantissa = 0U;
            biMantissa.bitArray(biExponent.queryValue()-1) = true;
            biExponent = 0U;
         };
      }
   thisType queryEpsilon() const
      {  thisType dResult = *this;
         dResult.setToEpsilon();
         return dResult;
      }

   typedef typename TypeTraits::Exponent Exponent;
   typedef typename TypeTraits::Mantissa Mantissa;
   const Mantissa& queryMantissa() const { return biMantissa; }
   Mantissa& querySMantissa() { return biMantissa; }

   typedef typename TypeTraits::DiffDouble DiffDouble;
#ifndef __BORLANDC__
   DiffDouble queryNumberOfFloatsBetween(const thisType& bdSource) const;
#else
   void retrieveNumberOfFloatsBetween(const thisType& bdSource, DiffDouble& ddResult) const;
   DiffDouble queryNumberOfFloatsBetween(const thisType& bdSource) const
      {  DiffDouble ddResult;
         retrieveNumberOfFloatsBetween(bdSource, ddResult);
         return ddResult;
      }
#endif

   thisType queryNthSuccessor(const DiffDouble& biIntSource) const;
   bool setToNext();
   thisType queryNthPredecessor(const DiffDouble& biIntSource) const;
   bool setToPrevious();

   thisType& plusAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& minusAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags);
   thisType& multAssign(unsigned int uValue, StatusAndControlFlags& scfFlags);
   thisType& multAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags)
      {  return multAssign(bdSource, MultParameters(scfFlags)); }
   thisType& multAndAddAssign(const thisType& bdMult, const thisType& bdAdd, StatusAndControlFlags& scfFlags)
      {  return multAssign(bdMult, MultParameters(scfFlags).setAdd(bdAdd)); }
   thisType& multAndSubAssign(const thisType& bdMult, const thisType& bdAdd, StatusAndControlFlags& scfFlags)
      {  return multAssign(bdMult, MultParameters(scfFlags).setAdd(bdAdd).setNegativeAdditive()); }
   thisType& multNegativeAndAddAssign(const thisType& bdMult, const thisType& bdAdd, StatusAndControlFlags& scfFlags)
      {  return multAssign(bdMult, MultParameters(scfFlags).setAdd(bdAdd).setNegativeMult()); }
   thisType& multNegativeAndSubAssign(const thisType& bdMult, const thisType& bdAdd, StatusAndControlFlags& scfFlags)
      {  return multAssign(bdMult, MultParameters(scfFlags).setAdd(bdAdd).setNegativeMult().setNegativeAdditive()); }
   thisType& multAssign(const thisType& bdSource, const MultParameters& mpFlags);
   thisType& divAssign(unsigned int uValue, StatusAndControlFlags& scfFlags);
   thisType& divAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags);

   thisType& operator+=(const thisType& bdSource)
      {  return plusAssign(bdSource, StatusAndControlFlags().setNearestRound()); }
   thisType operator+(const thisType& bdSource) const
      {  thisType bdThis = *this;
         bdThis.plusAssign(bdSource, StatusAndControlFlags().setNearestRound());
         return bdThis;
      }
   thisType& operator-=(const thisType& bdSource)
      {  return minusAssign(bdSource, StatusAndControlFlags().setNearestRound()); }
   thisType operator-(const thisType& bdSource) const
      {  thisType bdThis = *this;
         bdThis.minusAssign(bdSource, StatusAndControlFlags().setNearestRound());
         return bdThis;
      }
   thisType& operator*=(const thisType& bdSource)
      {  return multAssign(bdSource, StatusAndControlFlags().setNearestRound()); }
   thisType operator*(const thisType& bdSource) const
      {  thisType bdThis = *this;
         bdThis.multAssign(bdSource, StatusAndControlFlags().setNearestRound());
         return bdThis;
      }
   thisType& operator/=(const thisType& bdSource)
      {  return divAssign(bdSource, StatusAndControlFlags().setNearestRound()); }
   thisType operator/(const thisType& bdSource) const
      {  thisType bdThis = *this;
         bdThis.divAssign(bdSource, StatusAndControlFlags().setNearestRound());
         return bdThis;
      }
   void read(std::istream& isIn, StatusAndControlFlags& scfFlags);
   void write(std::ostream& osOut, const WriteParameters& wpParams) const;
   void writeDecimal(std::ostream& osOut) const;

   void clear()
      {  biMantissa.clear();
         biExponent.clear();
         fNegative = false;
      }
   void swap(thisType& bdSource)
      {  biMantissa.swap(bdSource.biMantissa);
         biExponent.swap(bdSource.biExponent);
         bool fTemp = fNegative;
         fNegative = bdSource.fNegative;
         bdSource.fNegative = fTemp;
      }

   thisType& sqrtAssign(); // u_{n+1} = (u_n + this/u_n)/2
   thisType& squareAssign(StatusAndControlFlags& scfFlags) { return multAssign(*this, scfFlags); }
   thisType& inverseAssign(StatusAndControlFlags& scfFlags)
      {  thisType bdResult;
         bdResult.biExponent = Exponent(typename Exponent::Zero());
         bdResult.divAssign(*this, scfFlags);
         return operator=(bdResult);
      }
   thisType& nthRootAssign(int n); // u_{p+1} = 1/n*[(n-1)*u_p + this/(u_p)^(n-1))]
   thisType& nthExponentAssign(int n);
};

template <class TypeTraits>
inline std::ostream&
operator<<(std::ostream& osOut, const TBuiltDouble<TypeTraits>& bdDouble) {
   typename TBuiltDouble<TypeTraits>::WriteParameters wpParams;
   bdDouble.write(osOut, wpParams);
   return osOut;
}

template <class TypeTraits>
inline std::istream&
operator<<(std::istream& isIn, TBuiltDouble<TypeTraits>& bdDouble) {
   typename TBuiltDouble<TypeTraits>::StatusAndControlFlags scfFlags;
   bdDouble.read(isIn, scfFlags);
   return isIn;
}

/*****************************/
/* Definition - class Errors */
/*****************************/

class Errors {
  private:
   unsigned int uErrors;
   enum Type { TPositiveOverflow, TNegativeOverflow, TQNaN, TSNaN, TPositiveUnderflow, TNegativeUnderflow };

  public:
   Errors() : uErrors(0) {}
   Errors(const Errors& eSource) : uErrors(eSource.uErrors) {}
   Errors& operator=(const Errors& eSource) { uErrors = eSource.uErrors; return *this; }

#define DefineIsError(TypeError) \
   bool is##TypeError() const { return (bool) (uErrors & (1U << T##TypeError)); }
   
   DefineIsError(PositiveOverflow)
   DefineIsError(NegativeOverflow)
   DefineIsError(QNaN)
   DefineIsError(SNaN)
   DefineIsError(PositiveUnderflow)
   DefineIsError(NegativeUnderflow)
#undef DefineIsError
   bool isNaN() const { return (bool) (uErrors & (3U << TQNaN)); }

#define DefineSetError(TypeError) \
   Errors& set##TypeError() { uErrors |= (1U << T##TypeError); return *this; }
   
   DefineSetError(PositiveOverflow)
   DefineSetError(NegativeOverflow)
   DefineSetError(QNaN)
   DefineSetError(SNaN)
   DefineSetError(PositiveUnderflow)
   DefineSetError(NegativeUnderflow)
#undef DefineSetError
};

}} // end of namespace Numerics::Double

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Double_FloatingH

