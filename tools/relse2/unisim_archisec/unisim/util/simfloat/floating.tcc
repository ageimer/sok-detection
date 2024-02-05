/***************************************************************************
  Floating.tcc  -  Template for various types of floating point computations
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

#ifndef Numerics_Double_FloatingTemplate
#define Numerics_Double_FloatingTemplate
#include <unisim/util/simfloat/floating.hh>
#include <iostream>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics {} // for precompiled headers

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#include <math.h>
#if defined(__GNUC__) && (GCC_VERSION < 30000)
#include <ctype.h>
#endif
#include <vector>
#include <unisim/util/simfloat/integer.tcc>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Double {

namespace Details { namespace DTDoubleElement {

template <class TypeMantissa, class TypeStatusAndControlFlags>
Access::Carry
Access::trightShift(TypeMantissa& mMantissa, int uShift, unsigned int uValue, TypeStatusAndControlFlags& scfFlags, bool fNegative, int uBitSizeMantissa)
{
   assert((uShift >= 0) && (uBitSizeMantissa >= uShift));
   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   Carry cResult;
   scfFlags.clearEffectiveRoundToEven();
   if (!mMantissa.hasZero(uShift)) {
      if (scfFlags.isNearestRound()) {
         if (!scfFlags.isApproximate(fNegative ? TypeStatusAndControlFlags::Down : TypeStatusAndControlFlags::Up)
               || !mMantissa.hasZero(uShift-1))
            fAdd = mMantissa.cbitArray(uShift-1);
         if (fAdd && !scfFlags.isApproximate() && scfFlags.isRoundToEven()) {
            fRoundToEven = mMantissa.hasZero(uShift-1) && !scfFlags.isApproximate();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      fApproximate = true;
   };
   mMantissa >>= uShift;
   bool fOddValue = (uBitSizeMantissa == uShift) and (uValue & 1U);
   if (fAdd && ((fAdd = (!fRoundToEven
         || (!fOddValue ? mMantissa.cbitArray(0): !mMantissa.cbitArray(0)))) != false)) {
      mMantissa.inc();
      if (mMantissa.cbitArray(uBitSizeMantissa-uShift)) {
         cResult.carry() = true;
         mMantissa.setFalseBitArray(uBitSizeMantissa-uShift);
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? TypeStatusAndControlFlags::Down : TypeStatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? TypeStatusAndControlFlags::Up : TypeStatusAndControlFlags::Down);
   };
   if (cResult.hasCarry()) {
      ++uValue;
      if ((uValue == 0U) || ((uShift < (int) (8*sizeof(unsigned int))) && (uValue >= (1U << uShift))))
         return cResult;
      else
         cResult.carry() = false;
   };
   if ((((uBitSizeMantissa-1) % (8*sizeof(unsigned int)))+1) >= (uShift % (8*sizeof(unsigned int))))
      mMantissa[(uBitSizeMantissa-uShift) / (8*sizeof(unsigned int))]
         |= (uValue << ((uBitSizeMantissa-uShift) % (8*sizeof(unsigned int))));
   else {
      mMantissa[(uBitSizeMantissa-uShift) / (8*sizeof(unsigned int))]
         |= (uValue << (uBitSizeMantissa-uShift) % (8*sizeof(unsigned int)));
      mMantissa[(uBitSizeMantissa-uShift) / (8*sizeof(unsigned int)) + 1]
         = (uValue >> (8*sizeof(unsigned int) - (uBitSizeMantissa-uShift) % (8*sizeof(unsigned int))));
   };
   return cResult;
}

}} // end of namespace Details::DTDoubleElement

/******************************************/
/* Implementation - template TBuiltDouble */
/******************************************/

#ifndef __BORLANDC__
#define Typename typename
#else
#define Typename
#endif

template <int BitSizeMantissa, int BitSizeExponent>
typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent
BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::eZeroExponent
   = Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent(
      Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent::Zero());

template <int BitSizeMantissa, int BitSizeExponent>
typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent
BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::eOneExponent
   = Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent(
      Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent::One());

template <int BitSizeMantissa, int BitSizeExponent>
typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent
BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::eMinusOneExponent
   = Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent(
      Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent::MinusOne());

template <int BitSizeMantissa, int BitSizeExponent>
typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent
BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::eInftyExponent
   = Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent(
      Typename BuiltDoubleTraits<BitSizeMantissa, BitSizeExponent>::Exponent::Max());

template <class TypeTraits>
TBuiltDouble<TypeTraits>::TBuiltDouble(unsigned int uValue)
   :  biMantissa(), biExponent(), fNegative(false) {
   if (uValue != 0U) {
      int uLogResult = log_base_2(uValue);
      assert(uLogResult <= bitSizeMantissa());
      biMantissa = uValue;
      biMantissa <<= (bitSizeMantissa()-uLogResult+1);
      biExponent = TypeTraits::getZeroExponent(biExponent);
      biExponent.add(uLogResult-1);
   };
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::setChunk(void const* pChunk, bool fChunkLittleEndian)
{
   biMantissa = 0U;
   biExponent = 0U;
   int uSizeMantissa = bitSizeMantissa(), uSizeExponent = bitSizeExponent();
   int uByteSizeImplantation = (uSizeMantissa + uSizeExponent + 1 + 7)/8;
   typename TypeTraits::CharChunk ccChunk;
   TypeTraits::setChunkSize(uByteSizeImplantation);
   TypeTraits::copyChunk(ccChunk, pChunk, uByteSizeImplantation);
   bool fBigEndian = Details::DTDoubleElement::Access::isBigEndian();

   unsigned char* pcMask = &ccChunk[0];
   int uMantissaIndex = 0, uLastMantissaIndex = (uSizeMantissa + 8*sizeof(unsigned int) - 1) / (8*sizeof(unsigned int)) - 1;
   int uCharInMantissa = 0;
   if (fBigEndian)
      uCharInMantissa = (sizeof(unsigned int) - 1);
   if (!fChunkLittleEndian)
      pcMask += uByteSizeImplantation-1;

   int uMantissaChar = (uSizeMantissa + 7) / 8;
   for (; uMantissaIndex <= uLastMantissaIndex; ++uMantissaIndex) {
      for (int uLocal = 0; uLocal < (int) sizeof(unsigned int); ++uLocal) {
         if (uMantissaChar == 0)
            goto LExponent;
         biMantissa[uMantissaIndex] |= ((unsigned int) *pcMask << (uCharInMantissa*8));
         if (fBigEndian)
            --uCharInMantissa;
         else
            ++uCharInMantissa;
         if (fChunkLittleEndian)
            ++pcMask;
         else
            --pcMask;
         --uMantissaChar;
      };
      uCharInMantissa = 0;
      if (fBigEndian)
         uCharInMantissa = (sizeof(unsigned int) - 1);
   };
LExponent:
   biMantissa.normalize();

   pcMask = &ccChunk[0];
   int uExponentIndex = 0, uLastExponentIndex = (uSizeExponent + 8*sizeof(unsigned int) - 1) / (8*sizeof(unsigned int)) - 1;
   int uCharInExponent = 0;
   if (!fBigEndian)
      uCharInExponent = (sizeof(unsigned int) - 1);
   if (fChunkLittleEndian)
      pcMask += uByteSizeImplantation-1;
   fNegative = *pcMask & 0x80;

   int uExponentChar = (uSizeExponent + 7) / 8;
   for (uExponentIndex = uLastExponentIndex; uExponentIndex >= 0; --uExponentIndex) {
      for (int uLocal = 0; uLocal < (int) sizeof(unsigned int); ++uLocal) {
         if (uExponentChar == 0)
            goto LEnd;
         biExponent[uExponentIndex] |= ((unsigned int) *pcMask << (uCharInExponent*8));
         if (fBigEndian)
            ++uCharInExponent;
         else
            --uCharInExponent;
         if (fChunkLittleEndian)
            --pcMask;
         else
            ++pcMask;
         --uExponentChar;
      };
      uCharInExponent = 0;
      if (!fBigEndian)
         uCharInExponent = (sizeof(unsigned int) - 1);
   };

LEnd:
   if ((uSizeExponent % 8) == 0) {
      if (uSizeExponent % (8*sizeof(unsigned int)) == 0)
         biExponent <<= 1;
      else
         biExponent >>= ((uLastExponentIndex + 1)*8*sizeof(unsigned int) - uSizeExponent - 1);
      if (*pcMask & 0x80)
         biExponent.setTrueBitArray(0);
   }
   else
      biExponent >>= ((uLastExponentIndex + 1)*8*sizeof(unsigned int) - uSizeExponent - 1);
   
   biExponent.normalize();
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::fillChunk(void* pChunk, bool fChunkLittleEndian) const { // uByteSize = UByteSizeImplantation/sizeof(unsigned int)+1
   int uSizeMantissa = bitSizeMantissa(), uSizeExponent = bitSizeExponent();
   int uByteSizeImplantation = (uSizeMantissa + uSizeExponent + 1 + 7)/8;
   typename TypeTraits::CharChunk ccChunk;
   TypeTraits::setChunkSize(uByteSizeImplantation);
   TypeTraits::clearChunk(ccChunk, uByteSizeImplantation);
   bool fBigEndian = Details::DTDoubleElement::Access::isBigEndian();

   unsigned char* pcMask = &ccChunk[0];
   int uMantissaIndex = 0, uLastMantissaIndex = (uSizeMantissa + 8*sizeof(unsigned int) - 1) / (8*sizeof(unsigned int)) - 1;
   int uCharInMantissa = 0;
   if (fBigEndian)
      uCharInMantissa = (sizeof(unsigned int) - 1);
   if (!fChunkLittleEndian)
      pcMask += uByteSizeImplantation-1;

   int uMantissaChar = (uSizeMantissa + 7) / 8;
   for (; uMantissaIndex <= uLastMantissaIndex; ++uMantissaIndex) {
      for (int uLocal = 0; uLocal < (int) sizeof(unsigned int); ++uLocal) {
         if (uMantissaChar == 0)
            goto LExponent;
         *pcMask = (unsigned char) (biMantissa[uMantissaIndex] >> (uCharInMantissa*8));
         if (fBigEndian)
            --uCharInMantissa;
         else
            ++uCharInMantissa;
         if (fChunkLittleEndian)
            ++pcMask;
         else
            --pcMask;
         --uMantissaChar;
      };
      uCharInMantissa = 0;
      if (fBigEndian)
         uCharInMantissa = (sizeof(unsigned int) - 1);
   };
LExponent:
   pcMask = &ccChunk[0];
   int uExponentIndex = 0, uLastExponentIndex = (uSizeExponent + 8*sizeof(unsigned int) - 1) / (8*sizeof(unsigned int)) - 1;
   int uCharInExponent = 0;
   if (!fBigEndian)
      uCharInExponent = (sizeof(unsigned int) - 1);
   if (fChunkLittleEndian)
      pcMask += uByteSizeImplantation-1;
   if (fNegative)
      *pcMask |= 0x80;

   typename TypeTraits::Exponent biCopyExponent = biExponent;
   bool fMinor = false;
   if (uSizeExponent % 8 == 0) {
      fMinor = biExponent.cbitArray(0);
      if (uSizeExponent % (8*sizeof(unsigned int)) == 0)
         biCopyExponent >>= 1;
      else
         biCopyExponent.leftShiftAssign((uLastExponentIndex + 1)*(8*sizeof(unsigned int)) - uSizeExponent - 1);
   }
   else
      biCopyExponent.leftShiftAssign((uLastExponentIndex + 1)*(8*sizeof(unsigned int)) - uSizeExponent - 1);

   int uExponentChar = (uSizeExponent + 7) / 8;
   for (uExponentIndex = uLastExponentIndex; uExponentIndex >= 0; --uExponentIndex) {
      for (int uLocal = 0; uLocal < (int) sizeof(unsigned int); ++uLocal) {
         if (uExponentChar == 0)
            goto LEnd;
         *pcMask |= (unsigned char) (biCopyExponent[uExponentIndex] >> (uCharInExponent*8));
         if (fBigEndian)
            ++uCharInExponent;
         else
            --uCharInExponent;
         if (fChunkLittleEndian)
            --pcMask;
         else
            ++pcMask;
         --uExponentChar;
      };
      uCharInExponent = 0;
      if (!fBigEndian)
         uCharInExponent = (sizeof(unsigned int) - 1);
   };
LEnd:
   if (((uSizeExponent % 8) == 0) && fMinor)
      *pcMask |= 0x80;

   TypeTraits::retrieveChunk(pChunk, ccChunk, uByteSizeImplantation);
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::setInteger(const IntConversion& icValueSource, StatusAndControlFlags& scfFlags) {
   biMantissa = 0U;
   biExponent = 0U;
   fNegative = icValueSource.isNegative();
   IntConversion icValue(icValueSource);
   if (fNegative)
      icValue.opposite();
   icValue.setUnsigned();
   if (icValue.isDifferentZero()) {
      int icBitSizeMantissa = icValue.log_base_2()-1;
      icValue.setFalseBitArray(icBitSizeMantissa);
      
      if (icBitSizeMantissa > bitSizeMantissa()) {
         trightShift(icValue, (icBitSizeMantissa-bitSizeMantissa()), 0U, scfFlags, fNegative, icValue.querySize());
         if (icValue.cbitArray(bitSizeMantissa())) {
            ++icBitSizeMantissa;
            icValue.setFalseBitArray(bitSizeMantissa());
            assert(not icValue.isDifferentZero());
         }
      }
      
      for (int uIndex = (bitSizeMantissa()-1)/(sizeof(unsigned int)*8); uIndex >= 0; --uIndex)
         biMantissa[uIndex] = icValue[uIndex];
      
      if (icBitSizeMantissa <= bitSizeMantissa())
         biMantissa <<= (bitSizeMantissa()-icBitSizeMantissa);
      
      biMantissa.normalize();
      biExponent = TypeTraits::getZeroExponent(biExponent);
      biExponent.add(icBitSizeMantissa);
   };
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::setFloat(const FloatConversion& fcValue, StatusAndControlFlags& scfFlags) {
   fNegative = fcValue.isNegative();
   biExponent = 0U;
   biMantissa = 0U;
   if (fcValue.isZeroExponent() && fcValue.isZeroMantissa())
      return;
   if (fcValue.isInftyExponent()) {
      biExponent = TypeTraits::getInftyExponent(biExponent);
      if (scfFlags.isAllInftyAvoided()) { // set to +- max float
         if (fcValue.isZeroMantissa())  // for infty
            scfFlags.setOverflow();
         else if (!fcValue.mantissa().cbitArray(fcValue.querySizeMantissa()-1))
            scfFlags.setSNaNOperand();
         biExponent.dec();
         biMantissa.neg();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         return;
      };
      if (fcValue.isZeroMantissa()) { // for infty
         scfFlags.setOverflow();
         return;
      };
      // for NaNs
      if (fcValue.querySizeMantissa() < bitSizeMantissa()) {
         for (int uIndex = (fcValue.querySizeMantissa()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biMantissa[uIndex] = fcValue.mantissa()[uIndex];
         biMantissa.normalize();
         biMantissa <<= (bitSizeMantissa()-fcValue.querySizeMantissa());
      }
      else { // fcValue.querySizeMantissa() >= bitSizeMantissa()
         typename FloatConversion::Mantissa fcmMantissa(fcValue.mantissa());
         fcmMantissa >>= (fcValue.querySizeMantissa()-bitSizeMantissa());
         for (int uIndex = (bitSizeMantissa()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biMantissa[uIndex] = fcmMantissa[uIndex];
         if (scfFlags.keepSignalingConversion() && biMantissa.isZero()) {
            biMantissa.neg();
            biMantissa.setFalseBitArray(bitSizeMantissa()-1);
         };
      };
      if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
         scfFlags.setSNaNOperand();
         if (!scfFlags.keepSignalingConversion())
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
      };
   }
   else if (fcValue.querySizeExponent() < bitSizeExponent()) { // double <- float
      assert((bitSizeExponent() >= log_base_2(bitSizeMantissa()))
         && (fcValue.querySizeMantissa() <= bitSizeMantissa()));

      int uLogMantissa = fcValue.isZeroExponent() ? fcValue.mantissa().log_base_2()
         : (fcValue.querySizeMantissa() + 1);

      for (int uIndex = (fcValue.querySizeExponent()-1)/(8*sizeof(unsigned int)); 
            uIndex >= 0; --uIndex)
         biExponent[uIndex] = fcValue.exponent()[uIndex];
      biExponent.normalize();
      typename TypeTraits::Exponent eAdd;
      biExponent.add(eAdd.neg(bitSizeExponent()-fcValue.querySizeExponent())
            <<= (fcValue.querySizeExponent()-1));
         
      if (fcValue.isZeroExponent()) 
         biExponent.sub(fcValue.querySizeMantissa() - uLogMantissa);

      for (int uIndex = (fcValue.querySizeMantissa()-1)/(8*sizeof(unsigned int)); 
            uIndex >= 0; --uIndex)
         biMantissa[uIndex] = fcValue.mantissa()[uIndex];
      biMantissa <<= (bitSizeMantissa() - uLogMantissa + 1);
      biMantissa.normalize();
   }
   else if (fcValue.querySizeExponent() > bitSizeExponent()) { // float <- double
      assert((fcValue.querySizeExponent() >= log_base_2(fcValue.querySizeMantissa()))
         && fcValue.querySizeMantissa() >= bitSizeMantissa());

      typename FloatConversion::Exponent fceSubExponent;
      fceSubExponent.neg(fcValue.querySizeExponent()-bitSizeExponent())
         <<= (bitSizeExponent()-1);
      typename FloatConversion::Exponent fceNewExponent = fcValue.exponent();
      if (!fceNewExponent.sub(fceSubExponent).hasCarry() && !fceNewExponent.isZero()) {
         if (fceNewExponent >= Typename FloatConversion::Exponent().neg(bitSizeExponent())) {
            // result is infty
            scfFlags.setOverflow();
            biExponent = TypeTraits::getInftyExponent(biExponent);
            biMantissa = 0U;
            if (scfFlags.upApproximateInfty()) {
               if (scfFlags.upApproximateInversionForNear() && scfFlags.isNearestRound()) {
                  typename FloatConversion::Mantissa fcmMantissa = fcValue.mantissa();
                  int uShift = fcValue.querySizeMantissa() - bitSizeMantissa();
                  if (uShift > 0) {
                     trightShift(fcmMantissa, uShift, 0U, scfFlags, fNegative, fcValue.querySizeMantissa());
                     if (scfFlags.upApproximateInversionForNear()) {
                        if (scfFlags.hasEffectiveRoundToEven())
                           scfFlags.setApproximate(scfFlags.isUpApproximate() ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                     };
                  };
               }
               else
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            };
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
            return;
         };
         for (int uIndex = (fcValue.querySizeExponent()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biExponent[uIndex] = fceNewExponent[uIndex];
         biExponent.normalize();

         typename FloatConversion::Mantissa fcmMantissa = fcValue.mantissa();
         int uShift = fcValue.querySizeMantissa() - bitSizeMantissa();
         if (uShift > 0) {
            trightShift(fcmMantissa, uShift, 0U, scfFlags, fNegative, fcValue.querySizeMantissa());
            if (fcmMantissa.cbitArray(bitSizeMantissa())) {
               ++biExponent;
               fcmMantissa.setFalseBitArray(bitSizeMantissa());
               if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
                  // result is infty
                  scfFlags.setOverflow();
                  if (!biMantissa.isZero()) {
                     biMantissa = 0U;
                     if (!scfFlags.isApproximate())
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  if (scfFlags.upApproximateInfty()) {
                     if (!(scfFlags.upApproximateInversionForNear() && scfFlags.isNearestRound()))
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                  };
                  if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  return;
               };
            };
         };
         for (int uIndex = (bitSizeMantissa()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biMantissa[uIndex] = fcmMantissa[uIndex];
         biMantissa.normalize();
      }
      else { // fceNewExponent = 0U || hasCarry -> result is almost always denormalized
         biExponent = 0U;
         fceNewExponent.neg().inc();
         bool hasZeroExponent = true;
         if (fceNewExponent < bitSizeMantissa()) {
            typename FloatConversion::Mantissa fcmMantissa = fcValue.mantissa();
            int uShift = (fcValue.querySizeMantissa() - bitSizeMantissa())
               + fceNewExponent.queryValue() + 1;
            if (uShift > 0) {
               if (trightShift(fcmMantissa, uShift, 1U, scfFlags,
                     fNegative, fcValue.querySizeMantissa()).hasCarry())
                  biExponent.inc();
               if (fcmMantissa.cbitArray(bitSizeMantissa())) {
                  biExponent.inc();
                  fcmMantissa.setFalseBitArray(bitSizeMantissa());
               };
               if (biExponent.isZero())
                  scfFlags.setUnderflow();
               else
                  hasZeroExponent = false;
            }
            else
               scfFlags.setUnderflow();
            if (hasZeroExponent && scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               return;
            };
            for (int uIndex = (bitSizeMantissa()-1)/(8*sizeof(unsigned int)); 
                  uIndex >= 0; --uIndex)
               biMantissa[uIndex] = fcmMantissa[uIndex];
            biMantissa.normalize();
         }
         else {
            scfFlags.setUnderflow();
            if (hasZeroExponent && scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               return;
            };
            bool fAdd = false;
            if (scfFlags.isNearestRound())
               fAdd = (fceNewExponent == bitSizeMantissa())
                  && (!scfFlags.isRoundToEven() || !fcValue.mantissa().isZero());
            else if (scfFlags.isHighestRound())
               fAdd = !fNegative;
            else if (scfFlags.isLowestRound())
               fAdd = fNegative;
            if (fNegative)
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            else
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            biMantissa = fAdd ? 1U : 0U;
            if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
               fNegative = false;
         };
      };
   }
   else { // fcValue.querySizeExponent() == bitSizeExponent()
      for (int uIndex = (fcValue.querySizeExponent()-1)/(8*sizeof(unsigned int)); 
            uIndex >= 0; --uIndex)
         biExponent[uIndex] = fcValue.exponent()[uIndex];
      biExponent.normalize();

      if (fcValue.querySizeMantissa() <= bitSizeMantissa()) {
         for (int uIndex = (fcValue.querySizeMantissa()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biMantissa[uIndex] = fcValue.mantissa()[uIndex];
         biMantissa.normalize();
      }
      else { // fcValue.querySizeMantissa() > bitSizeMantissa()
         typename FloatConversion::Mantissa fcmSourceMantissa(fcValue.mantissa());
         trightShift(fcmSourceMantissa, (fcValue.querySizeMantissa() - bitSizeMantissa()),
            0U, scfFlags, fNegative, fcValue.querySizeMantissa());
         if (fcmSourceMantissa.cbitArray(bitSizeMantissa())) {
            ++biExponent;
            fcmSourceMantissa.setFalseBitArray(bitSizeMantissa());
            if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
               scfFlags.setOverflow();
               biMantissa = 0U;
               if (!biMantissa.isZero()) {
                  biMantissa = 0U;
                  if (!scfFlags.isApproximate())
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               };
               if (scfFlags.upApproximateInfty()) {
                  if (!(scfFlags.upApproximateInversionForNear() && scfFlags.isNearestRound()))
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
               };
               if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                  biMantissa.neg();
                  biExponent.dec();
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               };
               return;
            };
         };
         for (int uIndex = (bitSizeMantissa()-1)/(8*sizeof(unsigned int)); 
               uIndex >= 0; --uIndex)
            biMantissa[uIndex] = fcmSourceMantissa[uIndex];
         biMantissa.normalize();
      };
      if (scfFlags.isDenormalizedAvoided() && biExponent.isZero() && !biMantissa.isZero()) {
         biMantissa = 0U;
         scfFlags.setUnderflow();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   };
}

#undef Typename

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::retrieveInteger(IntConversion& icResult, StatusAndControlFlags& scfFlags, unsigned fbits) const
{
   bool fNaN = isNaN();
   if (fNaN) {
      if (isSNaN())
         scfFlags.setSNaNOperand();
   } else if (fbits > 0) {
     thisType tmp( *this );
     if (tmp.biExponent.add(fbits).hasCarry() or tmp.biExponent == TypeTraits::getInftyExponent(biExponent))
       tmp.setInfty(fNegative);
     return tmp.retrieveInteger(icResult, scfFlags, 0);
   }
   
   if (fNegative && icResult.isUnsigned()) {
      scfFlags.setUpApproximate();
      icResult.assign((unsigned int) 0);
      return;
   };
   
   int exponent = queryExponentValue();
   
   if (exponent < 0) {
      bool fAdd = false;
      if (!isZero()) {
         if (scfFlags.isNearestRound()) {
            if ((fAdd = (biExponent == TypeTraits::getMinusOneExponent(biExponent))) != false)
               fAdd = !biMantissa.isZero();
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
      if (icResult.isUnsigned())
         icResult.assign(fAdd ? (unsigned int) 1 : (unsigned int) 0);
      else
         icResult.assign(fAdd ? (fNegative ? -1 : 1) : 0);
      return;
   };
   
   if (exponent >= icResult.queryMaxDigits()) {
      // Except for minimal signed value, this is an overflow
      if (not (fNegative and (exponent == icResult.queryMaxDigits()) and biMantissa.isZero())) {
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         scfFlags.setOverflow();
      };
      if (fNegative || (fNaN && scfFlags.isConvertNaNNegative()))
         icResult.setMin();
      else
         icResult.setMax();
      return;
   };
   
   if (bitSizeMantissa() > exponent) {
      Mantissa biResult = biMantissa;
      if (trightShift(biResult, bitSizeMantissa()-exponent, 1, scfFlags, fNegative, bitSizeMantissa()).hasCarry() or
          ((bitSizeMantissa() > icResult.queryMaxDigits()) && biResult.cbitArray(icResult.queryMaxDigits())))
      {
         if (bitSizeMantissa() >= icResult.queryMaxDigits()) {
            if (!fNegative || ((bitSizeMantissa() > icResult.queryMaxDigits())
                               && !biResult.hasZero(icResult.queryMaxDigits()))) {
              scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
              scfFlags.setOverflow();
            };
            if (fNegative)
              icResult.setMin();
            else
              icResult.setMax();
            return;
         }
         for (int idx = (bitSizeMantissa()-1)/(sizeof(unsigned int)*8); idx >= 0; --idx)
            icResult[idx] = biResult[idx];
         icResult.setTrueBitArray(bitSizeMantissa());
      }
      else {
         for (int idx = (std::min(bitSizeMantissa(),icResult.queryMaxDigits())-1)/(sizeof(unsigned int)*8); idx >= 0; --idx)
            icResult[idx] = biResult[idx];
      }
   }
   else {
      // bitSizeMantissa() < icResult.queryMaxDigits()
      for (int idx = (bitSizeMantissa()-1)/(sizeof(unsigned int)*8); idx >= 0; --idx)
         icResult[idx] = biMantissa[idx];
      icResult <<= (exponent-bitSizeMantissa());
      icResult.setTrueBitArray(exponent);
   };
   
   if (fNegative)
      icResult.opposite();
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::plusAssignSureNN(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && bdSource.isNormalized());
   if (biExponent == bdSource.biExponent) {
      typename Mantissa::Carry cCarry = biMantissa.add(bdSource.biMantissa);
      if (trightShift(biMantissa, 1, cCarry.carry(), scfFlags, fNegative, bitSizeMantissa()).hasCarry())
         biExponent.inc();
      biExponent.inc();
      if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.setOverflow();
         if (!biMantissa.isZero()) {
            biMantissa = 0U;
            if (!scfFlags.isApproximate())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
         if (scfFlags.upApproximateInfty())
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
      return *this;
   };
   if (biExponent < bdSource.biExponent) {
      if (bdSource.biExponent - biExponent > bitSizeMantissa()) {
         bool fAdd = false;
         bool fRoundToEven = false;
         if (scfFlags.isNearestRound()) {
            fAdd = ((bdSource.biExponent - biExponent) == bitSizeMantissa()+1);
            if (fAdd && scfFlags.isRoundToEven()) {
               fRoundToEven = biMantissa.isZero();
               if (fRoundToEven)
                  scfFlags.setEffectiveRoundToEven();
            };
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;

         biExponent = bdSource.biExponent;
         biMantissa = bdSource.biMantissa;
         if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
               && biMantissa.inc().hasCarry()) {
            biExponent.inc();
            if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
               scfFlags.setOverflow();
               if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                  biMantissa.neg();
                  biExponent.dec();
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  return *this;
               }
               else if (scfFlags.upApproximateInfty()) {
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                  return *this;
               };
            };
         };
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         return *this;
      };
      int uShift = (bdSource.biExponent - biExponent).queryValue();
      biExponent = bdSource.biExponent;
      bool fOverflow
         = trightShift(biMantissa, uShift, 1, scfFlags, fNegative, bitSizeMantissa()).hasCarry();
      if (biMantissa.add(bdSource.biMantissa).hasCarry() || fOverflow) {
         trightShift(biMantissa, 1, 0, scfFlags, fNegative, bitSizeMantissa());
         biExponent.inc();
         if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
            scfFlags.setOverflow();
            if (!biMantissa.isZero()) {
               biMantissa = 0U;
               if (!scfFlags.isApproximate())
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
            if (scfFlags.upApproximateInfty())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         };
      }
      else if (scfFlags.hasEffectiveRoundToEven()) {
         if (biMantissa.cbitArray(0)) {
            if (scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down)) {
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
               if (biMantissa.inc().hasCarry()) {
                  ++biExponent;
                  if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
                     scfFlags.setOverflow();
                     if (!biMantissa.isZero()) {
                        biMantissa = 0U;
                        if (!scfFlags.isApproximate())
                           scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                     };
                     if (scfFlags.upApproximateInfty())
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                     if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                        biMantissa.neg();
                        biExponent.dec();
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                     };
                  };
               };
            }
            else { // scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up)
               biMantissa.setFalseBitArray(0);
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         };
      };
      return *this;
   };
   // biExponent > bdSource.biExponent

   if ((biExponent - bdSource.biExponent) > bitSizeMantissa()) {
      bool fAdd = false;
      bool fRoundToEven = false;
      if (scfFlags.isNearestRound()) {
         fAdd = ((biExponent - bdSource.biExponent) == bitSizeMantissa()+1);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = bdSource.biMantissa.isZero();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;

      if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry()) {
         ++biExponent;
         if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
            scfFlags.setOverflow();
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               return *this;
            }
            else if (scfFlags.upApproximateInfty()) {
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
               return *this;
            };
         };
      };
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      return *this;
   };
   int uShift = (biExponent - bdSource.biExponent).queryValue();
   Mantissa biSourceMantissa = bdSource.biMantissa;
   if (trightShift(biSourceMantissa, uShift, 1, scfFlags, fNegative, bitSizeMantissa()).hasCarry()
         || biMantissa.add(biSourceMantissa).hasCarry()) {
      trightShift(biMantissa, 1, 0, scfFlags, fNegative, bitSizeMantissa());
      biExponent.inc();
      if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.setOverflow();
         if (!biMantissa.isZero()) {
            biMantissa = 0U;
            if (!scfFlags.isApproximate())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
         if (scfFlags.upApproximateInfty())
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
   }
   else if (scfFlags.hasEffectiveRoundToEven()) {
      if (biMantissa.cbitArray(0)) {
         if (scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down)) {
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            if (biMantissa.inc().hasCarry()) {
               ++biExponent;
               if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
                  scfFlags.setOverflow();
                  if (!biMantissa.isZero()) {
                     biMantissa = 0U;
                     if (!scfFlags.isApproximate())
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  if (scfFlags.upApproximateInfty())
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                  if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
               };
            };
         }
         else { // scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up)
            biMantissa.setFalseBitArray(0);
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::plusAssignSureND(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && (bdSource.biExponent.isZero()));
   int uMaxShift = bdSource.biMantissa.log_base_2();
   if ((uMaxShift == 1) && (bdSource.biMantissa.queryValue() == 0))
      return *this;
   if (biExponent > uMaxShift) {
      bool fAdd = false;
      bool fRoundToEven = false;
      if (scfFlags.isNearestRound()) {
         fAdd = biExponent == uMaxShift+1;
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = bdSource.biMantissa.hasZero(uMaxShift-1);
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry())
         ++biExponent;
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      return *this;
   };
   Mantissa biSourceMantissa = bdSource.biMantissa;
   if (trightShift(biSourceMantissa, biExponent.queryValue() - 1, 0, scfFlags, fNegative,
            bitSizeMantissa()).hasCarry()
         || biMantissa.add(biSourceMantissa).hasCarry()) {
      trightShift(biMantissa, 1, 0, scfFlags, fNegative, bitSizeMantissa());
      biExponent.inc();
      if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.setOverflow();
         if (!biMantissa.isZero()) {
            biMantissa = 0U;
            if (!scfFlags.isApproximate())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
         if (scfFlags.upApproximateInfty())
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
   }
   else if (scfFlags.hasEffectiveRoundToEven()) {
      if (biMantissa.cbitArray(0)) {
         if (scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down)) {
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            if (biMantissa.inc().hasCarry()) {
               ++biExponent;
               if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
                  scfFlags.setOverflow();
                  if (!biMantissa.isZero()) {
                     biMantissa = 0U;
                     if (!scfFlags.isApproximate())
                        scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  if (scfFlags.upApproximateInfty())
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                  if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
               };
            };
         }
         else { // scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up)
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            biMantissa.setFalseBitArray(0);
         };
      };
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::plusAssignSureDN(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(biExponent.isZero() && bdSource.isNormalized());
   int uMaxShift = biMantissa.log_base_2();
   if ((uMaxShift == 1) && (biMantissa.queryValue() == 0)) {
      biExponent = bdSource.biExponent;
      biMantissa = bdSource.biMantissa;
      return *this;
   };
   if (bdSource.biExponent > uMaxShift) {
      bool fAdd = false;
      bool fRoundToEven = false;
      if (scfFlags.isNearestRound()) {
         fAdd = (bdSource.biExponent == uMaxShift+1);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = biMantissa.hasZero(uMaxShift-1);
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      biExponent = bdSource.biExponent;
      biMantissa = bdSource.biMantissa;
      if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry()) {
         biExponent.inc();
         if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
            if (scfFlags.upApproximateInfty())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            scfFlags.setOverflow();
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               return *this;
            };
         };
      };
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      return *this;
   };
   biExponent = bdSource.biExponent;
   bool fOverflow = trightShift(biMantissa, bdSource.biExponent.queryValue() - 1, 0,
      scfFlags, fNegative, bitSizeMantissa()).hasCarry();
   if (biMantissa.add(bdSource.biMantissa).hasCarry() || fOverflow) {
      trightShift(biMantissa, 1, 0, scfFlags, fNegative, bitSizeMantissa());
      biExponent.inc();
      if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.setOverflow();
         if (!biMantissa.isZero()) {
            biMantissa = 0U;
            if (!scfFlags.isApproximate())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
         if (scfFlags.upApproximateInfty())
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
   }
   else if (scfFlags.hasEffectiveRoundToEven()) {
      if (biMantissa.cbitArray(0)) {
         if (scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down)) {
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            if (biMantissa.inc().hasCarry()) {
               biExponent.inc();
               if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
                  scfFlags.setOverflow();
                  if (scfFlags.upApproximateInfty())
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
                  if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
               };
            };
         }
         else { // scfFlags.isApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up)
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            biMantissa.setFalseBitArray(0);
         };
      };
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::plusAssignSureDD(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(biExponent.isZero() && bdSource.biExponent.isZero());
   if (biMantissa.add(bdSource.biMantissa).hasCarry())
      biExponent.inc();
   else {
      scfFlags.setUnderflow();
      if (!biMantissa.isZero() && scfFlags.isDenormalizedAvoided()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::minusAssignSureNN(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && bdSource.isNormalized());
   if (biExponent == bdSource.biExponent) {
      typename Mantissa::Carry cCarry = biMantissa.sub(bdSource.biMantissa);
      assert(!cCarry.hasCarry());
      if (biMantissa.isZero()) {
         biExponent = 0U;
         fNegative = (scfFlags.acceptMinusZero() && scfFlags.isLowestRound()) ? true : false;
         scfFlags.setUnderflow();
      }
      else {
         int uShift = bitSizeMantissa() - biMantissa.log_base_2() + 1;
         biMantissa <<= uShift;
         if (biExponent <= uShift) {
            biMantissa >>= (uShift-biExponent.queryValue()+1);
            biMantissa.setTrueBitArray(bitSizeMantissa()-(uShift-biExponent.queryValue()+1));
            biExponent = 0U;
            scfFlags.setUnderflow();
            if (scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         }
         else
            biExponent -= getBasicExponent(uShift);
      };
      return *this;
   };

   assert(biExponent > bdSource.biExponent);
   if ((biExponent - bdSource.biExponent) > bitSizeMantissa()) {
      bool fShouldDecFirst = ((biExponent - bdSource.biExponent) <= bitSizeMantissa()+2)
         && biMantissa.isZero();
      bool fSub = false;
      bool fDoubleSub = false, fActiveDouble = false;
      if (scfFlags.isNearestRound()) {
         if (!fShouldDecFirst) {
            fSub = ((biExponent - bdSource.biExponent) == bitSizeMantissa()+1);
            if (fSub && scfFlags.isRoundToEven()) {
               if (bdSource.biMantissa.isZero()) {
                  scfFlags.setEffectiveRoundToEven();
                  if (!biMantissa.cbitArray(0))
                     fSub = false;
               };
            };
         }
         else if ((biExponent - bdSource.biExponent) == bitSizeMantissa()+1) {
            // biMantissa.isZero()
            fSub = true;
            fDoubleSub = bdSource.biMantissa.cbitArray(bitSizeMantissa()-1);
            fActiveDouble = true;
            if (fDoubleSub && scfFlags.isRoundToEven()) {
               if (bdSource.biMantissa.hasZero(bitSizeMantissa()-1))
                  scfFlags.setEffectiveRoundToEven();
            };
         }
         else { // handle with the case fRoundToEven
            // biMantissa.isZero() && (biExponent - bdSource.biExponent) == bitSizeMantissa()+2
            fSub = !bdSource.biMantissa.isZero();
            fShouldDecFirst = false;
         };
      }
      else {
         if (scfFlags.isHighestRound())
            fSub = fNegative;
         else if (scfFlags.isLowestRound())
            fSub = !fNegative;
         else // scfFlags.isZeroRound()
            fSub = true;
         if (fShouldDecFirst) {
            if ((biExponent - bdSource.biExponent) == bitSizeMantissa()+1) {
               fDoubleSub = fSub;
               fActiveDouble = true;
               fSub = true;
            }
            else
               fShouldDecFirst = false;
         };
      }
      if (fSub && biMantissa.dec().hasCarry()) {
         --biExponent;
         if (((biExponent - bdSource.biExponent) == bitSizeMantissa()) && bdSource.biMantissa.isZero())
            return *this; // no approximation
         if (fDoubleSub)
            biMantissa.setFalseBitArray(0);
         if (fActiveDouble)
            fSub = fDoubleSub;
      };
      if (fNegative)
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      else
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      return *this;
   };

   int uShift = (biExponent - bdSource.biExponent).queryValue();
   Mantissa biSourceMantissa(bdSource.biMantissa);
   if (uShift == 1) { // biExponent >= 2
      bool fMinor = biSourceMantissa.cbitArray(0);
      biSourceMantissa >>= 1;
      biSourceMantissa.setTrueBitArray(bitSizeMantissa()-1);

      if (biMantissa.sub(biSourceMantissa).hasCarry()) {
         int uNewShift = bitSizeMantissa() - biMantissa.log_base_2() + 1;
         if (fMinor) {
            assert(biMantissa.cbitArray(bitSizeMantissa() - uNewShift));
            biMantissa <<= 1;
            if (biMantissa.dec().hasCarry() || ((uNewShift > 1)
                  && (!biMantissa.cbitArray(bitSizeMantissa() - uNewShift + 1))))
              ++uNewShift;
            if (uNewShift > 1)
               biMantissa <<= (uNewShift-1);
         }
         else
            biMantissa <<= uNewShift;

         if (biExponent <= uNewShift) {
            biMantissa >>= (uNewShift-biExponent.queryValue()+1);
            biMantissa.setTrueBitArray(bitSizeMantissa()-(uNewShift-biExponent.queryValue()+1));
            biExponent = 0;
            scfFlags.setUnderflow();
            if (scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               return *this;
            };
         }
         else
            biExponent -= getBasicExponent(uNewShift);
      }
      else if (fMinor) {
         bool fSub = false;
         if (scfFlags.isHighestRound())
            fSub = fNegative;
         else if (scfFlags.isLowestRound())
            fSub = !fNegative;
         else // scfFlags.isZeroRound()
            fSub = true;
         bool fDec = false;
         if ((biMantissa.isZero() && !scfFlags.isApproximate() && ((fDec = true) != false)
                  && biMantissa.dec().hasCarry())
               || (!fDec && fSub && ((fSub = (!scfFlags.isRoundToEven() || biMantissa.cbitArray(0))) != false)
                     && biMantissa.dec().hasCarry())) {
            --biExponent; // biExponent >= 1
            return *this; // no precision loss
         };
         if (fNegative)
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         else
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      };

      return *this;
   };

   bool fMinorTwo = biSourceMantissa.cbitArray(uShift-1),
        fMinorOne = biSourceMantissa.cbitArray(uShift-2);
   bool fSureApproximate = !biSourceMantissa.hasZero(uShift-2);
   biSourceMantissa >>= uShift;
   biSourceMantissa.setTrueBitArray(bitSizeMantissa()-uShift);
   bool fHasDigits = !biMantissa.sub(biSourceMantissa).hasCarry();
   // biExponent >= 3
   if (!fHasDigits) {
      biExponent.dec();
      // fHasDigits = biExponent.isZero(); biExponent >= 3
   };
   if (fHasDigits) {
      // biExponent >= 3
      if (fMinorOne || fMinorTwo || fSureApproximate) {
         bool fSub = false;
         bool fRoundToEven = false;
         if (scfFlags.isNearestRound()) {
            fSub = fMinorTwo;
            if (fSub && scfFlags.isRoundToEven()) {
               fRoundToEven = !fMinorOne && !fSureApproximate;
               if (fRoundToEven)
                  scfFlags.setEffectiveRoundToEven();
            };
         }
         else if (scfFlags.isHighestRound())
            fSub = fNegative;
         else if (scfFlags.isLowestRound())
            fSub = !fNegative;
         else // scfFlags.isZeroRound()
            fSub = true;

         bool fDec = false;
         if ((biMantissa.isZero()
                  && (fMinorTwo || (scfFlags.isNearestRound()
                        && fMinorOne && (!scfFlags.isRoundToEven() || fSureApproximate)))
                  && ((fDec = true) != false) && biMantissa.dec().hasCarry())
            || (!fDec && fSub && ((fSub = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
                  && biMantissa.dec().hasCarry())) { // if fDec, case fRoundToEven is naturally correct
            biExponent.dec();
            // biExponent >= 2
            if (scfFlags.isNearestRound())
               fSub = fMinorTwo ? fMinorOne : true;
            else if (fSub)
               fSub = fMinorOne || fSureApproximate;
            biMantissa.setBitArray(0, fMinorTwo ? !fSub : true);
            if (!fMinorOne && !fSureApproximate)
               return *this;
         };
         if (fNegative)
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         else
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      };
      return *this;
   };

   biMantissa <<= 1;
   if (fMinorTwo)
      biMantissa.dec();
   if (fMinorOne || fSureApproximate) {
      bool fSub = false;
      if (scfFlags.isNearestRound())
         fSub = fMinorOne && (!scfFlags.isRoundToEven() || fSureApproximate || biMantissa.cbitArray(0));
      else if (scfFlags.isHighestRound())
         fSub = fNegative;
      else if (scfFlags.isLowestRound())
         fSub = !fNegative;
      else // scfFlags.isZeroRound()
         fSub = true;
      if (fSub)
         biMantissa.dec();
      if (fNegative)
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      else
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::minusAssignSureND(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && bdSource.biExponent.isZero());
   if (bdSource.biMantissa.isZero())
      return *this;

   int uNbSourceDigits = bdSource.biMantissa.log_base_2();
   if (biExponent > uNbSourceDigits) {
      bool fShouldDecFirst = (biExponent <= uNbSourceDigits+2) && biMantissa.isZero();
      bool fSub = false;
      bool fDoubleSub = false, fActiveDouble = false;
      if (scfFlags.isNearestRound()) {
         if (!fShouldDecFirst) {
            fSub = (biExponent == uNbSourceDigits+1);
            if (fSub && scfFlags.isRoundToEven()) {
               if (bdSource.biMantissa.hasZero(uNbSourceDigits-1)) {
                  scfFlags.setEffectiveRoundToEven();
                  if (!biMantissa.cbitArray(0))
                     fSub = false;
               };
            };
         }
         else if (biExponent == uNbSourceDigits+1) {
            // biMantissa.isZero()
            fSub = true;
            fDoubleSub = bdSource.biMantissa.cbitArray(uNbSourceDigits-2);
            fActiveDouble = true;
            if (scfFlags.isRoundToEven()) {
               if ((uNbSourceDigits <= 2) && bdSource.biMantissa.hasZero(uNbSourceDigits-2))
                  scfFlags.setEffectiveRoundToEven();
            };
         }
         else { // handle with the case fRoundToEven
            fSub = (uNbSourceDigits > 1) && !bdSource.biMantissa.hasZero(uNbSourceDigits-1);
            fShouldDecFirst = false;
            // if (!fSub) scfFlags.setEffectiveRoundToEven();
         };
      }
      else {
         if (scfFlags.isHighestRound())
            fSub = fNegative;
         else if (scfFlags.isLowestRound())
            fSub = !fNegative;
         else // scfFlags.isZeroRound()
            fSub = true;
         if (fShouldDecFirst) {
            if (biExponent == uNbSourceDigits+1) {
               fDoubleSub = fSub;
               fActiveDouble = true;
               fSub = true;
            }
            else
               fShouldDecFirst = false;
         };
      };
      if (fSub && biMantissa.dec().hasCarry()) {
         biExponent.dec();
         if (scfFlags.isDenormalizedAvoided() && biExponent.isZero()) {
            biMantissa = 0U;
            scfFlags.setUnderflow();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            return *this;
         };
         if ((biExponent == uNbSourceDigits)
               && ((uNbSourceDigits <= 1) || bdSource.biMantissa.hasZero(uNbSourceDigits-1)))
            return *this; // no approximation
         if (fDoubleSub)
            biMantissa.setFalseBitArray(0);
         if (fActiveDouble)
            fSub = fDoubleSub;
      };
      if (fNegative)
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      else
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      return *this;
   };

   int uSourceShift = biExponent.queryValue()-1;
   if (uSourceShift == 0) {
      if (biMantissa.sub(bdSource.biMantissa).hasCarry()) {
         biExponent = 0;
         scfFlags.setUnderflow();
         if (scfFlags.isDenormalizedAvoided()) {
            biMantissa = 0U;
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      };
      return *this;
   };

   // biExponent >= 2
   Mantissa biSourceMantissa(bdSource.biMantissa);
   bool fMinorTwo = biSourceMantissa.cbitArray(uSourceShift-1),
        fMinorOne = (uSourceShift > 1) ? biSourceMantissa.cbitArray(uSourceShift-2) : 0;
   bool fSureApproximate = (uSourceShift > 1) ? !biSourceMantissa.hasZero(uSourceShift-2) : false;
   biSourceMantissa >>= uSourceShift;
   bool fHasDigits = !biMantissa.sub(biSourceMantissa).hasCarry();
   if (!fHasDigits) {
      biExponent.dec();
      // biExponent >= 1
      // fHasDigits = biExponent.isZero();
   };
   if (fHasDigits) {
      // biExponent >= 2
      if (fMinorOne || fMinorTwo || fSureApproximate) {
         bool fSub = false;
         bool fRoundToEven = false;
         if (scfFlags.isNearestRound()) {
            fSub = fMinorTwo;
            if (fSub && scfFlags.isRoundToEven()) {
               fRoundToEven = !fMinorOne && !fSureApproximate;
               if (fRoundToEven)
                  scfFlags.setEffectiveRoundToEven();
            };
         }
         else if (scfFlags.isHighestRound())
            fSub = fNegative;
         else if (scfFlags.isLowestRound())
            fSub = !fNegative;
         else // scfFlags.isZeroRound()
            fSub = true;
         bool fDec = false;
         if ((biMantissa.isZero()
                  && (fMinorTwo || (scfFlags.isNearestRound()
                        && fMinorOne && (!scfFlags.isRoundToEven() || fSureApproximate)))
                  && ((fDec = true) != false) && biMantissa.dec().hasCarry())
            || (!fDec && fSub && ((fSub = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
                  && biMantissa.dec().hasCarry())) { // if fDec, case fRoundToEven is naturally correct
            biExponent.dec();
            // biExponent >= 1
            if (scfFlags.isNearestRound())
               fSub = fMinorTwo ? fMinorOne : true;
            else if (fSub)
               fSub = fMinorOne || fSureApproximate;
            biMantissa.setBitArray(0, fMinorTwo ? !fSub : true);
            if (!fMinorOne && !fSureApproximate)
               return *this;
         };
         if (fNegative)
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         else
            scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      };
      return *this;
   };

   // biMantissa.sub(biSourceMantissa).hasCarry();
   // biExponent >= 1
   biMantissa <<= 1;
   if (fMinorTwo)
      biMantissa.dec();
   if (fMinorOne || fSureApproximate) { // biExponent >= 2
      bool fSub = false;
      if (scfFlags.isNearestRound())
         fSub = fMinorOne && (!scfFlags.isRoundToEven() || fSureApproximate || biMantissa.cbitArray(0));
      else if (scfFlags.isHighestRound())
         fSub = fNegative;
      else if (scfFlags.isLowestRound())
         fSub = !fNegative;
      else // scfFlags.isZeroRound()
         fSub = true;
      if (fSub)
         biMantissa.dec();
      if (fNegative)
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      else
         scfFlags.setApproximate(fSub ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::minusAssignSureDD(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(biExponent.isZero() && bdSource.biExponent.isZero());
   typename Mantissa::Carry cCarry = biMantissa.sub(bdSource.biMantissa);
   scfFlags.setUnderflow();
   assert(!cCarry.hasCarry());
   if (biMantissa.isZero())
      fNegative = (scfFlags.acceptMinusZero() && scfFlags.isLowestRound()) ? true : false;
   else if (scfFlags.isDenormalizedAvoided()) {
      biMantissa = 0U;
      scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::plusAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   if (!biExponent.isZero()) {
      if (biExponent != TypeTraits::getInftyExponent(biExponent)) {
         if (!bdSource.biExponent.isZero()) {
            if (bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)) {
               if (fNegative == bdSource.fNegative)
                  return plusAssignSureNN(bdSource, scfFlags);
               typename Exponent::ComparisonResult crCompareExponent = biExponent.compare(bdSource.biExponent);
               if ((crCompareExponent == Exponent::CRGreater)
                     || ((crCompareExponent == Exponent::CREqual) && biMantissa >= bdSource.biMantissa))
                  return minusAssignSureNN(bdSource, scfFlags);
               thisType ttThisCopy = *this;
               *this = bdSource;
               minusAssignSureNN(ttThisCopy, scfFlags);
               return *this;
            };
            // bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)
            fNegative = bdSource.fNegative;
            biMantissa = bdSource.biMantissa;
            if (!biMantissa.isZero()) {
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
            };
            biExponent = TypeTraits::getInftyExponent(biExponent);
            return *this;
         };

         if (fNegative == bdSource.fNegative)
            return plusAssignSureND(bdSource, scfFlags);
         return minusAssignSureND(bdSource, scfFlags);
      };

      // biExponent == TypeTraits::getInftyExponent(biExponent)
      if (biMantissa.isZero()) {
         if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
            if (!bdSource.biMantissa.isZero()) {
               biMantissa = bdSource.biMantissa;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               fNegative = bdSource.fNegative;
            }
            else if (bdSource.fNegative != fNegative) {
               scfFlags.setInftyMinusInfty();
               biMantissa = 0U;
               biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               if (scfFlags.produceAddNaNPositive())
                  fNegative = false;
            };
         };
      }
      else {
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         }
         else if (bdSource.isSNaN())
            scfFlags.setSNaNOperand();
      };
      return *this;
   };
   
   // biExponent == 0
   if (bdSource.biExponent.isZero()) {
      if (fNegative == bdSource.fNegative)
         return plusAssignSureDD(bdSource, scfFlags);
      if (biMantissa >= bdSource.biMantissa)
         minusAssignSureDD(bdSource, scfFlags);
      else {
         thisType ttThisCopy = *this;
         *this = bdSource;
         minusAssignSureDD(ttThisCopy, scfFlags);
      };
      return *this;
   };
      
   // biExponent == 0 && bdSource.biExponent != 0
   if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
      fNegative = bdSource.fNegative;
      biExponent = bdSource.biExponent;
      biMantissa = bdSource.biMantissa;
      if (!biMantissa.isZero()) {
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         };
      };
      return *this;
   };
   
   // biExponent == 0 && bdSource.biExponent != 0 && bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)
   if (fNegative == bdSource.fNegative)
      return plusAssignSureDN(bdSource, scfFlags);
   thisType ttThisCopy = *this;
   *this = bdSource;
   minusAssignSureND(ttThisCopy, scfFlags);
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::minusAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   if (!biExponent.isZero()) {
      if (biExponent != TypeTraits::getInftyExponent(biExponent)) {
         if (!bdSource.biExponent.isZero()) {
            if (bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)) {
               if (fNegative != bdSource.fNegative)
                  return plusAssignSureNN(bdSource, scfFlags);
               typename Mantissa::ComparisonResult crCompareExponent = biExponent.compare(bdSource.biExponent);
               if ((crCompareExponent == Mantissa::CRGreater)
                     || ((crCompareExponent == Mantissa::CREqual) && biMantissa >= bdSource.biMantissa))
                  return minusAssignSureNN(bdSource, scfFlags);
               thisType ttThisCopy = *this;
               *this = bdSource;
               fNegative = !fNegative;
               minusAssignSureNN(ttThisCopy, scfFlags);
               return *this;
            };
            
            // bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)
            fNegative = !bdSource.fNegative;
            biMantissa = bdSource.biMantissa;
            if (!biMantissa.isZero()) {
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               if (scfFlags.keepNaNSign())
                  fNegative = !fNegative;
            };
            biExponent = bdSource.biExponent;
            return *this;
         };

         // bdSource.biExponent == 0
         if (fNegative != bdSource.fNegative)
            return plusAssignSureND(bdSource, scfFlags);
         minusAssignSureND(bdSource, scfFlags);
         return *this;
      };

      // biExponent == TypeTraits::getInftyExponent(biExponent)
      if (biMantissa.isZero()) {
         if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
            if (!bdSource.biMantissa.isZero()) {
               biMantissa = bdSource.biMantissa;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               fNegative = bdSource.fNegative;
            }
            else if (bdSource.fNegative == fNegative) {
               scfFlags.setInftyMinusInfty();
               biMantissa = 0U;
               biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               if(scfFlags.produceSubNaNPositive())
                   fNegative=false;
            };
         };
      }
      else {
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         }
         else if (bdSource.isSNaN())
            scfFlags.setSNaNOperand();
      };

      return *this;
   };
   
   // biExponent == 0
   if (bdSource.biExponent.isZero()) {
      if (fNegative != bdSource.fNegative)
         return plusAssignSureDD(bdSource, scfFlags);
      if (biMantissa >= bdSource.biMantissa)
         minusAssignSureDD(bdSource, scfFlags);
      else {
        thisType ttThisCopy = *this;
        *this = bdSource;
        fNegative = !fNegative;
        minusAssignSureDD(ttThisCopy, scfFlags);
      };
      return *this;
   };

   // biExponent == 0 && bdSource.biExponent != 0
   if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
      fNegative = !bdSource.fNegative;
      biExponent = TypeTraits::getInftyExponent(biExponent);
      biMantissa = bdSource.biMantissa;
      if (!biMantissa.isZero()) {
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         };
         if (scfFlags.keepNaNSign())
            fNegative = !fNegative;
      };
      return *this;
   };
   
   // biExponent == 0 && bdSource.biExponent != 0 && bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)
   if (fNegative != bdSource.fNegative)
      return plusAssignSureDN(bdSource, scfFlags);
   thisType ttThisCopy = *this;
   *this = bdSource;
   fNegative = !fNegative;
   minusAssignSureND(ttThisCopy, scfFlags);
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssign(unsigned int uValue, StatusAndControlFlags& scfFlags) {
   if (uValue != 0) {
      int uValueDigits = log_base_2(uValue);
      if (isNormalized()) {
         typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
         typename TypeTraits::ExtendedMantissa::Carry cCarry = emMantissa.multAssign(uValue);
         if (cCarry.hasCarry()) {
            assert((uValueDigits == log_base_2(cCarry.carry()))
               || (uValueDigits == 1+log_base_2(cCarry.carry())));
            if ((cCarry.carry() & (1U << (uValueDigits-1))) == 0) {
               --uValueDigits;
               assert((cCarry.carry() & (1U << (uValueDigits-1))) != 0);
            };
            if (trightShift(emMantissa, uValueDigits, cCarry.carry() & ~(~0U << (uValueDigits-1)),
                  scfFlags, fNegative, bitSizeMantissa()+1).hasCarry())
               ++uValueDigits;
            biMantissa = emMantissa;
            bool fOverflowExponent = emMantissa.cbitArray(bitSizeMantissa())
                ? biExponent.plusAssign(uValueDigits + 1).hasCarry()
                : biExponent.plusAssign(uValueDigits).hasCarry();
            if (fOverflowExponent || (biExponent >= TypeTraits::getInftyExponent(biExponent))) {
               scfFlags.setOverflow();
               if (fOverflowExponent || (biExponent > TypeTraits::getInftyExponent(biExponent)) || !biMantissa.isZero()) {
                  biExponent = TypeTraits::getInftyExponent(biExponent);
                  biMantissa = 0U;
                  if (!scfFlags.isApproximate())
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               };
               if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
                  biMantissa.neg();
                  biExponent.dec();
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               }
               else if (scfFlags.upApproximateInfty())
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            };
         };
      }
      else if (biExponent.isZero()) {
         typename TypeTraits::Mantissa::Carry cCarry = biMantissa.multAssign(uValue);
         if (cCarry.hasCarry()) {
            int uShift = log_base_2(cCarry.carry())-1;
            if (uShift > 0) {
               if (trightShift(biMantissa, uShift, cCarry.carry(), scfFlags, fNegative, bitSizeMantissa()).hasCarry())
                  ++uShift;
               biMantissa.normalize();
               biExponent = uShift+1;
            }
            else
               biExponent = 1;
         }
         else {
            scfFlags.setUnderflow();
            if (scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         };
      }
      else { // biExponent == TypeTraits::getInftyExponent(biExponent);
         if (!queryMantissa().isZero())
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
      };
   }
   else if (biExponent != TypeTraits::getInftyExponent(biExponent)) { // uValue == 0
      biMantissa = 0U;
      biExponent = 0U;
      scfFlags.setUnderflow();
   }
   else { // biExponent == TypeTraits::getInftyExponent(biExponent)) -> NaN
      if (scfFlags.isAllInftyAvoided()) {
         biMantissa = 0U;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      }
      else if (biMantissa.isZero()) {
         biMantissa = 0U;
         biMantissa.neg();
         biMantissa.setFalseBitArray(bitSizeMantissa()-1);
      }
      else
         biMantissa.setTrueBitArray(bitSizeMantissa()-1);
   };
   return *this;
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::addExtension(const thisType& bdSource,
      typename TypeTraits::ExtendedMantissa::EnhancedMultResult& mprResult,
      StatusAndControlFlags& scfFlags, bool fPositiveAdd, int& uLogResult, bool& fExponentHasCarry,
      bool& fResultPositiveExponent, bool& fAddExponent) {
   TBuiltDouble<typename TypeTraits::MultExtension> bdMult, bdAdd;
   bdMult.setSign(!fNegative);
   for (int uIndex = 0; uIndex < biExponent.queryCellSize(); ++uIndex)
      bdMult.querySBasicExponent()[uIndex] = biExponent[uIndex];
   int uMultSize = ((const typename TypeTraits::ExtendedMantissa&) biMantissa).queryMultResultCellSize(mprResult);
   for (int uIndex = 0; uIndex < uMultSize; ++uIndex)
      bdMult.querySMantissa()[uIndex] = mprResult[uIndex];
   bdMult.querySMantissa().normalize();
   if (uLogResult < 2*bitSizeMantissa()+1)
      bdMult.querySMantissa() <<= 2*bitSizeMantissa()-uLogResult+1;
   if (bdMult.querySBasicExponent().cbitArray(bitSizeExponent()-1)) {
      bdMult.querySBasicExponent().setFalseBitArray(bitSizeExponent()-1);
      bdMult.querySBasicExponent().setTrueBitArray(bitSizeExponent());
      if (fExponentHasCarry) {
         if (fResultPositiveExponent)
            bdMult.querySBasicExponent().setTrueBitArray(bitSizeExponent()-1);
         else {
            bdMult.querySBasicExponent().setFalseBitArray(bitSizeExponent());
            if (bdMult.querySBasicExponent().isZero())
               bdMult.querySBasicExponent() = 1U;
         };
      };
   }
   else {
      if (fExponentHasCarry) {
         if (fResultPositiveExponent) {
            bdMult.querySBasicExponent().setTrueBitArray(bitSizeExponent()-1);
            bdMult.querySBasicExponent().setTrueBitArray(bitSizeExponent());
         }
         else {
            if (!bdMult.queryBasicExponent().cbitArray(bitSizeExponent()-1))
               bdMult.querySBasicExponent() = 1U;
            else
               bdMult.querySBasicExponent().setFalseBitArray(bitSizeExponent()-1);
         };
      }
      else
         bdMult.querySBasicExponent().setTrueBitArray(bitSizeExponent()-1);
   };
   uLogResult = 2*bitSizeMantissa()+1;
   if (fAddExponent) {
      bdMult.querySBasicExponent().inc();
      fAddExponent = false;
   };

   bdAdd.setSign(fPositiveAdd ? bdSource.isPositive() : !bdSource.isPositive());
   for (int uIndex = 0; uIndex < bdSource.queryBasicExponent().queryCellSize(); ++uIndex)
      bdAdd.querySBasicExponent()[uIndex] = bdSource.queryBasicExponent()[uIndex];
   for (int uIndex = 0; uIndex < bdSource.queryMantissa().queryCellSize(); ++uIndex)
      bdAdd.querySMantissa()[uIndex] = bdSource.queryMantissa()[uIndex];
   int uDenormalizedShift = 0;
   if (bdSource.queryBasicExponent().isZero()) {
      if (bdSource.queryMantissa().isZero())
         goto LSetResult;
      uDenormalizedShift = bitSizeMantissa()-bdSource.queryMantissa().log_base_2()+1;
      scfFlags.clearFlowException();
   };
   bdAdd.querySMantissa() <<= bitSizeMantissa()+1+uDenormalizedShift;
   if (bdAdd.querySBasicExponent().cbitArray(bitSizeExponent()-1)) {
      bdAdd.querySBasicExponent().setFalseBitArray(bitSizeExponent()-1);
      bdAdd.querySBasicExponent().setTrueBitArray(bitSizeExponent());
   }
   else {
      bdAdd.querySBasicExponent().setTrueBitArray(bitSizeExponent()-1);
      if (uDenormalizedShift > 1)
         bdAdd.querySBasicExponent().sub(uDenormalizedShift-1);
   };

   if (bdMult.isNegative() == bdAdd.isNegative())
      bdMult.plusAssignSureNN(bdAdd, scfFlags);
   else {
	  bdAdd.opposite();
	  if (bdMult.isNegative() ? (bdMult <= bdAdd) : (bdMult >= bdAdd))
         bdMult.minusAssignSureNN(bdAdd, scfFlags);
      else {
         bdAdd.opposite();
         bdAdd.minusAssignSureNN(bdMult, scfFlags);
         bdMult = bdAdd;
	  };
   };
LSetResult:
   fNegative = bdMult.isNegative();
   for (int uIndex = 0; uIndex < biExponent.queryCellSize(); ++uIndex)
      biExponent[uIndex] = bdMult.querySBasicExponent()[uIndex];
   biExponent.normalize();
   for (int uIndex = 0; uIndex < uMultSize; ++uIndex)
      mprResult[uIndex] = bdMult.querySMantissa()[uIndex];
   mprResult.setTrueBitArray(2*bitSizeMantissa()+1);
   if (bdMult.querySBasicExponent().cbitArray(bitSizeExponent())) {
      if (bdMult.querySBasicExponent().cbitArray(bitSizeExponent()-1)) { // infty
         fResultPositiveExponent = true;
         fExponentHasCarry = true;
      }
      else { // positive
         biExponent.setTrueBitArray(bitSizeExponent()-1);
         fExponentHasCarry = false;
      };
   }
   else {
      if (bdMult.querySBasicExponent().cbitArray(bitSizeExponent()-1)) { // negative
         biExponent.setFalseBitArray(bitSizeExponent()-1);
         fExponentHasCarry = false;
      }
      else { // zero
         biExponent.setTrueBitArray(bitSizeExponent()-1);
         fResultPositiveExponent = false;
         fExponentHasCarry = true;
      };
   };
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssignNN(const thisType& bdSource, const MultParameters& mpFlags) {
   assert(isNormalized() && bdSource.isNormalized());
   StatusAndControlFlags& scfFlags = mpFlags.readParams();
   typename TypeTraits::ExtendedMantissa::MultResult mrResult;
   typename TypeTraits::ExtendedMantissa::EnhancedMultResult&
      mprResult = (typename TypeTraits::ExtendedMantissa::EnhancedMultResult&) mrResult;

   typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
   typename TypeTraits::ExtendedMantissa emSourceMantissa(bdSource.biMantissa);
   emMantissa.mult(emSourceMantissa, mrResult);
   int uLogResult = 2*bitSizeMantissa()+1;
   bool fAddExponent = false;
   if (!mprResult.cbitArray(uLogResult))
      --uLogResult;
   else
      fAddExponent = true;
   assert(mprResult.cbitArray(uLogResult));

   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   bool fExponentHasCarry = false;
   bool fResultPositiveExponent = !bdSource.hasNegativeExponent();
   if (fResultPositiveExponent)
      fExponentHasCarry = biExponent.plusAssign(bdSource.biExponent
         -TypeTraits::getZeroExponent(biExponent)).hasCarry();
   else {
      Exponent biSubExponent = TypeTraits::getZeroExponent(biExponent);
      biSubExponent -= bdSource.biExponent;
      fExponentHasCarry = biExponent.sub(biSubExponent).hasCarry();
      fResultPositiveExponent = !fExponentHasCarry && (biExponent >= TypeTraits::getZeroExponent(biExponent));
   };

   bool fAddExtension = false;
   if (mpFlags.hasAdd()) {
      fAddExtension = mpFlags.hasSameSign(fNegative);
      addExtension(mpFlags.queryAddSource(), mprResult, scfFlags,
         mpFlags.isPositiveAdditive(), uLogResult, fExponentHasCarry, fResultPositiveExponent,
         fAddExponent);
   };

   int uShift = uLogResult-bitSizeMantissa();
   if (((fApproximate = !mprResult.hasZero(uShift)) != false) || scfFlags.isApproximate()) {
      if (scfFlags.isNearestRound()) {
         fAdd = mprResult.cbitArray(uShift-1);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = mprResult.hasZero(uShift-1) && !scfFlags.isApproximate();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? !fNegative : (!fNegative && fAddExtension);
      else if (scfFlags.isLowestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? fNegative : (fNegative && fAddExtension);
   };
   mprResult >>= uShift;
   assert(mprResult.cbitArray(bitSizeMantissa()));
   if (fAdd && ((fAdd = (!fRoundToEven || mprResult.cbitArray(0))) != false)) {
      mprResult.inc();
      if (!mprResult.cbitArray(bitSizeMantissa())) {
         mprResult >>= 1;
         assert(!fAddExponent);
         fAddExponent = true;
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = mrResult[uIndex];
   biMantissa.normalizeLastCell();

   if (fResultPositiveExponent) {
      if (fExponentHasCarry || (fAddExponent && biExponent.inc().hasCarry())) {
         biExponent = TypeTraits::getInftyExponent(biExponent);
         biMantissa = 0U;
      }
      else if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         if (!biMantissa.isZero()) {
            biMantissa = 0U;
            if (!scfFlags.isApproximate())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         };
      }
      else
         return *this;

      scfFlags.setOverflow();
      if (scfFlags.upApproximateInfty())
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
      return *this;
   };

   if (fAddExponent && biExponent.inc().hasCarry())
      fExponentHasCarry = false;
   if (fExponentHasCarry || biExponent.isZero()) {
      biExponent.neg().inc();
      Exponent biSubExponent = biExponent;
      biExponent = 0U;
      if (biSubExponent < bitSizeMantissa()) { // denormalized
         if (trightShift(biMantissa, biSubExponent.queryValue()+1, 1, scfFlags,
               fNegative, bitSizeMantissa()).hasCarry())
            biExponent.inc();
         else
            scfFlags.setUnderflow();
      }
      else {
         scfFlags.setUnderflow();
         bool fAdd = false;
         if (scfFlags.isNearestRound()) {
            fAdd = (biSubExponent == bitSizeMantissa());
            if (fAdd && biMantissa.isZero()) {
               if (!fNegative) {
                  if (scfFlags.isUpApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               }
               else {
                  if (scfFlags.isDownApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               };
            };
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         biMantissa = fAdd ? 1U : 0U;
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
            fNegative = false;
      };
      if (scfFlags.isDenormalizedAvoided() && !biMantissa.isZero()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   else if ((biExponent == 1U) && biMantissa.isZero()
         && scfFlags.isApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up))
      scfFlags.setUnderflow();
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssignND(const thisType& bdSource, const MultParameters& mpFlags) {
   assert(isNormalized() && bdSource.isDenormalized());
   StatusAndControlFlags& scfFlags = mpFlags.readParams();
   typename TypeTraits::ExtendedMantissa::MultResult mrResult;
   typename TypeTraits::ExtendedMantissa::EnhancedMultResult&
      mprResult = (typename TypeTraits::ExtendedMantissa::EnhancedMultResult&) mrResult;

   typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
   typename TypeTraits::ExtendedMantissa emSourceMantissa(bdSource.biMantissa);
   emSourceMantissa.setFalseBitArray(bitSizeMantissa());
   emMantissa.mult(emSourceMantissa, mrResult);
   int uLogResult = mprResult.log_base_2()-1; // <= 2*bitSizeMantissa()
   assert(mprResult.cbitArray(uLogResult));

   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   Exponent biSubExponent = TypeTraits::getZeroExponent(biExponent);
   int uAdd = 2*bitSizeMantissa()-uLogResult -1;
   if (uAdd > 0)
      biSubExponent.add(uAdd);
   else if (uAdd < 0)
      biSubExponent.sub(-uAdd);
   bool fResultPositiveExponent = false; 
   bool fExponentHasCarry = biExponent.sub(biSubExponent).hasCarry();

   bool fAddExtension = false;
   if (mpFlags.hasAdd()) {
      bool fAddExponent = false;
      fAddExtension = mpFlags.hasSameSign(fNegative);
      addExtension(mpFlags.queryAddSource(), mprResult, scfFlags,
         mpFlags.isPositiveAdditive(), uLogResult, fExponentHasCarry, fResultPositiveExponent,
         fAddExponent);
   };

   assert(mprResult.cbitArray(uLogResult));
   int uShift = uLogResult-bitSizeMantissa();
   if (((fApproximate = !mprResult.hasZero(uShift)) != false) || scfFlags.isApproximate()) {
      if (scfFlags.isNearestRound()) {
         fAdd = mprResult.cbitArray(uShift-1);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = mprResult.hasZero(uShift-1) && !scfFlags.isApproximate();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? !fNegative : (!fNegative && fAddExtension);
      else if (scfFlags.isLowestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? fNegative : (fNegative && fAddExtension);
   };
   mprResult >>= uShift;
   assert(mprResult.cbitArray(bitSizeMantissa()));
   if (fAdd && ((fAdd = (!fRoundToEven || mprResult.cbitArray(0))) != false)) {
      mprResult.inc();
      if (!mprResult.cbitArray(bitSizeMantissa())) {
         mprResult >>= 1;
         biExponent.inc();
         if (biExponent.isZero())
            fExponentHasCarry = false;
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = mrResult[uIndex];
   biMantissa.normalizeLastCell();

   if (fExponentHasCarry || biExponent.isZero()) {
      biExponent.neg().inc();
      if (biExponent < bitSizeMantissa()) { // denormalized
         if (trightShift(biMantissa, biExponent.queryValue()+1, 1, scfFlags,
               fNegative, bitSizeMantissa()).hasCarry())
            biExponent = 1U;
         else
            scfFlags.setUnderflow();
      }
      else {
         scfFlags.setUnderflow();
         bool fAdd = false;
         if (scfFlags.isNearestRound()) {
            fAdd = biExponent == bitSizeMantissa();
            if (fAdd && biMantissa.isZero()) {
               if (!fNegative) {
                  if (scfFlags.isUpApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               }
               else {
                  if (scfFlags.isDownApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               };
            };
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         biMantissa = fAdd ? 1U : 0U;
         if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
            fNegative = false;
      };
      biExponent = 0U;
      if (scfFlags.isDenormalizedAvoided() && !biMantissa.isZero()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   else if ((biExponent == 1U) && biMantissa.isZero()
         && scfFlags.isApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up))
      scfFlags.setUnderflow();
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssignDN(const thisType& bdSource, const MultParameters& mpFlags) {
   assert(isDenormalized() && bdSource.isNormalized());
   StatusAndControlFlags& scfFlags = mpFlags.readParams();
   typename TypeTraits::ExtendedMantissa::MultResult mrResult;
   typename TypeTraits::ExtendedMantissa::EnhancedMultResult&
      mprResult = (typename TypeTraits::ExtendedMantissa::EnhancedMultResult&) mrResult;

   typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
   typename TypeTraits::ExtendedMantissa emSourceMantissa(bdSource.biMantissa);
   emMantissa.setFalseBitArray(bitSizeMantissa());
   emMantissa.mult(emSourceMantissa, mrResult);
   int uLogResult = mprResult.log_base_2()-1; // <= 2*bitSizeMantissa()
   assert(mprResult.cbitArray(uLogResult));

   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   Exponent biSubExponent = TypeTraits::getZeroExponent(biExponent);
   int uAdd = 2*bitSizeMantissa()-uLogResult -1;
   if (uAdd > 0)
      biSubExponent.add(uAdd);
   else if (uAdd < 0)
      biSubExponent.sub(-uAdd);
   bool fResultPositiveExponent = false; 
   biExponent = bdSource.biExponent;
   bool fExponentHasCarry = biExponent.sub(biSubExponent).hasCarry();

   bool fAddExtension = false;
   if (mpFlags.hasAdd()) {
      bool fAddExponent = false;
      fAddExtension = mpFlags.hasSameSign(fNegative);
      addExtension(mpFlags.queryAddSource(), mprResult, scfFlags,
         mpFlags.isPositiveAdditive(), uLogResult, fExponentHasCarry, fResultPositiveExponent,
         fAddExponent);
   };
   
   assert(mprResult.cbitArray(uLogResult));
   int uShift = uLogResult-bitSizeMantissa();
   if (((fApproximate = !mprResult.hasZero(uShift)) != false) || scfFlags.isApproximate()) {
      if (scfFlags.isNearestRound()) {
         fAdd = mprResult.cbitArray(uShift-1);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = mprResult.hasZero(uShift-1) && !scfFlags.isApproximate();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? !fNegative : (!fNegative && fAddExtension);
      else if (scfFlags.isLowestRound())
         fAdd = (fApproximate || !mpFlags.hasAdd()) ? fNegative : (fNegative && fAddExtension);
   };
   mprResult >>= uShift;
   assert(mprResult.cbitArray(bitSizeMantissa()));
   bool fAddExponent = false;
   if (fAdd && ((fAdd = (!fRoundToEven || mprResult.cbitArray(0))) != false)) {
      mprResult.inc();
      if (!mprResult.cbitArray(bitSizeMantissa())) {
         mprResult >>= 1;
         fAddExponent = true;
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = mrResult[uIndex];
   biMantissa.normalizeLastCell();

   if (fAddExponent && biExponent.inc().hasCarry())
      fExponentHasCarry = false;
   if (fExponentHasCarry || biExponent.isZero()) {
      biExponent.neg().inc();
      if (biExponent < bitSizeMantissa()) { // denormalized
         if (trightShift(biMantissa, biExponent.queryValue()+1, 1, scfFlags, fNegative,
               bitSizeMantissa()).hasCarry())
            biExponent = 1U;
         else
            scfFlags.setUnderflow();
      }
      else {
         scfFlags.setUnderflow();
         bool fAdd = false;
         if (scfFlags.isNearestRound()) {
            fAdd = biExponent == bitSizeMantissa();
            if (fAdd && biMantissa.isZero()) {
               if (!fNegative) {
                  if (scfFlags.isUpApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               }
               else {
                  if (scfFlags.isDownApproximate()
                        || (!scfFlags.isApproximate() && scfFlags.isRoundToEven()))
                     fAdd = false;
               };
            };
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         biMantissa = fAdd ? 1U : 0U;
         if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
            fNegative = false;
      };
      biExponent = 0U;
      if (scfFlags.isDenormalizedAvoided() && !biMantissa.isZero()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   else if ((biExponent == 1U) && biMantissa.isZero()
         && scfFlags.isApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up))
      scfFlags.setUnderflow();
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssignDD(const thisType& bdSource, const MultParameters& mpFlags) {
   assert(isDenormalized() && bdSource.isDenormalized());
   StatusAndControlFlags& scfFlags = mpFlags.readParams();
   scfFlags.setUnderflow();
   bool fAdd = false;
   if (scfFlags.isHighestRound())
      fAdd = !fNegative;
   else if (scfFlags.isLowestRound())
      fAdd = fNegative;
   if (fNegative)
      scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
   else
      scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   if (mpFlags.hasAdd() && !mpFlags.queryAddSource().isZero()) {
      scfFlags.clearFlowException();
      const thisType& bdAddSource = mpFlags.queryAddSource();
      if (bdAddSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.clearApproximate();
         fNegative = mpFlags.isPositiveAdditive() ? bdAddSource.fNegative
            : !bdAddSource.fNegative;
         biMantissa = bdAddSource.biMantissa;
         if (!biMantissa.isZero()) {
            fNegative = (scfFlags.keepNaNSign() || mpFlags.isPositiveAdditive())
               ? bdAddSource.fNegative : !bdAddSource.fNegative;
            if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
               scfFlags.setSNaNOperand();
               biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            };
         };
         biExponent = TypeTraits::getInftyExponent(biExponent);
         if (scfFlags.isAllInftyAvoided()) {
            biMantissa = 0U;
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         }
         return *this;
      };
      biMantissa = bdAddSource.queryMantissa();
      biExponent = bdAddSource.queryBasicExponent();
      bool fSub =  mpFlags.isPositiveAdditive()
         ? (fNegative != bdAddSource.fNegative) : (fNegative == bdAddSource.fNegative);
      if (fSub) {
         fNegative = mpFlags.isPositiveAdditive() ? bdAddSource.fNegative : !bdAddSource.fNegative;
         if (scfFlags.isHighestRound() || scfFlags.isLowestRound())
            fSub = fAdd;
         else if (scfFlags.isNearestRound())
            fSub = false;
         fAdd = false;
      };
      if (fAdd && biMantissa.inc().hasCarry()) {
         biExponent.inc();
         if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            }
            else if (scfFlags.upApproximateInfty())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         };
      }
      else if (fSub) {
         if (biMantissa.dec().hasCarry())
            biExponent.dec();
         scfFlags.clearApproximate();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
      if (isDenormalized()) {
         scfFlags.setUnderflow();
         if (scfFlags.isDenormalizedAvoided()) {
            biMantissa = 0U;
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      }
      else if (isInfty()) {
         scfFlags.setOverflow();
         if (scfFlags.isAllInftyAvoided()) {
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         }
      }
   }
   else {
      if (scfFlags.isDenormalizedAvoided()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         return *this;
      };
      biMantissa = fAdd ? 1U : 0U;
      if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
         fNegative = false;
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::multAssign(const thisType& bdSource, const MultParameters& mpFlags) {
   StatusAndControlFlags& scfFlags = mpFlags.readParams();
   bool fOldNegative = fNegative;
   fNegative = fNegative ? !bdSource.fNegative : bdSource.fNegative;
   if (mpFlags.hasAdd() && mpFlags.isNegativeMult())
      fNegative = !fNegative;
   if (!biExponent.isZero()) {
      if (biExponent != TypeTraits::getInftyExponent(biExponent)) {
         if (!bdSource.biExponent.isZero()) {
            if (bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)) {
               if (mpFlags.hasAdd() && (mpFlags.queryAddSource().biExponent == TypeTraits::getInftyExponent(biExponent))) {
                  biExponent = mpFlags.queryAddSource().biExponent;
                  fNegative = mpFlags.queryAddSource().fNegative;
                  if (mpFlags.isNegativeAdditive())
                     fNegative = !fNegative;
                  biMantissa = mpFlags.queryAddSource().biMantissa;
                  if (!biMantissa.isZero()) {
                     if (scfFlags.keepNaNSign())
                        fNegative = mpFlags.queryAddSource().fNegative;
                     if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                        scfFlags.setSNaNOperand();
                        biMantissa.setTrueBitArray(bitSizeMantissa()-1);
                     };
                  };
                  if (scfFlags.isAllInftyAvoided()) {
                     biMantissa = 0U;
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  return *this;
               };
               return multAssignNN(bdSource, mpFlags);
            };
            // bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)
            biMantissa = bdSource.biMantissa;
            biExponent = TypeTraits::getInftyExponent(biExponent);
            if (!biMantissa.isZero()) {
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               if (scfFlags.keepNaNSign())
                  fNegative = bdSource.fNegative;
            };
            if (!bdSource.biMantissa.isZero() && scfFlags.keepNaNSign())
               fNegative = bdSource.fNegative;
            if (mpFlags.hasAdd()) {
               if (scfFlags.chooseNaNAddBeforeMult() && mpFlags.queryAddSource().isNaN()) {
                  biExponent = mpFlags.queryAddSource().biExponent;
                  fNegative = mpFlags.isPositiveAdditive()
                     ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
                  biMantissa = mpFlags.queryAddSource().biMantissa;
                  if (!biMantissa.isZero()) {
                     if (scfFlags.keepNaNSign())
                        fNegative = mpFlags.queryAddSource().fNegative;
                     if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                        scfFlags.setSNaNOperand();
                        biMantissa.setTrueBitArray(bitSizeMantissa()-1);
                     };
                  };
                  if (scfFlags.isAllInftyAvoided()) {
                     biMantissa = 0U;
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
                  return *this;
               };
               if (mpFlags.isPositiveAdditive())
                  plusAssign(mpFlags.queryAddSource(), scfFlags);
               else
                  minusAssign(mpFlags.queryAddSource(), scfFlags);
            };
            return *this;
         };
         
         // bdSource.biExponent == 0
         if (mpFlags.hasAdd() && (mpFlags.queryAddSource().biExponent == TypeTraits::getInftyExponent(biExponent))) {
            biExponent = mpFlags.queryAddSource().biExponent;
            fNegative = mpFlags.isPositiveAdditive()
               ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
            biMantissa = mpFlags.queryAddSource().biMantissa;
            if (!biMantissa.isZero()) {
               if (scfFlags.keepNaNSign())
                  fNegative = mpFlags.queryAddSource().fNegative;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
            };
            if (scfFlags.isDenormalizedAvoided()) {
               biMantissa = 0U;
               scfFlags.setUnderflow();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
            return *this;
         };
         if (bdSource.biMantissa.isZero()) {
            biMantissa = 0U;
            biExponent = 0U;
            if (!scfFlags.acceptMinusZero())
               fNegative = false;
            if (mpFlags.hasAdd()) {
               if (!mpFlags.queryAddSource().isZero()) {
                  biExponent = mpFlags.queryAddSource().biExponent;
                  fNegative = mpFlags.isPositiveAdditive()
                     ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
                  biMantissa = mpFlags.queryAddSource().biMantissa;
                  if (mpFlags.queryAddSource().isNaN()) {
                     if (scfFlags.keepNaNSign())
                        fNegative = mpFlags.queryAddSource().fNegative;
                     if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                        scfFlags.setSNaNOperand();
                        biMantissa.setTrueBitArray(bitSizeMantissa()-1);
                     };
                  };
                  if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
                     biMantissa = 0U;
                     biMantissa.neg();
                     biExponent.dec();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  }
                  if (scfFlags.isDenormalizedAvoided() && biExponent.isZero() && !biMantissa.isZero()) {
                     biMantissa = 0U;
                     scfFlags.setUnderflow();
                     scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
                  };
               }
               else if ((mpFlags.isPositiveAdditive()
                        ? (fNegative != mpFlags.queryAddSource().fNegative)
                        : (fNegative == mpFlags.queryAddSource().fNegative))
                     && scfFlags.isPositiveZeroMAdd())
                  fNegative = !scfFlags.isLowestRound() ? mpFlags.isNegativeMult() : !mpFlags.isNegativeMult();
            };
            return *this;
         };
         return multAssignND(bdSource, mpFlags);
      };

      // biExponent == TypeTraits::getInftyExponent(biExponent)
      bool fThisNaN = false;
      if (!biMantissa.isZero()) {
         fThisNaN = true;
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         }
         else if (bdSource.isSNaN())
            scfFlags.setSNaNOperand();
         if (scfFlags.keepNaNSign())
            fNegative = fOldNegative;
      }
      else if (bdSource.isNaN()) {
         biMantissa = bdSource.biMantissa;
         if (scfFlags.keepNaNSign())
            fNegative = bdSource.fNegative;
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         };
      }
      else if (bdSource.biMantissa.isZero() && bdSource.biExponent.isZero()) {
         scfFlags.setInftyMultZero();
         biMantissa = 0;
         biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         if (scfFlags.keepNaNSign())
            fNegative = fOldNegative;
         if (scfFlags.produceMultNaNPositive())
            fNegative = false;
      };
      if (mpFlags.hasAdd()) {
         if (!fThisNaN && scfFlags.chooseNaNAddBeforeMult() && mpFlags.queryAddSource().isNaN()) {
            biExponent = mpFlags.queryAddSource().biExponent;
            fNegative = mpFlags.isPositiveAdditive()
               ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
            biMantissa = mpFlags.queryAddSource().biMantissa;
            if (!biMantissa.isZero()) {
               if (scfFlags.keepNaNSign())
                  fNegative = mpFlags.queryAddSource().fNegative;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
            };
            if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
               biMantissa = 0U;
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            }
            return *this;
         };
         if (mpFlags.isPositiveAdditive())
            plusAssign(mpFlags.queryAddSource(), scfFlags);
         else
            minusAssign(mpFlags.queryAddSource(), scfFlags);
      }
      else {
         if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
            biMantissa = 0U;
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         }
      };
      return *this;
   };
   
   // biExponent == 0
   if (bdSource.biExponent.isZero()) {
      if (!biMantissa.isZero() && !bdSource.biMantissa.isZero())
         return multAssignDD(bdSource, mpFlags);
      biMantissa = 0U;
      if (!scfFlags.acceptMinusZero())
         fNegative = false;
      if (mpFlags.hasAdd()) {
         if (!mpFlags.queryAddSource().isZero()) {
            biExponent = mpFlags.queryAddSource().biExponent;
            fNegative = mpFlags.isPositiveAdditive()
               ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
            biMantissa = mpFlags.queryAddSource().biMantissa;
            if (mpFlags.queryAddSource().isNaN()) {
               if (scfFlags.keepNaNSign())
                  fNegative = mpFlags.queryAddSource().fNegative;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
            };
            if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
               biMantissa = 0U;
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            }
            if (scfFlags.isDenormalizedAvoided() && biExponent.isZero() && !biMantissa.isZero()) {
               biMantissa = 0U;
               scfFlags.setUnderflow();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         }
         else if ((mpFlags.isPositiveAdditive()
                  ? (fNegative != mpFlags.queryAddSource().fNegative) 
                  : (fNegative == mpFlags.queryAddSource().fNegative))
               && scfFlags.isPositiveZeroMAdd())
            fNegative = !scfFlags.isLowestRound() ? mpFlags.isNegativeMult() : !mpFlags.isNegativeMult();
      };
      return *this;
   };

   // biExponent == 0 && bdSource.biExponent != 0
   if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
      biExponent = TypeTraits::getInftyExponent(biExponent);
      if (!bdSource.biMantissa.isZero() || biMantissa.isZero()) {
         if (bdSource.biMantissa.isZero()) {
            scfFlags.setInftyMultZero();
            biMantissa = 0U;
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            if (scfFlags.produceMultNaNPositive())
               fNegative = false;
         }
         else {
            biMantissa = bdSource.biMantissa;
            if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
               scfFlags.setSNaNOperand();
               biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            };
            if (scfFlags.keepNaNSign())
               fNegative = bdSource.fNegative;
         };
         if (mpFlags.hasAdd()) {
            if (scfFlags.chooseNaNAddBeforeMult() && mpFlags.queryAddSource().isNaN()) {
               biExponent = mpFlags.queryAddSource().biExponent;
               fNegative = (scfFlags.keepNaNSign() || mpFlags.isPositiveAdditive())
                  ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
               biMantissa = mpFlags.queryAddSource().biMantissa;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
                  biMantissa = 0U;
                  biMantissa.neg();
                  biExponent.dec();
                  scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
               }
               return *this;
            };
            if (mpFlags.isPositiveAdditive())
               plusAssign(mpFlags.queryAddSource(), scfFlags);
            else
               minusAssign(mpFlags.queryAddSource(), scfFlags);
         };
         return *this;
      };
      
      // bdSource.biMantissa == 0 && bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)
      // && biExponent == 0 && biMantissa != 0
      biMantissa = 0U;
      if (mpFlags.hasAdd()) {
         if (mpFlags.isPositiveAdditive())
            plusAssign(mpFlags.queryAddSource(), scfFlags);
         else
            minusAssign(mpFlags.queryAddSource(), scfFlags);
      }
      else if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
      return *this;
   };
   
   // biExponent == 0 && bdSource.biExponent != 0 && bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)
   if (biMantissa.isZero()) {
      if (!scfFlags.acceptMinusZero())
         fNegative = false;
      if (mpFlags.hasAdd()) {
         if (!mpFlags.queryAddSource().isZero()) {
            biExponent = mpFlags.queryAddSource().biExponent;
            fNegative = mpFlags.isPositiveAdditive()
               ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
            biMantissa = mpFlags.queryAddSource().biMantissa;
            if (mpFlags.queryAddSource().isNaN()) {
               if (scfFlags.keepNaNSign())
                  fNegative = mpFlags.queryAddSource().fNegative;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
            };
            if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
               biMantissa = 0U;
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            }
            if (scfFlags.isDenormalizedAvoided() && biExponent.isZero() && !biMantissa.isZero()) {
               biMantissa = 0U;
               scfFlags.setUnderflow();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
         }
         else if ((mpFlags.isPositiveAdditive()
                  ? (fNegative != mpFlags.queryAddSource().fNegative)
                  : (fNegative == mpFlags.queryAddSource().fNegative))
               && scfFlags.isPositiveZeroMAdd())
            fNegative = !scfFlags.isLowestRound() ? mpFlags.isNegativeMult() : !mpFlags.isNegativeMult();
      };
      return *this;
   };
   if (mpFlags.hasAdd() && (mpFlags.queryAddSource().biExponent == TypeTraits::getInftyExponent(biExponent))) {
      biExponent = mpFlags.queryAddSource().biExponent;
      fNegative = mpFlags.isPositiveAdditive()
         ? mpFlags.queryAddSource().fNegative : !mpFlags.queryAddSource().fNegative;
      biMantissa = mpFlags.queryAddSource().biMantissa;
      if (!biMantissa.isZero()) {
         if (scfFlags.keepNaNSign())
            fNegative = mpFlags.queryAddSource().fNegative;
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         };
      };
      if (scfFlags.isAllInftyAvoided() && hasInftyExponent()) {
         biMantissa = 0U;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      }
      if (scfFlags.isDenormalizedAvoided() && biExponent.isZero() && !biMantissa.isZero()) {
         biMantissa = 0U;
         scfFlags.setUnderflow();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
      return *this;
   };
   return multAssignDN(bdSource, mpFlags);
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssign(unsigned int uValue, StatusAndControlFlags& scfFlags) {
   assert((uValue > 0) && (uValue < (1U << (sizeof(unsigned int)*4))));
   if (isNormalized()) {
      typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
      typename TypeTraits::ExtendedMantissa::AtomicDivisionResult adrResult = emMantissa.divAssign(uValue);
      unsigned int uShift = (bitSizeMantissa()+1 - emMantissa.log_base_2());
      assert((log_base_2(uValue) == (int) uShift) || (log_base_2(uValue) == (int) (uShift+1)));
      unsigned int uLeftQuotient = 0U;
      if ((uShift == (4*sizeof(unsigned int)+1))
            && ((adrResult.remainder() & (1U << 4*sizeof(unsigned int))) != 0U)) {
         adrResult.remainder() <<= 4*sizeof(unsigned int);
         uLeftQuotient = adrResult.remainder() / uValue;
         adrResult.remainder() %= uValue;
         adrResult.remainder() <<= 1;
         uLeftQuotient <<= 1;
         if (adrResult.remainder() >= uValue) {
            ++uLeftQuotient;
            adrResult.remainder() -= uValue;
         };
         assert(uLeftQuotient < (1U << 4*sizeof(unsigned int)));
      }
      else {
         adrResult.remainder() <<= uShift;
         uLeftQuotient = adrResult.remainder() / uValue;
         adrResult.remainder() %= uValue;
      };
      emMantissa <<= uShift;
      emMantissa[0] |= uLeftQuotient;
      if (biExponent.isAtomic() && (biExponent.queryValue() <= uShift)) {
         int uLeftshift = uShift-biExponent.queryValue() + 1;
         bool fAdd = false;
         bool fRoundToEven = false;
         bool fApproximate = false;
         if (!emMantissa.hasZero(uLeftshift) || (adrResult.remainder() != 0)) {
            if (scfFlags.isNearestRound()) {
               fAdd = emMantissa.cbitArray(uLeftshift-1);
               if (fAdd && scfFlags.isRoundToEven()) {
                  fRoundToEven = (adrResult.remainder() == 0U) && emMantissa.hasZero(uLeftshift-1);
                  if (fRoundToEven)
                     scfFlags.setEffectiveRoundToEven();
               };
            }
            else if (scfFlags.isHighestRound())
               fAdd = !fNegative;
            else if (scfFlags.isLowestRound())
               fAdd = fNegative;
            fApproximate = true;
         };
         emMantissa >>= uLeftshift;
         biMantissa = emMantissa;
         biExponent = 0;
         if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
               && biMantissa.inc().hasCarry())
            biExponent = 1U;
         else if (scfFlags.isDenormalizedAvoided()) {
            biMantissa = 0U;
            scfFlags.setUnderflow();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            return *this;
         };
         if (fApproximate) {
            if (fNegative)
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            else
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      }
      else {
         bool fAdd = false;
         biExponent.minusAssign(uShift);
         if (adrResult.remainder() != 0) {
            if (scfFlags.isNearestRound()) {
               fAdd = (2*adrResult.remainder() >= uValue);
               if (fAdd && scfFlags.isRoundToEven())
                  fAdd = (2*adrResult.remainder() != uValue) || biMantissa.cbitArray(0);
            }
            else if (scfFlags.isHighestRound())
               fAdd = !fNegative;
            else if (scfFlags.isLowestRound())
               fAdd = fNegative;
            if (fNegative)
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            else
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
         biMantissa = emMantissa;
         if (fAdd && biMantissa.inc().hasCarry()) {
            biMantissa >>= 1;
            biExponent.inc();
         };
      };
   }
   else if (biExponent.isZero()) {
      if (scfFlags.isDenormalizedAvoided()) {
         biMantissa = 0U;
         scfFlags.setUnderflow();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         return *this;
      };
      typename TypeTraits::ExtendedMantissa::AtomicDivisionResult adrResult = biMantissa.divAssign(uValue);
      if (adrResult.remainder() != 0) {
         bool fAdd = false;
         if (scfFlags.isNearestRound()) {
            fAdd = (2*adrResult.remainder() >= uValue);
            if (fAdd && scfFlags.isRoundToEven())
               fAdd = (2*adrResult.remainder() != uValue) || biMantissa.cbitArray(0);
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         if (fAdd)
            biMantissa.inc();
         if (fNegative)
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         else
            scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   else { // biExponent == TypeTraits::getInftyExponent(biExponent);
      if (scfFlags.isAllInftyAvoided()) {
         biMantissa = 0U;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      }
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssignNN(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && bdSource.isNormalized());
   typename Mantissa::NormalizedDivisionResult drResult;
   biMantissa.divNormalized(bdSource.biMantissa, drResult);
   assert((drResult.comma() == 0) || (drResult.comma() == -1));
   biMantissa = (const Mantissa&) drResult.quotient();
   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   if (!((const typename TypeTraits::ExtendedMantissa::EnhancedRemainderResult&) drResult.remainder()).isZero()) {
      if (scfFlags.isNearestRound()) {
         fAdd = ((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).cbitArray(bitSizeMantissa());
         if (!fAdd && ((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).cbitArray(bitSizeMantissa()-1)) {
            Mantissa biRemainder;
            biRemainder.assertSize(bdSource.biMantissa.querySize());
            for (int uIndex = 0; uIndex <= bdSource.biMantissa.lastCellIndex(); ++uIndex)
               biRemainder[uIndex] = drResult.remainder()[uIndex];
            fAdd = (biRemainder <<= 1) >= bdSource.biMantissa;
            if (fAdd && scfFlags.isNearestRound()) {
               fRoundToEven = (biRemainder == bdSource.biMantissa);
               if (fRoundToEven)
                  scfFlags.setEffectiveRoundToEven();
            };
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      fApproximate = true;
   };
   if (bdSource.biExponent >= TypeTraits::getZeroExponent(biExponent)) {
      Exponent biSubExponent = bdSource.biExponent;
      biSubExponent -= TypeTraits::getZeroExponent(biExponent);
      biSubExponent.add(-drResult.comma()); // 0 or -1
      bool hasUnderflow = false;
      bool doesReturn = false;
      if (biExponent <= biSubExponent) {
         biSubExponent -= biExponent;
         biExponent = 0U;
         hasUnderflow = true;
         if (biSubExponent < bitSizeMantissa()) {
            int uShift = biSubExponent.queryValue()+1;
            StatusAndControlFlags scfNewFlags(scfFlags);
            if (fApproximate)
               scfNewFlags.clearRoundToEven();
            if (trightShift(biMantissa, uShift, 1, scfNewFlags, fNegative, bitSizeMantissa()).hasCarry()) {
               biExponent.inc();
               hasUnderflow = false;
            };
            if (!scfNewFlags.isApproximate() && fAdd
                  && ((fAdd = !scfFlags.isNearestRound()) != false)) {
               if (biMantissa.inc().hasCarry()) {
                  biExponent.inc();
                  hasUnderflow = false;
               };
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
               doesReturn = true;
            }
            else if (scfNewFlags.isApproximate()) {
               scfFlags = scfNewFlags;
               doesReturn = true;
            };
         }
         else {
            fAdd = false;
            if (scfFlags.isNearestRound()) {
               fAdd = (biSubExponent == bitSizeMantissa());
               if (fAdd && scfFlags.isRoundToEven())
                  fAdd = !biMantissa.isZero() || !((const typename TypeTraits::ExtendedMantissa::EnhancedRemainderResult&)
                     drResult.remainder()).isZero();
            }
            else if (scfFlags.isHighestRound())
               fAdd = !fNegative;
            else if (scfFlags.isLowestRound())
               fAdd = fNegative;
            if (fNegative)
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            else
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            biMantissa = fAdd ? 1U : 0U;
            if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
               fNegative = false;
            doesReturn = true;
         };
      }
      else
         biExponent -= biSubExponent;
      if (!doesReturn && fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry()) {
         biExponent.inc();
         hasUnderflow = false;
      };
      if (hasUnderflow) {
         scfFlags.setUnderflow();
         if (scfFlags.isDenormalizedAvoided()) {
            biMantissa = 0U;
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            doesReturn = true;
         };
      };
      if (doesReturn)
         return *this;
   }
   else { // bdSource.biExponent < TypeTraits::getZeroExponent(biExponent)
      Exponent biSubExponent = TypeTraits::getZeroExponent(biExponent);
      biSubExponent -= bdSource.biExponent;
      biSubExponent.sub(-drResult.comma()); // 0 or -1
      if (biExponent.add(biSubExponent).hasCarry()
            || (biExponent == TypeTraits::getInftyExponent(biExponent))) {
         biExponent = TypeTraits::getInftyExponent(biExponent);
         biMantissa = 0U;
         scfFlags.setOverflow();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            fApproximate = false;
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         };
      }
      else if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry()) {
         biExponent.inc();
         if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
            scfFlags.setOverflow();
            if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
               fApproximate = false;
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            }
            else if (scfFlags.upApproximateInfty())
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         };
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssignND(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isNormalized() && bdSource.isDenormalized());
   typename TypeTraits::ExtendedMantissa::DivisionResult drResult;
   typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
   typename TypeTraits::ExtendedMantissa emSourceMantissa(bdSource.biMantissa);
   emSourceMantissa.setFalseBitArray(bitSizeMantissa());

   emMantissa.div(emSourceMantissa, drResult);
   assert(drResult.comma() >= 0);
   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   if (((const typename TypeTraits::ExtendedMantissa&) drResult.quotient()).cbitArray(0)
          || !((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).isZero()) {
      if (scfFlags.isNearestRound()) {
         fAdd = ((const typename TypeTraits::ExtendedMantissa&) drResult.quotient()).cbitArray(0);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = ((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).isZero();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      fApproximate = true;
   };
   ((typename TypeTraits::ExtendedMantissa&) drResult.quotient()) >>= 1;
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = drResult.quotient()[uIndex];
   biMantissa.normalizeLastCell();

   if (biExponent.add(TypeTraits::getZeroExponent(biExponent)).hasCarry()
         || biExponent.add(drResult.comma()-1).hasCarry()
         || (biExponent == TypeTraits::getInftyExponent(biExponent))) {
      biExponent = TypeTraits::getInftyExponent(biExponent);
      biMantissa = 0;
      scfFlags.setOverflow();
      if (scfFlags.upApproximateInfty())
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(StatusAndControlFlags::Up);
      if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
         fApproximate = false;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      };
   }
   else if (fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
         && biMantissa.inc().hasCarry()) {
      biExponent.inc();
      if (biExponent == TypeTraits::getInftyExponent(biExponent)) {
         scfFlags.setOverflow();
         if (scfFlags.isInftyAvoided() && scfFlags.doesAvoidInfty(fNegative)) {
            fApproximate = false;
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         }
         else if (scfFlags.upApproximateInfty())
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      };
   };
   if (fApproximate) {
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssignDN(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isDenormalized() && bdSource.isNormalized());
   typename TypeTraits::ExtendedMantissa::DivisionResult drResult;
   typename TypeTraits::ExtendedMantissa emMantissa(biMantissa);
   emMantissa.setFalseBitArray(bitSizeMantissa());
   typename TypeTraits::ExtendedMantissa emSourceMantissa(bdSource.biMantissa);
   emMantissa.div(emSourceMantissa, drResult);
   assert(drResult.comma() < 0);

   bool fAdd = false;
   bool fRoundToEven = false;
   bool fApproximate = false;
   if (((const typename TypeTraits::ExtendedMantissa&) drResult.quotient()).cbitArray(0)
          || !((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).isZero()) {
      if (scfFlags.isNearestRound()) {
         fAdd = ((const typename TypeTraits::ExtendedMantissa&) drResult.quotient()).cbitArray(0);
         if (fAdd && scfFlags.isRoundToEven()) {
            fRoundToEven = ((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).isZero();
            if (fRoundToEven)
               scfFlags.setEffectiveRoundToEven();
         };
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      fApproximate = true;
   };
   ((typename TypeTraits::ExtendedMantissa&) drResult.quotient()) >>= 1;
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = drResult.quotient()[uIndex];
   biMantissa.normalizeLastCell();

   bool fNeg = fNegative;
   bool hasUnderflow = false;
   bool doesReturn = false;
   if (bdSource.biExponent >= TypeTraits::getZeroExponent(biExponent)) {
      hasUnderflow = true;
      Exponent biSubExponent = bdSource.biExponent;
      biSubExponent -= TypeTraits::getZeroExponent(biExponent);
      biSubExponent.add(-drResult.comma());
      if (biSubExponent <= bitSizeMantissa()) {
         StatusAndControlFlags scfNewFlags(scfFlags);
         if (fApproximate)
            scfNewFlags.clearRoundToEven();
         if (trightShift(biMantissa, biSubExponent.queryValue(), 1, scfNewFlags,
               fNegative, bitSizeMantissa()).hasCarry()) {
            biExponent.inc();
            hasUnderflow = false;
         };
         if (!scfNewFlags.isApproximate() && fAdd
               && ((fAdd = !scfFlags.isNearestRound()) != false)) {
            if (biMantissa.inc().hasCarry()) {
               biExponent.inc();
               hasUnderflow = false;
            };
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            doesReturn = true;
         }
         else if (scfNewFlags.isApproximate()) {
            scfFlags = scfNewFlags;
            doesReturn = true;
         };
      }
      else {
         fAdd = false;
         if (scfFlags.isNearestRound()) {
            fAdd = (biSubExponent == bitSizeMantissa()+1);
            if (fAdd && scfFlags.isRoundToEven())
               fAdd = !biMantissa.isZero() || !((const typename TypeTraits::ExtendedMantissa&) drResult.remainder()).isZero();
         }
         else if (scfFlags.isHighestRound())
            fAdd = !fNegative;
         else if (scfFlags.isLowestRound())
            fAdd = fNegative;
         fApproximate = true;
         biMantissa = fAdd ? 1U : 0U;
         if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
            fNegative = false;
      };
   }
   else { // bdSource.biExponent < TypeTraits::getZeroExponent(biExponent)
      Exponent biSubExponent = TypeTraits::getZeroExponent(biExponent);
      biSubExponent -= bdSource.biExponent;
      if (biSubExponent >= -drResult.comma()) {
         biSubExponent.sub(-drResult.comma()-1);
         biExponent = biSubExponent;
      }
      else {
         StatusAndControlFlags scfNewFlags(scfFlags);
         if (fApproximate)
            scfNewFlags.clearRoundToEven();
         if (trightShift(biMantissa, -drResult.comma() - biSubExponent.queryValue(), 1, scfNewFlags,
               fNegative, bitSizeMantissa()).hasCarry())
            biExponent.inc();
         if (!scfNewFlags.isApproximate() && fAdd
               && ((fAdd = !scfFlags.isNearestRound()) != false)) {
            if (biMantissa.inc().hasCarry())
               biExponent.inc();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
         }
         else if (scfNewFlags.isApproximate())
            scfFlags = scfNewFlags;
         else if (fApproximate)
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         if (biExponent.isZero())
            hasUnderflow = true;
         doesReturn = true;
      };
         
      if (!doesReturn && fAdd && ((fAdd = (!fRoundToEven || biMantissa.cbitArray(0))) != false)
            && biMantissa.inc().hasCarry()) {
         hasUnderflow = false;
         biExponent.inc();
      };
   };
   if (hasUnderflow) {
      scfFlags.setUnderflow();
      if (scfFlags.isDenormalizedAvoided()) {
         biMantissa = 0U;
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         doesReturn = true;
      };
   };
   if (doesReturn)
      return *this;
   if (fApproximate) {
      if (fNeg)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssignDD(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   assert(isDenormalized() && bdSource.isDenormalized());
   typename Mantissa::DivisionResult drResult;
   biMantissa.div(bdSource.biMantissa, drResult);

   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      biMantissa[uIndex] = drResult.quotient()[uIndex];
   biExponent = TypeTraits::getZeroExponent(biExponent);
   if (drResult.comma() > 0)
      biExponent.add(drResult.comma());
   else if (drResult.comma() < 0)
      biExponent.sub(-drResult.comma());
   
   bool fAdd = false;
   if (!((const Mantissa&) drResult.remainder()).isZero()) {
      if (scfFlags.isNearestRound()) {
         fAdd = ((const Mantissa&) drResult.remainder()).cbitArray(bitSizeMantissa()-1);
         ((Mantissa&) drResult.remainder()) <<= 1;
         if (!fAdd)
            fAdd = (((const Mantissa&) drResult.remainder()) > bdSource.biMantissa);
         if (!fAdd && (!scfFlags.isRoundToEven() || biMantissa.cbitArray(0)))
            fAdd = (((const Mantissa&) drResult.remainder()) == bdSource.biMantissa);
      }
      else if (scfFlags.isHighestRound())
         fAdd = !fNegative;
      else if (scfFlags.isLowestRound())
         fAdd = fNegative;
      if (fNegative)
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
      else
         scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
   };

   if (fAdd && biMantissa.inc().hasCarry())
      ++biExponent;
   return *this;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::divAssign(const thisType& bdSource, StatusAndControlFlags& scfFlags) {
   bool fOldNegative = fNegative;
   fNegative = fNegative ? !bdSource.fNegative : bdSource.fNegative;
   if (!biExponent.isZero()) {
      if (biExponent != TypeTraits::getInftyExponent(biExponent)) {
         if (!bdSource.biExponent.isZero()) {
            if (bdSource.biExponent != TypeTraits::getInftyExponent(biExponent))
               return divAssignNN(bdSource, scfFlags);
            // bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)
            if (!bdSource.biMantissa.isZero()) {
               biMantissa = bdSource.biMantissa;
               if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
                  scfFlags.setSNaNOperand();
                  biMantissa.setTrueBitArray(bitSizeMantissa()-1);
               };
               biExponent = TypeTraits::getInftyExponent(biExponent);
               if (scfFlags.keepNaNSign())
                  fNegative = bdSource.fNegative;
            }
            else {
               biMantissa = 0U;
               biExponent = 0U;
               if (!scfFlags.acceptMinusZero())
                  fNegative = false;
            };
            return *this;
         };
         
         // bdSource.biExponent == 0
         if (bdSource.biMantissa.isZero()) {
            scfFlags.setDivisionByZero();
            biMantissa = 0U;
            biExponent = TypeTraits::getInftyExponent(biExponent);
            if (scfFlags.isAllInftyAvoided()) {
               biMantissa.neg();
               biExponent.dec();
               scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            };
            return *this;
         };
         return divAssignND(bdSource, scfFlags);
      };

      // biExponent == TypeTraits::getInftyExponent(biExponent)
      if (!biMantissa.isZero()) {
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         }
         else if (bdSource.isSNaN())
            scfFlags.setSNaNOperand();
         if (scfFlags.keepNaNSign())
            fNegative = fOldNegative;
      }
      else if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
         if (bdSource.biMantissa.isZero()) { // produces a qNaN
            scfFlags.setInftyOnInfty();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            if (scfFlags.produceDivNaNPositive())
               fNegative = false;
         }
         else {
            biMantissa = bdSource.biMantissa;
            if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
               scfFlags.setSNaNOperand();
               biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            }
            else if (bdSource.isSNaN())
               scfFlags.setSNaNOperand();
            if (scfFlags.keepNaNSign())
               fNegative = bdSource.fNegative;
         };
      };
      if (scfFlags.isAllInftyAvoided()) {
         biMantissa = 0U;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      }
      return *this;
   };
   
   // biExponent == 0
   if (bdSource.biExponent.isZero()) {
      if (!biMantissa.isZero() && !bdSource.biMantissa.isZero())
         return divAssignDD(bdSource, scfFlags);
      if (bdSource.biMantissa.isZero()) {
         biExponent = TypeTraits::getInftyExponent(biExponent);
         if (biMantissa.isZero()) { // produces a qNaN
            scfFlags.setZeroOnZero();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
            if (scfFlags.produceDivNaNPositive())
               fNegative = false;
         }
         else {
            biMantissa = 0U;
            scfFlags.setDivisionByZero();
         };
         if (scfFlags.isAllInftyAvoided()) {
            biMantissa = 0U;
            biMantissa.neg();
            biExponent.dec();
            scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
         }
      }
      else if (!scfFlags.acceptMinusZero())
         fNegative = false;

      return *this;
   };

   // biExponent == 0 && bdSource.biExponent != 0
   if (bdSource.biExponent == TypeTraits::getInftyExponent(biExponent)) {
      if (!bdSource.biMantissa.isZero()) {
         biExponent = TypeTraits::getInftyExponent(biExponent);
         biMantissa = bdSource.biMantissa;
         if (!biMantissa.cbitArray(bitSizeMantissa()-1)) {
            scfFlags.setSNaNOperand();
            biMantissa.setTrueBitArray(bitSizeMantissa()-1);
         };
         if (scfFlags.keepNaNSign())
            fNegative = bdSource.fNegative;
      }
      else
         // bdSource.biMantissa == 0 && bdSource.biExponent == TypeTraits::getInftyExponent(biExponent) && biExponent == 0
         biMantissa = 0U;
      if (scfFlags.isAllInftyAvoided()) {
         biMantissa = 0U;
         biMantissa.neg();
         biExponent.dec();
         scfFlags.setApproximate(fNegative ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
      }
      return *this;
   };
   
   // biExponent == 0 && bdSource.biExponent != 0 && bdSource.biExponent != TypeTraits::getInftyExponent(biExponent)
   if (biMantissa.isZero()) {
      if (!scfFlags.acceptMinusZero())
         fNegative = false;
      return *this;
   };
   return divAssignDN(bdSource, scfFlags);
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::read(std::istream& isIn, StatusAndControlFlags& scfFlags) {
   int uReadZero = 0;
   int uRead = isIn.get();
   int uDecimalShiftExponent = 0;
   operator=(thisType());
   bool fReadNegative = false;
   for (; isspace(uRead); uRead = isIn.get());
   if ((uRead == '-') || (uRead == '+')) {
      fReadNegative = (uRead == '-');
      uRead = isIn.get();
      for (; isspace(uRead); uRead = isIn.get());
   };
   for (; uRead == '0'; uRead = isIn.get());
   for (; (uRead >= '0') && (uRead <= '9'); uRead = isIn.get()) {
      if (uRead == '0')
         ++uReadZero;
      else {
         while (uReadZero > 0) {
            --uReadZero;
            multAssign(10U, scfFlags);
         };
         multAssign(10U, scfFlags);
         if (hasNegativeExponent()
               || (queryExponent().queryValue() < (unsigned int) bitSizeMantissa()+4)) // 2^4 > 10
            plusAssign(thisType((unsigned int) (uRead - '0')), scfFlags);
      };
   };

   if (uRead == '.') {
      uRead = isIn.get();
      for (; (uRead >= '0') && (uRead <= '9'); uRead = isIn.get()) {
         if (uRead == '0')
            ++uReadZero;
         else {
            while (uReadZero > 0) {
               --uReadZero;
               multAssign(10U, scfFlags);
            };
            multAssign(10U, scfFlags);
            if (hasNegativeExponent()
               || (queryExponent().queryValue() < (unsigned int) bitSizeMantissa()+4)) // 2^4 > 10
               plusAssign(thisType((unsigned int) (uRead - '0')), scfFlags);
         };
         --uDecimalShiftExponent;
      };
   };

   uDecimalShiftExponent += uReadZero;
   fNegative = fReadNegative;

   if (uRead == 'e') {
      if (isZero()) {
         uRead = isIn.get();
         if ((uRead == '+') || (uRead == '-'))
            uRead = isIn.get();
         for (; (uRead >= '0') && (uRead <= '9'); uRead = isIn.get());
         if (uRead != EOF)
            scfFlags.setPartialRead();
         return;
      };

      uRead = isIn.get();
      bool fNegativeExponent = false;
      if (uRead == '+')
         uRead = isIn.get();
      else if (uRead == '-') {
         uRead = isIn.get();
         fNegativeExponent = true;
      };
      int uDecimalExponent = 0;
      bool fInfty = false;
      for (; (uRead >= '0') && (uRead <= '9'); uRead = isIn.get()) {
         int uOldDecimalExponent = uDecimalExponent;
         uDecimalExponent *= 10;
         uDecimalExponent += uRead - '0';
         if (uDecimalExponent < uOldDecimalExponent) {
            uDecimalExponent = 0;
            fInfty = true;
            break;
         };
      };
      
      if (uRead != EOF) {
         isIn.putback((char) uRead);
         scfFlags.setPartialRead();
      };

      if (!fInfty) {
         int uOldDecimalExponent = uDecimalExponent;
         if (fNegativeExponent)
            uDecimalExponent = -uDecimalExponent;

         uDecimalExponent += uDecimalShiftExponent;
         if (((uDecimalShiftExponent > 0) && (uDecimalExponent < uOldDecimalExponent))
               || ((uDecimalShiftExponent < 0) && (uDecimalExponent > uOldDecimalExponent)))
            fInfty = true;
         else if ((fNegativeExponent = (uDecimalExponent < 0)) != false) {
            uDecimalExponent = -uDecimalExponent;
            if (uDecimalExponent < 0)
              fInfty = true;
         };
      };

      if (fInfty) {
         // +0, -0, +oo, -oo
         if (!fNegativeExponent)
            setInfty();
         if (fNegative)
            setSign(false);
         return;
      }
      else if (uDecimalExponent == 0)
         return;

      thisType dExponent(1U);
      unsigned int uSubExponent = 0;
      for (unsigned int uBitIndex = (1U << (log_base_2(uDecimalExponent)-1)); uBitIndex != 0;
            uBitIndex >>= 1) {
         dExponent.multAssign(dExponent, scfFlags);
         uSubExponent <<= 1;
         if (uDecimalExponent & uBitIndex)
            dExponent.multAssign(10U, scfFlags);
         if (fNegativeExponent && !uSubExponent && (dExponent.biExponent > biExponent)) {
            dExponent.biExponent -= TypeTraits::getZeroExponent(biExponent);
            uSubExponent += dExponent.biExponent.queryValue();
            dExponent.biExponent = TypeTraits::getZeroExponent(biExponent);
         };
      };
      if (!fNegativeExponent) {
         multAssign(dExponent, scfFlags);
         return;
      };

      if (!uSubExponent) {
         divAssign(dExponent, scfFlags);
         return;
      };

      divAssign(dExponent, scfFlags);

      Exponent biSubExponent = getBasicExponent(uSubExponent);
      if (biExponent > biSubExponent)
         biExponent.minusAssign(biSubExponent);
      else {
         biSubExponent.minusAssign(biExponent);
         biExponent = 0U;
         if (biSubExponent >= bitSizeMantissa()) {
            bool fAdd = false;
            if (scfFlags.isNearestRound())
               fAdd = (biSubExponent == bitSizeMantissa());
            else if (scfFlags.isHighestRound())
               fAdd = !fNegative;
            else if (scfFlags.isLowestRound())
               fAdd = fNegative;
            if (fNegative)
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Down : StatusAndControlFlags::Up);
            else
               scfFlags.setApproximate(fAdd ? StatusAndControlFlags::Up : StatusAndControlFlags::Down);
            biMantissa = fAdd ? 1U : 0U;
            if (!fAdd && fNegative && !scfFlags.acceptMinusZero())
               fNegative = false;
         }
         else if (trightShift(biMantissa, biSubExponent.queryValue()+1, 1, scfFlags,
               fNegative, bitSizeMantissa()).hasCarry())
            biExponent.inc();
         if (biExponent.isZero())
            scfFlags.setUnderflow();
      };
      return;
   };

   // uRead != 'e'
   if (uRead != EOF) {
      isIn.putback((char) uRead);
      scfFlags.setPartialRead();
   };
   bool fNegativeExponent = (uDecimalShiftExponent < 0);
   unsigned int uDecimalExponent = fNegativeExponent ? -uDecimalShiftExponent : uDecimalShiftExponent;
   if (uDecimalExponent == 0)
      return;

   thisType dExponent(1U);
   for (unsigned int uBitIndex = (1U << (log_base_2(uDecimalExponent)-1)); uBitIndex != 0;
         uBitIndex >>= 1) {
      dExponent.multAssign(dExponent, scfFlags);
      if (uDecimalExponent & uBitIndex)
         dExponent.multAssign(10U, scfFlags);
   };
   if (!fNegativeExponent)
      multAssign(dExponent, scfFlags);
   else
      divAssign(dExponent, scfFlags);
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::write(std::ostream& osOut, const WriteParameters& wpFlags) const {
   if (wpFlags.isBinary()) {
      osOut.put(isPositive() ? '+' : '-').put(' ');
      if (isDenormalized())
         osOut << "0.";
      else if (isNormalized())
         osOut << "1.";
#ifndef __BORLANDC__
      biMantissa.write(osOut, typename Mantissa::FormatParameters().setFullBinary(biMantissa.querySize()));
#else
      biMantissa.write(osOut, Mantissa::FormatParameters().setFullBinary(biMantissa.querySize()));
#endif
      osOut << " 2^ ";
      if (hasNegativeExponent())
         osOut.put('-');
      osOut << (int) queryExponent().queryValue();
   }
   else
      writeDecimal(osOut);
}

template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::writeDecimal(std::ostream& osOut) const {
   if (fNegative)
      osOut.put('-');
   if (isInfty()) {
      osOut << "oo";
      return;
   };
   if (isNaN()) {
      osOut << "NaN";
      return;
   };
   if (isZero()) {
      osOut.put('0');
      return;
   };
   StatusAndControlFlags scfFlags;
   scfFlags.setNearestRound();
   bool fNegativeExponent = biExponent < TypeTraits::getZeroExponent(biExponent);

   thisType dSource = *this;
   if (fNegative)
      dSource.opposite();
   thisType dExponent;
   std::vector<thisType> vSuccessiveExponents;
   unsigned int uAddNegativeDecimalExponent = 0;
   if (fNegativeExponent) {
      dExponent = thisType(10U);
      uAddNegativeDecimalExponent = 1;
      while (thisType(dExponent).multAssign(dSource, scfFlags).queryBasicExponent()
            < TypeTraits::getZeroExponent(biExponent)) {
         vSuccessiveExponents.push_back(dExponent);
         dExponent.multAssign(dExponent, scfFlags);
         uAddNegativeDecimalExponent *= 2;
      };
      uAddNegativeDecimalExponent /= 2;
   }
   else {
      dExponent = thisType(10U);
      while (dExponent <= dSource) {
         vSuccessiveExponents.push_back(dExponent);
         dExponent.multAssign(dExponent, scfFlags);
      };
   };
   
   unsigned int uDecimalExponent = 0;
   if (fNegativeExponent) {
      if (vSuccessiveExponents.empty()) {
         dSource.multAssign(10U, scfFlags);
         ++uAddNegativeDecimalExponent;
      }
      else {
         dSource.multAssign(vSuccessiveExponents.back(), scfFlags);
         int uExponentAdditional = 1;
         int uIndexExponent = 0;
         while (thisType(dSource).multAssign(vSuccessiveExponents[uIndexExponent], scfFlags)
               .queryBasicExponent() < TypeTraits::getZeroExponent(biExponent)) {
            if (uIndexExponent < (int) vSuccessiveExponents.size() - 1) {
               uExponentAdditional *= 2;
               ++uIndexExponent;
            }
            else {
               dSource.multAssign(vSuccessiveExponents.back(), scfFlags);
               uAddNegativeDecimalExponent += uExponentAdditional;
            };
         };
         int uCount = vSuccessiveExponents.size();
         while (++uIndexExponent < uCount)
            vSuccessiveExponents.pop_back();

         dSource.multAssign(vSuccessiveExponents.back(), scfFlags);
         uAddNegativeDecimalExponent += uExponentAdditional;
         assert(dSource.queryBasicExponent() >= TypeTraits::getZeroExponent(biExponent));
         vSuccessiveExponents.pop_back();
      };
   };
   while (!vSuccessiveExponents.empty()) {
      uDecimalExponent <<= 1;
      if (dSource >= vSuccessiveExponents.back()) {
         uDecimalExponent |= 1U;
         dSource.divAssign(vSuccessiveExponents.back(), scfFlags);
      };
      vSuccessiveExponents.pop_back();
   };

   assert((dSource >= thisType(1U)) && (dSource < thisType(10U)));
   bool fFirst = true;
   int uSignificantBits = (int) (((double) bitSizeMantissa())*log(2.0)/log(10.0));
   std::string result;
   thisType ten(10U), five(5U);
   do {
      StatusAndControlFlags scfFlags;
      scfFlags.setNearestRound();
      unsigned int uWriteValue = 0U;
      if (dSource.hasPositiveOrNullExponent()) {
         int uLocalExponent = dSource.queryExponent().queryValue();
         if (uLocalExponent == 0U)
            uWriteValue = 1;
         else if (uLocalExponent == 1U)
            uWriteValue = (dSource.biMantissa.cbitArray(bitSizeMantissa()-1) ? 3 : 2);
         else if (uLocalExponent == 2U)
            uWriteValue = (dSource.biMantissa.cbitArray(bitSizeMantissa()-1)
               ? (dSource.biMantissa.cbitArray(bitSizeMantissa()-2) ? 7 : 6)
               : (dSource.biMantissa.cbitArray(bitSizeMantissa()-2) ? 5 : 4));
         else if (uLocalExponent == 3U) {
            uWriteValue =  (dSource.biMantissa.cbitArray(bitSizeMantissa()-3) ? 9 : 8);
            assert(!dSource.biMantissa.cbitArray(bitSizeMantissa()-2)
               && !dSource.biMantissa.cbitArray(bitSizeMantissa()-1));
         }
         else
            assert(false);
         result.push_back((char) (uWriteValue + '0'));
         dSource.minusAssign(thisType(uWriteValue), scfFlags);
      }
      else
         result.push_back('0');
      if (fFirst) {
         result.push_back('.');
         fFirst = false;
      };
      dSource.multAssign(10U, scfFlags);
      if ((uSignificantBits > 0) ? (dSource == ten) : (dSource > five)) {
         int length = result.length();
         while (length > 0) {
            char ch = result[length-1];
            if (ch == '9') {
               result[length-1] = '0';
               --length;
            }
            else if ((ch >= '0') && (ch < '9')) {
               result[length-1] = (char) (ch + 1);
               break;
            }
            else // ch == '.'
               --length;
         };
         if (length == 0)
            result.insert('1', 0);
         break;      
      }
   } while (--uSignificantBits >= 0);
   osOut << result;
   if (fNegativeExponent)
      uDecimalExponent = uAddNegativeDecimalExponent-uDecimalExponent;
   if (uDecimalExponent)
      osOut.put('e').put(fNegativeExponent ? '-' : '+') << (int) uDecimalExponent;
}

#ifndef __BORLANDC__
template <class TypeTraits>
typename TBuiltDouble<TypeTraits>::DiffDouble
TBuiltDouble<TypeTraits>::queryNumberOfFloatsBetween(const thisType& bdSource) const {
   DiffDouble ddResult;
#else
template <class TypeTraits>
void
TBuiltDouble<TypeTraits>::retrieveNumberOfFloatsBetween(const thisType& bdSource, DiffDouble& ddResult) const {
#endif

   if (fNegative == bdSource.fNegative) {
      Mantissa biDiffMantissa;
      Exponent biDiffExponent = getZeroExponent();
      bool fIncrementThis = false;
      if (fNegative && bdSource.fNegative) {
         biDiffMantissa = biMantissa;
         fIncrementThis = biDiffMantissa.sub(bdSource.biMantissa).hasCarry();
         assert((biExponent > bdSource.biExponent)
                  || ((biExponent == bdSource.biExponent) && !fIncrementThis));
         biDiffExponent = biExponent;
         biDiffExponent -= bdSource.biExponent;
      }
      else {
         biDiffMantissa = bdSource.biMantissa;
         fIncrementThis = biDiffMantissa.sub(biMantissa).hasCarry();
         assert((biExponent < bdSource.biExponent)
                  || ((biExponent == bdSource.biExponent) && !fIncrementThis));
         biDiffExponent = bdSource.biExponent;
         biDiffExponent -= biExponent;
      };
      if (fIncrementThis)
         --biDiffExponent;

      for (int uIndex = 0; uIndex <= biDiffMantissa.lastCellIndex(); ++uIndex)
         ddResult[uIndex] = biDiffMantissa[uIndex];
      DiffDouble ddDiffExponent;
      for (int uIndex = 0; uIndex <= biDiffExponent.lastCellIndex(); ++uIndex)
         ddDiffExponent[uIndex] = biDiffExponent[uIndex];
      ddResult += (ddDiffExponent <<= bitSizeMantissa());
   }
   else {
      assert(fNegative && !bdSource.fNegative);
      Mantissa biAddMantissa = biMantissa;
      bool fIncrementThis = biAddMantissa.add(bdSource.biMantissa).hasCarry();
      fIncrementThis = biAddMantissa.inc().hasCarry() || fIncrementThis;

      Exponent biAddExponent = Exponent(biExponent);
      bool fCarryExponent = biAddExponent.add(bdSource.biExponent).hasCarry();
      if (fIncrementThis)
         fCarryExponent = biAddExponent.inc().hasCarry() || fCarryExponent;

      for (int uIndex = 0; uIndex <= biAddMantissa.lastCellIndex(); ++uIndex)
         ddResult[uIndex] = biAddMantissa[uIndex];
      DiffDouble ddAddExponent;
      for (int uIndex = 0; uIndex <= biAddExponent.lastCellIndex(); ++uIndex)
         ddAddExponent[uIndex] = biAddExponent[uIndex];
      ddResult += (ddAddExponent <<= bitSizeMantissa());
      if (fCarryExponent)
        ddResult.setTrueBitArray(bitSizeMantissa()+bitSizeExponent());
   };

#ifndef __BORLANDC__
   return ddResult;
#endif
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>
#ifndef __GNUC__
TBuiltDouble<TypeTraits>::queryNthSuccessor(const DiffDouble& ddDiff) const {
#else
TBuiltDouble<TypeTraits>::queryNthSuccessor(const TBuiltDouble<TypeTraits>::DiffDouble& ddDiff) const {
#endif
   if ((biExponent == TypeTraits::getInftyExponent(biExponent)) && (!biMantissa.isZero() || !fNegative))
      return *this;

   DiffDouble ddThis, ddThisExponent;
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      ddThis[uIndex] = biMantissa[uIndex];
   for (int uIndex = 0; uIndex <= biExponent.lastCellIndex(); ++uIndex)
      ddThisExponent[uIndex] = biExponent[uIndex];
   ddThis |= (ddThisExponent <<= bitSizeMantissa());
   thisType bdResult;
   if (!fNegative) {
      if (ddThis.add(ddDiff).hasCarry() || ddThis.cbitArray(bitSizeMantissa()+bitSizeExponent())) {
         bdResult.biExponent = TypeTraits::getInftyExponent(biExponent);
         return bdResult;
      };
   }
   else {
      if (ddThis.sub(ddDiff).hasCarry()) {
         ddThis.neg();
         if (ddThis.cbitArray(bitSizeMantissa()+bitSizeExponent())) {
            bdResult.biExponent = TypeTraits::getInftyExponent(biExponent);
            return bdResult;
         };
      }
      else
         bdResult.fNegative = true;
   };
   for (int uIndex = 0; uIndex <= bdResult.biMantissa.lastCellIndex(); ++uIndex)
      bdResult.biMantissa[uIndex] = ddThis[uIndex];
   bdResult.biMantissa.normalize();
   ddThis >>= bitSizeMantissa();
   for (int uIndex = 0; uIndex <= bdResult.biExponent.lastCellIndex(); ++uIndex)
      bdResult.biExponent[uIndex] = ddThis[uIndex];
   if (bdResult.biExponent == TypeTraits::getInftyExponent(biExponent))
      bdResult.biMantissa = 0U;
   return bdResult;
}

template <class TypeTraits>
bool
TBuiltDouble<TypeTraits>::setToNext() {
   if ((biExponent == TypeTraits::getInftyExponent(biExponent)) && (!biMantissa.isZero() || !fNegative))
      return false;

   if (!fNegative) {
      if (biMantissa.inc().hasCarry())
         biExponent.inc();
   }
   else {
      if (biMantissa.dec().hasCarry()) {
         if (biExponent.isZero()) {
            biMantissa = 1U;
            fNegative = false;
         }
         else
            biExponent.dec();
      }
      else if (biMantissa.isZero() && biExponent.isZero())
         fNegative = false;
   };
   return true;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>
TBuiltDouble<TypeTraits>::queryNthPredecessor(const DiffDouble& ddDiff) const {
   if ((biExponent == TypeTraits::getInftyExponent(biExponent)) && (!biMantissa.isZero() || fNegative))
      return *this;

   DiffDouble ddThis, ddThisExponent;
   for (int uIndex = 0; uIndex <= biMantissa.lastCellIndex(); ++uIndex)
      ddThis[uIndex] = biMantissa[uIndex];
   for (int uIndex = 0; uIndex <= biExponent.lastCellIndex(); ++uIndex)
      ddThisExponent[uIndex] = biExponent[uIndex];
   ddThis |= (ddThisExponent <<= bitSizeMantissa());
   thisType bdResult;
   bdResult.fNegative = true;
   if (fNegative) {
      if (ddThis.add(ddDiff).hasCarry() || ddThis.cbitArray(bitSizeMantissa()+bitSizeExponent())) {
         bdResult.biExponent = TypeTraits::getInftyExponent(biExponent);
         return bdResult;
      };
   }
   else {
      if (ddThis.sub(ddDiff).hasCarry()) {
         ddThis.neg();
         if (ddThis.cbitArray(bitSizeMantissa()+bitSizeExponent())) {
            bdResult.biExponent = TypeTraits::getInftyExponent(biExponent);
            return bdResult;
         };
      }
      else
         bdResult.fNegative = false;
   };
   for (int uIndex = 0; uIndex <= bdResult.biMantissa.lastCellIndex(); ++uIndex)
      bdResult.biMantissa[uIndex] = ddThis[uIndex];
   bdResult.biMantissa.normalize();
   ddThis >>= bitSizeMantissa();
   for (int uIndex = 0; uIndex <= bdResult.biExponent.lastCellIndex(); ++uIndex)
      bdResult.biExponent[uIndex] = ddThis[uIndex];
   return bdResult;
}

template <class TypeTraits>
bool
TBuiltDouble<TypeTraits>::setToPrevious() {
   if ((biExponent == TypeTraits::getInftyExponent(biExponent)) && (!biMantissa.isZero() || fNegative))
      return false;

   if (fNegative) {
      if (biMantissa.inc().hasCarry())
         biExponent.inc();
   }
   else {
      if (biMantissa.dec().hasCarry()) {
         if (biExponent.isZero()) {
            biMantissa = 1U;
            fNegative = true;
         }
         else
            biExponent.dec();
      };
   };
   return true;
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::sqrtAssign() { // u_{n+1} = (u_n + this/u_n)/2
   assert(!fNegative);
   if (isZero() || isInfty())
      return *this;
   thisType bdResult;
   bdResult.biExponent = biExponent;
   (bdResult.biExponent >>= 1).plusAssign((getZeroExponent() >>= 1));
   thisType bdNext;
   bool fContinue = false;
   StatusAndControlFlags scfFlags;
   scfFlags.setNearestRound().setRoundToEven();
   do {
      bdNext = *this;
      scfFlags.clear();
      bdNext.divAssign(bdResult, scfFlags); // bdNext = this/u_n
      scfFlags.clear();
      bdNext.plusAssign(bdResult, scfFlags); // bdNext = this/u_n + u_n
      bdNext.biExponent.dec(); // bdNext = (this/u_n + u_n)/2
      ComparisonResult crCompare = bdNext.compare(bdResult);
      if (crCompare == CRGreater) {
         if (bdNext.biExponent > bdResult.biExponent) {
            bdResult.biExponent.inc();
            fContinue = (bdNext.biExponent > bdResult.biExponent)
               || (bdResult.biMantissa.neg() != 0U) || (bdNext.biMantissa != 0U);
         }
         else
            fContinue = bdResult.biMantissa.inc().hasCarry()
               || (bdNext.biMantissa != bdResult.biMantissa);
      }
      else if (crCompare == CRLess) {
         if (bdNext.biExponent < bdResult.biExponent) {
            bdResult.biExponent.dec();
            fContinue = (bdNext.biExponent < bdResult.biExponent)
               || (Mantissa(bdNext.biMantissa).neg() != 0U) || (bdResult.biMantissa != 0U);
         }
         else
            fContinue = bdResult.biMantissa.dec().hasCarry()
               || (bdNext.biMantissa != bdResult.biMantissa);
      }
      else
         fContinue = false;
      bdResult = bdNext;
   } while (fContinue);
   // Continue with a better precision on the mantissa and with testing the both float around
   return operator=(bdResult);   
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::nthRootAssign(int n) {
   assert((n > 0) && (!fNegative || (n & 1)));
   if (n == 1)
      return *this;
   else if (n == 2)
      return sqrtAssign();
   
   StatusAndControlFlags scfFlags;
   scfFlags.setNearestRound().setRoundToEven();
   // u_{p+1} = 1/n*[(n-1)*u_p + this/(u_p)^(n-1))]
   thisType bdResult;
   bdResult.biExponent = getZeroExponent();
   if (biExponent >= getZeroExponent())
      bdResult.biExponent.plusAssign((Exponent(biExponent) -= getZeroExponent()) /= n);
   else
      bdResult.biExponent.minusAssign((getZeroExponent() -= biExponent) /= n);
   thisType bdNext;
   bool fContinue = false;
   do {
      bdNext = *this;
      scfFlags.clear();
      bdNext.divAssign(thisType(bdResult).nthExponentAssign(n-1), scfFlags);
      scfFlags.clear();
      StatusAndControlFlags scfFlagsCopy(scfFlags);
      bdNext.plusAssign(thisType(bdResult).multAssign(n-1, scfFlagsCopy), scfFlags);
      scfFlags.clear();
      bdNext.divAssign(n, scfFlags);
      ComparisonResult crCompare = bdNext.compare(bdResult);
      if (crCompare == CRGreater) {
         if (bdNext.biExponent > bdResult.biExponent) {
            bdResult.biExponent.inc();
            fContinue = (bdNext.biExponent > bdResult.biExponent)
               || (++((bdResult.biMantissa.neg() += bdNext.biMantissa).neg()) >= n-1);
         }
         else
            fContinue = (++((bdResult.biMantissa -= bdNext.biMantissa).neg()) >= n-1);
      }
      else if (crCompare == CRLess) {
         if (bdNext.biExponent < bdResult.biExponent) {
            bdResult.biExponent.dec();
            fContinue = (bdNext.biExponent < bdResult.biExponent)
               || (++((bdResult.biMantissa += Mantissa(bdNext.biMantissa)).neg()) >= n-1);
         }
         else
            fContinue = ((bdResult.biMantissa -= bdNext.biMantissa) >= n-1);
      }
      else
         fContinue = false;
      bdResult = bdNext;
   } while (fContinue);
   // Continue with a better precision on the mantissa and with testing the 2(n-1) float around
   return operator=(bdResult);   
}

template <class TypeTraits>
TBuiltDouble<TypeTraits>&
TBuiltDouble<TypeTraits>::nthExponentAssign(int n) {
   if (n == 0) {
      biMantissa = 0U;
      biExponent = getZeroExponent();
      fNegative = false;
      return *this;
   };
   StatusAndControlFlags scfFlags;
   scfFlags.setNearestRound().setRoundToEven();
   unsigned int uExponent = (n < 0) ? -n : n;
   if (uExponent == 1)
      return (n < 0) ? inverseAssign(scfFlags) : *this;
   thisType bdResult = *this;
   int uIndexBitExponent = Integer::Details::Access::log_base_2(uExponent)-2;
   while (uIndexBitExponent >= 0) {
      scfFlags.clear();
      bdResult.multAssign(bdResult, scfFlags);
      if (uExponent & (1U << uIndexBitExponent)) {
         scfFlags.clear();
         bdResult.multAssign(*this, scfFlags);
      };
      --uIndexBitExponent;
   };
   if (n < 0) {
      biExponent = getZeroExponent();
      biMantissa = 0U;
      fNegative = false;
      scfFlags.clear();
      return divAssign(bdResult, scfFlags);
   }
   else
      return operator=(bdResult);
}

}} // end of namespace Numerics::Double

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Double_FloatingTemplate
