/***************************************************************************
               integer.tcc  -  Template for various types of integer
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

#ifndef Numerics_Integer_IntegerTemplate
#define Numerics_Integer_IntegerTemplate
#include <unisim/util/simfloat/integer.hh>
#include <iostream>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Integer {

/*****************************************/
/* Implementation - template TBigCellInt */
/*****************************************/

namespace Details {

template <class IntegerTraits>
bool
TBigCellInt<IntegerTraits>::verifyAtomicity() const {
   for (int uIndex = 1; uIndex < inherited::querySize(); ++uIndex)
      if (array(uIndex) != 0U)
         return false;
   return true;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::Carry
TBigCellInt<IntegerTraits>::add(const thisType& biSource) {
   Carry cCarry;
   if (inherited::querySize() < biSource.inherited::querySize())
      inherited::adjustSize(biSource.inherited::querySize());
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex) {
      unsigned int uOldCell = array(uIndex);
      array(uIndex) += biSource.array(uIndex);
      if (cCarry.hasCarry()) {
         ++array(uIndex);
         cCarry.setCarry(array(uIndex) <= uOldCell);
      }
      else
         cCarry.setCarry(array(uIndex) < uOldCell);
   };
   return cCarry;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::Carry
TBigCellInt<IntegerTraits>::dec() {
   Carry cCarry;
   cCarry.setCarry();
   for (int uIndex = 0; (uIndex < inherited::querySize()) && cCarry.hasCarry(); ++uIndex)
      cCarry.setCarry(array(uIndex)-- == 0U);
   return cCarry;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::Carry
TBigCellInt<IntegerTraits>::inc() {
   Carry cCarry;
   cCarry.setCarry();
   for (int uIndex = 0; (uIndex < inherited::querySize()) && cCarry.hasCarry(); ++uIndex)
      cCarry.setCarry(++array(uIndex) == 0U);
   return cCarry;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::Carry
TBigCellInt<IntegerTraits>::multAssign(unsigned int uSource) {
   unsigned int uCarry, uThisLow, uThisHigh, uSourceLow, uSourceHigh;
   uCarry = 0;
   uSourceHigh = uSource >> (sizeof(unsigned int)*4);
   uSourceLow = uSource & ~(~0U << (sizeof(unsigned int)*4));
   for (int uThisIndex = 0; uThisIndex < inherited::querySize(); ++uThisIndex) {
      uThisHigh = array(uThisIndex) >> (sizeof(unsigned int)*4);
      uThisLow = array(uThisIndex) & ~(~0U << (sizeof(unsigned int)*4));
      array(uThisIndex) = uCarry;
      uCarry = 0U;
      uCarry += add(array(uThisIndex), uThisLow*uSourceLow);
      uCarry += add(array(uThisIndex), uThisLow*uSourceHigh << (sizeof(unsigned int)*4));
      uCarry += add(array(uThisIndex), uThisHigh*uSourceLow << (sizeof(unsigned int)*4));
      uCarry += ((uThisLow*uSourceHigh) >> (sizeof(unsigned int)*4));
      uCarry += ((uThisHigh*uSourceLow) >> (sizeof(unsigned int)*4));
      uCarry += uThisHigh*uSourceHigh;
   };
   return Carry(uCarry);
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::mult(const thisType& biSource, MultResult& mrResult) const {
   unsigned int uCarry, uThisLow, uThisHigh, uSourceLow, uSourceHigh;
   for (int uSourceIndex = 0; uSourceIndex < biSource.inherited::querySize(); ++uSourceIndex) {
      uCarry = 0;
      uSourceHigh = biSource.array(uSourceIndex) >> (sizeof(unsigned int)*4);
      uSourceLow = biSource.array(uSourceIndex) & ~(~0U << (sizeof(unsigned int)*4));
      for (int uThisIndex = 0; uThisIndex < inherited::querySize(); ++uThisIndex) {
         uThisHigh = array(uThisIndex) >> (sizeof(unsigned int)*4);
         uThisLow = array(uThisIndex) & ~(~0U << (sizeof(unsigned int)*4));
         uCarry = add(mrResult[uThisIndex + uSourceIndex], uCarry);
         uCarry += add(mrResult[uThisIndex + uSourceIndex], uThisLow*uSourceLow);
         uCarry += add(mrResult[uThisIndex + uSourceIndex], uThisLow*uSourceHigh << (sizeof(unsigned int)*4));
         uCarry += add(mrResult[uThisIndex + uSourceIndex], uThisHigh*uSourceLow << (sizeof(unsigned int)*4));
         uCarry += ((uThisLow*uSourceHigh) >> (sizeof(unsigned int)*4));
         uCarry += ((uThisHigh*uSourceLow) >> (sizeof(unsigned int)*4));
         uCarry += uThisHigh*uSourceHigh;
      };
      mrResult[inherited::querySize() + uSourceIndex] = uCarry;
   };
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator<<=(int uShift) {
   assert(uShift >= 0);
   int uShiftIndex = uShift / (sizeof(unsigned int)*8);
   int uLocalShift = uShift % (sizeof(unsigned int)*8);
   int uWriteIndex = inherited::querySize();
   while (--uWriteIndex >= uShiftIndex) {
      unsigned int uTemp = array(uWriteIndex-uShiftIndex);
      array(uWriteIndex) = uTemp << uLocalShift;
      if ((uLocalShift > 0) && (uWriteIndex > uShiftIndex))
         array(uWriteIndex) |= (array(uWriteIndex-uShiftIndex-1) >> (sizeof(unsigned int)*8-uLocalShift));
   };
   ++uWriteIndex;
   while (--uWriteIndex >= 0)
      array(uWriteIndex) = 0U;
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator>>=(int uShift) {
   assert(uShift >= 0);
   int uShiftIndex = uShift / (sizeof(unsigned int)*8);
   int uLocalShift = uShift % (sizeof(unsigned int)*8);
   int uWriteIndex;
   
   for (uWriteIndex = 0; uWriteIndex < inherited::querySize()-uShiftIndex; ++uWriteIndex) {
      unsigned int uTemp = array(uWriteIndex+uShiftIndex);
      array(uWriteIndex) = uTemp >> uLocalShift;
      if ((uLocalShift > 0) && (uWriteIndex + uShiftIndex < inherited::querySize()-1))
         array(uWriteIndex) |= (array(uWriteIndex+uShiftIndex+1) << (sizeof(unsigned int)*8-uLocalShift));
   };
   --uWriteIndex;
   while (++uWriteIndex < inherited::querySize())
      array(uWriteIndex) = 0U;
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator|=(const thisType& biSource) {
   if (inherited::querySize() < biSource.inherited::querySize())
      inherited::adjustSize(biSource.inherited::querySize());
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex)
      array(uIndex) |= biSource.array(uIndex);
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator^=(const thisType& biSource) {
   if (inherited::querySize() < biSource.inherited::querySize())
      inherited::adjustSize(biSource.inherited::querySize());
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex)
      array(uIndex) ^= biSource.array(uIndex);
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator&=(const thisType& biSource) {
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex)
      array(uIndex) &= biSource.array(uIndex);
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::neg() {
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex)
      array(uIndex) = ~array(uIndex);
   return *this;
}

template <class IntegerTraits>
TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::neg(int uShift) {
   if (uShift >= 0) {
      int uSize = uShift/(8*sizeof(unsigned int));
      for (int uIndex = 0; uIndex < uSize; ++uIndex)
         array(uIndex) = ~array(uIndex);
      if (uShift % (8*sizeof(unsigned int)) != 0) {
         int uNeg = uShift - 8*sizeof(unsigned int)*uSize;
         array(uSize) = (array(uSize) & (~0U << uNeg)) | (~array(uSize) & ~(~0U << uNeg));
      };
   };
   return *this;
}

template <class IntegerTraits>
unsigned int
TBigCellInt<IntegerTraits>::log_base_2() const {
   int uIndex = inherited::querySize();
   while ((uIndex > 0) && (array(--uIndex) == 0U));
   if (array(uIndex) == 0U)
      return 1;
   return Details::Access::log_base_2(array(uIndex)) + uIndex*sizeof(unsigned int)*8;
}

template <class IntegerTraits>
unsigned int
TBigCellInt<IntegerTraits>::retrieveSignificantMidDivide(int uLogBase2, bool& fExact) const {
   assert(uLogBase2 > 0);
   int uIndex = (uLogBase2-1) / (8*sizeof(unsigned int));
   assert(array(uIndex) != 0U);
   
   int uBitIndex = ((uLogBase2-1) % (8*sizeof(unsigned int)))+1;
   unsigned int uResult = 0U;
   if (uBitIndex >= (int)(sizeof(unsigned int)*4)) {
      uResult = array(uIndex) >> (uBitIndex - sizeof(unsigned int)*4);
      fExact = (~(~0U << (uBitIndex-sizeof(unsigned int)*4)) & array(uIndex)) == 0U;
   }
   else {
      if (uIndex > 0) {
         uResult = array(uIndex) << (sizeof(unsigned int)*4 - uBitIndex);
         uResult |= (array(--uIndex) >> (sizeof(unsigned int)*4+uBitIndex));
         fExact = (~(~0U << (uBitIndex+sizeof(unsigned int)*4)) & array(uIndex)) == 0U;
      }
      else {
         uResult = array(uIndex);
         fExact = true;
      };
   };
   while (fExact && (--uIndex >= 0))
      fExact = (array(uIndex) == 0U);
   return uResult;
}

template <class IntegerTraits>
unsigned int
TBigCellInt<IntegerTraits>::retrieveSignificantMidDivideNormalized(bool& fExact) const {
   unsigned int uResult = (array(inherited::querySize()-1) >> (sizeof(unsigned int)*4+1))
      | (1U << (sizeof(unsigned int)*4-1));
   fExact = (~(~0U << (sizeof(unsigned int)*4+1)) & array(inherited::querySize()-1)) == 0U;

   for (int uIndex = inherited::querySize()-1; fExact && (--uIndex >= 0); )
      fExact = (array(uIndex) == 0U);
   return uResult;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::AtomicDivisionResult
TBigCellInt<IntegerTraits>::divAssign(unsigned int uDivide) {
   assert((uDivide > 0) && (uDivide < (1U << (sizeof(unsigned int)*4))));
   unsigned int uRemainder = 0U;

   int uIndex = inherited::querySize();
   while ((uIndex > 0) && (array(--uIndex) == 0U));
   if (array(uIndex) == 0U)
      return AtomicDivisionResult();

   uIndex = uIndex*2+1;
   if (cmidArray(uIndex) == 0)
      --uIndex;

   if (cmidArray(uIndex) >= uDivide)
      ++uIndex;
   else {
      uRemainder = cmidArray(uIndex);
      setMidArray(uIndex, 0);
   };

   while (--uIndex >= 0) {
      uRemainder <<= sizeof(unsigned int)*4;
      uRemainder += cmidArray(uIndex);

      setMidArray(uIndex, uRemainder / uDivide);
      uRemainder %= uDivide;
   };
   return AtomicDivisionResult(uRemainder);
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::div(const thisType& biSource, DivisionResult& drResult) const {
   int uShiftNumerator = log_base_2(), uShiftDenominator = biSource.log_base_2();
   bool fExact = false;
   unsigned int uMidDivide = biSource.retrieveSignificantMidDivide(uShiftDenominator, fExact);

   if (fExact) {
      int uResultSize = drResult.quotient().querySize();
      drResult.quotient() = *this;
      drResult.comma() = uShiftNumerator;
      if (uShiftDenominator > (int) (4*sizeof(unsigned int)))
         drResult.comma() -= (uShiftDenominator-4*sizeof(unsigned int));
      TBigCellInt<QuotientResult>& pqrPromotedQuotientResult = (TBigCellInt<QuotientResult>&) drResult.quotient();
      assert((int) ((uResultSize+1)*sizeof(unsigned int)*8) >= uShiftNumerator);
      if ((int) (uResultSize*sizeof(unsigned int)*8) > uShiftNumerator)
         pqrPromotedQuotientResult <<= (uResultSize*sizeof(unsigned int)*8 - uShiftNumerator);
      else
         drResult.comma() -= (uShiftNumerator - (uResultSize*sizeof(unsigned int)*8));
      AtomicDivisionResult adrResult = pqrPromotedQuotientResult.divAssign(uMidDivide);
      assert(((int) (uResultSize*sizeof(unsigned int)*8) >= uShiftNumerator)
         || (drResult.quotient()[uResultSize] == 0U));
      int uShift = sizeof(unsigned int)*8
         - log_base_2(drResult.quotient()[uResultSize-1]) + 1;
      pqrPromotedQuotientResult <<= uShift;
      pqrPromotedQuotientResult.setSize(uResultSize);
      drResult.comma() -= uShift;
      if (uShift <= (int)(sizeof(unsigned int)*4)) {
         adrResult.remainder() <<= uShift;
         pqrPromotedQuotientResult += (adrResult.remainder() / uMidDivide);
         drResult.remainder()[0] = (adrResult.remainder() % uMidDivide);
      }
      else {
         assert(uShift <= (int)(sizeof(unsigned int)*8));
         adrResult.remainder() <<= sizeof(unsigned int)*4;
         unsigned int uAdd = adrResult.remainder() / uMidDivide;
         adrResult.remainder() = (adrResult.remainder() % uMidDivide);
         adrResult.remainder() <<= (uShift - sizeof(unsigned int)*4);
         uAdd <<= (uShift - sizeof(unsigned int)*4);
         uAdd += adrResult.remainder() / uMidDivide;
         drResult.remainder()[0] = (adrResult.remainder() % uMidDivide);
         pqrPromotedQuotientResult += uAdd;
      };
      if (uShiftDenominator > (int) (4*sizeof(unsigned int)))
         ((TBigCellInt<typename inherited::RemainderResult>&) drResult.remainder())
            <<= (uShiftDenominator-4*sizeof(unsigned int));
      return;
   };

   TBigCellInt<typename inherited::ExtendedInteger> biDenominator, biNumerator;
   int uMaxSize = (inherited::querySize() < biSource.inherited::querySize())
      ? (biSource.inherited::querySize()+1) : (inherited::querySize()+1);
      
   biDenominator.assertSize(uMaxSize);
   biNumerator.assertSize(uMaxSize);
   for (int uNumeratorIndex = 0; uNumeratorIndex < inherited::querySize(); ++uNumeratorIndex)
     biNumerator[uNumeratorIndex] = array(uNumeratorIndex);
   for (int uDenominatorIndex = 0; uDenominatorIndex < biSource.inherited::querySize(); ++uDenominatorIndex)
     biDenominator[uDenominatorIndex] = biSource[uDenominatorIndex];

   int uSizeQuotient = 2*drResult.quotient().querySize();
   int uRemainderShift = 0;

   drResult.comma() = uShiftNumerator-uShiftDenominator;
   if (uShiftDenominator < uShiftNumerator) {
      uRemainderShift -= uShiftNumerator-uShiftDenominator;
      biDenominator <<= (uShiftNumerator-uShiftDenominator);
      if (biNumerator < biDenominator) {
         biDenominator >>= 1;
         ++uRemainderShift;
         --drResult.comma();
      };
   }
   else if (uShiftDenominator == uShiftNumerator) {
      if (biNumerator < biDenominator) {
         biNumerator <<= 1;
         --drResult.comma();
      };
   }
   else {
      biNumerator <<= (uShiftDenominator-uShiftNumerator);
      if (biNumerator < biDenominator) {
         biNumerator <<= 1;
         --drResult.comma();
      };
   };
   biNumerator -= biDenominator;
   if ((uShiftDenominator-uRemainderShift) % (4*sizeof(unsigned int)) != 0) {
      int uLocalShift = 4*sizeof(unsigned int)-(uShiftDenominator-uRemainderShift) % (4*sizeof(unsigned int));
      uRemainderShift -= uLocalShift;
      biDenominator <<= uLocalShift;
      biNumerator <<= uLocalShift;
   };

   int uIndexNumerator = (uShiftDenominator-uRemainderShift-1) / (4*sizeof(unsigned int));

   while (uSizeQuotient > 0) {
      if (biDenominator.cmidArray(0) == 0U) {
         biDenominator >>= 4*sizeof(unsigned int);
         uRemainderShift += 4*sizeof(unsigned int);
      }
      else {
         biNumerator <<= 4*sizeof(unsigned int);
         ++uIndexNumerator;
      };
      unsigned int uQuotient
         = ((biNumerator.cmidArray(uIndexNumerator) << (4*sizeof(unsigned int)))
               | biNumerator.cmidArray(uIndexNumerator-1)) / uMidDivide;
      TBigCellInt<typename inherited::ExtendedInteger> biMult(biDenominator);
      biMult.multAssign(uQuotient);
      if (biMult > biNumerator) {
         biMult -= biDenominator;
         --uQuotient;
         if (biMult > biNumerator) {
            biMult -= biDenominator;
            --uQuotient;
         };
         biNumerator -= biMult;
      }
      else {
         biNumerator -= biMult;
         if (biNumerator > biDenominator) {
            ++uQuotient;
            biNumerator -= biDenominator;
         };
      };
      assert(biNumerator < biDenominator);
      ((TBigCellInt<QuotientResult>&) drResult.quotient()).setMidArray(--uSizeQuotient, uQuotient);
      --uIndexNumerator;
   };

   if (uRemainderShift > 0)
      biNumerator <<= uRemainderShift;
   else
      biNumerator >>= -uRemainderShift;

   int uRemainderIndex = biNumerator.querySize();
   while (--uRemainderIndex >= 0 && (biNumerator[uRemainderIndex] == 0U));
   if (uRemainderIndex >= 0) {
      do {
         drResult.remainder()[uRemainderIndex] = biNumerator[uRemainderIndex];
      } while (--uRemainderIndex >= 0);
   };
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const {
   bool fExact = false;
   unsigned int uMidDivide = biSource.retrieveSignificantMidDivideNormalized(fExact);
   drResult.comma() = (*this >= biSource) ? 0 : -1;

   if (fExact) {
      if (uMidDivide == 1U) {
         drResult.quotient() = *this;
         return;
      };
      drResult.quotient() = *this;
      unsigned int uLowBit = (drResult.quotient()[0] & 1U);
      TBigCellInt<typename inherited::QuotientResult>& pqrPromotedQuotientResult = (TBigCellInt<typename inherited::QuotientResult>&) drResult.quotient();
      pqrPromotedQuotientResult >>= 1;
      drResult.quotient()[drResult.quotient().querySize()-1] |= (~0U << (8*sizeof(unsigned int)-1));
      AtomicDivisionResult adrResult = pqrPromotedQuotientResult.divAssign(uMidDivide);
      int uShift = sizeof(unsigned int)*8
         - log_base_2(drResult.quotient()[drResult.quotient().querySize()-1]) + 1;
      pqrPromotedQuotientResult <<= uShift;
      if (uShift <= (int)(sizeof(unsigned int)*4)) {
         adrResult.remainder() <<= uShift;
         adrResult.remainder() |= (uLowBit << (uShift-1));
         pqrPromotedQuotientResult += (adrResult.remainder() / uMidDivide);
         drResult.remainder()[0] = (adrResult.remainder() % uMidDivide);
      }
      else {
         assert(uShift <= (int)(sizeof(unsigned int)*8));
         adrResult.remainder() <<= sizeof(unsigned int)*4;
         adrResult.remainder() |= (uLowBit << (sizeof(unsigned int)*4-1));
         int uAdd = adrResult.remainder() / uMidDivide;
         adrResult.remainder() = (adrResult.remainder() % uMidDivide);
         adrResult.remainder() <<= (uShift - sizeof(unsigned int)*4);
         uAdd <<= (uShift - sizeof(unsigned int)*4);
         uAdd += adrResult.remainder() / uMidDivide;
         drResult.remainder()[0] = (adrResult.remainder() % uMidDivide);
         pqrPromotedQuotientResult += uAdd;
      };
      ((TBigCellInt<typename inherited::RemainderResult>&) drResult.remainder())
         <<= (biSource.querySize()*8*sizeof(unsigned int)+1-4*sizeof(unsigned int));
      return;
   };

   TBigCellInt<typename inherited::ExtendedInteger> biDenominator, biNumerator;
   int uMaxSize = (inherited::querySize() < biSource.inherited::querySize())
      ? (biSource.inherited::querySize()+1) : (inherited::querySize()+1);
      
   biDenominator.assertSize(uMaxSize);
   biNumerator.assertSize(uMaxSize);
   for (int uNumeratorIndex = 0; uNumeratorIndex < inherited::querySize(); ++uNumeratorIndex)
     biNumerator[uNumeratorIndex] = array(uNumeratorIndex);
   for (int uDenominatorIndex = 0; uDenominatorIndex < biSource.inherited::querySize(); ++uDenominatorIndex)
     biDenominator[uDenominatorIndex] = biSource[uDenominatorIndex];

   biDenominator[biSource.inherited::querySize()] |= 1U;
   biNumerator[inherited::querySize()] |= 1U;
   int uSizeQuotient = 2*drResult.quotient().querySize();

   if (drResult.comma() < 0) // biNumerator < biDenominator
      biNumerator <<= 4*sizeof(unsigned int);
   else
      biNumerator <<= 4*sizeof(unsigned int)-1;
   biDenominator <<= 4*sizeof(unsigned int)-1;
   biNumerator -= biDenominator;
   int uRemainderShift = -4*((int) sizeof(unsigned int))+1;

   int uIndexNumerator = 2*drResult.quotient().querySize()-2;

   while (uSizeQuotient > 0) {
      if (biDenominator.cmidArray(0) == 0U) {
         biDenominator >>= 4*sizeof(unsigned int);
         uRemainderShift += 4*sizeof(unsigned int);
      }
      else {
         biNumerator <<= 4*sizeof(unsigned int);
         ++uIndexNumerator;
      };
      unsigned int uQuotient
         = ((biNumerator.cmidArray(uIndexNumerator) << (4*sizeof(unsigned int)))
               | biNumerator.cmidArray(uIndexNumerator-1)) / uMidDivide;
      TBigCellInt<typename inherited::ExtendedInteger> biMult(biDenominator);
      biMult.multAssign(uQuotient);
      if (biMult > biNumerator) {
         biMult -= biDenominator;
         --uQuotient;
         biNumerator -= biMult;
      }
      else {
         biNumerator -= biMult;
         if (biNumerator > biDenominator) {
            ++uQuotient;
            biNumerator -= biDenominator;
         };
      };
      assert(biNumerator < biDenominator);
      ((TBigCellInt<QuotientResult>&) drResult.quotient()).setMidArray(--uSizeQuotient, uQuotient);
      --uIndexNumerator;
   };

   if (uRemainderShift > 0)
      biNumerator <<= uRemainderShift;
   else
      biNumerator >>= uRemainderShift;

   for (int uRemainderIndex = 0; uRemainderIndex < drResult.remainder().querySize(); ++uRemainderIndex)
     drResult.remainder()[uRemainderIndex] = biNumerator[uRemainderIndex];
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::writeFullBinary(std::ostream& osOut, const FormatParameters& pParams) const {
   int uIndex = ((pParams.queryLength()-1) / (sizeof(unsigned int)*8)) + 1;
   int uBitIndex = ((pParams.queryLength()-1) % (sizeof(unsigned int)*8)) + 1;
   
   while (--uIndex >= 0) {
      unsigned int uValue = array(uIndex) << (sizeof(unsigned int)*8 - uBitIndex);
      while (--uBitIndex >= 0) {
         osOut.put(((uValue & (1U << (sizeof(unsigned int)*8-1))) == 0) ? '0' : '1');
         uValue <<= 1;
      };
      uBitIndex = sizeof(unsigned int)*8;
   };
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::writeFullHexaDecimal(std::ostream& osOut, const FormatParameters& pParams) const {
   int uIndex = ((pParams.queryLength()-1) / (sizeof(unsigned int)*8)) + 1;
   int uHexaIndex = ((pParams.queryLength()-1) % (sizeof(unsigned int)*2)) + 1;
   
   while (--uIndex >= 0) {
      unsigned int uValue = array(uIndex) << (sizeof(unsigned int)*2 - uHexaIndex);
      while (--uHexaIndex >= 0) {
         unsigned int uShow = (uValue & (15U << (sizeof(unsigned int)*8-4)));
         osOut.put((uShow < 10) ? (char) (uShow + '0') : (char) (uShow-10 + 'a'));
         uValue <<= 4;
      };
      uHexaIndex = sizeof(unsigned int)*2;
   };
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::writeCells(std::ostream& osOut, const FormatParameters& pParams) const {
   int uIndex = inherited::querySize();
   while ((uIndex > 0) && (array(--uIndex) == 0U));
   if (array(uIndex) == 0U)
      osOut.put('0');
   else {
      if (pParams.isBinary()) {
         unsigned int uValue = array(uIndex);
         int uBitIndex = 0;
         while ((uValue & (1U << (sizeof(unsigned int)*8-1))) == 0) {
            uValue <<= 1;
            ++uBitIndex;
         };
         osOut.put('1');
         uValue <<= 1;
         
         while (++uBitIndex < (int) sizeof(unsigned int)*8) {
            osOut.put(((uValue & (1U << (sizeof(unsigned int)*8-1))) == 0) ? '0' : '1');
            uValue <<= 1;
         };
      }
      else
         osOut << (int) array(uIndex);
      while (--uIndex >= 0) {
         if (pParams.isBinary()) {
            unsigned int uValue = array(uIndex);
            int uBitIndex = sizeof(unsigned int)*8;
            while (--uBitIndex >= 0) {
               osOut.put(((uValue & (1U << (sizeof(unsigned int)*8-1))) == 0) ? '0' : '1');
               uValue <<= 1;
            };
         }
         else
            osOut.put(' ') << (int) array(uIndex);
      };
   };
}

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::writeDecimal(std::ostream& osOut, const FormatParameters&) const {
   unsigned int* auDecimal = new unsigned int[(inherited::querySize()*8*sizeof(unsigned int)-1)/3+1];
   int uIndex = -1;
   thisType biThis(*this);
   while (biThis != 0U)
      auDecimal[++uIndex] = biThis.divAssign(10).remainder();
   ++uIndex;
   while (--uIndex >= 0)
      osOut.put((char) ('0' + auDecimal[uIndex]));
   if (auDecimal)
      delete [] auDecimal;
}

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::HexaChars TBigCellInt<IntegerTraits>::hcHexaChars;

template <class IntegerTraits>
void
TBigCellInt<IntegerTraits>::read(std::istream& isIn, const FormatParameters& pParams) {
   for (int uCellIndex = 0; uCellIndex < inherited::querySize(); ++uCellIndex)
      array(uCellIndex) = 0U;
   int uChar;
   while (isspace(uChar = isIn.get()));
   if (!pParams.isDecimal()) {
      if (pParams.isBinary() || pParams.isFullHexaDecimal()) {
         while (uChar == '0')
            uChar = isIn.get();
         unsigned int uValue = 0;
         if (!pParams.isFullHexaDecimal()) {
            if (uChar == '1') {
               while ((uChar == '0') || (uChar == '1')) {
                  uValue = ((uChar == '1') ? 1U : 0U);
                  int uBitIndex = 0;
                  while ((++uBitIndex < (int) sizeof(unsigned int)*8)
                           && (((uChar = isIn.get()) == '0') || (uChar == '1'))) {
                     uValue <<= 1;
                     if (uChar == '1')
                        uValue |= 1U;
                  };
                  operator<<=(uBitIndex);
                  array(0) |= uValue;
                  uChar = isIn.get();
               };
            };
         }
         else { // pParams.isFullHexaDecimal()
            while (hcHexaChars.acceptChar(uChar)) {
               uValue = hcHexaChars.queryValue(uChar);
               int uHexaIndex = 0;
               while ((++uHexaIndex < (int) sizeof(unsigned int)*2)
                        && hcHexaChars.acceptChar(uChar = isIn.get())) {
                  uValue <<= 4;
                  uValue |= hcHexaChars.queryValue(uChar);
               };
               operator<<=(uHexaIndex*4);
               array(0) |= uValue;
               uChar = isIn.get();
            };
         };
      }
      else {
         assert(pParams.isIntegerCell());
         while ((uChar == ' ') || ((uChar >= '0') && (uChar <= '9'))) {
            if (uChar == ' ')
               uChar = isIn.get();
            if ((uChar >= '0') && (uChar <= '9')) {
               unsigned int uValue = uChar - '0';
               while (((uChar = isIn.get()) >= '0') && (uChar <= '9')) {
                  uValue *= 10;
                  uValue += (uChar-'0');
               };
               operator<<=(sizeof(unsigned int)*8);
               array(0) = uValue;
            };
         };
      };
   }
   else {
      while ((uChar >= '0') && (uChar <= '9')) {
         operator*=(10);
         operator+=(uChar-'0');
         uChar = isIn.get();
      };
   };
   if (uChar != EOF)
      isIn.unget();
}

} // end of namespace Details

/*************************************/
/* Implementation - template TBigInt */
/*************************************/

template <class IntegerTraits>
void
TBigInt<IntegerTraits>::div(const thisType& biSource, DivisionResult& drResult) const {
   typename ArrayCells::DivisionResult adrResult;
   cells().div(biSource.cells(), adrResult);
   if (!drResult.quotient().isComplete()) {
      int uShift = (8*sizeof(unsigned int)-drResult.quotient().lastCellSize());
      unsigned int uDivLeft = adrResult.quotient()[0] & ~(~0U << uShift);
      TBigCellInt<typename ArrayCells::QuotientResult> quotient;
      memcpy((void *)(typename ArrayCells::DivisionResult::InheritedQuotientResult*) &quotient, (const void *)&adrResult.quotient(), sizeof(typename ArrayCells::DivisionResult::InheritedQuotientResult));
      quotient >>= uShift;

      ArrayCells acNewRemainder(biSource.cells());
      Carry cCarry = acNewRemainder.multAssign(uDivLeft);
      assert(!cCarry.hasCarry());
      cCarry = acNewRemainder.add((const ArrayCells&) adrResult.remainder());
#ifndef DefineUseLongLongIntForDoubleInt
      assert(!cCarry.hasCarry() && ((acNewRemainder[0] & ~(~0U << uShift)) == 0));
#endif
      acNewRemainder >>= uShift;
      for (int uQuotientIndex = 0; uQuotientIndex <= drResult.quotient().lastCellIndex(); ++uQuotientIndex)
         drResult.quotient()[uQuotientIndex] = quotient[uQuotientIndex];
      for (int uRemainderIndex = 0; uRemainderIndex <= drResult.remainder().lastCellIndex(); ++uRemainderIndex)
         drResult.remainder()[uRemainderIndex] = acNewRemainder[uRemainderIndex];
      drResult.comma() = adrResult.comma();
   }
   else {
      for (int uQuotientIndex = 0; uQuotientIndex <= drResult.quotient().lastCellIndex(); ++uQuotientIndex)
         drResult.quotient()[uQuotientIndex] = adrResult.quotient()[uQuotientIndex];
      for (int uRemainderIndex = 0; uRemainderIndex <= drResult.remainder().lastCellIndex(); ++uRemainderIndex)
         drResult.remainder()[uRemainderIndex] = adrResult.remainder()[uRemainderIndex];
      drResult.comma() = adrResult.comma();
   };
}

template <class IntegerTraits>
void
TBigInt<IntegerTraits>::divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const {
   if (!inherited::isComplete()) {
      typename ArrayCells::DivisionResult adrResult;
      ArrayCells acThis, acSource;
      acThis.assertSize(querySize()/(8*sizeof(unsigned int))+1);
      acSource.assertSize(biSource.querySize()/(8*sizeof(unsigned int))+1);
      for (int uNumeratorIndex = 0; uNumeratorIndex <= inherited::lastCellIndex(); ++uNumeratorIndex)
         acThis[uNumeratorIndex] = (*this)[uNumeratorIndex];
      acThis.setTrueBitArray(querySize());
      for (int uDenominatorIndex = 0; uDenominatorIndex <= biSource.inherited::lastCellIndex(); ++uDenominatorIndex)
         acSource[uDenominatorIndex] = biSource[uDenominatorIndex];
      acSource.setTrueBitArray(biSource.querySize());

      acThis.div(acSource, adrResult);
      int uShift = (8*sizeof(unsigned int)-drResult.quotient().lastCellSize());
      unsigned int uDivLeft = adrResult.quotient()[0] & ~(~0U << uShift);
      TBigCellInt<typename ArrayCells::QuotientResult> quotient;
      memcpy((void *)(typename ArrayCells::DivisionResult::InheritedQuotientResult*) &quotient, (const void *)&adrResult.quotient(), sizeof(typename ArrayCells::DivisionResult::InheritedQuotientResult));
      quotient >>= uShift;

      typename ArrayCells::Carry cMult = acSource.multAssign(uDivLeft);
      if (acSource.add((const ArrayCells&) adrResult.remainder()).hasCarry())
         ++cMult.carry();
      assert(((acSource[0] & ~(~0U << uShift)) == 0) && (cMult.carry() <= 1));
      acSource >>= uShift;
      if (cMult.hasCarry())
         acSource[acSource.querySize()-1] |= (cMult.carry() << biSource.lastCellSize());
      for (int uQuotientIndex = 0; uQuotientIndex <= drResult.quotient().lastCellIndex(); ++uQuotientIndex)
         drResult.quotient()[uQuotientIndex] = quotient[uQuotientIndex];
      for (int uRemainderIndex = 0; uRemainderIndex <= drResult.remainder().lastCellIndex(); ++uRemainderIndex)
         drResult.remainder()[uRemainderIndex] = acSource[uRemainderIndex];
      drResult.comma() = adrResult.comma();
   }
   else {
      assert(biSource.inherited::isComplete());
      typename ArrayCells::NormalizedDivisionResult adrResult;
      cells().divNormalized(biSource.cells(), adrResult);
      for (int uQuotientIndex = 0; uQuotientIndex <= drResult.quotient().lastCellIndex(); ++uQuotientIndex)
         drResult.quotient()[uQuotientIndex] = adrResult.quotient()[uQuotientIndex];
      for (int uRemainderIndex = 0; uRemainderIndex <= drResult.remainder().lastCellIndex(); ++uRemainderIndex)
         drResult.remainder()[uRemainderIndex] = adrResult.remainder()[uRemainderIndex];
      drResult.comma() = adrResult.comma();
   };
}

/*
template <class IntegerTraits>
typename TBigInt<IntegerTraits>::AtomicDivisionResult
TBigInt<IntegerTraits>::divAssign(unsigned int uSource) {
   AtomicDivisionResult adrResult = cells().divAssign(uSource);
   if (!inherited::isComplete()) {
      unsigned int uDivLeft = biSource.cells()[0]
         & ~(~0U << (8*sizeof(unsigned int)-uSizeLastCell));
      unsigned int
         uLowSource = uSource & ~(~0U << 4*sizeof(unsigned int)),
         uHighSource = uSource >> (4*sizeof(unsigned int)),
         uLowDivLeft = uDivLeft & ~(~0U << 4*sizeof(unsigned int)),
         uHighDivLeft = uDivLeft >> (4*sizeof(unsigned int));
      uSource = uLowSource * uLowDivLeft;
      unsigned int uCarry = 0;
      uCarry = add(uSource, (uHighSource*uLowDivLeft) << (4*sizeof(unsigned int)));
      uCarry += add(uSource, (uLowSource*uHighDivLeft) << (4*sizeof(unsigned int)));
      uCarry += add(uSource, adrResult.remainder());
      uCarry += (uHighSource*uLowDivLeft) >> (4*sizeof(unsigned int));
      uCarry += (uLowSource*uHighDivLeft) >> (4*sizeof(unsigned int));
      uCarry += uHighSource * uHighDivLeft;

      assert((uSource & ~(~0U << (8*sizeof(unsigned int)-inherited::lastCellSize())) == 0)
            && (uCarry & (~0U << (8*sizeof(unsigned int)-inherited::lastCellSize())) == 0));
      uSource >>= (8*sizeof(unsigned int)-inherited::lastCellSize());
      uSource |= uCarry << (8*sizeof(unsigned int)-inherited::lastCellSize());
      adrResult.remainder() = uSource;
   };
   return adrResult;
}
*/

}} // end of namespace Numerics::Integer

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Integer_IntegerTemplate
