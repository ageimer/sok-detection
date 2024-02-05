/***************************************************************************
               Integer.hh  -  Template for various types of integer
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

#ifndef Numerics_Integer_IntegerH
#define Numerics_Integer_IntegerH

#include <unisim/util/endian/endian.hh>
#include <iosfwd>
#include <climits>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cassert>
#if !defined(__GNUC__) || !defined(__SUN__)
#include <string.h>
#include <ctype.h>
#endif

#ifdef __GNUC__
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Integer {

namespace Details {

class Access {
  public:
   enum ComparisonResult { CRLess=0, CREqual=1, CRGreater=2 };
   static int log_base_2(unsigned int uValue)
      {  int uResult = 1;
         while ((uValue >>= 1) != 0)
            ++uResult;
         return uResult;
      }
};

class CellIntegerTraitsContract {
  public:
   CellIntegerTraitsContract() {}
   CellIntegerTraitsContract(const CellIntegerTraitsContract& biSource) { assert(false); }
   CellIntegerTraitsContract& operator=(const CellIntegerTraitsContract& itSource) { assert(false); return *this; }
   typedef unsigned int& ArrayProperty;
   ArrayProperty array(int uIndex) { assert(false); return *((unsigned int*) NULL); }
   unsigned int array(int uIndex) const { assert(false); return 0; }
   unsigned int carray(int uIndex) const { assert(false); return 0; }
   ArrayProperty operator[](int uIndex) { assert(false); return *((unsigned int*) NULL); }
   unsigned int operator[](int uIndex) const { assert(false); return 0; }
   typedef CellIntegerTraitsContract MultResult;

   typedef CellIntegerTraitsContract QuotientResult;
   typedef CellIntegerTraitsContract RemainderResult;
   typedef CellIntegerTraitsContract NormalizedRemainderResult;
   void copyLow(const MultResult& mrResult) { assert(false); }
   int querySize() const { assert(false); return 0; }
   void adjustSize(int uNewSize) { assert(false); }
   void setSize(int uExactSize) { assert(false); }
   void normalize() { assert(false); }
   void assertSize(int uNewSize) { assert(false); }
   void clear() { assert(false); }
   typedef CellIntegerTraitsContract ExtendedInteger;
};

template <int uSize>
class TBasicCellIntegerTraits : public CellIntegerTraitsContract
{
  private:
   unsigned int auArray[uSize];
   typedef TBasicCellIntegerTraits<uSize> thisType;

  protected:
   unsigned int* _array() { return auArray; }
   const unsigned int* _array() const { return auArray; }

  public:
   TBasicCellIntegerTraits() { memset(auArray, 0, uSize*sizeof(unsigned int)); }
   TBasicCellIntegerTraits(const thisType& biSource)
      {  memcpy(auArray, biSource.auArray, uSize*sizeof(unsigned int)); }
   thisType& operator=(const thisType& itSource)
      {  memcpy(auArray, itSource.auArray, uSize*sizeof(unsigned int));
         return *this;
      }
   thisType& operator=(unsigned int uSource)
      {  if (uSize > 1)
            memset(auArray, 0, uSize*sizeof(unsigned int));
         auArray[0] = uSource;
         return *this;
      }
   typedef unsigned int& ArrayProperty;
   ArrayProperty array(int uIndex)
      {  assert(uIndex >= 0 && (uIndex < uSize));
         return auArray[uIndex];
      }
   unsigned int array(int uIndex) const
      {  assert(uIndex >= 0);
         return (uIndex < uSize) ? auArray[uIndex] : 0U;
      }
   unsigned int carray(int uIndex) const { return array(uIndex); }
   ArrayProperty operator[](int uIndex)
      {  assert(uIndex >= 0 && (uIndex < uSize));
         return auArray[uIndex];
      }
   unsigned int operator[](int uIndex) const
      {  assert(uIndex >= 0);
         return (uIndex < uSize) ? auArray[uIndex] : 0U;
      }

   static int querySize() { return uSize; }
   void normalize() {}
   void adjustSize(int uNewSize) { assert(false); }
   void assertSize(int uNewSize) { assert(uNewSize <= uSize); }
   void setSize(int uExactSize) { assert(uExactSize == uSize); }
   void clear() { memset(auArray, 0, uSize*sizeof(unsigned int)); }
   void swap(thisType& biSource)
      {  unsigned int auTemp[uSize];
         memcpy(auTemp, auArray, uSize*sizeof(unsigned int));
         memcpy(auArray, biSource.auArray, uSize*sizeof(unsigned int));
         memcpy(biSource.auArray, auTemp, uSize*sizeof(unsigned int));
      }
};

template <int uSize>
class TCellIntegerTraits : public TBasicCellIntegerTraits<uSize> {
  private:
   typedef TBasicCellIntegerTraits<uSize> inherited;
   typedef TCellIntegerTraits<uSize> thisType;

  public:
   TCellIntegerTraits() : inherited() {}
   TCellIntegerTraits(const thisType& biSource) : inherited(biSource) {}
   thisType& operator=(const thisType& itSource)
      {  return (thisType&) inherited::operator=(itSource); }
   thisType& operator=(unsigned int uSource)
      {  return (thisType&) inherited::operator=(uSource); }

   class MultResult : public TBasicCellIntegerTraits<2*uSize> {
     private:
      typedef TBasicCellIntegerTraits<2*uSize> inherited;
     public:
      MultResult() {}
      MultResult(const MultResult& mrSource) : inherited(mrSource) {}
      MultResult(const TBasicCellIntegerTraits<uSize>& itSource)
         {  memcpy(inherited::_array(), itSource._array(), uSize*sizeof(unsigned int)); }
      friend class TCellIntegerTraits<uSize>;
   };
   friend class MultResult;
   thisType& operator=(const MultResult& mrSource)
      {  memcpy(inherited::_array(), mrSource._array(), uSize*sizeof(unsigned int)); return *this; }

   typedef TCellIntegerTraits<uSize> QuotientResult;
   typedef TCellIntegerTraits<uSize> RemainderResult;
   typedef TBasicCellIntegerTraits<uSize+1> NormalizedRemainderResult;
   void copyLow(const MultResult& mrResult)
      {  memcpy(inherited::_array(), mrResult._array(), uSize*sizeof(unsigned int)); }
   typedef TBasicCellIntegerTraits<uSize+1> ExtendedInteger;
};

/*************************************/
/* Definition - template TBigCellInt */
/*************************************/

template <class IntegerTraits>
class TBigCellInt : public Details::Access, protected IntegerTraits {
  public:
   class FormatParameters {
     private:
      enum Type { TIntern, TBinary, TFullBinary, TFullHexaDecimal, TIntegerCell, TDecimal };
      Type tType;
      int uLength;
      
     public:
      FormatParameters() : tType(TIntern), uLength(0) {}
      FormatParameters(const FormatParameters& pSource) : tType(pSource.tType), uLength(pSource.uLength) {}

      bool isBinary() const { return (tType == TFullBinary) || (tType == TBinary); }
      bool isFullBinary() const { return tType == TFullBinary; }
      bool isLightBinary() const { return tType == TBinary; }
      bool isFullHexaDecimal() const { return tType == TFullHexaDecimal; }
      bool isIntern() const { return tType == TIntern; }
      bool isIntegerCell() const { return tType == TIntegerCell; }
      bool isDecimal() const { return tType == TDecimal; }

      FormatParameters& setIntern() { tType = TIntern; return *this; }
      FormatParameters& setFullBinary(int uLengthSource)
         {  tType = TFullBinary;
            uLength = uLengthSource;
            return *this;
         }
      FormatParameters& setFullHexaDecimal(int uLengthSource)
         {  tType = TFullHexaDecimal;
            uLength = uLengthSource;
            return *this;
         }
      FormatParameters& setBinary() { tType = TBinary; return *this; }
      FormatParameters& setIntegerCell() { tType = TIntegerCell; return *this; }
      FormatParameters& setDecimal() { tType = TDecimal; return *this; }
      const int& queryLength() const
         {  assert((tType == TFullBinary) || (tType == TFullHexaDecimal));
            return uLength;
         }
   };

  private:
   typedef TBigCellInt<IntegerTraits> thisType;
   typedef IntegerTraits inherited;
   class HexaChars {
     public:
      HexaChars() {}

      bool acceptChar(char chChar) const
         {  return ((chChar >= '0') && (chChar <= '9'))
                || ((chChar >= 'a') && (chChar <= 'f')) || ((chChar >= 'A') && (chChar <= 'F'));
         }
      unsigned int queryValue(char cChar) const
         {  return ((cChar >= '0') && (cChar <= '9')) ? (cChar-'0')
               : (((cChar >= 'a') && (cChar <= 'f')) ? (cChar-'a'+10)
               : (((cChar >= 'A') && (cChar <= 'F')) ? (cChar-'A'+10)
               : -1));
         }
   };
   static HexaChars hcHexaChars;

   static unsigned int add(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell += uValue;
         return (uCell < uTemp) ? 1U : 0U;
      }
   static unsigned int sub(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell -= uValue;
         return (uCell > uTemp) ? 1U : 0U;
      }
   bool verifyAtomicity() const;
   unsigned int retrieveSignificantMidDivide(int uLogBase2, bool& fExact) const;
   unsigned int retrieveSignificantMidDivideNormalized(bool& fExact) const;

#if !defined(__GNUC__) || (GCC_VERSION >= 29600)
   template <class TypeIntegerTraits> friend class TBigCellInt;
#endif
   void writeFullBinary(std::ostream& osOut, const FormatParameters& pParams) const;
   void writeFullHexaDecimal(std::ostream& osOut, const FormatParameters& pParams) const;
   void writeCells(std::ostream& osOut, const FormatParameters& pParams) const;
   void writeDecimal(std::ostream& osOut, const FormatParameters& pParams) const;

  protected:
   static int log_base_2(unsigned int uValue)
      {  return Details::Access::log_base_2(uValue); }

  public:
   typedef typename inherited::ArrayProperty ArrayProperty;
   ArrayProperty array(int uIndex) { return inherited::array(uIndex); }
   unsigned int array(int uIndex) const { return inherited::array(uIndex); }
   unsigned int carray(int uIndex) const { return array(uIndex); }
   class MidArray {
     private:
      IntegerTraits* pitArray;
      int uIndex;

     public:
      MidArray(TBigCellInt<IntegerTraits>& biSource, int uIndexSource)
         : pitArray(&biSource), uIndex(uIndexSource) {}
      MidArray& operator=(unsigned int uValue)
         {  unsigned int uStore = pitArray->array(uIndex >> 1);
            pitArray->array(uIndex >> 1) = (uIndex & 1U)
               ? ((uValue << (4*sizeof(unsigned int)))
                  | (uStore & ~(~0U << 4*sizeof(unsigned int))))
               : ((uStore & (~0U << 4*sizeof(unsigned int))) | uValue);
            return *this;
         }
      operator unsigned int() const
         {  return (uIndex & 1U) ? (pitArray->array(uIndex >> 1) >> 4*sizeof(unsigned int))
               :  (pitArray->array(uIndex >> 1) & ~(~0U << 4*sizeof(unsigned int)));
         }
   };
   friend class MidArray;
   MidArray midArray(int uIndex)
      {  return MidArray(*this, uIndex); }
   unsigned int midArray(int uIndex) const
      {  return (uIndex & 1U) ? (array(uIndex >> 1) >> 4*sizeof(unsigned int))
            :  (array(uIndex >> 1) & ~(~0U << 4*sizeof(unsigned int)));
      }
   void setMidArray(int uIndex, unsigned int uValue)
      {  unsigned int uStore = array(uIndex >> 1);
         array(uIndex >> 1) = (uIndex & 1U)
            ? ((uValue << (4*sizeof(unsigned int)))
               | (uStore & ~(~0U << 4*sizeof(unsigned int))))
            : ((uStore & (~0U << 4*sizeof(unsigned int))) | uValue);
      }
   unsigned int cmidArray(int uIndex) const { return midArray(uIndex); }

   class BitArray {
     private:
      IntegerTraits* pitArray;
      int uIndex;

     public:
      BitArray(TBigCellInt<IntegerTraits>& biSource, int uIndexSource)
         : pitArray(&biSource), uIndex(uIndexSource) {}
      BitArray(const BitArray& baSource) : pitArray(baSource.pitArray), uIndex(baSource.uIndex) {}
      BitArray& operator=(const BitArray& baSource)
         {  pitArray = baSource.pitArray;
            uIndex = baSource.uIndex;
            return *this;
         }
      BitArray& operator=(bool fValue)
         {  if (fValue)
               pitArray->array(uIndex/(sizeof(unsigned int)*8)) 
                  |= (1U << (uIndex%(sizeof(unsigned int)*8)));
            else
               pitArray->array(uIndex/(sizeof(unsigned int)*8))
                  &= ~(1U << (uIndex%(sizeof(unsigned int)*8)));
            return *this;
         }
      operator bool() const
         {  return (pitArray->array(uIndex/(sizeof(unsigned int)*8))
                  & (1U << (uIndex%(sizeof(unsigned int)*8))))
               ? true : false;
         }
   };
   friend class BitArray;
   BitArray bitArray(int uIndex)
      {  return BitArray(*this, uIndex); }
   bool bitArray(int uIndex) const
      {  return (array(uIndex/(sizeof(unsigned int)*8)) & (1U << (uIndex%(sizeof(unsigned int)*8))))
            ? true : false;
      }
   bool cbitArray(int uIndex) const { return bitArray(uIndex); }
   void setBitArray(int uIndex, bool fValue)
      {  if (fValue)
            array(uIndex/(sizeof(unsigned int)*8)) |= (1U << (uIndex%(sizeof(unsigned int)*8)));
         else
            array(uIndex/(sizeof(unsigned int)*8)) &= ~(1U << (uIndex%(sizeof(unsigned int)*8)));
      }
   void setTrueBitArray(int uIndex)
      {  array(uIndex/(sizeof(unsigned int)*8)) |= (1U << (uIndex%(sizeof(unsigned int)*8))); }
   void setFalseBitArray(int uIndex)
      {  array(uIndex/(sizeof(unsigned int)*8)) &= ~(1U << (uIndex%(sizeof(unsigned int)*8))); }

   TBigCellInt() : inherited() {}
   TBigCellInt(unsigned int uInt) : inherited() { array(0) = uInt; }
   TBigCellInt(const thisType& biSource) : inherited(biSource) {}
   thisType& operator=(const thisType& biSource)
      {  return (thisType&) inherited::operator=(biSource); }
   thisType& operator=(unsigned int uInt)
      {  inherited::clear();
         array(0) = uInt;
         return *this;
      }

   unsigned int operator[](int uIndex) const { return inherited::array(uIndex); }
   typename inherited::ArrayProperty operator[](int uIndex) { return inherited::array(uIndex); }
#ifndef __BORLANDC__
typename TBigCellInt<IntegerTraits>::ComparisonResult
#else
Integer::Details::Access::ComparisonResult
#endif
   compare(const thisType& biSource) const
   {
      ComparisonResult crResult = CREqual;
      int uIndex = inherited::querySize();
      if (uIndex < biSource.inherited::querySize())
         uIndex = biSource.inherited::querySize();
       
      while ((--uIndex >= 0) && (crResult == CREqual)) {
         if (array(uIndex) < biSource.array(uIndex))
            crResult = CRLess;
         else if (array(uIndex) > biSource.array(uIndex))
            crResult = CRGreater;
      };
      return crResult;
   }
   bool operator<(const thisType& biSource) const
      {  return compare(biSource) == CRLess; }
   bool operator>(const thisType& biSource) const
      {  return compare(biSource) == CRGreater; }
   bool operator<=(const thisType& biSource) const
      {  return compare(biSource) <= CREqual; }
   bool operator>=(const thisType& biSource) const
      {  return compare(biSource) >= CREqual; }
   bool operator==(const thisType& biSource) const
      {  return compare(biSource) == CREqual; }
   bool operator!=(const thisType& biSource) const
      {  return compare(biSource) != CREqual; }
   thisType& operator<<=(int uShift);
   thisType& operator>>=(int uShift);
   thisType& operator|=(const thisType& biSource);
   thisType& operator^=(const thisType& biSource);
   thisType& operator&=(const thisType& biSource);
   thisType& neg();
   thisType& neg(int uShift);
   bool isZero() const
   {
     bool fResult = true;
     for (int uIndex = inherited::querySize(); fResult && (--uIndex >= 0); )
       fResult = array(uIndex) == 0;
     return fResult;
   } 
   bool hasZero(int uShift) const
   {
      bool fResult = true;
      if (uShift > 0) {
         for (int uIndex = uShift/(8*sizeof(unsigned int)); fResult && (--uIndex >= 0); )
            fResult = array(uIndex) == 0;
         if (fResult && (uShift % (8*sizeof(unsigned int)) != 0))
            fResult = ((array(uShift/(8*sizeof(unsigned int)))
                        << ((8*sizeof(unsigned int))-(uShift% (8*sizeof(unsigned int))))) == 0);
      };
      return fResult;
   }
   
   class Carry {
     private:
      unsigned int uCarry;

     public:
      Carry(unsigned int uCarrySource=0U) : uCarry(uCarrySource) {}
      Carry(const Carry& cSource) : uCarry(cSource.uCarry) {}
      Carry& operator=(const Carry& cSource) { uCarry = cSource.uCarry; return *this; }

      void setCarry(bool fCarrySource=true) { uCarry = fCarrySource ? 1U : 0U; }
      bool hasCarry() const { return uCarry != 0U; }
      void setIntCarry(unsigned int uCarrySource) { uCarry = uCarrySource; }
      const unsigned int& carry() const { return uCarry; }
      unsigned int& carry() { return uCarry; }
   };
   Carry add(const thisType& biSource);
   Carry sub(const thisType& biSource);
   Carry plusAssign(const thisType& biSource) { return add(biSource); }
   Carry minusAssign(const thisType& biSource) { return sub(biSource); }
   Carry inc();
   Carry dec();

   thisType& operator+=(const thisType& biSource) { add(biSource); return *this; }
   thisType operator+(const thisType& biSource) const
      {  thisType biResult = *this; biResult += biSource; return biResult; }
   thisType& operator-=(const thisType& biSource) { sub(biSource); return *this; }
   thisType operator-(const thisType& biSource) const
      {  thisType biResult = *this; biResult -= biSource; return biResult; }
   thisType& operator--() { dec(); return *this; }
   thisType& operator++() { inc(); return *this; }
   Carry multAssign(unsigned int uSource);
   typedef typename inherited::MultResult MultResult;
   void mult(const thisType& biSource, MultResult& mrResult) const;
   thisType& operator*=(const thisType& biSource)
      {  MultResult mrResult;
         mult(biSource, mrResult);
         inherited::copyLow(mrResult);
         return *this;
      }
   thisType& operator*=(unsigned int uSource)
      {  Carry crCarry = multAssign(uSource); assert(!crCarry.hasCarry()); return *this; }

#ifndef __BORLANDC__
   class DivisionResult;
   class NormalizedDivisionResult;
   class AtomicDivisionResult;
   void div(const thisType& biSource, DivisionResult& drResult) const;
   void divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const;
   AtomicDivisionResult divAssign(unsigned int uSource);
#endif
   typedef typename inherited::QuotientResult QuotientResult;
   typedef typename inherited::RemainderResult RemainderResult;
   typedef typename inherited::NormalizedRemainderResult NormalizedRemainderResult;
   int querySize() const { return inherited::querySize(); }
   void assertSize(int uNewSize) { inherited::assertSize(uNewSize); }
   
   class DivisionResult {
     public:
      typedef typename inherited::QuotientResult InheritedQuotientResult;
      typedef typename inherited::RemainderResult InheritedRemainderResult;

     private:
      typename inherited::QuotientResult qrQuotient;
      typename inherited::RemainderResult rrRemainder;
      int uComma;

#ifndef __BORLANDC__
      friend void TBigCellInt<IntegerTraits>::div(const thisType& biSource, DivisionResult& drResult) const;
#endif

     public:
      DivisionResult() : qrQuotient(), rrRemainder(), uComma(0) {}
      DivisionResult(const DivisionResult& drSource)
         : qrQuotient(drSource.qrQuotient), rrRemainder(drSource.rrRemainder), uComma(drSource.uComma) {}
      DivisionResult& operator=(const DivisionResult& drSource)
         {  qrQuotient = drSource.qrQuotient;
            rrRemainder = drSource.rrRemainder;
            uComma = drSource.uComma;
            return *this;
         }

      const typename inherited::QuotientResult& quotient() const { return qrQuotient; }
      typename inherited::QuotientResult& quotient() { return qrQuotient; }
      const typename inherited::RemainderResult& remainder() const { return rrRemainder; }
      typename inherited::RemainderResult& remainder() { return rrRemainder; }
      const int& comma() const { return uComma; }
      int& comma() { return uComma; }
   };
   class NormalizedDivisionResult {
    private:
      typename inherited::QuotientResult qrQuotient;
      typename inherited::NormalizedRemainderResult rrRemainder;
      int uComma;

#ifndef __BORLANDC__
      friend void TBigCellInt<IntegerTraits>::divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const;
#endif

     public:
      NormalizedDivisionResult() : qrQuotient(), rrRemainder(), uComma(0) {}
      NormalizedDivisionResult(const NormalizedDivisionResult& drSource)
         : qrQuotient(drSource.qrQuotient), rrRemainder(drSource.rrRemainder), uComma(drSource.uComma) {}
      NormalizedDivisionResult& operator=(const NormalizedDivisionResult& drSource)
         {  qrQuotient = drSource.qrQuotient;
            rrRemainder = drSource.rrRemainder;
            uComma = drSource.uComma;
            return *this;
         }

      const typename inherited::QuotientResult& quotient() const { return qrQuotient; }
      typename inherited::QuotientResult& quotient() { return qrQuotient; }
      const typename inherited::NormalizedRemainderResult& remainder() const { return rrRemainder; }
      typename inherited::NormalizedRemainderResult& remainder() { return rrRemainder; }
      const int& comma() const { return uComma; }
      int& comma() { return uComma; } 
   };

   class AtomicDivisionResult {
     private:
      unsigned int uRemainder;
      
#ifndef __BORLANDC__
      friend AtomicDivisionResult TBigCellInt<IntegerTraits>::divAssign(unsigned int uSource);
#endif
     public:
      AtomicDivisionResult(unsigned int uRemainderSource=0U) : uRemainder(uRemainderSource) {}
      AtomicDivisionResult(const AtomicDivisionResult& adrSource) : uRemainder(adrSource.uRemainder) {}
      AtomicDivisionResult& operator=(const AtomicDivisionResult& adrSource)
         {  uRemainder = adrSource.uRemainder;
            return *this;
         }
      const unsigned int& modulo() const { return uRemainder; }
      const unsigned int& remainder() const { return uRemainder; }
      unsigned int& modulo() { return uRemainder; }
      unsigned int& remainder() { return uRemainder; }
   };

#ifdef __BORLANDC__
   void div(const thisType& biSource, DivisionResult& drResult) const;
   void divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const;
   AtomicDivisionResult divAssign(unsigned int uSource);
#endif
   thisType& operator/=(const thisType& biSource);
   thisType& operator/=(unsigned int uSource)
      {  divAssign(uSource);
         return *this;
      } 
  typename inherited::QuotientResult operator/(const thisType& biSource) const;
   unsigned int operator%(unsigned int uSource) const
      {  thisType bciCopy(*this);
         return bciCopy.divAssign(uSource).remainder();
      }
   thisType& operator%=(const thisType& biSource);

   unsigned int log_base_2() const;
   void write(std::ostream& osOut, const FormatParameters& pParams) const;
   void read(std::istream& isIn, const FormatParameters& pParams);
   unsigned int queryValue() const
      {  assert(verifyAtomicity());
         return array(0);
      }
   bool isAtomic() const { return verifyAtomicity(); }
   const IntegerTraits& implantation() const { return (inherited&) *this; }
   IntegerTraits& implantation() { return (inherited&) *this; }
   void swap(thisType& biSource) { inherited::swap(biSource); }
   void clear() { inherited::clear(); }
};

template <class IntegerTraits>
typename TBigCellInt<IntegerTraits>::Carry
TBigCellInt<IntegerTraits>::sub(const thisType& biSource) {
   Carry cCarry;
   if (inherited::querySize() < biSource.inherited::querySize())
      inherited::adjustSize(biSource.inherited::querySize());
   for (int uIndex = 0; uIndex < inherited::querySize(); ++uIndex) {
      unsigned int uOldCell = array(uIndex);
      array(uIndex) -= biSource.array(uIndex);
      if (cCarry.hasCarry()) {
         --array(uIndex);
         cCarry.setCarry(array(uIndex) >= uOldCell);
      }
      else
         cCarry.setCarry(array(uIndex) > uOldCell);
   };
   return cCarry;
}
  
template <class IntegerTraits>
inline TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator/=(const thisType& biSource) {
   DivisionResult drResult;
   div(biSource, drResult);
   if (drResult.comma() > 0) {
      inherited::operator=(drResult.quotient());
      operator>>=(inherited::querySize()*sizeof(unsigned int)*8-drResult.comma());
      setTrueBitArray(drResult.comma());
   }
   else if (drResult.comma() == 0)
      *this = 1U;
   else
      *this = 0U;
   return *this;
}

template <class IntegerTraits>
inline typename IntegerTraits::QuotientResult
TBigCellInt<IntegerTraits>::operator/(const thisType& biSource) const {
   DivisionResult drResult;
   div(biSource, drResult);
   if (drResult.comma() > 0) {
      TBigCellInt<typename inherited::QuotientResult>& pqrPromotedResult = (TBigCellInt<typename inherited::QuotientResult>&) drResult.quotient();
      int uShift = drResult.quotient().querySize()*sizeof(unsigned int)*8-drResult.comma();
      pqrPromotedResult >>= uShift;
      pqrPromotedResult.setTrueBitArray(drResult.comma());
   }
   else {
      drResult.quotient().clear();
      drResult.quotient()[0] = (drResult.comma() == 0) ? 1U : 0U;
   };
   return drResult.quotient();
}


template <class IntegerTraits>
inline TBigCellInt<IntegerTraits>&
TBigCellInt<IntegerTraits>::operator%=(const thisType& biSource) {
   DivisionResult drResult;
   div(biSource, drResult);
   if (drResult.comma() > 0) {
      TBigCellInt<typename inherited::QuotientResult>& pqrPromotedResult = (TBigCellInt<typename inherited::QuotientResult>&) drResult.quotient();
      pqrPromotedResult >>= (inherited::querySize()*sizeof(unsigned int)*8-drResult.comma());
      drResult.quotient()[drResult.comma()/sizeof(unsigned int)*8]
            |= (1U << (drResult.comma() % sizeof(unsigned int)*8));
      pqrPromotedResult *= biSource;
      *this -= pqrPromotedResult;
   }
   else if (drResult.comma() == 0)
      *this -= biSource;

   return *this;
}

template <class IntegerTraits>
inline std::ostream&
operator<<(std::ostream& osOut, const TBigCellInt<IntegerTraits>& bciInt) {
   bciInt.write(osOut, TBigCellInt<IntegerTraits>::FormatParameters());
   return osOut;
}

template <class IntegerTraits>
inline std::istream&
operator<<(std::istream& isIn, TBigCellInt<IntegerTraits>& bciInt) {
   bciInt.read(isIn, TBigCellInt<IntegerTraits>::FormatParameters());
   return isIn;
}

template <class IntegerTraits>
inline void
TBigCellInt<IntegerTraits>::write(std::ostream& osOut, const FormatParameters& pParams) const {
   if (pParams.isFullBinary())
      writeFullBinary(osOut, pParams);
   else if (pParams.isFullHexaDecimal())
      writeFullHexaDecimal(osOut, pParams);
   else if (!pParams.isDecimal())
      writeCells(osOut, pParams);
   else // pParams.isDecimal()
      writeDecimal(osOut, pParams);
}

} // end of namespace Details

template <class IntegerTraits>
class TBigCellInt : public Details::TBigCellInt<IntegerTraits> {
  private:
   typedef TBigCellInt<IntegerTraits> thisType;
   typedef Details::TBigCellInt<IntegerTraits> inherited;

  public:
   TBigCellInt() : inherited() {}
   TBigCellInt(unsigned int uInt) : inherited(uInt) {}
   TBigCellInt(const thisType& biSource) : inherited(biSource) {}
};

/* Optimization for the exponent of floating point numbers */

typedef Details::TBigCellInt<Details::TCellIntegerTraits<1> > AloneBigCellInt;

template <>
class TBigCellInt<Details::TCellIntegerTraits<1> > : public AloneBigCellInt {
  private:
   typedef TBigCellInt<Details::TCellIntegerTraits<1> > thisType;
   typedef AloneBigCellInt inherited;

   unsigned int& value() { return _array()[0]; }
   const unsigned int& value() const { return _array()[0]; }

   static unsigned int add(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell += uValue;
         return (uCell < uTemp) ? 1U : 0U;
      }
   static unsigned int sub(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell -= uValue;
         return (uCell > uTemp) ? 1U : 0U;
      }

  protected:
   static int log_base_2(unsigned int uValue)
      {  return Details::Access::log_base_2(uValue); }
   unsigned int& array(int uIndex) { return value(); }
   unsigned int array(int uIndex) const { return value(); }
   unsigned int carray(int uIndex) const { return value(); }

  public:
   class MidArray {
     private:
      unsigned int& uArrayValue;
      int uIndex;

     public:
      MidArray(thisType& biSource, int uIndexSource)
         : uArrayValue(biSource.value()), uIndex(uIndexSource) {}
      MidArray& operator=(unsigned int uValue)
         {  uArrayValue = (uIndex > 0)
               ? ((uValue << (4*sizeof(unsigned int)))
                  | (uArrayValue & ~(~0U << 4*sizeof(unsigned int))))
               : ((uArrayValue & (~0U << 4*sizeof(unsigned int))) | uValue);
            return *this;
         }
      operator unsigned int() const
         {  return (uIndex > 0) ? (uArrayValue >> 4*sizeof(unsigned int))
               :  (uArrayValue & ~(~0U << 4*sizeof(unsigned int)));
         }
   };
   friend class MidArray;
   MidArray midArray(int uIndex)
      {  return MidArray(*this, uIndex); }
   unsigned int midArray(int uIndex) const
      {  return (uIndex > 0) ? (value() >> 4*sizeof(unsigned int))
            :  (value() & ~(~0U << 4*sizeof(unsigned int)));
      }
   unsigned int cmidArray(int uIndex) const { return midArray(uIndex); }
   void setMidArray(int uIndex, unsigned int uValue)
      {  value() = (uIndex > 0)
            ? ((uValue << (4*sizeof(unsigned int)))
               | (value() & ~(~0U << 4*sizeof(unsigned int))))
            : ((value() & (~0U << 4*sizeof(unsigned int))) | uValue);
      }

   class BitArray {
     private:
      unsigned int& uArrayValue;
      int uIndex;

     public:
      BitArray(thisType& biSource, int uIndexSource)
         : uArrayValue(biSource.value()), uIndex(uIndexSource) {}
      BitArray(const BitArray& baSource) : uArrayValue(baSource.uArrayValue), uIndex(baSource.uIndex) {}
      BitArray& operator=(const BitArray& baSource)
         {  uArrayValue = baSource.uArrayValue;
            uIndex = baSource.uIndex;
            return *this;
         }
      BitArray& operator=(bool fValue)
         {  if (fValue)
               uArrayValue |= (1U << uIndex);
            else
               uArrayValue &= ~(1U << uIndex);
            return *this;
         }
      operator bool() const
         {  return (uArrayValue & (1U << uIndex)) ? true : false; }
   };
   friend class BitArray;
   BitArray bitArray(int uIndex)
      {  return BitArray(*this, uIndex); }
   bool bitArray(int uIndex) const
      {  return (value() & (1U << uIndex)) ? true : false; }
   bool cbitArray(int uIndex) const { return bitArray(uIndex); }
   void setBitArray(int uIndex, bool fValue)
      {  if (fValue)
            value() |= (1U << uIndex);
         else
            value() &= ~(1U << uIndex);
      }
   void setTrueBitArray(int uIndex) { value() |= (1U << uIndex); }
   void setFalseBitArray(int uIndex) { value() &= ~(1U << uIndex); }

   TBigCellInt() : inherited() {}
   TBigCellInt(unsigned int uInt) : inherited(uInt) {}
   TBigCellInt(const thisType& biSource) : inherited(biSource) {}
   thisType& operator=(const thisType& biSource)
      {  return (thisType&) inherited::operator=(biSource); }
   thisType& operator=(unsigned int uInt)
      {  value() = uInt; return *this; }

   unsigned int operator[](int uIndex) const { return value(); }
   unsigned int& operator[](int uIndex) { return value(); }
   ComparisonResult compare(const thisType& biSource) const
      {  return (value() < biSource.value()) ? CRLess
            : ((value() > biSource.value()) ? CRGreater : CREqual);
      }
   bool operator<(const thisType& biSource) const { return value() < biSource.value(); }
   bool operator>(const thisType& biSource) const { return value() > biSource.value(); }
   bool operator<=(const thisType& biSource) const { return value() <= biSource.value(); }
   bool operator>=(const thisType& biSource) const { return value() >= biSource.value(); }
   bool operator==(const thisType& biSource) const { return value() == biSource.value(); }
   bool operator!=(const thisType& biSource) const { return value() != biSource.value(); }
   thisType& operator<<=(int uShift) { value() <<= uShift; return *this; }
   thisType& operator>>=(int uShift) { value() >>= uShift; return *this; }
   thisType& operator|=(const thisType& biSource) { value() |= biSource.value(); return *this; }
   thisType& operator^=(const thisType& biSource) { value() ^= biSource.value(); return *this; }
   thisType& operator&=(const thisType& biSource) { value() &= biSource.value(); return *this; }
   thisType& neg() { value() = ~value(); return *this; }
   thisType& neg(int uShift)
      {  if (uShift > 0)
            value() = (value() & (~0U << uShift)) | (~value() & ~(~0U << uShift));
         return *this;
      }
   bool isZero() const { return value() == 0U; }
   bool hasZero(int uShift) const
      {  assert(uShift <= (int) (8*sizeof(unsigned int)));
         return (uShift <= 0)
            || ((value() << (8*sizeof(unsigned int)-uShift)) == 0U);
      }
 
   Carry add(const thisType& biSource)
      {  value() += biSource.value();
         return Carry((value() < biSource.value()) ? 1U : 0U);
      }
   Carry sub(const thisType& biSource)
      {  Carry cCarry((value() < biSource.value()) ? 1U : 0U);
         value() -= biSource.value();
         return cCarry;
      }
   Carry plusAssign(const thisType& biSource) { return add(biSource); }
   Carry minusAssign(const thisType& biSource) { return sub(biSource); }
   Carry inc() { return Carry(++value() == 0U ? 1U : 0U); }
   Carry dec() { return Carry(value()-- == 0U ? 1U : 0U); }

   thisType& operator+=(const thisType& biSource) { add(biSource); return *this; }
   thisType operator+(const thisType& biSource) const
      {  thisType biResult = *this; biResult += biSource; return biResult; }
   thisType& operator-=(const thisType& biSource) { sub(biSource); return *this; }
   thisType operator-(const thisType& biSource) const
      {  thisType biResult = *this; biResult -= biSource; return biResult; }
   thisType& operator--() { dec(); return *this; }
   thisType& operator++() { inc(); return *this; }

   int querySize() const { return 1; }
   void assertSize(int uNewSize) { assert(uNewSize <= 1); }
   
   thisType& operator/=(const thisType& biSource)
      {  assert(biSource.value() != 0U);
         value() /= biSource.value();
         return *this;
      }
   thisType& operator/=(unsigned int uSource)
      {  assert(uSource != 0U);
         value() /= uSource;
         return *this;
      }
   unsigned int operator%(unsigned int uSource) const
      {  return value() % uSource; }
   thisType& operator%=(const thisType& biSource)
      {  value() %= biSource.value(); return *this; }

   unsigned int log_base_2() const { return log_base_2(value()); }
   unsigned int queryValue() const { return value(); }
   bool isAtomic() const { return true; }
   void swap(thisType& biSource) { inherited::swap(biSource); }
   void clear() { value() = 0U; }
};

#ifdef DefineUseLongLongIntForDoubleInt
namespace Details {

template <>
class TBasicCellIntegerTraits<2> : public CellIntegerTraitsContract {
  private:
   unsigned long long int ulValue;
   typedef TBasicCellIntegerTraits<2> thisType;

  protected:
   unsigned int* _array() { return (unsigned int*) &ulValue; }
   const unsigned int* _array() const { return (const unsigned int*) &ulValue; }
   unsigned long long int& value() { return ulValue; }
   const unsigned long long int& value() const { return ulValue; }

  public:
   TBasicCellIntegerTraits() : ulValue(0) {}
   TBasicCellIntegerTraits(unsigned int uValue) : ulValue(uValue) {}
   TBasicCellIntegerTraits(const thisType& biSource) : ulValue(biSource.ulValue) {}
   thisType& operator=(const thisType& itSource)
      {  ulValue = itSource.ulValue;
         return *this;
      }
   thisType& operator=(unsigned int uSource)
      {  ulValue = uSource;
         return *this;
      }
   typedef unsigned int& ArrayProperty;
   ArrayProperty array(int uIndex)
      {  assert(!(uIndex & ~1U));
         return _array()[uIndex];
      }
   unsigned int array(int uIndex) const
      {  assert(uIndex >= 0);
         return (uIndex < 2) ? _array()[uIndex] : 0U;
      }
   unsigned int carray(int uIndex) const { return array(uIndex); }
   ArrayProperty operator[](int uIndex)
      {  assert(!(uIndex & ~1U));
         return _array()[uIndex];
      }
   unsigned int operator[](int uIndex) const
      {  assert(uIndex >= 0);
         return (uIndex < 2) ? _array()[uIndex] : 0U;
      }

   static int querySize() { return 2; }
   void normalize() {}
   void adjustSize(int uNewSize) { assert(false); }
   void assertSize(int uNewSize) { assert(uNewSize <= 2); }
   void setSize(int uExactSize) { assert(uExactSize == 2); }
   void clear() { ulValue = 0; }
   void swap(thisType& biSource)
      {  unsigned long long int ulTemp = ulValue;
         ulValue = biSource.ulValue;
         biSource.ulValue = ulTemp;
      }
};

} // end of namespace Details

typedef Details::TBigCellInt<Details::TCellIntegerTraits<2> > DoubleBigCellInt;

template <>
class TBigCellInt<Details::TCellIntegerTraits<2> > : public DoubleBigCellInt {
  private:
   typedef TBigCellInt<Details::TCellIntegerTraits<2> > thisType;
   typedef DoubleBigCellInt inherited;

   unsigned long long int& value() { return inherited::value(); } // { return *((unsigned long long int*) _array()); }
   const unsigned long long int& value() const { return inherited::value(); } // { return *((unsigned long long int*) _array()); }

   static unsigned int add(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell += uValue;
         return (uCell < uTemp) ? 1U : 0U;
      }
   static unsigned int sub(unsigned int& uCell, unsigned int uValue)
      {  unsigned int uTemp = uCell;
         uCell -= uValue;
         return (uCell > uTemp) ? 1U : 0U;
      }

  protected:
   static int log_base_2(unsigned long long int uValue)
      {  int uResult = 1;
         while ((uValue >>= 1) != 0)
            ++uResult;
         return uResult;
      }
   static int log_base_2(unsigned int uValue)
      {  return Details::Access::log_base_2(uValue); }

  public:
   class MidArray {
     private:
      unsigned long long int* plluValue;
      int uIndex;

     public:
      MidArray(thisType& biSource, int uIndexSource)
         : plluValue(&biSource.value()), uIndex(uIndexSource) { assert(uIndex < 4); }
      MidArray& operator=(unsigned int uValue)
         {  *plluValue &= (~(~0ULL << 4*sizeof(unsigned int)) << (uIndex*4*sizeof(unsigned int)));
            *plluValue |= (((unsigned long long int) uValue) << (uIndex*4*sizeof(unsigned int)));
            return *this;
         }
      operator unsigned int() const
         {  return (*plluValue >> (uIndex*4*sizeof(unsigned int)))
               & ~(~0ULL << 4*sizeof(unsigned int));
         }
   };
   friend class MidArray;
   MidArray midArray(int uIndex)
      {  return MidArray(*this, uIndex); }
   unsigned int midArray(int uIndex) const
      {  assert(uIndex < 4);
         return (value() >> (uIndex*4*sizeof(unsigned int)))
               & ~(~0ULL << 4*sizeof(unsigned int));
      }
   unsigned int cmidArray(int uIndex) const { return midArray(uIndex); }
   void setMidArray(int uIndex, unsigned int uValue)
      {  assert(uIndex < 4);
         value() &= (~(~0ULL << 4*sizeof(unsigned int)) << (uIndex*4*sizeof(unsigned int)));
         value() |= (((unsigned long long int) uValue) << (uIndex*4*sizeof(unsigned int)));
      }

   class BitArray {
     private:
      unsigned long long int* plluValue;
      int uIndex;

     public:
      BitArray(thisType& biSource, int uIndexSource)
         : plluValue(&biSource.value()), uIndex(uIndexSource) { assert(uIndex < 2*8*sizeof(unsigned int)); }
      BitArray(const BitArray& baSource) : plluValue(baSource.plluValue), uIndex(baSource.uIndex) {}
      BitArray& operator=(const BitArray& baSource)
         {  plluValue = baSource.plluValue;
            uIndex = baSource.uIndex;
            return *this;
         }
      BitArray& operator=(bool fValue)
         {  if (fValue)
               *plluValue |= (1ULL << uIndex);
            else
               *plluValue &= ~(1ULL << uIndex);
            return *this;
         }
      operator bool() const
         {  return (*plluValue & (1ULL << uIndex)) != 0ULL; }
   };
   friend class BitArray;
   BitArray bitArray(int uIndex)
      {  return BitArray(*this, uIndex); }
   bool bitArray(int uIndex) const
      {  assert(uIndex < 2*8*sizeof(unsigned int));
         return (value() & (1ULL << uIndex)) != 0ULL;
      }
   bool cbitArray(int uIndex) const { return bitArray(uIndex); }
   void setBitArray(int uIndex, bool fValue)
      {  assert(uIndex < 2*8*sizeof(unsigned int));
         if (fValue)
            value() |= (1ULL << uIndex);
         else
            value() &= ~(1ULL << uIndex);
      }
   void setTrueBitArray(int uIndex)
      {  assert(uIndex < 2*8*sizeof(unsigned int));
         value() |= (1ULL << uIndex);
      }
   void setFalseBitArray(int uIndex)
      {  assert(uIndex < 2*8*sizeof(unsigned int));
         value() &= ~(1ULL << uIndex);
      }

   TBigCellInt() : inherited() {}
   TBigCellInt(unsigned int uInt) : inherited(uInt) {}
   TBigCellInt(const thisType& biSource) : inherited(biSource) {}
   thisType& operator=(const thisType& biSource)
      {  return (thisType&) inherited::operator=(biSource); }
   thisType& operator=(unsigned int uInt)
      {  value() = uInt; return *this; }

   ComparisonResult compare(const thisType& biSource) const
      {  return (value() < biSource.value()) ? CRLess
            : ((value() > biSource.value()) ? CRGreater : CREqual);
      }
   bool operator<(const thisType& biSource) const { return value() < biSource.value(); }
   bool operator>(const thisType& biSource) const { return value() > biSource.value(); }
   bool operator<=(const thisType& biSource) const { return value() <= biSource.value(); }
   bool operator>=(const thisType& biSource) const { return value() >= biSource.value(); }
   bool operator==(const thisType& biSource) const { return value() == biSource.value(); }
   bool operator!=(const thisType& biSource) const { return value() != biSource.value(); }
   thisType& operator<<=(int uShift) { value() <<= uShift; return *this; }
   thisType& operator>>=(int uShift) { value() >>= uShift; return *this; }
   thisType& operator|=(const thisType& biSource) { value() |= biSource.value(); return *this; }
   thisType& operator^=(const thisType& biSource) { value() ^= biSource.value(); return *this; }
   thisType& operator&=(const thisType& biSource) { value() &= biSource.value(); return *this; }
   thisType& neg()
      {  value() = ~value();
         return *this;
      }
   thisType& neg(int uShift)
      {  if (uShift > 0)
            value() = (value() & (~0ULL << uShift)) | (~value() & ~(~0ULL << uShift));
         return *this;
      }
   bool isZero() const { return value() == 0U; }
   bool hasZero(int uShift) const
      {  assert(uShift <= 8*sizeof(unsigned long long int));
         return (uShift <= 0)
            || ((value() << (8*sizeof(unsigned long long int)-uShift)) == 0ULL);
      }
 
   Carry add(const thisType& biSource)
      {  value() += biSource.value();
         return Carry((value() < biSource.value()) ? 1U : 0U);
      }
   Carry sub(const thisType& biSource)
      {  Carry cCarry((value() < biSource.value()) ? 1U : 0U);
         value() -= biSource.value();
         return cCarry;
      }
   Carry plusAssign(const thisType& biSource) { return add(biSource); }
   Carry minusAssign(const thisType& biSource) { return sub(biSource); }
   Carry inc() { return Carry(++value() == 0U ? 1U : 0U); }
   Carry dec() { return Carry(value()-- == 0U ? 1U : 0U); }

   thisType& operator+=(const thisType& biSource) { add(biSource); return *this; }
   thisType operator+(const thisType& biSource) const
      {  thisType biResult = *this; biResult += biSource; return biResult; }
   thisType& operator-=(const thisType& biSource) { sub(biSource); return *this; }
   thisType operator-(const thisType& biSource) const
      {  thisType biResult = *this; biResult -= biSource; return biResult; }
   thisType& operator--() { dec(); return *this; }
   thisType& operator++() { inc(); return *this; }

   int querySize() const { return 2; }
   void assertSize(int uNewSize) { assert(uNewSize <= 2); }
   
   thisType& operator/=(const thisType& biSource)
      {  assert(biSource.value() != 0U);
         value() /= biSource.value();
         return *this;
      }
   thisType& operator/=(unsigned int uSource)
      {  assert(uSource != 0U);
         value() /= uSource;
         return *this;
      }
   unsigned long long int operator%(unsigned int uSource) const
      {  return value() % uSource; }
   thisType& operator%=(const thisType& biSource)
      {  value() %= biSource.value(); return *this; }

   unsigned int log_base_2() const { return log_base_2(value()); }
   unsigned int queryValue() const { return value(); }
   bool isAtomic() const { return !_array()[1]; }
   void swap(thisType& biSource) { inherited::swap(biSource); }
   void clear() { value() = 0U; }
};

#endif // DefineUseLongIntForDoubleInt

/*********************************/
/* Definition - template TBigInt */
/*********************************/

template <class IntegerTraits>
class TBigInt;

namespace Details {

template <int uSize>
class TIntegerTraits {
  public:
   static const int uCellSize = (uSize-1)/(8*sizeof(unsigned int))+1;
#ifndef __BORLANDC__
   typedef TCellIntegerTraits<uCellSize> CellTraits;
#if defined(__GNUC__) && GCC_VERSION >= 40400
   typedef TBigCellInt<CellTraits> BigCellTraits;
#endif
#else
   typedef TCellIntegerTraits<(uSize-1)/(8*sizeof(unsigned int))+1> CellTraits;
#endif

  private:
   typedef TIntegerTraits<uSize> thisType;
#if defined(__GNUC__) && GCC_VERSION >= 40400
   BigCellTraits ctTraits;
#else
   CellTraits ctTraits;
#endif

  protected:
#if defined(__GNUC__) && GCC_VERSION >= 40400
   BigCellTraits& cellTraits() { return ctTraits; }
   const BigCellTraits& cellTraits() const { return ctTraits; }
#else
   CellTraits& cellTraits() { return ctTraits; }
   const CellTraits& cellTraits() const { return ctTraits; }
#endif
  public:
   TIntegerTraits() : ctTraits() {}
   TIntegerTraits(const thisType& itSource) : ctTraits(itSource.ctTraits) {}
   TIntegerTraits& operator=(const thisType& itSource)
      {  ctTraits = itSource.ctTraits;
         return *this;
      }
   TIntegerTraits& operator=(unsigned int uSource)
      {  ctTraits = uSource;
         return *this;
      }

   static int lastCellIndex() { return (uSize-1)/(8*sizeof(unsigned int)); }
   static int lastCellSize() { return ((uSize-1) % (8*sizeof(unsigned int)) +1); }
   static bool isComplete() { return ((uSize % (8*sizeof(unsigned int))) == 0); }
   void normalizeLastCell()
      {  if (lastCellSize() < (int)(8*sizeof(unsigned int)))
            ctTraits[lastCellIndex()] &= ~(~0U << lastCellSize());
      }
   void normalize()
      {  if (lastCellSize() < (int) (8*sizeof(unsigned int)))
            ctTraits[lastCellIndex()] &= ~(~0U << lastCellSize());
         // for (int uIndex = lastCellIndex()+1; uIndex < ctTraits.querySize(); ++uIndex)
         //   ctTraits[uIndex] = 0U;
      }
   
   typedef unsigned int& ArrayProperty;
   ArrayProperty array(int uIndex) { return ctTraits.array(uIndex); }
   unsigned int array(int uIndex) const { return ctTraits.array(uIndex); }
   unsigned int carray(int uIndex) const { return array(uIndex); }
   ArrayProperty operator[](int uIndex) { return ctTraits[uIndex]; }
   unsigned int operator[](int uIndex) const { return ctTraits[uIndex]; }
   static int querySize() { return uSize; }

   typedef TIntegerTraits<2*uSize> MultResult;
   typedef TIntegerTraits<uSize> QuotientResult;
   typedef TIntegerTraits<uSize> RemainderResult;
   typedef TIntegerTraits<uSize+1> NormalizedRemainderResult;
   void assertSize(int uNewSize) { assert(uSize >= uNewSize); }
};

} // end of namespace Details

template <class IntegerTraits>
class TBigInt : public Details::Access, protected IntegerTraits {
  private:
   typedef IntegerTraits inherited;
   typedef TBigInt<IntegerTraits> thisType;
#if defined(__GNUC__) && GCC_VERSION >= 40400
   typedef typename IntegerTraits::BigCellTraits ArrayCells;
#else
   typedef TBigCellInt<typename IntegerTraits::CellTraits> ArrayCells;
#endif

  protected:
   static int log_base_2(unsigned int uValue)
      {  return Details::Access::log_base_2(uValue); }
   ArrayCells& cells() { return (ArrayCells&) inherited::cellTraits(); }
   const ArrayCells& cells() const { return (const ArrayCells&) inherited::cellTraits(); }

  public:
   typedef typename ArrayCells::MidArray MidArray;
   MidArray midArray(int uIndex) { return cells().midArray(uIndex); }
   unsigned int midArray(int uIndex) const { return cells().midArray(uIndex); }
   unsigned int cmidArray(int uIndex) const { return midArray(uIndex); }

   typedef typename ArrayCells::BitArray BitArray;
   BitArray bitArray(int uIndex) { return cells().bitArray(uIndex); }
   bool bitArray(int uIndex) const { return cells().bitArray(uIndex); }
   bool cbitArray(int uIndex) const { return bitArray(uIndex); }
   void setBitArray(int uIndex, bool fValue) { cells().setBitArray(uIndex, fValue); }
   void setTrueBitArray(int uIndex) { cells().setTrueBitArray(uIndex); }
   void setFalseBitArray(int uIndex) { cells().setFalseBitArray(uIndex); }

   TBigInt() {}
   TBigInt(unsigned int uInt) { cells() = uInt; }
   TBigInt(const thisType& biSource) : inherited(biSource) {}
   thisType& operator=(const thisType& biSource)
      {  return (thisType&) inherited::operator=(biSource); }
   thisType& operator=(unsigned int uValue)
      {  return (thisType&) inherited::operator=(uValue); }

   typedef typename IntegerTraits::CellTraits::ArrayProperty ArrayProperty;
   unsigned int operator[](int uIndex) const { return inherited::operator[](uIndex); }
   ArrayProperty operator[](int uIndex) { return inherited::operator[](uIndex); }
   unsigned int array(int uIndex) const { return inherited::array(uIndex); }
   unsigned int carray(int uIndex) const { return array(uIndex); }
   ArrayProperty array(int uIndex) { return inherited::array(uIndex); }
   ComparisonResult compare(const thisType& biSource) const { return cells().compare(biSource.cells()); }
   bool operator<(const thisType& biSource) const { return cells() < biSource.cells(); }
   bool operator>(const thisType& biSource) const { return cells() > biSource.cells(); }
   bool operator<=(const thisType& biSource) const { return cells() <= biSource.cells(); }
   bool operator>=(const thisType& biSource) const { return cells() >= biSource.cells(); }
   bool operator==(const thisType& biSource) const { return cells() == biSource.cells(); }
   bool operator!=(const thisType& biSource) const { return cells() != biSource.cells(); }
   thisType& operator<<=(int uShift)
      {  cells() <<= uShift;
         inherited::normalize();
         return *this;
      }
   thisType& leftShiftAssign(int uShift)
      {  cells() <<= uShift;
         return *this;
      }
   thisType& operator>>=(int uShift) {  cells() >>= uShift; return *this; }
   thisType& operator|=(const thisType& biSource) { cells() |= biSource.cells(); return *this; }
   thisType& operator^=(const thisType& biSource) { cells() ^= biSource.cells(); return *this; }
   thisType& operator&=(const thisType& biSource) { cells() &= biSource.cells(); return *this; }
   thisType& neg()
      {  cells().neg();
         inherited::normalize();
         return *this;
      }
   thisType& neg(int uShift)
      {  assert(uShift <= inherited::querySize());
         cells().neg(uShift);
         return *this;
      }
   thisType operator&(const thisType& biSource) const { thisType biResult(*this); biResult &= biSource; return biResult; }
   thisType operator|(const thisType& biSource) const { thisType biResult(*this); biResult |= biSource; return biResult; }
   thisType operator<<(int uShift) const { thisType biResult(*this); biResult <<= uShift; return biResult; }
   thisType operator>>(int uShift) const { thisType biResult(*this); biResult >>= uShift; return biResult; }
   thisType operator~() const { thisType biResult(*this); biResult.neg(); return biResult; }
   
   void normalize() { inherited::normalize(); }
   int lastCellIndex() const { return inherited::lastCellIndex(); }
   typedef typename ArrayCells::Carry Carry;
   Carry add(const thisType& biSource)
      {  Carry cResult = cells().add(biSource.cells());
         if (!inherited::isComplete()) {
            cResult = Carry((cells().cbitArray(inherited::querySize())));
            cells().setFalseBitArray(inherited::querySize());
         };
         return cResult;
      }
   Carry sub(const thisType& biSource)
      {  Carry cResult = cells().sub(biSource.cells());
         if (cResult.hasCarry() && !inherited::isComplete())
            inherited::normalize();
         return cResult;
      }
   Carry plusAssign(const thisType& biSource) { return add(biSource); }
   Carry minusAssign(const thisType& biSource) { return sub(biSource); }
   Carry inc()
      {  Carry cResult = cells().inc();
         if (!inherited::isComplete()) {
            cResult = Carry((cells().cbitArray(inherited::querySize())));
            cells().setFalseBitArray(inherited::querySize());
         };
         return cResult;
      }
   Carry dec()
      {  Carry cResult = cells().dec();
         if (cResult.hasCarry() && !inherited::isComplete())
            inherited::normalize();
         return cResult;
      }
   int querySize() const { return inherited::querySize(); }
   int queryCellSize() const { return cells().querySize(); }

   thisType& operator+=(const thisType& biSource) { add(biSource); return *this; }
   thisType operator+(const thisType& biSource) const
      {  thisType biResult = *this; biResult += biSource; return biResult; }
   thisType& operator-=(const thisType& biSource) { sub(biSource); return *this; }
   thisType operator-(const thisType& biSource) const
      {  thisType biResult = *this; biResult -= biSource; return biResult; }
   thisType& operator--() { dec(); return *this; }
   thisType& operator++() { inc(); return *this; }

   Carry multAssign(unsigned int uSource)
      {  Carry crResult = cells().multAssign(uSource);
         if (!inherited::isComplete()) {
            if (inherited::lastCellIndex() < cells().querySize()-1) {
               assert(!crResult.hasCarry());
               crResult.carry() = cells()[inherited::lastCellIndex()+1];
            };

            crResult.carry() <<= (8*sizeof(unsigned int) - inherited::lastCellSize());
            if (inherited::lastCellSize() < (int) (8*sizeof(unsigned int)))
               crResult.carry() |= (cells()[inherited::lastCellIndex()] >> inherited::lastCellSize());
            inherited::normalize();
         };
         return crResult;    
      }
   typedef typename inherited::MultResult MultResult;
   void mult(const thisType& biSource, MultResult& mrResult) const
      {  typename IntegerTraits::CellTraits::MultResult cmrLocalResult;
         cells().mult(biSource.cells(), cmrLocalResult);
         int uLast = mrResult.lastCellIndex();
         for (int uIndex = 0; uIndex <= uLast; ++uIndex)
            mrResult[uIndex] = cmrLocalResult[uIndex];
      }
   thisType& operator*=(const thisType& biSource)
      {  cells() *= biSource.cells();
         inherited::normalize();
         return *this;
      }
   thisType& operator*=(unsigned int uSource)
      {  multAssign(uSource); return *this; }

   typedef typename inherited::QuotientResult QuotientResult;
   typedef typename inherited::RemainderResult RemainderResult;
   class DivisionResult {
     public:
      typedef typename inherited::QuotientResult InheritedQuotientResult;
      typedef typename inherited::RemainderResult InheritedRemainderResult;

     private:
      typename inherited::QuotientResult qrQuotient;
      typename inherited::RemainderResult rrRemainder;
      int uComma;

     public:
      DivisionResult() : qrQuotient(), rrRemainder(), uComma(0) {}
      DivisionResult(const DivisionResult& drSource)
         : qrQuotient(drSource.qrQuotient), rrRemainder(drSource.rrRemainder), uComma(drSource.uComma) {}
      DivisionResult& operator=(const DivisionResult& drSource)
         {  qrQuotient = drSource.qrQuotient;
            rrRemainder = drSource.rrRemainder;
            uComma = drSource.uComma;
            return *this;
         }

      const typename inherited::QuotientResult& quotient() const { return qrQuotient; }
      typename inherited::QuotientResult& quotient() { return qrQuotient; }
      const typename inherited::RemainderResult& remainder() const { return rrRemainder; }
      typename inherited::RemainderResult& remainder() { return rrRemainder; }
      const int& comma() const { return uComma; }
      int& comma() { return uComma; }
   };
   typedef typename inherited::NormalizedRemainderResult NormalizedRemainderResult;
   class NormalizedDivisionResult {
     private:
      typename inherited::QuotientResult qrQuotient;
      typename inherited::NormalizedRemainderResult rrRemainder;
      int uComma;

     public:
      NormalizedDivisionResult() : qrQuotient(), rrRemainder(), uComma(0) {}
      NormalizedDivisionResult(const NormalizedDivisionResult& drSource)
         : qrQuotient(drSource.qrQuotient), rrRemainder(drSource.rrRemainder), uComma(drSource.uComma) {}
      NormalizedDivisionResult& operator=(const NormalizedDivisionResult& drSource)
         {  qrQuotient = drSource.qrQuotient;
            rrRemainder = drSource.rrRemainder;
            uComma = drSource.uComma;
            return *this;
         }

      const typename inherited::QuotientResult& quotient() const { return qrQuotient; }
      typename inherited::QuotientResult& quotient() { return qrQuotient; }
      const typename inherited::NormalizedRemainderResult& remainder() const { return rrRemainder; }
      typename inherited::NormalizedRemainderResult& remainder() { return rrRemainder; }
      const int& comma() const { return uComma; }
      int& comma() { return uComma; }
   };
   typedef typename ArrayCells::AtomicDivisionResult AtomicDivisionResult;

   void div(const thisType& biSource, DivisionResult& drResult) const;
   void divNormalized(const thisType& biSource, NormalizedDivisionResult& drResult) const;
   AtomicDivisionResult divAssign(unsigned int uSource) { return cells().divAssign(uSource); }

   thisType& operator/=(const thisType& biSource);
   thisType& operator/=(unsigned int uSource)
      {  divAssign(uSource);
         return *this;
      }
   typename inherited::QuotientResult operator/(const thisType& biSource) const;
   unsigned int operator%(unsigned int uSource) const
      {  return ArrayCells(cells()).divAssign(uSource).remainder(); }
   thisType& operator%=(const thisType& biSource) { cells() %= biSource.cells(); return *this; }

   unsigned int log_base_2() const { return cells().log_base_2(); }
   typedef typename ArrayCells::FormatParameters FormatParameters;
   void write(std::ostream& osOut, const FormatParameters& pParams) const
      {  cells().write(osOut, pParams); }
   void read(std::istream& isIn, const FormatParameters& pParams)
      {  cells().read(isIn, pParams); }
   unsigned int queryValue() const { return cells().queryValue(); }
   bool isAtomic() const { return cells().isAtomic(); }
   bool isZero() const { return cells().isZero(); }
   bool hasZero(int uShift) const { return cells().hasZero(uShift); }
   void assertSize(int uNewSize) { inherited::assertSize(uNewSize); }
   void clear() { cells().clear(); }
   void swap(thisType& biSource) {  cells().swap(biSource.cells()); }
};

template <class IntegerTraits>
inline TBigInt<IntegerTraits>&
TBigInt<IntegerTraits>::operator/=(const thisType& biSource) {
   DivisionResult drResult;
   div(biSource, drResult);
   if (drResult.comma() > 0) {
      inherited::operator=(drResult.quotient());
      operator>>=(inherited::querySize()-drResult.comma());
      setTrueBitArray(drResult.comma());
   }
   else if (drResult.comma() == 0)
      *this = 1U;
   else
      *this = 0U;
   return *this;
}

template <class IntegerTraits>
inline typename IntegerTraits::QuotientResult
TBigInt<IntegerTraits>::operator/(const thisType& biSource) const {
   DivisionResult drResult;
   div(biSource, drResult);
   if (drResult.comma() > 0) {
      TBigInt<typename IntegerTraits::QuotientResult>& pqrPromotedResult
		  = (TBigInt<typename IntegerTraits::QuotientResult>&) drResult.quotient();
      pqrPromotedResult >>= (inherited::querySize()-drResult.comma());
      pqrPromotedResult.setTrueBitArray(drResult.comma());
   }
   else if (drResult.comma() == 0)
      drResult.quotient()[0] = 1U;
   return drResult.quotient();
}

template <class IntegerTraits>
inline std::ostream&
operator<<(std::ostream& osOut, const TBigInt<IntegerTraits>& biInt) {
#ifndef __BORLANDC__
   biInt.write(osOut, typename TBigInt<IntegerTraits>::FormatParameters());
#else
   biInt.write(osOut, TBigInt<IntegerTraits>::FormatParameters());
#endif
   return osOut;
}

template <class IntegerTraits>
inline std::istream&
operator<<(std::istream& isIn, TBigInt<IntegerTraits>& biInt) {
   biInt.read(isIn, typename TBigInt<IntegerTraits>::FormatParameters());
   return isIn;
}

}} // end of namespace Numerics::Integer

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Integer_IntegerH

