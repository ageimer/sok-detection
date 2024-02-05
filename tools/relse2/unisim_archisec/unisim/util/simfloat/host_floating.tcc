/***************************************************************************
 host_floating.tcc  -  Template for various types of floating point computations
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

#ifndef Numerics_Double_HostFloatingTemplate
#define Numerics_Double_HostFloatingTemplate
#include <unisim/util/simfloat/host_floating.hh>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics {} // for precompiled headers

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#include <unisim/util/simfloat/floating.tcc>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Double {

/*******************************************/
/* Implementation - template TFloatingBase */
/*******************************************/

template <class TypeTraits>
void
TFloatingBase<TypeTraits>::fillMantissa(Mantissa& mMantissa) const {
   unsigned int auDouble[UByteSizeImplantation/sizeof(unsigned int)+1];
   memcpy(auDouble, &dDouble, UByteSizeImplantation);
   unsigned int* puMask = (unsigned int*) auDouble;
   if (TypeTraits::isBigEndian())
      puMask += (UByteSizeImplantation/sizeof(unsigned int)-1);
   for (int uMantissaIndex = 0;
         uMantissaIndex < mMantissa.lastCellIndex(); ++uMantissaIndex) {
      mMantissa[uMantissaIndex] = *puMask;
      if (TypeTraits::isBigEndian())
         --puMask;
      else
         ++puMask;
   };
   int uShift = TypeTraits::UBitSizeMantissa % (sizeof(unsigned int)*8);
   mMantissa[mMantissa.lastCellIndex()] = (uShift == 0) ? *puMask
      : ((*puMask) & ~((~0U) << uShift));
}

template <class TypeTraits>
void
TFloatingBase<TypeTraits>::setMantissa(const Mantissa& mMantissa) {
   unsigned int auDouble[UByteSizeImplantation/sizeof(unsigned int)+1];
   memcpy(auDouble, &dDouble, UByteSizeImplantation);
   unsigned int* puMask = (unsigned int*) auDouble;
   if (TypeTraits::isBigEndian())
      puMask += (UByteSizeImplantation/sizeof(unsigned int)-1);
   for (int uMantissaIndex = 0;
         uMantissaIndex < mMantissa.lastCellIndex(); ++uMantissaIndex) {
      *puMask = mMantissa[uMantissaIndex];
      if (TypeTraits::isBigEndian())
         --puMask;
      else
         ++puMask;
   };
   int uShift = TypeTraits::UBitSizeMantissa % (sizeof(unsigned int)*8);
   if (uShift == 0)
      *puMask = mMantissa[mMantissa.lastCellIndex()];
   else
      *puMask |= (mMantissa[mMantissa.lastCellIndex()] & ~((~0U) << uShift));
   memcpy(&dDouble, auDouble, UByteSizeImplantation);
}

template <class TypeTraits>
TFloatingBase<TypeTraits>&
TFloatingBase<TypeTraits>::operator=(const BuiltDouble& bdSource) {
   setMantissa(bdSource.queryMantissa());
   setBasicExponent(bdSource.queryBasicExponent().queryValue());
   setSign(bdSource.isPositive());
   return *this;
}

template <class TypeTraits>
unsigned int
TFloatingBase<TypeTraits>::queryBasicExponent() const {
   unsigned char auDouble[UByteSizeImplantation];
   memcpy(auDouble, &dDouble, UByteSizeImplantation);
   unsigned char* pcMask = (unsigned char*) auDouble;
   if (TypeTraits::isLittleEndian())
      pcMask += UByteSizeImplantation-1;
   unsigned int uResult = 0;
   int uShift = TypeTraits::UBitSizeExponent-7;
   uResult |= (*pcMask & 0x7f) << uShift;
   while ((uShift -= 8) >= 0) {
      if (TypeTraits::isLittleEndian())
         --pcMask;
      else
         ++pcMask;
      uResult |= *pcMask << uShift;
   };
   if (TypeTraits::isLittleEndian())
      --pcMask;
   else
      ++pcMask;
   if (uShift > -8)
      uResult |= *pcMask >> (-uShift);
   return uResult;
}

template <class TypeTraits>
void
TFloatingBase<TypeTraits>::setBasicExponent(unsigned int uExponent) {
   unsigned char auDouble[UByteSizeImplantation];
   memcpy(auDouble, &dDouble, UByteSizeImplantation);
   unsigned char* pcMask = (unsigned char*) auDouble;
   if (TypeTraits::isLittleEndian())
      pcMask += UByteSizeImplantation-1;
   int uShift = TypeTraits::UBitSizeExponent-7;
   assert((TypeTraits::UBitSizeExponent == sizeof(unsigned int))
         || (((~0U << TypeTraits::UBitSizeExponent) & uExponent) == 0));
   *pcMask |= uExponent >> uShift;
   while ((uShift -= 8) >= 0) {
      if (TypeTraits::isLittleEndian())
         --pcMask;
      else
         ++pcMask;
      *pcMask |= uExponent >> uShift;
   };
   if (TypeTraits::isLittleEndian())
      --pcMask;
   else
      ++pcMask;
   if (uShift > -8)
      *pcMask |= uExponent << (-uShift);
   memcpy(&dDouble, auDouble, UByteSizeImplantation);
}

/********************************************/
/* Implementation - template TDoubleElement */
/********************************************/

template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isNaN() const {
   if (!hasInftyExponent())
      return false;
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return !mMantissa.isZero();
}

template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isInternZero() const {
   if (inherited::queryBasicExponent() != 0)
      return false;
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return mMantissa.isZero();
}

template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isSNaN() const {
   if (!hasInftyExponent())
      return false;
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return !mMantissa.isZero() && !mMantissa.cbitArray(UBitSizeMantissa-1);
}

template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isQNaN() const {
   if (!hasInftyExponent())
      return false;
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return mMantissa.cbitArray(UBitSizeMantissa-1);
}

template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isInfty() const {
   if (!hasInftyExponent())
      return false;
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return mMantissa.isZero();
}

template <class FloatingBaseTraits>
void
TDoubleElement<FloatingBaseTraits>::write(std::ostream& osOut, const WriteParameters& wpFlags) const {
   if (wpFlags.isDecimal())
      osOut << inherited::implantation();
   else {
      Mantissa mMantissa;
      fillMantissa(mMantissa);
      osOut.put(inherited::isPositive() ? '+' : '-').put(' ');
#ifndef __BORLANDC__
      mMantissa.write(osOut, typename Mantissa::FormatParameters().setFullBinary(mMantissa.querySize()));
#else
      mMantissa.write(osOut, Mantissa::FormatParameters().setFullBinary(mMantissa.querySize()));
#endif
      osOut << " 2^ " << inherited::queryExponent();
   };
}


template <class FloatingBaseTraits>
bool
TDoubleElement<FloatingBaseTraits>::isPuiss2() const {
   Mantissa mMantissa;
   fillMantissa(mMantissa);
   return mMantissa.isZero();
}

template <class FloatingBaseTraits>
Errors
TDoubleElement<FloatingBaseTraits>::queryErrors() const {
   unsigned int uBasicExponent = inherited::queryBasicExponent();
   if (uBasicExponent == 0) {
      if (inherited::isZero())
         return Errors();
      return inherited::isPositive() ? Errors().setPositiveUnderflow() : Errors().setNegativeUnderflow();
   }
   else if (uBasicExponent == inherited::getMaxExponent()+inherited::getZeroExponent()+1) {
      if (isInfty())
         return inherited::isPositive() ? Errors().setPositiveOverflow() : Errors().setNegativeOverflow();
      return isQNaN() ? Errors().setQNaN() : Errors().setSNaN();
   };
   return Errors();
}

template <class FloatingBaseTraits>
void
TDoubleElement<FloatingBaseTraits>::read(std::istream& isIn, StatusAndControlFlags& scfFlags) {
   BuiltDouble bdDouble;
   bdDouble.read(isIn, scfFlags);
   operator=(bdDouble);
}

}} // end of namespace Numerics::Double

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Double_HostFloatingTemplate
