/***************************************************************************
  host_floating.hh  -  Template for various types of floating point computations
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

#ifndef Numerics_Double_HostFloatingH
#define Numerics_Double_HostFloatingH

#include <unisim/util/simfloat/floating.hh>

namespace unisim {
namespace util {
namespace simfloat {

namespace Numerics { namespace Double {

class DoubleTraits {
  public:
   typedef double TypeFloat;
   static double max()              { return DBL_MAX; }
   static double normalizedMin()    { return DBL_MIN; }
   static double denormalizedMin()  { return DBL_MIN*DBL_EPSILON; }
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
         return *((unsigned char*) &dummy) == 0x12;
#endif
      }
   static bool isLittleEndian() { return !isBigEndian(); }

   static const int UBitSizeMantissa = DBL_MANT_DIG-1;
   static const int UByteSizeImplantation = sizeof(TypeFloat);
   static const int UBitSizeExponent = UByteSizeImplantation*8-DBL_MANT_DIG;
   static unsigned int getMaxExponent() { return DBL_MAX_EXP-1; }
   static unsigned int getZeroExponent() { return DBL_MAX_EXP-1; }
   static double epsilon() { return DBL_EPSILON; }
   static bool isValid() { return (UBitSizeExponent <= (int) sizeof(int)*8); }
};

class FloatTraits {
  public:
   typedef float TypeFloat;
   static float max()              { return FLT_MAX; }
   static float normalizedMin()    { return FLT_MIN; }
   static float denormalizedMin()  { return FLT_MIN*FLT_EPSILON; }
   static bool isBigEndian()
      {
#if defined(__GNUC__) && !defined(__LINUX__)
#if BYTE_ORDER == BIG_ENDIAN
         return true;
#else
         return false;
#endif
#else
         int dummy = 0x1234;
         return *((unsigned char*) &dummy) == 0x12;
#endif
      }

   inline static bool isLittleEndian() { return !isBigEndian(); }

   static const int UBitSizeMantissa = FLT_MANT_DIG-1;
   static const int UByteSizeImplantation = sizeof(TypeFloat);
   static const int UBitSizeExponent = UByteSizeImplantation*8-FLT_MANT_DIG;
   inline static unsigned int getMaxExponent() { return FLT_MAX_EXP-1; }
   inline static unsigned int getZeroExponent() { return FLT_MAX_EXP-1; }
   inline static float epsilon() { return FLT_EPSILON; }
   inline static bool isValid() { return (UBitSizeExponent <= (int) sizeof(int)*8); }
};

class LongDoubleTraits {
  public:
   typedef long double TypeFloat;
   static long double max()              { return LDBL_MAX; }
   static long double normalizedMin()    { return LDBL_MIN; }
   static long double denormalizedMin()  { return LDBL_MIN*LDBL_EPSILON; }
   static bool isBigEndian()
      {
#if defined(__GNUC__) && !defined(__LINUX__)
#if BYTE_ORDER == BIG_ENDIAN
         return true;
#else
         return false;
#endif
#else
         int dummy = 0x1234;
         return *((unsigned char*) &dummy) == 0x12;
#endif
      }
   static bool isLittleEndian() { return !isBigEndian(); }

   static const int UBitSizeMantissa = LDBL_MANT_DIG-1;
   static const int UByteSizeImplantation = sizeof(TypeFloat);
   static const int UBitSizeExponent = UByteSizeImplantation*8-LDBL_MANT_DIG;
   static unsigned int getMaxExponent() { return LDBL_MAX_EXP-1; }
   static unsigned int getZeroExponent() { return LDBL_MAX_EXP-1; }
   static long double epsilon() { return LDBL_EPSILON; }
   static bool isValid() { return (UBitSizeExponent <= (int) sizeof(int)*8); }
};

template <class TypeTraits>
class TFloatingBase {
  public:
   typedef TBuiltDouble<BuiltDoubleTraits<TypeTraits::UBitSizeMantissa, TypeTraits::UBitSizeExponent> >
      BuiltDouble;

  protected:
   typedef typename TypeTraits::TypeFloat Implantation;
   typedef TFloatingBase<TypeTraits> thisType;

  private:
   Implantation dDouble;

  public:
   TFloatingBase() : dDouble(0.0) {}
   TFloatingBase(const Implantation& dDoubleSource) : dDouble(dDoubleSource) {}
   TFloatingBase(const BuiltDouble& bdDouble) : dDouble(0.0) { operator=(bdDouble); }
   TFloatingBase(const thisType& sSource) : dDouble(sSource.dDouble) {}
   thisType& operator=(const thisType& dsSource)
      {  dDouble = dsSource.dDouble; return *this; }
   thisType& operator=(const BuiltDouble& bdDouble);
   operator BuiltDouble() const
      {  BuiltDouble bdResult;
         fillMantissa(bdResult.querySMantissa());
#ifndef __BORLANDC__
         bdResult.setBasicExponent(typename BuiltDouble::Exponent(typename BuiltDouble::Exponent::Basic(), queryBasicExponent()));
#else
         bdResult.setBasicExponent(BuiltDouble::Exponent(BuiltDouble::Exponent::Basic(), queryBasicExponent()));
#endif
         bdResult.setSign(isPositive());
         return bdResult;
	  }
   
   Implantation& implantation() { return dDouble; } 
   const Implantation& implantation() const { return dDouble; } 
   thisType queryEpsilon() const
      {  Implantation dtiResult = implantation()*TypeTraits::epsilon();
         if ((dtiResult == 0.0) && (implantation() != 0.0))
            return thisType(TypeTraits::denormalizedMin());
         return thisType((dtiResult >= 0.0) ? dtiResult : -dtiResult);
      }
   
   bool isZero() const { return (dDouble == 0.0) || (-dDouble == 0.0); }
   
   typedef Details::DTDoubleElement::Access::StatusAndControlFlags StatusAndControlFlags;
   thisType& plusAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags);
   thisType& minusAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags);
   thisType& multAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags);
   thisType& divAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags);

   thisType& operator-=(const thisType& ttSource)
      {  dDouble -= ttSource.dDouble; return *this; }
   thisType& operator*=(const thisType& ttSource)
      {  dDouble *= ttSource.dDouble; return *this; }
   thisType& operator+=(const thisType& ttSource)
      {  dDouble += ttSource.dDouble; return *this; }
   thisType& operator/=(const thisType& ttSource)
      {  dDouble /= ttSource.dDouble; return *this; }

   static const int UByteSizeImplantation = TypeTraits::UByteSizeImplantation;
   static const int UBitSizeMantissa = TypeTraits::UBitSizeMantissa;
   static const int UBitSizeExponent = TypeTraits::UBitSizeExponent;
   typedef typename BuiltDouble::Mantissa Mantissa;
   void fillMantissa(Mantissa& mMantissa) const;
   void setMantissa(const Mantissa& mMantissa);
   static unsigned int getMaxExponent() { return TypeTraits::getMaxExponent(); }
   static unsigned int getZeroExponent() { return TypeTraits::getZeroExponent(); }
   thisType& opposite() { dDouble = -dDouble; return *this; }
 
   unsigned int queryBasicExponent() const;
   int queryExponent() const
      {  return ((int) queryBasicExponent()) - getZeroExponent(); }
   void setBasicExponent(unsigned int uExponent);
   void setExponent(int uExponent)
      {  setBasicExponent(uExponent+getZeroExponent()); }
   bool isPositive() const
      {  unsigned char auDouble[UByteSizeImplantation];
         memcpy(auDouble, &dDouble, UByteSizeImplantation);
         unsigned char* pcMask = (unsigned char*) auDouble;
         if (TypeTraits::isLittleEndian())
            pcMask += UByteSizeImplantation-1;
         return !((*pcMask) & 0x80);
      }
   bool isNegative() const { return !isPositive(); }
   void setSign(bool fPositive)
      {  unsigned char auDouble[UByteSizeImplantation];
         memcpy(auDouble, &dDouble, UByteSizeImplantation);
         unsigned char* pcMask = (unsigned char*) auDouble;
         if (TypeTraits::isLittleEndian())
            pcMask += UByteSizeImplantation-1;
         if (fPositive)
            *pcMask &= 0x7f;
         else
            *pcMask |= 0x80;
         memcpy(&dDouble, auDouble, UByteSizeImplantation);
      }
   void setPositive() { setSign(true); }
   void setNegative() { setSign(false); }
   bool isNormalised() const
      {  return ((TypeTraits::normalizedMin() <= dDouble) && (dDouble <= TypeTraits::max()))
            || ((-TypeTraits::normalizedMin() >= dDouble) && (dDouble >= -TypeTraits::max()));
      }
   bool isRanged() const
      {  return ((TypeTraits::denormalizedMin() <= dDouble) && (dDouble <= TypeTraits::max()))
            || ((-TypeTraits::denormalizedMin() >= dDouble) && (dDouble >= -TypeTraits::max()));
      }
   void clear() { dDouble = 0.0; }
   void swap(thisType& dSource)
      {  Implantation dTemp = dDouble;
         dDouble = dSource.dDouble;
         dSource.dDouble = dTemp;
      }
};

#ifdef __BORLANDC__
#define _MCW_RC 0x00000300
#define _RC_CHOP 0x00000300
#define _RC_UP 0x00000200
#define _RC_DOWN 0x00000100
#define _RC_NEAR 0x00000000
#endif

template <class TypeTraits>
inline TFloatingBase<TypeTraits>&
TFloatingBase<TypeTraits>::plusAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags) {  
#ifdef DefineComputeParameters
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   _controlfp(_RC_DOWN, _MCW_RC);
   double dMin = dDouble+ttSource.dDouble;
   _controlfp(_RC_UP, _MCW_RC);
   double dMax = dDouble+ttSource.dDouble;
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble += ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   fpsetround(FP_RM);
   double dMin = dDouble+ttSource.dDouble;
   fpsetround(FP_RP);
   double dMax = dDouble+ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble += ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   fesetround(FE_DOWNWARD);
   double dMin = dDouble+ttSource.dDouble;
   fesetround(FE_UPWARD);
   double dMax = dDouble+ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble += ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
   if (dMin != dMax) {
      if (dDouble == dMin)
         scfFlags.setDownApproximate();
      else {
         assert(dDouble == dMax);
         scfFlags.setUpApproximate();
      };
   };
#else
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble += ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble += ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble += ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
#endif // DefineComputeParameters
   return *this;
}

template <class TypeTraits>
inline TFloatingBase<TypeTraits>&
TFloatingBase<TypeTraits>::minusAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags) {  
#ifdef DefineComputeParameters
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   _controlfp(_RC_DOWN, _MCW_RC);
   double dMin = dDouble-ttSource.dDouble;
   _controlfp(_RC_UP, _MCW_RC);
   double dMax = dDouble-ttSource.dDouble;
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble -= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   fpsetround(FP_RM);
   double dMin = dDouble-ttSource.dDouble;
   fpsetround(FP_RP);
   double dMax = dDouble-ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble -= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   fesetround(FE_DOWNWARD);
   double dMin = dDouble-ttSource.dDouble;
   fesetround(FE_UPWARD);
   double dMax = dDouble-ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble -= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
   if (dMin != dMax) {
      if (dDouble == dMin)
         scfFlags.setDownApproximate();
      else {
         assert(dDouble == dMax);
         scfFlags.setUpApproximate();
      };
   };
#else
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble -= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble -= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble -= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
#endif
   return *this;
}

template <class TypeTraits>
inline TFloatingBase<TypeTraits>&
TFloatingBase<TypeTraits>::multAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags) {  
#ifdef DefineComputeParameters
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   _controlfp(_RC_DOWN, _MCW_RC);
   double dMin = dDouble*ttSource.dDouble;
   _controlfp(_RC_UP, _MCW_RC);
   double dMax = dDouble*ttSource.dDouble;
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble *= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   fpsetround(FP_RM);
   double dMin = dDouble*ttSource.dDouble;
   fpsetround(FP_RP);
   double dMax = dDouble*ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble *= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   fesetround(FE_DOWNWARD);
   double dMin = dDouble*ttSource.dDouble;
   fesetround(FE_UPWARD);
   double dMax = dDouble*ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble *= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
   if (dMin != dMax) {
      if (dDouble == dMin)
         scfFlags.setDownApproximate();
      else {
         assert(dDouble == dMax);
         scfFlags.setUpApproximate();
      };
   };
#else
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble *= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble *= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble *= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
#endif
   return *this;
}

template <class TypeTraits>
inline TFloatingBase<TypeTraits>&
TFloatingBase<TypeTraits>::divAssign(const thisType& ttSource, const StatusAndControlFlags& scfFlags) {  
#ifdef DefineComputeParameters
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   _controlfp(_RC_DOWN, _MCW_RC);
   double dMin = dDouble/ttSource.dDouble;
   _controlfp(_RC_UP, _MCW_RC);
   double dMax = dDouble/ttSource.dDouble;
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble /= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   fpsetround(FP_RM);
   double dMin = dDouble/ttSource.dDouble;
   fpsetround(FP_RP);
   double dMax = dDouble/ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble /= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   fesetround(FE_DOWNWARD);
   double dMin = dDouble/ttSource.dDouble;
   fesetround(FE_UPWARD);
   double dMax = dDouble/ttSource.dDouble;
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble /= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
   if (dMin != dMax) {
      if (dDouble == dMin)
         scfFlags.setDownApproximate();
      else {
         assert(dDouble == dMax);
         scfFlags.setUpApproximate();
      };
   };
#else
#if defined(_MSC_VER) || defined(__BORLANDC__)
   int uOldState = _controlfp(0, _MCW_RC);
   if (scfFlags.isLowestRound())
      _controlfp(_RC_DOWN, _MCW_RC);
   else if (scfFlags.isHighestRound())
      _controlfp(_RC_UP, _MCW_RC);
   else if (scfFlags.isNearestRound())
      _controlfp(_RC_NEAR, _MCW_RC);
   else // (scfFlags.isZeroRound())
      _controlfp(_RC_CHOP, _MCW_RC);
   dDouble /= ttSource.dDouble;
   _controlfp(uOldState, _MCW_RC);
#else
#ifdef __SUN__
   if (scfFlags.isLowestRound())
      fpsetround(FP_RM);
   else if (scfFlags.isHighestRound())
      fpsetround(FP_RP);
   else if (scfFlags.isNearestRound())
      fpsetround(FP_RN);
   else // (scfFlags.isZeroRound())
      fpsetround(FP_RZ);
   dDouble /= ttSource.dDouble;
   fpsetround(FP_RN);
#else
#ifdef __LINUX__
   if (scfFlags.isLowestRound())
      fesetround(FE_DOWNWARD);
   else if (scfFlags.isHighestRound())
      fesetround(FE_UPWARD);
   else if (scfFlags.isNearestRound())
      fesetround(FE_TONEAREST);
   else // (scfFlags.isZeroRound())
      fesetround(FE_TOWARDZERO);
#endif
   dDouble /= ttSource.dDouble;
#ifdef __LINUX__
   fesetround(FE_TONEAREST);
#endif
#endif
#endif
#endif
   return *this;
}

template <class FloatingBaseTraits>
class TDoubleElement : public FloatingBaseTraits, public Details::DTDoubleElement::Access {
  private:
   typedef FloatingBaseTraits inherited;
   typedef TDoubleElement<FloatingBaseTraits> thisType;

   typedef typename FloatingBaseTraits::Mantissa Mantissa;

  public:
   typedef typename inherited::BuiltDouble BuiltDouble;
   typedef Details::DTDoubleElement::Access::StatusAndControlFlags StatusAndControlFlags;
   TDoubleElement() : inherited() {}
   TDoubleElement(int iValue, StatusAndControlFlags& scfFlags)
      {  typename BuiltDouble::IntConversion icValue;
         icValue.setSigned().assign(iValue);
         BuiltDouble bdDouble(icValue, scfFlags);
         operator=(bdDouble);
      }
   TDoubleElement(typename FloatingBaseTraits::Implantation fbtSource) : inherited(fbtSource) {}
   TDoubleElement(const BuiltDouble& bdDouble) : inherited(bdDouble) {}
   TDoubleElement(const thisType& dSource) : inherited(dSource) {}

   int queryInteger(StatusAndControlFlags& scfFlags) const
      {  typename BuiltDouble::IntConversion icResult;
         BuiltDouble(*this).retrieveInteger(icResult.setSigned(), scfFlags);
         return icResult.queryInt();
      }
   unsigned int queryUnsignedInteger(StatusAndControlFlags& scfFlags) const
      {  typename BuiltDouble::IntConversion icResult;
         BuiltDouble(*this).retrieveInteger(icResult.setUnsigned(), scfFlags);
         return icResult.queryUnsignedInt();
      }

   bool isInternZero() const;
   bool isZero() const { return inherited::isZero(); }
   bool isNaN() const;
   bool isQNaN() const;
   bool isSNaN() const;
   bool isInfty() const;
   bool hasInftyExponent() const
      {  return inherited::queryBasicExponent() == inherited::getMaxExponent()+inherited::getZeroExponent()+1; }

   enum ComparisonResult { CRNaN, CRLess, CREqual, CRGreater };
   ComparisonResult compare(const thisType& bdSource) const
      {  ComparisonResult crResult = CRNaN;
         if (!isNaN() && !bdSource.isNaN())
            crResult = (inherited::implantation() < bdSource.inherited::implantation()) ? CRLess
               : ((inherited::implantation() > bdSource.inherited::implantation()) ? CRGreater : CREqual);
         return crResult;
      }
   bool operator==(const thisType& bdSource) const { return compare(bdSource) == CREqual; }
   bool operator!=(const thisType& bdSource) const
      {  register ComparisonResult crResult = compare(bdSource);
         return (crResult == CRLess) || (crResult == CRGreater);
      }
   bool operator<(const thisType& bdSource) const { return compare(bdSource) == CRLess; }
   bool operator>(const thisType& bdSource) const { return compare(bdSource) == CRGreater; }
   bool operator<=(const thisType& bdSource) const
      {  register ComparisonResult crResult = compare(bdSource);
         return (crResult == CRLess) || (crResult == CREqual);
      }
   bool operator>=(const thisType& bdSource) const
      {  register ComparisonResult crResult = compare(bdSource);
         return (crResult == CRGreater) || (crResult == CREqual);
      }

   static const int UByteSizeImplantation = inherited::UByteSizeImplantation;
   static const int UBitSizeMantissa = inherited::UBitSizeMantissa;
   static const int UBitSizeExponent = inherited::UBitSizeExponent;

   typedef typename BuiltDouble::DiffDouble DiffDouble;
   DiffDouble queryNumberOfFloatsBetween(const thisType& deElement) const
      {  BuiltDouble bdThis = *this, bdElement = deElement;
         return bdThis.queryNumberOfFloatsBetween(bdElement);
      }
   thisType queryNthSuccessor(const DiffDouble& biIntSource) const
      {  BuiltDouble bdThis = *this;
         return thisType(bdThis.queryNthSuccessor(biIntSource));
      }
   thisType queryNthPredecessor(const DiffDouble& biIntSource) const
      {  BuiltDouble bdThis = *this;
         return thisType(bdThis.queryNthPredecessor(biIntSource));
      }
   bool isPuiss2() const;
   Errors queryErrors() const;

   thisType& opposite() { return (thisType&) inherited::opposite(); }
   thisType& plusAssign(const thisType& ttSource, StatusAndControlFlags& scfFlags)
      {  return (thisType&) inherited::plusAssign(ttSource, scfFlags); }
   thisType& minusAssign(const thisType& ttSource, StatusAndControlFlags& scfFlags)
      {  return (thisType&) inherited::minusAssign(ttSource, scfFlags); }
   thisType& multAssign(const thisType& ttSource, StatusAndControlFlags& scfFlags)
      {  return (thisType&) inherited::multAssign(ttSource, scfFlags); }
   thisType& divAssign(const thisType& ttSource, StatusAndControlFlags& scfFlags)
      {  return (thisType&) inherited::divAssign(ttSource, scfFlags); }

   thisType& operator-=(const thisType& ttSource)
      {  return (thisType&) inherited::operator-=(ttSource); }
   thisType& operator*=(const thisType& ttSource)
      {  return (thisType&) inherited::operator*=(ttSource); }
   thisType& operator+=(const thisType& ttSource)
      {  return (thisType&) inherited::operator+=(ttSource); }
   thisType& operator/=(const thisType& ttSource)
      {  return (thisType&) inherited::operator/=(ttSource); }

   thisType operator-(const thisType& ttSource) const
      {  thisType ttResult(*this);
         return (ttResult -= ttSource);
      }
   thisType operator+(const thisType& ttSource) const
      {  thisType ttResult(*this);
         return (ttResult += ttSource);
      }
   thisType operator*(const thisType& ttSource) const
      {  thisType ttResult(*this);
         return (ttResult *= ttSource);
      }
   thisType operator/(const thisType& ttSource) const
      {  thisType ttResult(*this);
         return (ttResult /= ttSource);
      }

   thisType& setOpposite()
      {  inherited::setSign(!inherited::isPositive());
         return *this;
      }
   thisType& setInftyExponent()
      {  inherited::setBasicExponent(-1);
         return *this;
      }

   void write(std::ostream& osOut, const WriteParameters& wpFlags) const;
   void read(std::istream& isIn, StatusAndControlFlags& scfFlags);
};

template <class FloatingBaseTraits>
inline std::ostream&
operator<<(std::ostream& osOut, const TDoubleElement<FloatingBaseTraits>& deDouble) {
   typename TDoubleElement<FloatingBaseTraits>::WriteParameters wpParams;
   deDouble.write(osOut, wpParams);
   return osOut;
}

template <class FloatingBaseTraits>
inline std::istream&
operator<<(std::istream& isIn, TDoubleElement<FloatingBaseTraits>& deDouble) {
   typename TDoubleElement<FloatingBaseTraits>::StatusAndControlFlags scfFlags;
   deDouble.read(isIn, scfFlags);
   return isIn;
}

}} // end of namespace Numerics::Double

} // end of namespace simfloat
} // end of namespace util
} // end of namespace unisim

#endif // Numerics_Double_FloatingH

