/*
 *  Copyright (c) 2013,
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
 * Authors: Gilles Mouchard (gilles.mouchard@cea.fr)
 */
 
#ifndef __UNISIM_UTIL_INLINING_INLINING_HH__
#define __UNISIM_UTIL_INLINING_INLINING_HH__

#if defined(ALWAYS_INLINE)
#undef ALWAYS_INLINE
#endif

#if defined(NEVER_INLINE)
#undef NEVER_INLINE
#endif

#if defined(__GNUC__)
#if (__GNUC__ > 4) || ((__GNUC__ >= 4) && ((__GNUC_MINOR__ > 1) || ((__GNUC_MINOR__ >= 1) && (__GNUC_PATCHLEVEL__ >= 3))))     // GNU C version >= 4.1.3
#define ALWAYS_INLINE __attribute__((always_inline))
#define NEVER_INLINE __attribute__ ((noinline))
#else
#define ALWAYS_INLINE
#endif

#elif defined(__clang__)

#if __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline))
#define NEVER_INLINE __attribute__ ((noinline))
#else
#define ALWAYS_INLINE
#endif

#endif // __clang__




// #if defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ >= 4) && ((__GNUC_MINOR__ > 1) || ((__GNUC_MINOR__ >= 1) && (__GNUC_PATCHLEVEL__ >= 3)))))     // GNU C version >= 4.1.3
// #if defined(ALWAYS_INLINE)
// #undef ALWAYS_INLINE
// #endif
// #define ALWAYS_INLINE __attribute__((always_inline))
// #else
// #define ALWAYS_INLINE
// #endif

#endif // __UNISIM_UTIL_INLINING_INLINING_HH__
