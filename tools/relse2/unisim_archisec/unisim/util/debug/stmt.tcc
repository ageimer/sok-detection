/*
 *  Copyright (c) 2010,
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

#ifndef __UNISIM_UTIL_DEBUG_STMT_TCC__
#define __UNISIM_UTIL_DEBUG_STMT_TCC__

#include <iostream>

namespace unisim {
namespace util {
namespace debug {

template <class MEMORY_ADDR>
Statement<MEMORY_ADDR>::Statement(MEMORY_ADDR _addr, bool _is_beginning_of_source_statement, bool _is_beginning_of_basic_block, const char *_source_dirname, const char *_source_filename, unsigned int _lineno, unsigned int _colno, unsigned int _isa, unsigned int _discriminator)
	: addr(_addr)
	, is_beginning_of_source_statement(_is_beginning_of_source_statement)
	, is_beginning_of_basic_block(_is_beginning_of_basic_block)
	, source_dirname(_source_dirname)
	, source_filename(_source_filename)
	, lineno(_lineno)
	, colno(_colno)
	, isa(_isa)
	, discriminator(_discriminator)
{
}

template <class MEMORY_ADDR>
MEMORY_ADDR Statement<MEMORY_ADDR>::GetAddress() const
{
	return addr;
}

template <class MEMORY_ADDR>
bool Statement<MEMORY_ADDR>::IsBeginningOfSourceStatement() const
{
	return is_beginning_of_source_statement;
}

template <class MEMORY_ADDR>
bool Statement<MEMORY_ADDR>::IsBeginningOfBasicBlock() const
{
	return is_beginning_of_basic_block;
}

template <class MEMORY_ADDR>
const char *Statement<MEMORY_ADDR>::GetSourceDirname() const
{
	return source_dirname;
}

template <class MEMORY_ADDR>
const char *Statement<MEMORY_ADDR>::GetSourceFilename() const
{
	return source_filename;
}

template <class MEMORY_ADDR>
unsigned int Statement<MEMORY_ADDR>::GetLineNo() const
{
	return lineno;
}

template <class MEMORY_ADDR>
unsigned int Statement<MEMORY_ADDR>::GetColNo() const
{
	return colno;
}

template <class MEMORY_ADDR>
unsigned int Statement<MEMORY_ADDR>::GetISA() const
{
	return isa;
}

template <class MEMORY_ADDR>
unsigned int Statement<MEMORY_ADDR>::GetDiscriminator() const
{
	return discriminator;
}

template <class MEMORY_ADDR>
std::ostream& operator << (std::ostream& os, const Statement<MEMORY_ADDR>& stmt)
{
	os << "addr=0x" << std::hex << stmt.addr << std::dec
	   << ", is_stmt=" << stmt.is_beginning_of_source_statement
	   << ", basic_block=" << stmt.is_beginning_of_basic_block
	   << ", dir=\"" << (stmt.source_dirname ? stmt.source_dirname : "") << "\""
	   << ", file=\"" << (stmt.source_filename ? stmt.source_filename : "") << "\""
	   << ", line=" << stmt.lineno
	   << ", col=" << stmt.colno
	   << ", isa=" << stmt.isa
	   << ", discr=" << stmt.discriminator;
	return os;
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
