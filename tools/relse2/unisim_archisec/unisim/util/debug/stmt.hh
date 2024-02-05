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

#ifndef __UNISIM_UTIL_DEBUG_STMT_H__
#define __UNISIM_UTIL_DEBUG_STMT_H__

#include <iosfwd>
#include <string>

namespace unisim {
namespace util {
namespace debug {

template <class MEMORY_ADDR> class Statement;
template <class MEMORY_ADDR>
std::ostream& operator << (std::ostream& os, const Statement<MEMORY_ADDR>& stmt);

template <class MEMORY_ADDR>
class Statement
{
public:
	Statement(MEMORY_ADDR addr, bool is_beginning_of_source_statement, bool is_beginning_of_basic_block, const char *source_dirname, const char *source_filename, unsigned int lineno, unsigned int colno, unsigned int isa, unsigned int discriminator);
	MEMORY_ADDR GetAddress() const;
	bool IsBeginningOfSourceStatement() const;
	bool IsBeginningOfBasicBlock() const;
	const char *GetSourceDirname() const;
	const char *GetSourceFilename() const;
	unsigned int GetLineNo() const;
	unsigned int GetColNo() const;
	unsigned int GetISA() const;
	unsigned int GetDiscriminator() const;
	friend std::ostream& operator << <MEMORY_ADDR>(std::ostream& os, const Statement<MEMORY_ADDR>& stmt);
private:
	MEMORY_ADDR addr;
	bool is_beginning_of_source_statement;
	bool is_beginning_of_basic_block;
	const char *source_dirname;
	const char *source_filename;
	unsigned int lineno;
	unsigned int colno;
	unsigned int isa;
	unsigned int discriminator;
};

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif
