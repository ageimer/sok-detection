/*
 *  Copyright (c) 2020,
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

#include <unisim/util/debug/decl_location.hh>

namespace unisim {
namespace util {
namespace debug {

DeclLocation::DeclLocation(const std::string& decl_filename, unsigned int decl_line, unsigned decl_column)
	: source_code_location(decl_filename, decl_line, decl_column)
	, ref_count(0)
{
}

DeclLocation::DeclLocation(const unisim::util::debug::SourceCodeLocation& _source_code_location)
	: source_code_location(_source_code_location)
{
}

const unisim::util::debug::SourceCodeLocation& DeclLocation::GetSourceCodeLocation() const
{
	return source_code_location;
}

const std::string& DeclLocation::GetDeclFilename() const
{
	return source_code_location.GetSourceCodeFilename();
}

unsigned int DeclLocation::GetDeclLine() const
{
	return source_code_location.GetLineNo();
}

unsigned int DeclLocation::GetDeclColumn() const
{
	return source_code_location.GetColNo();
}

void DeclLocation::Catch() const
{
	++ref_count;
}

void DeclLocation::Release() const
{
	if(ref_count)
	{
		if(--ref_count == 0)
		{
			delete this;
		}
	}
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim
