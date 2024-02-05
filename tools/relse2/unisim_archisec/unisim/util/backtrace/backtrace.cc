/*
 *  Copyright (c) 2008,
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

#include <unisim/util/backtrace/backtrace.hh>
#include <stdlib.h>
#include <iostream>

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#if defined(__GNUC__) && (__GNUC__ >= 3) && defined(HAVE_CXXABI)
#include <execinfo.h>
#include <cxxabi.h>
#endif

namespace unisim {
namespace util {
namespace backtrace {

BackTrace::BackTrace(unsigned int max_depth) :
	stack_depth(0),
	stack_addrs(0)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && defined(HAVE_CXXABI)
	stack_addrs = (void **) malloc((max_depth + 1) * sizeof(void *));
	stack_depth = ::backtrace(stack_addrs, max_depth + 1);
	stack_addrs = (void **) realloc(stack_addrs, stack_depth * sizeof(void *));
#endif
}

BackTrace::~BackTrace()
{
	if(stack_addrs) free(stack_addrs);
}

std::ostream& operator << (std::ostream& os, const BackTrace& backtrace)
{
#if defined(__GNUC__) && (__GNUC__ >= 3) && defined(HAVE_CXXABI)
	char **stack_strings;
	stack_strings = backtrace_symbols(backtrace.stack_addrs, backtrace.stack_depth);

	int i;
	for(i = 1; i < backtrace.stack_depth; i++)
	{
		char *begin_of_mangled_name = 0;
		char *end_of_mangled_name = 0;
		char *begin_of_file_location = stack_strings[i];
		char *end_of_file_location = 0;
		char *begin_of_offset = 0;
		char *end_of_offset = 0;
		char *begin_of_address = 0;
		char *end_of_address = 0;

		// find the parentheses and address offset surrounding the mangled name
		char *j = begin_of_file_location;
		while(*j)
		{
			if (*j == '(')
			{
				*j = 0;
				end_of_file_location = j++;
				begin_of_mangled_name = j;
				break;
			}
			j++;
		}

		while(*j)
		{
			if (*j == '+')
			{
				*j = 0;
				end_of_mangled_name = j++;
				begin_of_offset = j;
				break;
			}
			j++;
		}

		while(*j)
		{
			if (*j == ')')
			{
				*j = 0;
				end_of_offset = j++;
				break;
			}
			j++;
		}

		while(*j)
		{
			if (*j == '[')
			{
				j++;
				begin_of_address = j;
				break;
			}
			j++;
		}

		while(*j)
		{
			if (*j == ']')
			{
				*j = 0;
				end_of_address = j;
				break;
			}
			j++;
		}

		os << "#" << i << "  ";

		if(begin_of_address && end_of_address)
		{
			os << begin_of_address;
		}

		if(begin_of_mangled_name && end_of_mangled_name)
		{
			os << " in ";

			size_t length = 32; // initial length
			char *output = 0;
			int status;
			char *demangled_name = abi::__cxa_demangle(begin_of_mangled_name, output, &length, &status);
			// meaning of status:
			// * 0: The demangling operation succeeded.
			// * -1: A memory allocation failiure occurred.
			// * -2: mangled_name is not a valid name under the C++ ABI mangling rules.
			// * -3: One of the arguments is invalid.
			if(status == 0 && demangled_name)
			{
				os << demangled_name;
			}
			else
			{
				os << begin_of_mangled_name;
			}
			if(status != -1) free(output);
			if(demangled_name) free(demangled_name);
		}

		if(begin_of_offset && end_of_offset)
		{
			os << "+" << begin_of_offset;
		}

		if(begin_of_file_location && end_of_file_location)
		{
			os << " from " << begin_of_file_location;
		}

		os << std::endl;
	}

	free(stack_strings); // malloc()ed by backtrace_symbols

#endif
	return os;
}

} // end of backtrace namespace
} // end of util namespace
} // end of unisim namespace
