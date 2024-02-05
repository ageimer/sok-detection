/*
 *  Copyright (c) 2018,
 *  Commissariat a l'Energie Atomique (CEA),
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
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 *          Gilles Mouchard (gilles.mouchard@cea.fr)
 */

#ifndef __UNISIM_UTIL_NAT_SORT_NAT_SORT_HH__
#define __UNISIM_UTIL_NAT_SORT_NAT_SORT_HH__

#include <string>
#include <stdint.h>

namespace unisim {
namespace util {
namespace nat_sort {
	
struct nat_ltstr
{
	static bool is_digit(char c)
	{
		return (c >= '0') && (c <= '9');
	}
#if 1

	static int pretty_compare( char const* lhs, char const* rhs)
	{
		for (;; lhs++, rhs++)
		{
			if (not is_digit(*lhs) and not is_digit(*rhs) && (*lhs == *rhs))
			{
				if (*rhs) continue;
				else break;
			}
			/* *rhs != *lhs */
			if (not is_digit(*lhs) or not is_digit(*rhs))
				return (std::tolower(*lhs) == std::tolower(*rhs) ? (*lhs - *rhs) : (std::tolower(*lhs) - std::tolower(*rhs)));  //*lhs - *rhs;
			/*compare numerical value*/
			char const* lhb = lhs;
			char const* rhb = rhs;
			while (is_digit(lhs[1])) ++lhs;
			while (is_digit(rhs[1])) ++rhs;
			bool borrow = false, zero = true;
			for (char const *lhp = lhs, *rhp = rhs; (lhp >= lhb) or (rhp >= rhb);)
			{
				unsigned lhd = (lhp >= lhb) ? (*lhp--) - '0' : 0;
				unsigned rhd = (rhp >= rhb) ? (*rhp--) - '0' : 0;
				rhd += unsigned(borrow);
				zero &= (lhd == rhd);
				borrow = lhd < rhd;
			}
			if (not zero)
				return borrow ? -1 : +1;
			if (intptr_t delta = (lhs-lhb)-(rhs-rhb))
				return delta < 0 ? -1 : +1;
		}
		return 0;
	}
	
	static bool Less(const std::string& s1, const std::string& s2)
	{
		return pretty_compare(s1.c_str(), s2.c_str()) < 0;
	}
#else
	enum Token
	{
		STRING,
		NUMBER
	};
	
	static Token Scan(const std::string& s, std::size_t begin, std::size_t& tok_len, unsigned int& val)
	{
		int state = 0;
		unsigned int acc = 0;
		std::size_t len = s.length();
		std::size_t pos;
		
		for(pos = begin; pos < len; pos++)
		{
			char c = s[pos];

			switch(state)
			{
				case 0:
					if(is_digit(c))
					{
						acc = c - '0';
						state = 1;
					}
					else
					{
						state = 2;
					}
					break;
				case 1:
					if(is_digit(c))
					{
						acc *= 10;
						acc += c - '0';
					}
					else
					{
						tok_len = pos - begin;
						val = acc;
						return NUMBER;
					}
					break;
				case 2:
					if(is_digit(c))
					{
						tok_len = pos - begin;
						return STRING;
					}
					break;
			}
		}
		
		tok_len = pos - begin;
		if(state == 1)
		{
			val = acc;
			return NUMBER;
		}
		return STRING;
	}
	
	static int Compare(const char *s1, std::size_t s1_len, const char *s2, std::size_t s2_len)
	{
		std::size_t n = std::min(s1_len, s2_len);
		while(n--)
		{
			char c1 = *s1++;
			char c2 = *s2++;
			if(c1 != c2)
			{
				if(std::tolower(c1) < std::tolower(c2)) return -1;
				if(std::tolower(c1) > std::tolower(c2)) return +1;
			}
		}
		return (s1_len == s2_len) ? 0 : ((s1_len < s2_len) ? -1 : +1);
	}
	
	static bool Less(const std::string& s1, const std::string& s2)
	{
		std::size_t s1_len = s1.length();
		std::size_t s2_len = s2.length();
		std::size_t s1_pos = 0;
		std::size_t s2_pos = 0;
		while((s1_pos < s1_len) && (s2_pos < s2_len))
		{
			std::size_t tok1_len = 0;
			unsigned int val1 = 0;
			Token tok1 = Scan(s1, s1_pos, tok1_len, val1);
			std::size_t tok2_len = 0;
			unsigned int val2 = 0;
			Token tok2 = Scan(s2, s2_pos, tok2_len, val2);
			if((tok1 == NUMBER) && (tok2 == NUMBER))
			{
				if(val1 < val2) return true;
				else if(val1 > val2) return false;
			}
			else
			{
				int r = Compare(&s1[s1_pos], tok1_len, &s2[s2_pos], tok2_len);
				if(r < 0) return true;
				else if(r > 0) return false;
// 				if(s1.compare(s1_pos, tok1_len, s2, s2_pos, tok2_len) < 0) return true;
// 				else if(s1.compare(s1_pos, tok1_len, s2, s2_pos, tok2_len) > 0) return false;
			}
			s1_pos += tok1_len;
			s2_pos += tok2_len;
		}
		
		return s1_len < s2_len;
	}
#endif

	bool operator () (const std::string& s1, const std::string& s2) const
	{
		bool less = Less(s1, s2);
		//std::cerr << "\"" << s1 << "\"" << (less ? "<" : ">=") << "\"" << s2 << "\"" << std::endl;
		return less;
	}
};

} // end of namespace nat_sort
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_NAT_SORT_NAT_SORT_HH__
