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

#ifndef __UNISIM_UTIL_DICTIONARY_DICTIONARY_TCC__
#define __UNISIM_UTIL_DICTIONARY_DICTIONARY_TCC__

#include <iostream>
#include <string.h>

namespace unisim {
namespace util {
namespace dictionary {

template <class TYPE>
DictionaryEntry<TYPE>::DictionaryEntry(char _c, DictionaryEntry<TYPE> *_left, DictionaryEntry<TYPE> *_right, bool _match, unsigned int _id, const TYPE& _value)
	: c(_c)
	, left(_left)
	, right(_right)
	, match(_match)
	, id(_id)
	, value(_value)
{
}

template <class TYPE>
DictionaryEntry<TYPE>::~DictionaryEntry()
{
	if(left) delete left;
	if(right) delete right;
}

template <class TYPE>
bool DictionaryEntry<TYPE>::Matches() const
{
	return match;
}

template <class TYPE>
unsigned int DictionaryEntry<TYPE>::GetId() const
{
	return id;
}

template <class TYPE>
const TYPE& DictionaryEntry<TYPE>::GetValue() const
{
	return value;
}

template <class TYPE>
std::ostream& operator << (std::ostream& os, const DictionaryEntry<TYPE>& entry)
{
	os << "DictionaryEntry(match=" << entry.match << ",id=" << entry.id << ",c='" << entry.c << "',value=[" << entry.value << "],left=";
	if(entry.left) os << *entry.left; else os << "null";
	os << ",right=";
	if(entry.right) os << *entry.right; else os << "null";
	os << ")";
	return os;
}

template <class TYPE>
Dictionary<TYPE>::Dictionary(std::ostream& _debug_info_stream, std::ostream& _debug_warning_stream, std::ostream& _debug_error_stream, bool _debug)
	: root(0)
	, num_entries(0)
	, debug_info_stream(_debug_info_stream)
	, debug_warning_stream(_debug_warning_stream)
	, debug_error_stream(_debug_error_stream)
	, debug(_debug)
{
}

template <class TYPE>
Dictionary<TYPE>::~Dictionary()
{
	if(root) delete root;
}

template <class TYPE>
DictionaryEntry<TYPE> *Dictionary<TYPE>::FindDictionaryEntry(const char *text, unsigned int& pos)
{
	if(root)
	{
		DictionaryEntry<TYPE> *entry = root;
		
		pos = 0;
		
		char c = text[pos++];
		
		if(c)
		{
			char next_c = text[pos++];
			
			DictionaryEntry<TYPE> *last_match = 0;
			
			do
			{
				if(entry->c == c)
				{
					last_match = entry;
					
					if(!next_c)
					{
						break;
					}
					
					DictionaryEntry<TYPE> *right_entry = entry->right;
					
					if(right_entry)
					{
						if(right_entry->c == next_c)
						{
							entry = right_entry;
							c = next_c;
							next_c = text[pos++];
							continue;
						}
					}
				}
				entry = entry->left;
			}
			while(entry);
			
			pos--;
			
			if(last_match)
			{
				return last_match;
			}
		}
	}
	
	return 0;
}

template <class TYPE>
DictionaryEntry<TYPE> *Dictionary<TYPE>::FindDictionaryEntry(std::istream *stream, std::string& text)
{
	if(root)
	{
		if(!stream->good()) return 0;
		
		DictionaryEntry<TYPE> *entry = root;
		
		char c = 0;
		if(stream->get(c).eof() || stream->fail()) return 0;
		if(debug)
		{
			debug_info_stream << "get '" << c << "'" << std::endl;
		}
		
		char next_c = 0;
		stream->get(next_c);
		
		if(debug)
		{
			if(stream->good()) debug_info_stream << "get '" << next_c << "'" << std::endl;
		}
		
		DictionaryEntry<TYPE> *last_match = 0;
		
		do
		{
			if(entry->c == c)
			{
				last_match = entry;
				
				if(stream->eof()) // relative to fetch of next_c
				{
					break;
				}
				
				if(stream->fail()) break; // relative to fetch of next_c
				
				DictionaryEntry<TYPE> *right_entry = entry->right;
				
				if(right_entry)
				{
					if(right_entry->c == next_c)
					{
						entry = right_entry;
						text += c;
						c = next_c;
						
						stream->get(next_c);
						
						if(debug)
						{
							if(stream->good()) debug_info_stream << "get '" << next_c << "'" << std::endl;
						}
						continue;
					}
				}
			}
			
			entry = entry->left;
		}
		while(entry);

		if(!stream->fail() && !stream->eof())
		{
			if(debug)
			{
				debug_info_stream << "putback '" << next_c << "'" << std::endl;
			}
			stream->putback(next_c);
			if(stream->fail()) return 0;
		}
		
		if(last_match)
		{
			if(last_match->match)
			{
				text += last_match->c;
				return last_match;
			}
			else
			{
				// putback characters into stream
				stream->clear();
				stream->putback(last_match->c);
				unsigned int n = text.length();
				while(n)
				{
					if(debug)
					{
						debug_info_stream << "putback '" << text[n - 1] << "'" << std::endl;
					}
					stream->putback(text[n - 1]);
					n--;
				}
				text.clear();
			}
		}
		else
		{
			stream->clear();
			if(debug)
			{
				debug_info_stream << "putback '" << c << "'" << std::endl;
			}
			stream->putback(c);
		}
	}
	
	return 0;
}

template <class TYPE>
DictionaryEntry<TYPE> *Dictionary<TYPE>::Create(const char *text, const TYPE& value)
{
	char c = *text;
	if(!c) return 0;
	char next_c = *(text + 1);
	return new DictionaryEntry<TYPE>(c, 0, Create(text + 1, value), next_c == 0, num_entries++, value);
}

template <class TYPE>
void Dictionary<TYPE>::Add(const char *text, const TYPE& value)
{
	unsigned int pos = 0;
	DictionaryEntry<TYPE> *entry = FindDictionaryEntry(text, pos);

	if(entry)
	{
		unsigned int text_length = strlen(text);
		if(pos == text_length)
		{
			if(debug)
			{
				debug_info_stream << "making entry " << entry->id << " matching \"" << text << "\"" << std::endl;
			}
			entry->match = true;
			entry->value = value;
		}
		else
		{
			DictionaryEntry<TYPE> *new_right_entry = Create(text + pos, value);
			DictionaryEntry<TYPE> *new_left_entry = new DictionaryEntry<TYPE>(entry->c, entry->left, new_right_entry, entry->match, num_entries++, entry->value);
			new_left_entry->left = entry->left;
			entry->left = new_left_entry;
			if(debug)
			{
				debug_info_stream << "created new entry " << new_right_entry->id << " matching \"" << text << "\"" << std::endl;
			}
		}
	}
	else
	{
		DictionaryEntry<TYPE> *new_entry = Create(text, value);
		if(debug)
		{
			debug_info_stream << "created new entry " << new_entry->id << " matching \"" << text << "\"" << std::endl;
		}
		new_entry->left = root ? root->left : 0;
		if(root)
		{
			new_entry->left = root->left;
			root->left = new_entry;
		}
		else
		{
			if(debug)
			{
				debug_info_stream << "new entry " << new_entry->id << " is root" << std::endl;
			}
			root = new_entry;
		}
	}
}

template <class TYPE>
std::ostream& operator << (std::ostream& os, const Dictionary<TYPE>& dictionary)
{
	if(dictionary.root)
	{
		os << *dictionary.root;
	}
	else
	{
		os << "null";
	}
	return os;
}

} // end of namespace dictionary
} // end of namespace util
} // end of namespace unisim

#endif
