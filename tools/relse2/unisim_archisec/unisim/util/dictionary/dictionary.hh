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

#ifndef __UNISIM_UTIL_DICTIONARY_DICTIONARY_HH__
#define __UNISIM_UTIL_DICTIONARY_DICTIONARY_HH__

#include <iosfwd>
#include <string>

namespace unisim {
namespace util {
namespace dictionary {

template <class TYPE> class DictionaryEntry;
template <class TYPE> class Dictionary;

template <class TYPE>
std::ostream& operator << (std::ostream& os, const DictionaryEntry<TYPE>& entry);

template <class TYPE>
class DictionaryEntry
{
public:
	const TYPE& GetValue() const;
private:
	char c;
	DictionaryEntry *left;
	DictionaryEntry *right;
	bool match;
	unsigned int id;
	TYPE value;
	
	friend class Dictionary<TYPE>;
	friend std::ostream& operator << <TYPE>(std::ostream& os, const DictionaryEntry<TYPE>& entry);

	DictionaryEntry(char c, DictionaryEntry<TYPE> *left, DictionaryEntry<TYPE> *right, bool match, unsigned int id, const TYPE& value);
	~DictionaryEntry();
	bool Matches() const;
	unsigned int GetId() const;
};

template <class TYPE>
std::ostream& operator << (std::ostream& os, const Dictionary<TYPE>& dictionary);

template <class TYPE>
class Dictionary
{
public:
	Dictionary(std::ostream& debug_info_stream, std::ostream& debug_warning_stream, std::ostream& debug_error_stream, bool debug = false);
	~Dictionary();

	// Add a valued string in the dictionary
	void Add(const char *text, const TYPE& value);
	
	// Find the longest match in the dictionary and tell the recognized text
	DictionaryEntry<TYPE> *FindDictionaryEntry(std::istream *stream, std::string& text);
private:
	
	DictionaryEntry<TYPE> *root;

	unsigned int num_entries;
	std::ostream& debug_info_stream;
	std::ostream& debug_warning_stream;
	std::ostream& debug_error_stream;
	bool debug;
	
	DictionaryEntry<TYPE> *Create(const char *text, const TYPE& value);
	DictionaryEntry<TYPE> *FindDictionaryEntry(const char *text, unsigned int& pos);
	
	friend std::ostream& operator << <TYPE>(std::ostream& os, const Dictionary<TYPE>& dictionary);
};

} // end of namespace dictionary
} // end of namespace util
} // end of namespace unisim

#endif
