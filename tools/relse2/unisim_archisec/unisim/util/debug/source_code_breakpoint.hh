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

#ifndef __UNISIM_UTIL_DEBUG_SOURCE_CODE_BREAKPOINT_HH__
#define __UNISIM_UTIL_DEBUG_SOURCE_CODE_BREAKPOINT_HH__

#include <unisim/util/debug/event.hh>
#include <unisim/util/debug/breakpoint.hh>
#include <unisim/util/debug/source_code_location.hh>
#include <ostream>
#include <set>

namespace unisim {
namespace util {
namespace debug {

////////////////////////////// declarations ///////////////////////////////////

////////////////////////// SourceCodeBreakpoint<> /////////////////////////////

template <typename ADDRESS>
class SourceCodeBreakpoint : public CustomEvent<ADDRESS, SourceCodeBreakpoint<ADDRESS> >
{
public:
	SourceCodeBreakpoint(const SourceCodeLocation& source_code_location);
	SourceCodeBreakpoint(const char *source_code_filename, unsigned int lineno, unsigned int colno = 0);
	virtual ~SourceCodeBreakpoint();
	
	int GetId() const { return id; }
	const SourceCodeLocation& GetSourceCodeLocation() const { return source_code_location; }
	const std::string& GetSourceCodeFilename() const { return source_code_location.GetSourceCodeFilename(); }
	unsigned int GetLineNo() const { return source_code_location.GetLineNo(); }
	unsigned int GetColNo() const { return source_code_location.GetColNo(); }
	
	void Attach(Breakpoint<ADDRESS> *brkp);
	void SetId(int _id) { id = _id; }
	
	/* struct Visitor { void Visit(Breakpoint<ADDRESS> *) {} }; */
	template <class VISITOR> void Scan(VISITOR& visitor);
	
private:
	SourceCodeLocation source_code_location;
	typedef std::set<Breakpoint<ADDRESS> *> Breakpoints;
	Breakpoints breakpoints;
	int id;
};

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const SourceCodeBreakpoint<ADDRESS>& src_code_brkp);

/////////////////////////////// definitions ///////////////////////////////////

////////////////////////// SourceCodeBreakpoint<> /////////////////////////////

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const SourceCodeBreakpoint<ADDRESS>& src_code_brkp)
{
	os << "source code breakpoint #" << src_code_brkp.GetId() << " at " << src_code_brkp.GetSourceCodeLocation() << " for processor #" << src_code_brkp.GetProcessorNumber() << " and front-end #" << src_code_brkp.GetFrontEndNumber();
	
	return os;
}

template <typename ADDRESS>
SourceCodeBreakpoint<ADDRESS>::SourceCodeBreakpoint(const char *source_code_filename, unsigned int lineno, unsigned int colno)
	: CustomEvent<ADDRESS, SourceCodeBreakpoint<ADDRESS> >()
	, source_code_location(source_code_filename, lineno, colno)
{
}

template <typename ADDRESS>
SourceCodeBreakpoint<ADDRESS>::SourceCodeBreakpoint(const SourceCodeLocation& _source_code_location)
	: CustomEvent<ADDRESS, SourceCodeBreakpoint<ADDRESS> >()
	, source_code_location(_source_code_location)
{
}

template <typename ADDRESS>
SourceCodeBreakpoint<ADDRESS>::~SourceCodeBreakpoint()
{
	for(typename Breakpoints::iterator it = breakpoints.begin(); it != breakpoints.end(); ++it)
	{
		Breakpoint<ADDRESS> *breakpoint = *it;
		breakpoint->Release();
	}
}

template <typename ADDRESS>
void SourceCodeBreakpoint<ADDRESS>::Attach(Breakpoint<ADDRESS> *brkp)
{
	std::pair<typename Breakpoints::iterator , bool> r = breakpoints.insert(brkp);
	if(r.second)
	{
		brkp->Catch();
	}
}

template <typename ADDRESS>
template <class VISITOR>
void SourceCodeBreakpoint<ADDRESS>::Scan(VISITOR& visitor)
{
	for(typename Breakpoints::iterator it = breakpoints.begin(); it != breakpoints.end(); ++it)
	{
		Breakpoint<ADDRESS> *breakpoint = *it;
		visitor.Visit(breakpoint);
	}
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_SOURCE_CODE_BREAKPOINT_HH__
