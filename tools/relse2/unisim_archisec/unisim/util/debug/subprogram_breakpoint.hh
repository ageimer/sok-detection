/*
 *  Copyright (c) 2022,
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

#ifndef __UNISIM_UTIL_DEBUG_SUBPROGRAM_BREAKPOINT_HH__
#define __UNISIM_UTIL_DEBUG_SUBPROGRAM_BREAKPOINT_HH__

#include <unisim/util/debug/event.hh>
#include <unisim/util/debug/breakpoint.hh>
#include <unisim/util/debug/subprogram.hh>
#include <ostream>

namespace unisim {
namespace util {
namespace debug {

////////////////////////////// declarations ///////////////////////////////////

////////////////////////// SubProgramBreakpoint<> /////////////////////////////

template <typename ADDRESS>
class SubProgramBreakpoint : public CustomEvent<ADDRESS, SubProgramBreakpoint<ADDRESS> >
{
public:
	SubProgramBreakpoint(const SubProgram<ADDRESS> *subprogram);
	virtual ~SubProgramBreakpoint();
	
	int GetId() const { return id; }
	const SubProgram<ADDRESS> *GetSubProgram() const { return subprogram; }
	
	void Attach(Breakpoint<ADDRESS> *brkp);
	void SetId(int _id) { id = _id; }
	
	/* struct Visitor { void Visit(Breakpoint<ADDRESS> *) {} }; */
	template <class VISITOR> void Scan(VISITOR& visitor);
	
private:
	const SubProgram<ADDRESS> *subprogram;
	Breakpoint<ADDRESS> *breakpoint;
	int id;
};

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const SubProgramBreakpoint<ADDRESS>& subprogram_brkp);

/////////////////////////////// definitions ///////////////////////////////////

////////////////////////// SubProgramBreakpoint<> /////////////////////////////

template <typename ADDRESS>
inline std::ostream& operator << (std::ostream& os, const SubProgramBreakpoint<ADDRESS>& subprogram_brkp)
{
	os << "subprogram breakpoint #" << subprogram_brkp.GetId() << " at " << subprogram_brkp.GetSubProgram()->GetName() << " for processor #" << subprogram_brkp.GetProcessorNumber() << " and front-end #" << subprogram_brkp.GetFrontEndNumber();
	
	return os;
}

template <typename ADDRESS>
SubProgramBreakpoint<ADDRESS>::SubProgramBreakpoint(const SubProgram<ADDRESS> *_subprogram)
	: CustomEvent<ADDRESS, SubProgramBreakpoint<ADDRESS> >()
	, subprogram(_subprogram)
{
}

template <typename ADDRESS>
SubProgramBreakpoint<ADDRESS>::~SubProgramBreakpoint()
{
	breakpoint->Release();
}

template <typename ADDRESS>
void SubProgramBreakpoint<ADDRESS>::Attach(Breakpoint<ADDRESS> *brkp)
{
	breakpoint = brkp;
	brkp->Catch();
}

template <typename ADDRESS>
template <class VISITOR>
void SubProgramBreakpoint<ADDRESS>::Scan(VISITOR& visitor)
{
	visitor.Visit(breakpoint);
}

} // end of namespace debug
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_DEBUG_SUBPROGRAM_BREAKPOINT_HH__
