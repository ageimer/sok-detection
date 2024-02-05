/*
 *  Copyright (c) 2012,
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
 
#ifndef __UNISIM_SERVICE_INTERFACES_DEBUG_EVENT_HH__
#define __UNISIM_SERVICE_INTERFACES_DEBUG_EVENT_HH__

#include <unisim/service/interfaces/interface.hh>
#include <unisim/util/debug/event.hh>
#include <unisim/util/debug/memory_access_type.hh>
#include <list>

namespace unisim {
namespace service {
namespace interfaces {
	
template <class ADDRESS>
class DebugEventScanner : public ServiceInterface
{
public:
	virtual void Append(unisim::util::debug::Event<ADDRESS> *event) = 0;
};

namespace detail
{
template <class ADDRESS, class CONTAINER> class DebugEventScannerInserter;
template <class ADDRESS, class CONTAINER> class DebugEventScannerFrontInserter;
template <class ADDRESS, class CONTAINER> class DebugEventScannerBackInserter;
} // end of namespace detail

template <class ADDRESS, class CONTAINER> detail::DebugEventScannerInserter<ADDRESS, CONTAINER> DebugEventScannerInserter(CONTAINER& container, typename CONTAINER::iterator iter);
template <class ADDRESS, class CONTAINER> detail::DebugEventScannerFrontInserter<ADDRESS, CONTAINER> DebugEventScannerFrontInserter(CONTAINER& container, typename CONTAINER::iterator iter);
template <class ADDRESS, class CONTAINER> detail::DebugEventScannerBackInserter<ADDRESS, CONTAINER> DebugEventScannerBackInserter(CONTAINER& container, typename CONTAINER::iterator iter);

template <class ADDRESS>
class DebugEventTrigger : public ServiceInterface
{
public:
	// "named" events
	virtual bool Listen(unisim::util::debug::Event<ADDRESS> *event) = 0;
	virtual bool Unlisten(unisim::util::debug::Event<ADDRESS> *event) = 0;
	virtual bool IsEventListened(unisim::util::debug::Event<ADDRESS> *event) const = 0;
	virtual void ScanListenedEvents(DebugEventScanner<ADDRESS>& scanner) const = 0;
	virtual void ClearEvents() = 0;
	
	// idem potent interface: anonymous events
	virtual bool SetBreakpoint(ADDRESS addr) = 0;
	virtual bool RemoveBreakpoint(ADDRESS addr) = 0;
	virtual bool HasBreakpoints(ADDRESS addr) = 0;
	virtual bool SetWatchpoint(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size, bool overlook) = 0;
	virtual bool RemoveWatchpoint(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size) = 0;
	virtual bool HasWatchpoints(unisim::util::debug::MemoryAccessType mat, unisim::util::debug::MemoryType mt, ADDRESS addr, uint32_t size) = 0;
};

template <class ADDRESS>
class DebugEventListener : public ServiceInterface
{
public:
	virtual void OnDebugEvent(const unisim::util::debug::Event<ADDRESS> *event) = 0;
};

namespace detail
{

template <class ADDRESS, class CONTAINER>
class DebugEventScannerInserter : DebugEventScanner<ADDRESS>
{
public:
	DebugEventScannerInserter(CONTAINER& _container, typename CONTAINER::iterator _iter) : container(_container), iter(_iter) {}
	virtual void Append(unisim::util::debug::Event<ADDRESS> *event) { container.insert(event); }
private:
	CONTAINER& container;
	typename CONTAINER::iterator iter;
};

template <class ADDRESS, class CONTAINER>
class DebugEventScannerFrontInserter : DebugEventScanner<ADDRESS>
{
public:
	DebugEventScannerFrontInserter(CONTAINER& _container, typename CONTAINER::iterator _iter) : container(_container), iter(_iter) {}
	virtual void Append(unisim::util::debug::Event<ADDRESS> *event) { container.push_front(event); }
private:
	CONTAINER& container;
	typename CONTAINER::iterator iter;
};

template <class ADDRESS, class CONTAINER>
class DebugEventScannerBackInserter : DebugEventScanner<ADDRESS>
{
public:
	DebugEventScannerBackInserter(CONTAINER& _container, typename CONTAINER::iterator _iter) : container(_container), iter(_iter) {}
	virtual void Append(unisim::util::debug::Event<ADDRESS> *event) { container.push_back(event); }
private:
	CONTAINER& container;
	typename CONTAINER::iterator iter;
};

} // end of namespace detail

template <class ADDRESS, class CONTAINER>
detail::DebugEventScannerInserter<ADDRESS, CONTAINER> DebugEventScannerInserter(CONTAINER& container, typename CONTAINER::iterator iter)
{
	return detail::DebugEventScannerInserter<ADDRESS, CONTAINER>(container, iter);
}

template <class ADDRESS, class CONTAINER>
detail::DebugEventScannerFrontInserter<ADDRESS, CONTAINER> DebugEventScannerFrontInserter(CONTAINER& container, typename CONTAINER::iterator iter)
{
	return detail::DebugEventScannerFrontInserter<ADDRESS, CONTAINER>(container, iter);
}

template <class ADDRESS, class CONTAINER>
detail::DebugEventScannerBackInserter<ADDRESS, CONTAINER> DebugEventScannerBackInserter(CONTAINER& container, typename CONTAINER::iterator iter)
{
	return detail::DebugEventScannerBackInserter<ADDRESS, CONTAINER>(container, iter);
}

} // end of namespace interfaces
} // end of namespace service
} // end of namespace unisim

#endif
