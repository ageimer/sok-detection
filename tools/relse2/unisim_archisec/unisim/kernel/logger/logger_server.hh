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
 * Author: Yves Lhuillier (yves.lhuillier@cea.fr) 
 */

#ifndef __UNISIM_KERNEL_LOGGER_LOGGER_SERVER_HH__
#define __UNISIM_KERNEL_LOGGER_LOGGER_SERVER_HH__

#include <unisim/kernel/kernel.hh>
#include <unisim/kernel/logger/logger.hh>
#include <pthread.h>
#include <set>

namespace unisim {
namespace kernel {
namespace logger {

struct Logger;

struct Printer
{
	Printer();
	virtual ~Printer();
	virtual void Print(mode_t mode, const char *name, const char *buffer) = 0;
};

struct LoggerServer : unisim::kernel::Object
{
	/** Constructor */
	LoggerServer(const char *name, unisim::kernel::Object *parent = 0);
	/** Destructor */
	~LoggerServer();

	/** Register a client logger.
	 * 
	 * This method should be called by the different loggers when
	 * being constructed.
	 */
	void AddClient( Logger const* client );
	
	/** Register a printer
	 * 
	 * This method should be called by the different printers when
	 * being constructed.
	 */
	void AddPrinter( Printer *printer );

	/** Unregister a client logger and close server if needed
	 *  
	 *  This method should be called by the different client
	 *  loggers when being destroyed.
	 */
	void RemoveClient( Logger const* client );

	/** Unregister a printer
	 *  
	 *  This method should be called by the different printers
	 *  when being destroyed.
	 */
	void RemovePrinter( Printer *printer );

	/** Message debug log command
	 * Loggers should call this method (using the handle obtained with GetInstance)
	 *   to log a debug message.
	 *
	 * @param mode type of debug message (info, warning or error)
	 * @param obj the unisim::kernel::Object that is sending the debug message
	 * @param buffer the debug message
	 */
	void Print( mode_t mode, const char *name, const char *buffer );

	/** Message debug null log command
	 * Loggers should call this method (using the handle obtained with GetInstance)
	 *   to log a debug null message.
	 *
	 * @param obj the unisim::kernel::Object that is sending the debug info message
	 * @param buffer the debug null message
	 */
	void DebugNull( const char *name, const char *buffer );
	/** Message debug info log command
	 * Loggers should call this method (using the handle obtained with GetInstance)
	 *   to log a debug info message.
	 *
	 * @param obj the unisim::kernel::Object that is sending the debug info message
	 * @param buffer the debug info message
	 */
	void DebugInfo( const char *name, const char *buffer );
	/** Message debug warning log command
	 * Loggers should call this method (using the handle obtained with GetInstance)
	 *   to log a debug warning message.
	 *
	 * @param obj the unisim::kernel::Object that is sending the debug warning message
	 * @param buffer the debug warning message
	 */
	void DebugWarning( const char *name, const char *buffer );
	/** Message debug error log command
	 * Loggers should call this method (using the handle obtained with GetInstance)
	 *   to log a debug error message.
	 *
	 * @param obj the unisim::kernel::Object that is sending the debug error message
	 * @param buffer the debug error message
	 */
	void DebugError( const char *name, const char *buffer );

	/** For each client logger calls operator () (Logger const* client) of visitor
	 * @param visitor a non-const reference to a visitor that have an operator () (Logger const*)
	 */
	template <class VISITOR> void ForEachClient(VISITOR& visitor);
	
private:
	/** Pointer set to the client loggers */
	typedef std::set<Logger const*> Clients;
	Clients clients;
	
	/** Pointer set to the printers */
	typedef std::set<Printer *> Printers;
	Printers printers;

	pthread_mutex_t mutex;
	
	/** Server internal closing method
	* 
	* Invoked when no client are connected anymore
	*/
	void Close();
};

template <class VISITOR>
void LoggerServer::ForEachClient(VISITOR& visitor)
{
	Clients::iterator client_iter;
	for(client_iter = clients.begin(); client_iter != clients.end(); client_iter++)
	{
		Logger const* client = *client_iter;
		visitor(client);
	}
}

} // end of namespace logger
} // end of namespace kernel
} // end of namespace unisim

#endif // __UNISIM_KERNEL_LOGGER_LOGGER_SERVER_HH__
