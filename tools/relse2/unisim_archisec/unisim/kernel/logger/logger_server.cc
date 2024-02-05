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

#include <unisim/kernel/logger/logger_server.hh>
#include <unisim/kernel/kernel.hh>

#include <iostream>

namespace unisim {
namespace kernel {
namespace logger {

Printer::Printer()
{
	Logger::StaticServerInstance()->AddPrinter(this);
}

Printer::~Printer()
{
	Logger::StaticServerInstance()->RemovePrinter(this);
}

LoggerServer::LoggerServer(const char *name, unisim::kernel::Object *parent)
	: unisim::kernel::Object(name, parent, "Logger")
	, clients()
	, printers()
	, mutex()
{
	pthread_mutex_init(&mutex, NULL);
}

LoggerServer::~LoggerServer()
{
	Close();
	pthread_mutex_destroy(&mutex);
}

void LoggerServer::Close()
{
	if (clients.size())
	{
		std::cerr << "Error(LoggerServer::close): "
		          << "client loggers still connected" << std::endl;
		Clients::iterator client_iter;
		for(client_iter = clients.begin(); client_iter != clients.end(); client_iter++)
		{
			Logger const* client = *client_iter;
			std::cerr << "Error(LoggerServer::close): client \"" << client->GetName() << "\" still connected" << std::endl;
		}
	}
	if (printers.size())
	{
		std::cerr << "Error(LoggerServer::close): "
		          << "some printers are still connected" << std::endl;
	}
}

void LoggerServer::AddClient( Logger const* client )
{
	if (not clients.insert( client ).second)
	{
		std::cerr << "Error(LoggerServer::AddClient): "
		          << "internal issue, client already connected" << std::endl;
	}
}

void LoggerServer::AddPrinter( Printer* printer )
{
	if (not printers.insert( printer ).second)
	{
		std::cerr << "Error(LoggerServer::AddPrinter): "
		          << "internal issue, printer already connected" << std::endl;
	}
}

void LoggerServer::RemoveClient( Logger const* client )
{
	if (not clients.erase( client ))
	{
		std::cerr << "Error(LoggerServer::RemoveClient): "
		          << "internal issue, attempting to disconnect a unknown client" << std::endl;
	}
}

void LoggerServer::RemovePrinter( Printer* printer )
{
	if (not printers.erase( printer ))
	{
		std::cerr << "Error(LoggerServer::RemovePrinter): "
		          << "internal issue, attempting to disconnect a unknown printer" << std::endl;
	}
}

void LoggerServer::Print(mode_t mode, const char *name, const char *buffer)
{
	pthread_mutex_lock(&mutex);
	for(Printers::iterator printer_iter = printers.begin(); printer_iter != printers.end(); printer_iter++)
	{
		Printer* printer = *printer_iter;
		printer->Print(mode, name, buffer);
	}
	pthread_mutex_unlock(&mutex);
}

void LoggerServer::DebugNull( const char *name, const char *buffer )
{
}

void LoggerServer::DebugInfo(const char *name, const char *buffer)
{
	Print(INFO_MODE, name, buffer);
}

void LoggerServer::DebugWarning(const char *name, const char *buffer)
{
	Print(WARNING_MODE, name, buffer);
}

void LoggerServer::DebugError(const char *name, const char *buffer)
{
	Print(ERROR_MODE, name, buffer);
}

} // end of namespace logger
} // end of namespace kernel
} // end of namespace unisim

