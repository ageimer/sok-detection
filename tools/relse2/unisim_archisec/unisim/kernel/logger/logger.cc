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
 *         Gilles Mouchard (gilles.mouchard@cea.fr)
 *         Yves Lhuillier (yves.lhuillier@cea.fr) 
 */

#include "unisim/kernel/logger/logger.hh"
#include "unisim/kernel/logger/logger_server.hh"

#include <iostream>

namespace unisim {
namespace kernel {
namespace logger {

LoggerServer *Logger::static_server_instance = 0;

unisim::kernel::logger::LoggerServer *Logger::StaticServerInstance()
{
	if(!static_server_instance)
	{
		static_server_instance = new LoggerServer("logger");
	}
	
	return static_server_instance;
}

void Logger::ReleaseStaticServiceInstance()
{
	if(static_server_instance)
	{
		delete static_server_instance;
		static_server_instance = 0;
	}
}

unisim::kernel::logger::LoggerServer *Logger::GetServerInstance()
{
	if(not server)
	{
		server = StaticServerInstance();
		server->AddClient(this);
	}
	
	return server;
}

LoggerStreamBuffer::LoggerStreamBuffer(Logger& _owner, LoggerServerOutputMethodPtr _logger_server_output_method_ptr)
	: owner(_owner)
	, logger_server_output_method_ptr(_logger_server_output_method_ptr)
	, buffer()
	, mutex()
{
	pthread_mutex_init(&mutex, NULL);
}

LoggerStreamBuffer::~LoggerStreamBuffer()
{
	if(!buffer.empty())
	{
		Flush();
	}
	
	pthread_mutex_destroy(&mutex);
}

std::streambuf::int_type LoggerStreamBuffer::overflow(int_type c)
{
	Append(c);
	
	return c;
}

std::streamsize LoggerStreamBuffer::xsputn(const char* s, std::streamsize n)
{
	if(n)
	{
		int count = n;
		
		do
		{
			char c = *s;
			Append(c);
		}
		while(++s, --count);
	}
	
	return n;
}

void LoggerStreamBuffer::Append(char c)
{
	if(c == '\n')
	{
		Flush();
	}
	else
	{
		pthread_mutex_lock(&mutex);
		buffer.append(1, c);
		pthread_mutex_unlock(&mutex);
	}
}

void LoggerStreamBuffer::Flush()
{
	pthread_mutex_lock(&mutex);
	(owner.GetServerInstance()->*logger_server_output_method_ptr)(owner.GetName(), buffer.c_str());
	buffer.clear();
	pthread_mutex_unlock(&mutex);
}

LoggerStream::LoggerStream(Logger& owner, LoggerServerOutputMethodPtr logger_server_output_method_ptr)
	: logger_stream_buffer(owner, logger_server_output_method_ptr)
{
	rdbuf(&logger_stream_buffer);
}

LoggerStream::~LoggerStream()
{
}

Logger::Logger(const std::string& _name)
	: name(_name)
	, buffer()
	, mode(NO_MODE)
	, server(0)
	, null_stream(*this, &unisim::kernel::logger::LoggerServer::DebugNull)
	, info_stream(*this, &unisim::kernel::logger::LoggerServer::DebugInfo)
	, warning_stream(*this, &unisim::kernel::logger::LoggerServer::DebugWarning)
	, error_stream(*this, &unisim::kernel::logger::LoggerServer::DebugError)
{
	GetServerInstance();
}

Logger::Logger(const char * _name)
	: name(_name)
	, buffer()
	, mode(NO_MODE)
	, server(0)
	, null_stream(*this, &unisim::kernel::logger::LoggerServer::DebugNull)
	, info_stream(*this, &unisim::kernel::logger::LoggerServer::DebugInfo)
	, warning_stream(*this, &unisim::kernel::logger::LoggerServer::DebugWarning)
	, error_stream(*this, &unisim::kernel::logger::LoggerServer::DebugError)
{
	GetServerInstance();
}

Logger::Logger(const unisim::kernel::Object& object)
	: name(object.GetName())
	, buffer()
	, mode(NO_MODE)
	, server(0)
	, null_stream(*this, &unisim::kernel::logger::LoggerServer::DebugNull)
	, info_stream(*this, &unisim::kernel::logger::LoggerServer::DebugInfo)
	, warning_stream(*this, &unisim::kernel::logger::LoggerServer::DebugWarning)
	, error_stream(*this, &unisim::kernel::logger::LoggerServer::DebugError)
{
	GetServerInstance();
}

Logger::~Logger()
{
	server->RemoveClient(this);
}

Logger& operator <<(Logger& logger, std::ostream& (*f)(std::ostream &))
{
	if (logger.mode == NO_MODE) return logger;
	logger.buffer << f;
	return logger;
}

Logger& operator <<(Logger& logger, std::ios_base& (*f)(std::ios_base &))
{
	if (logger.mode == NO_MODE) return logger;
	logger.buffer << f;
	return logger;
}

Logger& operator <<(Logger& logger, Logger& (*f)(Logger &))
{
	return f(logger);
}

void Logger::PrintMode()
{
	std::cerr << "Current mode (" << name << "): ";
	switch (mode)
	{
		default:           std::cerr << "?_MODE"; break;
		case NO_MODE:      std::cerr << "NO_MODE"; break;
		case INFO_MODE:    std::cerr << "INFO_MODE"; break;
		case WARNING_MODE: std::cerr << "WARNING_MODE"; break;
		case ERROR_MODE:   std::cerr << "ERROR_MODE"; break;
	}
	std::cerr << std::endl;
}

void Logger::DebugInfo()
{
	if (mode != NO_MODE) return;
	mode = INFO_MODE;
	buffer.clear();
	buffer.str("");
}

void Logger::EndDebugInfo() {
	if (mode != INFO_MODE) return;
	mode = NO_MODE;
	server->DebugInfo(name.c_str(), buffer.str().c_str());
}

void Logger::DebugWarning()
{
	if (mode != NO_MODE) return;
	mode = WARNING_MODE;
	buffer.clear();
	buffer.str("");
}

void Logger::EndDebugWarning()
{
	if (mode != WARNING_MODE) return;
	mode = NO_MODE;
	server->DebugWarning(name.c_str(), buffer.str().c_str());
}

void Logger::DebugError()
{
	if (mode != NO_MODE) return;
	mode = ERROR_MODE;
	buffer.clear();
	buffer.str("");
}

void Logger::EndDebugError()
{
	if (mode != ERROR_MODE) return;
	mode = NO_MODE;
	server->DebugError(name.c_str(), buffer.str().c_str());
}

void Logger::EndDebug()
{
	switch (mode)
	{
		case NO_MODE:
			/* nothing to do */
			break;
		case INFO_MODE:
			EndDebugInfo();
			break;
		case WARNING_MODE:
			EndDebugWarning();
			break;
		case ERROR_MODE:
			EndDebugError();
			break;
	}
}

Logger& DebugInfo(Logger &l)
{
	l.DebugInfo();
	return l;
}

Logger& EndDebugInfo(Logger &l)
{
	l.EndDebugInfo();
	return l;
}

Logger& DebugWarning(Logger &l)
{
	l.DebugWarning();
	return l;
}

Logger& EndDebugWarning(Logger &l)
{
	l.EndDebugWarning();
	return l;
}

Logger& DebugError(Logger &l)
{
	l.DebugError();
	return l;
}

Logger& EndDebugError(Logger &l)
{
	l.EndDebugError();
	return l;
}

Logger& EndDebug(Logger &l)
{
	l.EndDebug();
	return l;
}

} // end of namespace logger
} // end of namespace kernel
} // end of namespace unisim
