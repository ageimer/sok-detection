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

#ifndef __UNISIM_KERNEL_LOGGER_LOGGER_HH__
#define __UNISIM_KERNEL_LOGGER_LOGGER_HH__

#include <unisim/kernel/kernel.hh>
#include <string>
#include <ios>
#include <ostream>
#include <sstream>
#include <pthread.h>

namespace unisim {
namespace kernel {
namespace logger {

struct LoggerServer;
struct Logger;

enum mode_t { NO_MODE = 0, INFO_MODE, WARNING_MODE, ERROR_MODE };

typedef void (LoggerServer::*LoggerServerOutputMethodPtr)(const char *, const char *);

class LoggerStreamBuffer : public std::streambuf
{
public:
	LoggerStreamBuffer(Logger& owner, LoggerServerOutputMethodPtr logger_server_output_method_ptr);
	~LoggerStreamBuffer();
	
protected:
	virtual int_type overflow(int_type c);
	virtual std::streamsize xsputn(const char* s, std::streamsize n);
	
private:
	void Append(char c);
	void Flush();
	
	Logger& owner;
	LoggerServerOutputMethodPtr logger_server_output_method_ptr;
	std::string buffer;
	pthread_mutex_t mutex;
};

class LoggerStream : public std::ostream
{
public:
	LoggerStream(Logger& owner, LoggerServerOutputMethodPtr logger_server_output_method_ptr);
	~LoggerStream();
	
private:
	LoggerStreamBuffer logger_stream_buffer;
};

struct Logger
{
	Logger(const std::string& name);
	Logger(const char *name);
	Logger(const unisim::kernel::Object& object);
	~Logger();
	
	friend Logger& operator << (Logger& logger, std::ios_base& (*f)(std::ios_base &));
	friend Logger& operator << (Logger& logger, std::ostream& (*f)(std::ostream &));
	friend Logger& operator << (Logger& logger, Logger& (*f)(Logger &));

	template<typename T> Logger& operator << (const T& t)
	{
		buffer << t;
		return *this;
	}

#if 0
	template <typename T>
	Logger& operator << (const std::vector<T>& bv)
	{
		typename std::vector<T>::size_type length = bv.size();
		typename std::vector<T>::size_type i;
		
		for(i = 0; i < length; i++)
		{
			if(i) buffer << " ";
			
			const T& v = bv[i];
			
			buffer << v;
		}
		
		return *this;
	}
#endif

	void DebugInfo();
	void EndDebugInfo();
	void DebugWarning();
	void EndDebugWarning();
	void DebugError();
	void EndDebugError();
	void EndDebug();
	
	LoggerStream& DebugNullStream() { return null_stream; }
	LoggerStream& DebugInfoStream() { return info_stream; }
	LoggerStream& DebugWarningStream() { return warning_stream; }
	LoggerStream& DebugErrorStream() { return error_stream; }
	
	const char *GetName() const { return name.c_str(); }
private:
	friend class LoggerStreamBuffer;
	friend class unisim::kernel::Simulator;
	
	unisim::kernel::logger::LoggerServer* GetServerInstance();
public:
	static unisim::kernel::logger::LoggerServer* StaticServerInstance();
private:
	static void ReleaseStaticServiceInstance();
	void PrintMode();

	std::string name;
	std::stringstream buffer;
	mode_t mode;
	unisim::kernel::logger::LoggerServer *server;
	LoggerStream null_stream;
	LoggerStream info_stream;
	LoggerStream warning_stream;
	LoggerStream error_stream;
	
	static LoggerServer *static_server_instance;
};

Logger& DebugInfo(Logger&);
Logger& EndDebugInfo(Logger&);
Logger& DebugWarning(Logger&);
Logger& EndDebugWarning(Logger&);
Logger& DebugError(Logger&);
Logger& EndDebugError(Logger&);
Logger& EndDebug(Logger&);

} // end of namespace logger
} // end of namespace kernel
} // end of namespace unisim

#endif // __UNISIM_KERNEL_LOGGER_LOGGER_HH__

