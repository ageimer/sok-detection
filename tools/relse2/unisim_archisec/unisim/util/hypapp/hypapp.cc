/*
 *  Copyright (c) 2017,
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
 * Authors: Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#include <unisim/util/hypapp/hypapp.hh>
#include <iostream>
#include <sstream>
#include <vector>

#include <cstring>
#include <cstdlib>

#include <errno.h>

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)

#include <winsock2.h>

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>

#endif

namespace unisim {
namespace util {
namespace hypapp {

namespace 
{
  char const*
  GetHeaderEnd( char const* buf, uintptr_t size )
  {
    for (char const* end = &buf[size-3]; buf < end;)
      {
        if       (buf[3] == '\r')                          buf += 1;
        else if ((buf[2] == '\r') and (buf[3] == '\n'))
          {
            if  ((buf[0] == '\r') and (buf[1] == '\n'))    return buf;
            else                                           buf += 2;
          }
        else                                               buf += 4;
      }
    
    return 0;
  }
  
  char const*
  streat( char const* ptr, char const* from, bool case_sensitive = false )
  {
    while (*ptr and ((case_sensitive && ((*ptr) == (*from))) || (!case_sensitive && (tolower(*ptr) == tolower(*from)))))
      ++ptr, ++from;
    return *ptr ? 0 : from;
  }
  
  char const*
  strseek( char const* search_for, char const* ptr, bool case_sensitive = false, bool after = false)
  {
    if((*search_for) == 0) return ptr;
    while(*ptr)
    {
      char const *ptr1 = ptr;
      char const *ptr2 = search_for;
      while(*ptr2)
      {
        if((*ptr1) == 0) return 0;
        if(((case_sensitive && ((*ptr1) != (*ptr2)))) || (!case_sensitive && (tolower(*ptr1) == tolower(*ptr2)))) break;
        ++ptr1;
        ++ptr2;
      }
      if((*ptr2) == 0)
      {
        return after ? ptr1 : ptr;
      }
      
      ++ptr;
    }
    return 0;
  }
  
  void sleep(unsigned int msec)
  {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
    Sleep(msec);
#else
    struct timespec tim_req, tim_rem;
    tim_req.tv_sec = msec / 1000;
    tim_req.tv_nsec = 1000000 * (msec % 1000);
    
    for(;;)
    {
      int status = nanosleep(&tim_req, &tim_rem);
      
      if(status == 0) break;
      
      if(status != -1) break;
      
      if(errno != EINTR) break;
      
      tim_req.tv_nsec = tim_rem.tv_nsec;
    }
#endif
  }
}

InputStreamBuffer::InputStreamBuffer()
	: buffer(0)
	, length(0)
	, pos(0)
{
}

InputStreamBuffer::InputStreamBuffer(char const* _buffer, std::streamsize _length, std::streampos _pos)
{
	Initialize(_buffer, _length, _pos);
}

void InputStreamBuffer::Initialize(char const* _buffer, std::streamsize _length, std::streampos _pos)
{
	buffer = _buffer;
	length = _length;
	pos = _pos;
}

InputStreamBuffer::int_type InputStreamBuffer::underflow()
{
	if(pos < length)
	{
		int_type c = buffer[pos];
		pos += 1;
		return c;
	}
	
	return std::char_traits<char>::eof();
}

std::streamsize InputStreamBuffer::xsgetn(char* s, std::streamsize n)
{
	std::streamsize m = ((pos + std::streamoff(n)) > (std::ios::beg + std::streamoff(length))) ? (std::ios::beg + std::streamoff(length) - pos) : n;
	if(m > 0)
	{
		memcpy(s, buffer + pos, m);
		pos += m;
	}
	return m;
}

OutputStreamBuffer::OutputStreamBuffer()
  : buffer()
{
}

OutputStreamBuffer::int_type OutputStreamBuffer::overflow(int_type c)
{
  reserve(1);
  buffer.append(1, c);
  return c;
}

std::streamsize OutputStreamBuffer::xsputn(const char* s, std::streamsize n)
{
  if(n)
  {
    reserve(n);
    buffer.append(s, n);
  }
  
  return n;
}

void OutputStreamBuffer::reserve(std::streamsize n)
{
  std::size_t m = ((buffer.size() + n + 4095) & -4096);
  if(m > buffer.capacity()) buffer.reserve(m);
}

std::ostream& operator << (std::ostream& os, const HeaderField& f) 
{
	return os << f.key << ": " << f.value;
}

std::ostream& operator << (std::ostream& os, const Request::request_type_t& request_type)
{
  switch(request_type)
  {
    case Request::NO_REQ : os << "Not a request"; break;
    case Request::OPTIONS: os << "OPTIONS"; break;
    case Request::GET    : os << "GET"; break;
    case Request::HEAD   : os << "HEAD"; break;
    case Request::POST   : os << "POST"; break;
    default              : os << "unknown"; break;
  }
  return os;
}

std::ostream& operator << (std::ostream& os, const Request& req)
{
  os << req.GetRequestType() << " " << req.GetRequestURI() << " HTTP/1.1" << std::endl;
  for(unsigned int i = 0; i < req.GetHeaderFieldCount(); i++)
  {
	  HeaderField const *header_field = req.GetHeaderField(i);
	  os << (*header_field) << std::endl;
  }
  os << std::endl;
  if(req.GetContentLength())
  {
    os << std::string(req.GetContent(), req.GetContentLength()) << std::endl;
  }
  return os;
}

HttpRequest::HttpRequest(const Request& _req, std::ostream& _log, std::ostream& _warn_log, std::ostream& _err_log)
  : valid(false)
  , has_query(false)
  , has_fragment(false)
  , req(_req)
  , abs_path()
  , server_root()
  , path()
  , query()
  , fragment()
  , domain()
  , has_port(false)
  , port(0)
  , content_stream_buffer(req.GetContent(), req.GetContentLength(), 0)
  , parts()
  , log(_log)
  , warn_log(_warn_log)
  , err_log(_err_log)
{
  rdbuf(&content_stream_buffer);
  
  unsigned int part_count = req.GetPartCount();
  parts.reserve(part_count);
  for(unsigned int part_num = 0; part_num < part_count; part_num++)
  {
    parts.push_back(new HttpRequestPart(req.GetPart(part_num)));
  }
  
  valid = URL_AbsolutePathDecoder::Decode(req.GetRequestURI(), abs_path, warn_log);
  if(valid)
  {
    server_root = "/";
    path = abs_path.substr(1);
  }
  const char *p_request_uri = req.GetRequestURI();
  if(p_request_uri)
  {
    const char *p_query = strchr(p_request_uri, '?');
    if(p_query) p_query++;
    const char *p_fragment = strchr(p_query ? p_query : p_request_uri, '#');
    if(p_fragment) p_fragment++;
    if(p_fragment)
    {
      fragment = std::string(p_fragment);
      has_fragment = true;
    }
    if(p_query)
    {
      if(p_fragment)
      {
        query = std::string(p_query, p_fragment - p_query);
      }
      else
      {
        query = std::string(p_query);
      }
      has_query = true;
    }
  }
  const char *p_host = req.GetHost();
  if(p_host)
  {
    const char *p_port = strchr(p_host, ':');
    if(p_port)
    {
      domain = std::string(p_host, p_port - p_host);
      std::istringstream sstr(p_port + 1);
      sstr >> port;
      has_port = true;
    }
    else
    {
      domain = std::string(p_host);
    }
  }
}

HttpRequest::HttpRequest(const std::string& _server_root, const std::string& _path, const HttpRequest& http_request)
  : valid(http_request.valid)
  , has_query(http_request.has_query)
  , has_fragment(http_request.has_fragment)
  , req(http_request.req)
  , abs_path(http_request.abs_path)
  , server_root(_server_root)
  , path(_path)
  , query(http_request.query)
  , fragment(http_request.fragment)
  , domain(http_request.domain)
  , has_port(http_request.has_port)
  , port(http_request.port)
  , content_stream_buffer(req.GetContent(), req.GetContentLength(), 0)
  , parts()
  , log(http_request.log)
  , warn_log(http_request.warn_log)
  , err_log(http_request.err_log)
{
  rdbuf(&content_stream_buffer);
  
  unsigned int part_count = req.GetPartCount();
  for(unsigned int part_num = 0; part_num < part_count; part_num++)
  {
    parts.push_back(new HttpRequestPart(req.GetPart(part_num)));
  }
}

HttpRequest::~HttpRequest()
{
  unsigned int part_count = parts.size();
  for(unsigned int part_num = 0; part_num < part_count; part_num++)
  {
    delete parts[part_num];
  }
}

std::ostream& operator << (std::ostream& os, const HttpRequest& http_request)
{
  os << http_request.req;
  os << "Valid: " << http_request.IsValid() << std::endl;
  if(http_request.IsValid())
  {
    os << "Absolute Path: \"" << http_request.GetAbsolutePath() << "\"" <<std::endl;
    os << "Server Root: \"" << http_request.GetServerRoot() << "\"" <<std::endl;
    os << "Path: \"" << http_request.GetPath() << "\"" << std::endl;
  }
  if(http_request.HasQuery())
  {
    os << "Query: \"" << http_request.GetQuery() << "\"" << std::endl;
  }
  if(http_request.HasFragment())
  {
    os << "Fragment: \"" << http_request.GetFragment() << "\"" << std::endl;
  }
  os << "Host: \"" << http_request.GetHost() << "\"" << std::endl;
  os << "Domain: \"" << http_request.GetDomain() << "\"" << std::endl;
  if(http_request.HasPort())
  {
    os << "Port: " << http_request.GetPort() << std::endl;
  }
  return os;
}

HttpResponse::HttpResponse()
  : status_code(OK)
  , content_type("text/html; charset=utf-8")
  , enable_cache(false)
  , keep_alive(true)
  , allow()
  , accept_ranges("none")
  , content_stream_buffer()
  , header_fields()
{
  rdbuf(&content_stream_buffer);
}

std::string HttpResponse::ToString(bool header_only) const
{
  std::ostringstream sstr;
  Print(sstr, header_only);
  return sstr.str();
}

void HttpResponse::Print(std::ostream& os, bool header_only) const
{
  const std::string& content(content_stream_buffer.str());
  os << "HTTP/1.1 " << status_code << "\r\n";
  os << "Server: UNISIM-VP\r\n";
  
  if(IsSuccessful())
  {
    if(!allow.empty())
    {
      os << "Allow: " << allow << "\r\n";
    }
    if(!accept_ranges.empty())
    {
      os << "Accept-Ranges: " << accept_ranges << "\r\n";
    }
    if(enable_cache)
    {
      os << "Cache-control: public, max-age=600\r\n";
    }
    else
    {
      os << "Cache-control: no-cache\r\n";
    }
  }
  
  if(content.length())
  {
    if(content_type.length())
    {
      os << "Content-Type: " << content_type << "\r\n";
    }
    else
    {
      os << "Content-Type: application/octet-stream\r\n";
    }
  }
  
  os << "Content-length: " << content.length() << "\r\n";
   
  if(keep_alive)
  {
    os << "Connection: keep-alive\r\n";
  }
  
  for(HeaderFields::const_iterator it = header_fields.begin(); it != header_fields.end(); it++)
  {
    const HeaderField& header_field = *it;
    const std::string& key = header_field.key;
    const std::string& value = header_field.value;
    
    os << key << ": " << value << "\r\n";
  }
  
  os << "\r\n";
  
  if(!header_only)
  {
    os << content;
  }
}

std::ostream& operator << (std::ostream& os, const HttpResponse::StatusCode& status_code)
{
  os << (unsigned int) status_code << ' ';
  switch(status_code)
  {
    case HttpResponse::CONTINUE                     : os << "Continue"; break;
    case HttpResponse::SWITCHING_PROTOCOLS          : os << "Switching Protocols"; break;
    
    // successful
    case HttpResponse::OK                           : os << "OK"; break;
    case HttpResponse::CREATED                      : os << "Created"; break;
    case HttpResponse::ACCEPTED                     : os << "Accepted"; break;
    case HttpResponse::NON_AUTHORITATIVE_INFORMATION: os << "Non-Authoritative Information"; break;
    case HttpResponse::NO_CONTENT                   : os << "No Content"; break;
    case HttpResponse::RESET_CONTENT                : os << "Reset Content"; break;
    case HttpResponse::PARTIAL_CONTENT              : os << "Partial Content"; break;

    // redirection
    case HttpResponse::MULTIPLE_CHOICES             : os << "Multiple Choices"; break;
    case HttpResponse::MOVED_PERMANENTLY            : os << "Moved Permanently"; break;
    case HttpResponse::FOUND                        : os << "Found"; break;
    case HttpResponse::SEE_OTHER                    : os << "See Other"; break;
    case HttpResponse::NOT_MODIFIED                 : os << "Not Modified"; break;
    case HttpResponse::USE_PROXY                    : os << "Use Proxy"; break;
    case HttpResponse::UNUSED                       : os << "Unused"; break;
    case HttpResponse::TEMPORARY_REDIRECT           : os << "Temporary Redirect"; break;

    // client error
    case HttpResponse::BAD_REQUEST                  : os << "Bad Request"; break;
    case HttpResponse::UNAUTHORIZED                 : os << "Unauthorized"; break;
    case HttpResponse::PAYMENT_REQUIRED             : os << "Payment Required"; break;
    case HttpResponse::FORBIDDEN                    : os << "Forbidden"; break;
    case HttpResponse::NOT_FOUND                    : os << "Not Found"; break;
    case HttpResponse::METHOD_NOT_ALLOWED           : os << "Method Not Allowed"; break;
    case HttpResponse::NOT_ACCEPTABLE               : os << "Not Acceptable"; break;
    case HttpResponse::PROXY_AUTHENTICATION_REQUIRED: os << "Proxy Authentication Required"; break;
    case HttpResponse::REQUEST_TIMEOUT              : os << "Request Timeout"; break;
    case HttpResponse::CONFLICT                     : os << "Conflict"; break;
    case HttpResponse::GONE                         : os << "Gone"; break;
    case HttpResponse::LENGH_REQUIRED               : os << "Lengh Required"; break;
    case HttpResponse::PRECONDITION_FAILED          : os << "Precondition Failed"; break;
    case HttpResponse::REQUEST_ENTITY_TOO_LARGE     : os << "Request Entity Too Large"; break;
    case HttpResponse::UNSUPPORTED_MEDIA_TYPE       : os << "Unsupported Media Type"; break;
    case HttpResponse::REQUEST_RANGE_NOT_SATISFIABLE: os << "Request Range Not Satisfiable"; break;
    case HttpResponse::EXPECTATION_FAILED           : os << "Expectation Failed"; break;

    // server error
    case HttpResponse::INTERNAL_SERVER_ERROR        : os << "Internal Server Error"; break;
    case HttpResponse::NOT_IMPLEMENTED              : os << "Not Implemented"; break;
    case HttpResponse::BAD_GATEWAY                  : os << "Bad Gateway"; break;
    case HttpResponse::SERVICE_UNAVAILABLE          : os << "Service Unavailable"; break;
    case HttpResponse::GATEWAY_TIMEOUT              : os << "Gateway Timeout"; break;
    case HttpResponse::HTTP_VERSION_NOT_SUPPORTED   : os << "HTTP Version Not Supported"; break;
    
    default                                         : break;
  }
  return os;
}

std::ostream& operator << (std::ostream& os, const HttpResponse& http_response)
{
	http_response.Print(os, false);
	return os;
}

struct IPAddrRepr
{
  IPAddrRepr( uint32_t _ipaddr ) : addr(ntohl(_ipaddr)) {} uint32_t addr;
  friend std::ostream& operator << (std::ostream& sink, IPAddrRepr const& ip)
  {
    sink << unsigned((ip.addr << 3*8) >> 24) << "."
         << unsigned((ip.addr << 2*8) >> 24) << "."
         << unsigned((ip.addr << 1*8) >> 24) << "."
         << unsigned((ip.addr << 0*8) >> 24);
    return sink;
  }
};

void MessageLoop::Run(ClientConnection const& conn)
{
  std::vector<char> ibuf;
  std::vector<HeaderField> header_fields;
  ibuf.reserve(4096);
  header_fields.reserve(16);
    
  for (;;)
    {
      char const* ptr = &ibuf[0];
#if 1
      {
        uintptr_t skip = 0, size = ibuf.size();
        while ((size-skip) >= 2 and ptr[skip] == '\r' and ptr[skip+1] == '\n')
          skip += 2;
        if (skip)
          ibuf.erase( ibuf.begin(), ibuf.begin() + skip );
        ptr = &ibuf[0];
      }
#endif

      char const* soh = ptr;
      char const* eoh = GetHeaderEnd(ptr, ibuf.size());
        
      if (not eoh)
        {
          /* Partial header */
          if(ibuf.size() == ibuf.capacity()) ibuf.reserve(ibuf.capacity() + 4096);
          uintptr_t resume = ibuf.size(), end = ibuf.capacity();
          ibuf.resize(end);
          if(end == resume) throw 0;
          if(http_server.Killed()) return;
#if 0
          if(http_server.Verbose())
          {
            log << "trying to receive " << (end - resume) << " bytes" << std::endl;
          }
#endif
          intptr_t bytes = recv(conn.socket, &ibuf[resume], end - resume, 0);
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
          if((bytes == 0) || (bytes == SOCKET_ERROR))
#else
          if(bytes <= 0)
#endif
          {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
            if(bytes == SOCKET_ERROR)
#else
            if(bytes < 0)
#endif
            {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
              if(WSAGetLastError() == WSAEWOULDBLOCK)
#else
              if((errno == EAGAIN) || (errno == EWOULDBLOCK))
#endif
              {
                sleep(1); // try again later
              }
              else
              {
                err_log << "[" << conn.socket << "] recv error\n"; return; 
              }
            }
            else
            {
              if(resume)
              {
                err_log << "[" << conn.socket << "] header short read (got " << resume << " bytes)\n";
              }  
              return; 
            }
            ibuf.resize(resume);
          }
          else
          {
            ibuf.resize(resume + bytes);
            if(http_server.Verbose())
            {
              log << "received " << bytes << " bytes [";
              for(intptr_t i = 0; i < bytes; i++)
              {
                if(i) log << ' ';
                char c = ibuf[resume + i];
                if((c >= 32) && (c <= 126))
                {
                  log << '\'' << c << '\'';
                }
                else
                {
                  log << '\'' << "0x" << std::hex << (unsigned int) c << '\'' << std::dec;
                }
              }
              log << "]" << std::endl;
            }
          }
          continue;
        }
        
      eoh += 2; // first "\r\n" is inside header
      uintptr_t request_size = eoh - ptr;
      ibuf[request_size] = '\0';
      request_size += 2; // second "\r\n" before next part

      Request request;
      header_fields.clear();
      if      (char const* p = streat("OPTIONS ", ptr)) { ptr = p; request.request_type = Request::OPTIONS; }
      else if (char const* p = streat("GET ", ptr))     { ptr = p; request.request_type = Request::GET; }
      else if (char const* p = streat("HEAD ", ptr))    { ptr = p; request.request_type = Request::HEAD; }
      else if (char const* p = streat("POST ", ptr))    { ptr = p; request.request_type = Request::POST; }
      else {
        if (char const* p = strchr(ptr, '\r'))
          ibuf[p-soh] = '\0';
        err_log << "unknown method in: " << ptr << std::endl;
        return;
      }
      
      {
        char const* uri = ptr;
        if (not (ptr = strchr(uri, ' '))) { err_log << "[" << conn.socket << "] URI parse error\n"; return; }
        ibuf[ptr++-soh] = '\0';
        if(http_server.Verbose())
        {
          log << "[" << conn.socket << "] URI: " << uri << std::endl;
        }
        request.uri = (char const *)(uri - &ibuf[0]);
      }
      
      if (not (ptr = streat("HTTP/1.", ptr))) { err_log << "[" << conn.socket << "] HTTP version parse error\n"; return; }
      
      {
        unsigned http_version = 0;
        for (unsigned digit; *ptr != '\r'; ++ptr) {
          if ((digit = (*ptr - '0')) >= 10) { err_log << "[" << conn.socket << "] HTTP version parse error\n"; return; }
          http_version = 10*http_version+digit;
        }
        if (http_version != 1)
          { err_log << "[" << conn.socket << "] HTTP/1." << http_version <<  " != 1 makes me nervous\n"; return; }
      }
      if (not (ptr = streat("\r\n", ptr))) { err_log << "[" << conn.socket << "] HTTP request parse error\n"; return; }
        
      bool keep_alive = false;
      int cseq = 0;
      unsigned content_length = 0;
      bool var_content = false;
      char const* multipart_boundary = 0;
        
      while (ptr < eoh)
        {
          char const* key = ptr;
          if (not (ptr = strchr(ptr, ':'))) { err_log << "[" << conn.socket << "] HTTP headers parse error\n"; return; }
          ibuf[ptr++-soh] = '\0';
          while (isblank(*ptr)) ptr += 1;
          char const* val = ptr;
          if (not (ptr = strchr(ptr, '\r'))) { err_log << "[" << conn.socket << "] HTTP headers parse error\n"; return; }
          for (char const* p = ptr; (--p > val) and isspace(*p);) ibuf[p-soh] = '\0';
          ibuf[ptr++-soh] = '\0';
          if (*ptr++ != '\n') { err_log << "[" << conn.socket << "] HTTP headers parse error\n"; return; }
            
          // header field parsed
          if(header_fields.capacity() == header_fields.size())
          {
            header_fields.reserve(header_fields.capacity() + 16);
          }
          header_fields.push_back(HeaderField((char const *)(key - soh), (char const *)(val - soh)));
            
          if      (streat("Connection", key))
            {
              keep_alive = streat("Keep-Alive", val);
              if(http_server.Verbose())
              {
                log << "[" << conn.socket << "] keep alive: " << keep_alive << "\n";
              }
            }
          else if (streat("Content-Type", key))
            {
              multipart_boundary = streat("multipart/form-data; boundary=",val);
              if(multipart_boundary) multipart_boundary = (char const *)(multipart_boundary - &ibuf[0]);
              if(http_server.Verbose()) { log << "[" << conn.socket << "] " << key << ": " << val << "\n"; } request.content_type = (char const *)(val - &ibuf[0]);
            }
          else if (streat("CSeq", key))
            { cseq = strtoul( val, 0, 0 ); if(http_server.Verbose()) { log << "[" << conn.socket << "] cseq:" << cseq << "\n"; } }
          else if (streat("Host", key))
            {
              if(http_server.Verbose()) { log << "[" << conn.socket << "] " << key << ": " << val << "\n"; }
              request.host = (char const *)(val - &ibuf[0]);
            }
          else if (streat("Range", key))
            { err_log << "[" << conn.socket << "] " << key << ": " << val << "\n"; return; }
          else if (streat("Content-Length", key))
            { if(http_server.Verbose()) { log << "[" << conn.socket << "] " << key << ": " << val << "\n"; }
              content_length = 0;
              for (unsigned digit; *val != 0; ++val) {
                if ((digit = (*val - '0')) >= 10) { err_log << "[" << conn.socket << "] Content length parse error\n"; return; }
                content_length = 10*content_length+digit;
              }
              if(content_length) request.content_length = content_length;
              var_content = (request.request_type == Request::POST) && (content_length == 0);
              if(var_content) keep_alive = false;
            }
          else if(http_server.Verbose())
            { log << "[" << conn.socket << "] unhandled: {key:" << key << ", val:" << val << "}\n"; }
        }
        
      if(http_server.Verbose())
      {
        log << "Header (size: " << request_size << ") received and processed.\n";
        switch (request.request_type) {
        case Request::OPTIONS: log << "Options request." << std::endl; break;
        case Request::GET    : log << "Get request." << std::endl; break;
        case Request::HEAD   : log << "Head request." << std::endl; break;
        case Request::POST   : log << "Post request." << std::endl; break;
        default: break;
        }
      }
      
      if(var_content || (content_length != 0))
      {
        if(content_length != 0)
        {
          ibuf.reserve(request_size + content_length); // header + content
        }
        
        unsigned int rem_content_length = content_length;

        unsigned int lookahead_size = ibuf.size() - request_size;
        
        if(lookahead_size != 0)
        {
          if(var_content)
          {
            content_length = lookahead_size;
          }
          else
          {
            rem_content_length -= lookahead_size;
          }
        }
      
        while(var_content || (rem_content_length != 0))
        {
          if(var_content && (ibuf.size() == ibuf.capacity())) ibuf.reserve(ibuf.capacity() + 4096);
          uintptr_t resume = ibuf.size(), end = var_content ? (ibuf.capacity() /*- 1*/): (request_size + content_length);
          ibuf.resize(end);
          if(http_server.Killed()) return;
          int bytes = recv(conn.socket, &ibuf[resume], end - resume, 0);
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
          if((bytes == 0) || (bytes == SOCKET_ERROR))
#else
          if(bytes <= 0)
#endif
          {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
            if(bytes == SOCKET_ERROR)
#else
            if(bytes < 0)
#endif
            {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
              if(WSAGetLastError() == WSAEWOULDBLOCK)
#else
              if((errno == EAGAIN) || (errno == EWOULDBLOCK))
#endif
              {
                sleep(1); // try again later
                ibuf.resize(resume);
                continue;
              }
              else
              {
                err_log << "[" << conn.socket << "] recv error\n"; return; 
              }
            }
            
            // connection closed by peer
            if(var_content) break;
            if(rem_content_length)
            {
              err_log << "[" << conn.socket << "] content short read (" << (content_length - rem_content_length) << " instead of " << content_length << " bytes)\n";
            }
            return; 
          }
          
          ibuf.resize(resume + bytes);

          if(var_content) content_length += bytes; else rem_content_length -= bytes;
        }
        
        if(http_server.Verbose())
        {
          log << "[" << conn.socket << "] content " << ":" << "\n=-=-=-=-=-=-=-=-=-=-=\n" << std::string(&ibuf[request_size], content_length) << "\n=-=-=-=-=-=-=-=-=-=-=\n";
        }
        
        request.content_length = content_length;
        request.content = &ibuf[request_size];
        
        soh = &ibuf[0];
      }
      
      if(request.uri) request.uri = &ibuf[(uintptr_t) request.uri];
      if(request.host) request.host = &ibuf[(uintptr_t) request.host];
      if(request.content_type) request.content_type = &ibuf[(uintptr_t) request.content_type];
      if(multipart_boundary) multipart_boundary = &ibuf[(uintptr_t) multipart_boundary];
      request.header_field_count = header_fields.size();

      if(request.content && multipart_boundary)
      {
        bool last_part = false;
        ptr = request.content;
        if((ptr = strseek("--", ptr, true, true)) == 0) break;
        if((ptr = streat(multipart_boundary, ptr, true)) == 0) break;
        while (isblank(*ptr)) ptr += 1;
        if((ptr = streat("\r\n", ptr)) == 0) break;
        char const *start_of_part = ptr;
        
        do
        {
          if((ptr = strseek("--", ptr, true)) == 0) break;
          char const *end_of_part = ptr;
          ptr += 2;
          if((ptr = streat(multipart_boundary, ptr, true)) == 0) break;
          if(char const* p = streat("--", ptr)) { ptr = p; last_part = true; }
          while (isblank(*ptr)) ptr += 1;
          if((ptr = streat("\r\n", ptr)) == 0) break;
          char const *start_of_next_part = last_part ? 0 : ptr;
          ptr = start_of_part;
          char const* end_of_part_header = GetHeaderEnd(ptr, end_of_part - start_of_part);
          if(!end_of_part_header) break;
          unsigned int part_num = request.parts.size();
          request.parts.resize(part_num + 1);
          RequestPart& part = request.parts[part_num];
          while (ptr < end_of_part_header)
          {
            char const* key = ptr;
            if (not (ptr = strchr(ptr, ':'))) { err_log << "[" << conn.socket << "] HTTP Part header field parse error\n"; return; }
            ibuf[ptr++-soh] = '\0';
            while (isblank(*ptr)) ptr += 1;
            char const* val = ptr;
            if (not (ptr = strchr(ptr, '\r'))) { err_log << "[" << conn.socket << "] HTTP Part header field parse error\n"; return; }
            for (char const* p = ptr; (--p > val) and isspace(*p);) ibuf[p-soh] = '\0';
            ibuf[ptr++-soh] = '\0';
            if (*ptr++ != '\n') { err_log << "[" << conn.socket << "] HTTP Part header field parse error\n"; return; }
            if(header_fields.capacity() == header_fields.size())
            {
              header_fields.reserve(header_fields.capacity() + 16);
            }
            header_fields.push_back(HeaderField((char const *)(key - soh), (char const *)(val - soh)));
            part.header_field_count++;
          }
          
          end_of_part_header += 4; // skip "\r\n\r\n"
          part.ibuf = &ibuf[0];
          part.header_fields = part.header_field_count ? (HeaderField const *)(&header_fields[header_fields.size() - part.header_field_count] - &header_fields[0]) : 0;
          part.content = (char const *)(end_of_part_header - &ibuf[0]);
          part.content_length = end_of_part - end_of_part_header;
          
          start_of_part = ptr = start_of_next_part;
        }
        while(!last_part);
        
        unsigned int part_count = request.parts.size();
        for(unsigned int part_num = 0; part_num < part_count; part_num++)
        {
          RequestPart& part = request.parts[part_num];
          part.header_fields = part.header_field_count ? &header_fields[(uintptr_t) part.header_fields] : 0;
          part.content = &ibuf[(uintptr_t) part.content];
        }
      }
      
      unsigned int header_field_count = header_fields.size();
      for(unsigned int header_field_num = 0; header_field_num < header_field_count; header_field_num++)
      {
        HeaderField& header_field = header_fields[header_field_num];
        header_field.key = &ibuf[(uintptr_t) header_field.key];
        header_field.value = &ibuf[(uintptr_t) header_field.value];
      }
  
      request.header_fields = request.header_field_count ? &header_fields[0] : 0;

      if(http_server.Verbose())
      {
        log << "Received HTTP request:" << std::endl << request << "8<--8<--8<--8<--8<--8<--8<--8<" << std::endl;
      }
      if (not SendResponse(request, conn) or not keep_alive) return;

      ibuf.erase(ibuf.begin(), ibuf.begin() + request_size + content_length);
    }
}

static bool IsHexDigit(char c)
{
  return ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
}

static bool IsAlphaNumeric(char c)
{
  return ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9'));
}

static bool IsReserved(char c)
{
  return (c == '!') || (c == '*') || (c == '\'') || (c == '(') || (c == ')') || (c == ';') || (c == ':') || (c == '@') || (c == '&') || (c == '=') || (c == '+') || (c == '$') || (c == ',') || (c == '/') || (c == '?') || (c == '#') || (c == '[') || (c == ']');
}

static bool IsUnreserved(char c)
{
  return IsAlphaNumeric(c) || (c == '-') || (c == '_') || (c == '.') || (c == '~');
}

static bool IsSafe(char c)
{
  return IsAlphaNumeric(c) || (c == '$') || (c == '-') || (c == '_') || (c == '.') || (c == '+') || (c == '!') || (c == '*') || (c == '\'') || (c == '(') || (c == ')') || (c == ',');
}

static unsigned int AsciiHexToUInt(char c)
{
  return ((c >= '0') && (c <= '9')) ? (c - '0') : (((c >= 'a') && (c <= 'f')) ? (10 + (c - 'a')) : (((c >= 'A') && (c <= 'F')) ? (10 + (c - 'A')) : ~int(0)));
}

bool Form_URL_Encoded_Decoder::Decode(const std::string& s, std::ostream& err_log)
{
  int state = 0;
  std::size_t pos = 0;
  std::size_t len = s.length();
  std::size_t eos_pos = len ? (len - 1) : 0;
  std::string name;
  std::string value;
  char non_alpha_numeric = ' ';
  
  // syntax: name'='value('&'name'='value)*
  //         '+' is replaced by space
  //         non alpha-numeric ASCII characters are encoded as %HH where H is an hexadecimal digit
  while(pos < len)
  {
    char c = s[pos];
    
    switch(state)
    {
      case 0: // name parsing
        if(c == '&')
        {
          err_log << "In \"" << s << "\", expecting '=' after \"" << name << "\"" << std::endl;
          return false;
        }
        else if(c == '=')
        {
          value.clear();
          state = 3;
          if(pos == eos_pos)
          {
            if(!FormAssign(name, value)) return false;
          }
        }
        else if(c == '+')
        {
          name.append(1, ' ');
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting '=' after \"" << name << "\"" << std::endl;
            return false;
          }
        }
        else if(c == '%')
        {
          state = 1;
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting '=' after \"" << name << "\"" << std::endl;
            return false;
          }
        }
        else if(IsSafe(c))
        {
          name.append(1, c);
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting '=' after \"" << name << "\"" << std::endl;
            return false;
          }
        }
        else
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }
        break;
      case 1: // first hexadecimal digit after % while parsing name
        if(IsHexDigit(c))
        {
          non_alpha_numeric = AsciiHexToUInt(c);
          state = 2;
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting a second hexadecimal digit before end of string" << std::endl;
            return false;
          }
        }
        else
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }
        break;
      case 2: // second hexadecimal digit after % while parsing name
        if(IsHexDigit(c))
        {
          non_alpha_numeric = (non_alpha_numeric << 4) | AsciiHexToUInt(c);
          name.append(1, non_alpha_numeric);
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting '=' after \"" << name << "\"" << std::endl;
            return false;
          }
          state = 0;
        }
        else
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }
        break;
      case 3: // value parsing
        if(c == '+')
        {
          value.append(1, ' ');
        }
        else if(c == '%')
        {
          state = 4;
        }
        else if(IsSafe(c))
        {
          value.append(1, c);
        }
        else if(c != '&')
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }

        if((c == '&') || (pos == eos_pos))
        {
          if(!FormAssign(name, value)) return false;
          name.clear();
          state = 0;
        }

        break;
        
      case 4: // first hexadecimal digit after % while parsing value
        if(IsHexDigit(c))
        {
          non_alpha_numeric = AsciiHexToUInt(c);
          state = 5;
          if(pos == eos_pos)
          {
            err_log << "In \"" << s << "\", expecting a second hexadecimal digit before end of string" << std::endl;
            return false;
          }
        }
        else
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }
        break;
      case 5: // first hexadecimal digit after % while parsing value
        if(IsHexDigit(c))
        {
          non_alpha_numeric = (non_alpha_numeric << 4) | AsciiHexToUInt(c);
          value.append(1, non_alpha_numeric);
          
          if(pos == eos_pos)
          {
            if(!FormAssign(name, value)) return false;
          }
          state = 3;
        }
        else
        {
          err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
          return false;
        }
        break;
    }

    pos++;
  }
  
  return true;
}

std::string URI_Encoder::Encode(const std::string& s)
{
	std::string r;
	std::size_t len = s.length();
	std::size_t pos;
	for(pos = 0; pos < len; pos++)
	{
		char c = s[pos];
		if(IsReserved(c) || IsUnreserved(c))
		{
			r.append(1, c);
		}
		else
		{
			char h = (c >> 4) & 15;
			char l = c & 15;
			r.append(1, '%');
			r.append(1, ((h < 10) ? ('0' + h) : ('a' + h - 10)));
			r.append(1, ((l < 10) ? ('0' + l) : ('a' + l - 10)));
		}
	}
	return r;
}

std::string URI_Encoder::EncodeComponent(const std::string& s)
{
	std::string r;
	std::size_t len = s.length();
	std::size_t pos;
	for(pos = 0; pos < len; pos++)
	{
		char c = s[pos];
		if(IsSafe(c))
		{
			r.append(1, c);
		}
		else
		{
			char h = (c >> 4) & 15;
			char l = c & 15;
			r.append(1, '%');
			r.append(1, ((h < 10) ? ('0' + h) : ('a' + h - 10)));
			r.append(1, ((l < 10) ? ('0' + l) : ('a' + l - 10)));
		}
	}
	return r;
}

std::string HTML_Encoder::Encode(const std::string& s)
{
	std::stringstream sstr;
	std::size_t pos = 0;
	std::size_t len = s.length();
	
	for(pos = 0; pos < len; pos++)
	{
		char c = s[pos];

		switch(c)
		{
			case '\n':
				sstr << "<br>";
				break;
			case '<':
				sstr << "&lt;";
				break;
			case '>':
				sstr << "&gt;";
				break;
			case '&':
				sstr << "&amp;";
				break;
			case '"':
				sstr << "&quot;";
				break;
			case '\'':
				sstr << "&apos;";
				break;
			case ' ':
				sstr << "&nbsp;";
				break;
			case '\t':
				sstr << "&nbsp;&nbsp;&nbsp;&nbsp;";
				break;
			default:
				if((c >= 32) && (c < 127))
				{
					sstr << c;
				}
				else
				{
					sstr << "&nbsp;";
				}
				break;
		}
	}
	
	return sstr.str();
}


bool URL_AbsolutePathDecoder::Decode(const std::string& url, std::string& abs_path, std::ostream& err_log)
{
	std::size_t pos = 0;
	std::size_t len = url.length();
	std::size_t eos_pos = len ? (len - 1) : 0;
	char non_alpha_numeric = ' ';
	
	std::string s;
	std::vector<std::string> stack;
	int state = 0;

	while((pos < len) && (state < 7))
	{
		char c = url[pos];
	
		switch(state)
		{
			case 0: // expecting '/'
				if(c != '/') return false;
				stack.push_back("/");
				state = 1;
				break;
			case 1:
				if(c == '.') // got '.'
				{
					state = 2;
				}
				else if(c == '?') // got '?'
				{
					state = 7;
				}
				else if(c == '%') // got '%'
				{
					state = 5;
				}
				else if(c != '/') // got normal character
				{
					s += c;
					state = 4;
					if(pos == eos_pos)
					{
						stack.push_back(s);
						s.clear();
					}
				}
				break;
			case 2: // '.'
				if(c == '.') // got '..'
				{
					if(pos == eos_pos)
					{
						stack.pop_back();
						if(stack.empty()) return false;
					}
					state = 3;
				}
				else if(c == '?') // got '.?'
				{
					stack.push_back(".");
					state = 7;
				}
				else if(c == '%') // got '.%'
				{
					stack.push_back(".");
					state = 5;
				}
				else if(c == '/') // got './'
				{
					state = 1;
				}
				else // got '.' followed by a normal character
				{
					s += '.';
					s += c;
					state = 4;
					if(pos == eos_pos)
					{
						stack.push_back(s);
						s.clear();
					}
				}
				break;
			case 3: // '..'
				if(c == '/') // got '../'
				{
					stack.pop_back();
					if(stack.empty()) return false;
					state = 1;
				}
				else if(c == '?') // got '..?'
				{
					stack.pop_back();
					if(stack.empty()) return false;
					state = 7;
				}
				else if(c == '%') // got '..%'
				{
					stack.pop_back();
					if(stack.empty()) return false;
					state = 5;
				}
				else // got '..' followed by a normal character
				{
					s += "..";
					s += c;
					state = 4;
					if(pos == eos_pos)
					{
						stack.push_back(s);
						s.clear();
					}
				}
				break;
			case 4: // normal characters
				if(c == '?') // normal character(s) followed by '?'
				{
					stack.push_back(s);
					s.clear();
					state = 7;
				}
				else if(c == '%')
				{
					state = 5;
				}
				else
				{
					s += c;
					if(c == '/') // normal character(s) followed by '/'
					{
						stack.push_back(s);
						s.clear();
						state = 1;
					}
					else if(pos == eos_pos)
					{
						stack.push_back(s);
						s.clear();
					}
				}
				break;
			case 5: // first hexadecimal digit after %
				if(IsHexDigit(c))
				{
					non_alpha_numeric = AsciiHexToUInt(c);
					state = 6;
					if(pos == eos_pos)
					{
						err_log << "In \"" << s << "\", expecting a second hexadecimal digit before end of string" << std::endl;
						return false;
					}
				}
				else
				{
					err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
					return false;
				}
				break;
			case 6: // second hexadecimal digit after %
				if(IsHexDigit(c))
				{
					non_alpha_numeric = (non_alpha_numeric << 4) | AsciiHexToUInt(c);
					s.append(1, non_alpha_numeric);
					state = 4;
				}
				else
				{
					err_log << "In \"" << s << "\", at character position #" << pos << ", unexpected character '" << c << "'" << std::endl;
					return false;
				}
				break;
		}
		
		pos++;
	}
	
	abs_path.clear();
	for(std::vector<std::string>::const_iterator it = stack.begin(); it != stack.end(); it++)
	{
		abs_path.append(*it);
	}
	
	return true;
}

HttpServer::HttpServer()
  : port(0)
  , maxclients(0)
  , mutex()
  , clients()
  , socket()
  , killed( false )
  , running( false )
  , verbose( false )
  , log(&std::cout)
  , warn_log(&std::cout)
  , err_log(&std::cerr)
{
  Init();
}

HttpServer::HttpServer( int _port, int _maxclients)
  : port(_port)
  , maxclients(_maxclients)
  , mutex()
  , clients()
  , socket()
  , killed( false )
  , running( false )
  , verbose( false )
  , log(&std::cout)
  , warn_log(&std::cout)
  , err_log(&std::cerr)
{
  Init();
}

void HttpServer::Init()
{
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
  // Loads the winsock2 dll
  WORD wVersionRequested = MAKEWORD( 2, 2 );
  WSADATA wsaData;
  if(WSAStartup(wVersionRequested, &wsaData) != 0)
  {
    throw std::runtime_error("WSAStartup failed: Windows sockets not available");
  }
#endif
  pthread_mutex_init( &mutex, 0 );
}

HttpServer::~HttpServer()
{
  pthread_mutex_destroy(&mutex);
  
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
  //releases the winsock2 resources
  WSACleanup();
#endif
}

void HttpServer::SetTCPPort(int _port)
{
	port = _port;
}

void HttpServer::SetMaxClients(int _maxclients)
{
	maxclients = _maxclients;
}

void HttpServer::SetLog(std::ostream& os)
{
	log = &os;
}

void HttpServer::SetWarnLog(std::ostream& os)
{
	warn_log = &os;
}

void HttpServer::SetErrLog(std::ostream& os)
{
	err_log = &os;
}

void HttpServer::StartLoopThread()
{
  if (this->running)
    {
      (*err_log) << "error: server instance already running\n";
      return;
    }
  
  running = true;
  killed = false;

  struct launcher { static void* routine(void* obj) { static_cast<HttpServer*>(obj)->LoopThread(); return 0; } };
  if (int err = pthread_create(&tid, 0, launcher::routine, static_cast<void*>(this)))
    {
      (*err_log) << "error in thread creation (" << err << ")\n";
      running = false;
    }
}

void HttpServer::Kill()
{
	killed = true;
}

void HttpServer::JoinLoopThread()
{
  if ( !this->running)
    {
      (*err_log) << "error: server instance is not running\n";
      return;
    }
    
  if (int err = pthread_join(tid, 0))
    {
      (*err_log) << "error while joining with thread (" << err << ")\n";
    }
}

bool HttpServer::Killed() const
{
	return killed;
}

bool HttpServer::Running() const
{
	return running;
}

bool HttpServer::Verbose() const
{
  return verbose;
}

bool ClientConnection::Send( char const* buf, uintptr_t size ) const
{
  if(http_server.Verbose())
  {
    http_server.GetLog() << "Sending HTTP response:" << std::endl << std::string(buf, size) << "8<--8<--8<--8<--8<--8<--8<--8<" << std::endl;
  }
  for (intptr_t done; size > 0; size -= done)
    {
      if(http_server.Killed()) return false;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
      done = ::send( socket, buf, size, 0);
#else
      done = ::write( socket, buf, size );
#endif
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
      if((done == 0) || (done == SOCKET_ERROR))
#else
      if(done <= 0)
#endif
      {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
        if(done == SOCKET_ERROR)
#else
        if(done < 0)
#endif
        {
           done = 0;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
           if(WSAGetLastError() == WSAEWOULDBLOCK)
#else
           if((errno == EAGAIN) || (errno == EWOULDBLOCK))
#endif
           {
             sleep(1); // try again later
             continue;
           }
           return false;
        }
      }
      buf += done;
    }
  return true;
}

void
HttpServer::LoopThread()
{
  struct LoopGuard
  {
    LoopGuard( HttpServer& _hs ) : hs(_hs) {}
    ~LoopGuard() { hs.running = false; hs.killed = false; }
    HttpServer& hs;
  } loopGuard(*this);

  if (this->maxclients == 0)
    {
      (*err_log) << "error: maximum clients not configured\n";
      return;
    }
  
  // create a new socket
  if ((socket = ::socket(AF_INET,SOCK_STREAM,0)) <= 0)
    {
      (*err_log) << "Error creating socket\n";
      return;
    }

  if (this->ALLOW_REUSE_PORT_NUMBER)
    {
      int data = 1;
      int status = setsockopt(socket,SOL_SOCKET,SO_REUSEADDR, (char*)&data,sizeof(data));
      if (status < 0) {
        (*err_log) << "Error configuring reusable socket\n";
        return;
      }
    }
  
  // bind it to the http port
  {
    struct sockaddr_in sinAddress;
    memset( &sinAddress, 0, sizeof(struct sockaddr_in) );
    
    sinAddress.sin_family = AF_INET;
    sinAddress.sin_addr.s_addr = htonl(0); // INADDR_ANY is 0
    sinAddress.sin_port = htons(this->port); // http port
    
    int status = bind(socket,(struct sockaddr*)&sinAddress, sizeof(struct sockaddr_in));
    
    if (status < 0)
      {
        (*err_log) << "Error binding on port " << this->port << "\n";
        return;
      }
  }

  // Set listening socket to non-blocking in order to avoid lockout
  // issue (see Section 15.6 in Unix network programming book)
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
  u_long non_blocking_flag = 1;
  ioctlsocket(socket, FIONBIO, &non_blocking_flag);
#else
  fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) | O_NONBLOCK);
#endif
  
  // listen on the socket for incoming calls
  if (listen(socket, this->maxclients-1))
    {
      (*err_log) << "Error: can't listen on port " << this->port << " with socket " << socket << "\n";
      return;
    }
  if(Verbose()) (*log) << "Listening on port " << this->port << " with socket " << socket << "\n";

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
  WSAPOLLFD listenpoll;
#else
  struct pollfd listenpoll;
#endif
  listenpoll.fd = socket;
  listenpoll.events = POLLIN;
  
  std::vector<pthread_t> client_thread_ids;
  
  // Entering main processing loop
  for (this->killed = false; not this->killed;)
    {
      //(*log) << "MainLoopIteration\n";
      if (this->clients >= maxclients)
        {
          sleep(1);
          continue;
        }
      
      listenpoll.revents = 0;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	  if (WSAPoll( &listenpoll, 1, 1000) <= 0)
#else
      if (poll( &listenpoll, 1, 1000 ) <= 0)
#endif
        continue;
      
      struct Shuttle {
        static void* routine(void* obj)
        {
          Shuttle shuttle( *static_cast<Shuttle*>(obj) );
          
          /* Client's Connection Data are Saved, release the caller */
          pthread_mutex_unlock( &shuttle.server.mutex );
          if(shuttle.server.Verbose()) (*shuttle.server.log) << "[" << shuttle.socket << "] Client Connection from IP: " << IPAddrRepr(shuttle.ipaddr) << "\n";
          
          /* Finish servicing client */
          ClientConnection conn(shuttle.server, shuttle.socket);
          shuttle.server.Serve(conn);
          
          if(shuttle.server.Verbose()) (*shuttle.server.log) << "[" << shuttle.socket << "] closing connection\n";
          
          pthread_mutex_lock(&shuttle.server.mutex);
          shuttle.server.clients -= 1;
          pthread_mutex_unlock(&shuttle.server.mutex);
          if(shuttle.server.Verbose()) (*shuttle.server.log) << "Connected clients: " << shuttle.server.clients << "\n";
          
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
          closesocket( shuttle.socket );
#else
          close( shuttle.socket );
#endif
          
          return 0;
        }
        Shuttle( HttpServer& _server )
          : server(_server)
        {
          // accept connection socket
          struct sockaddr_in addr;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
          int addrlen = sizeof (addr);
#else
          socklen_t addrlen = sizeof (addr);
#endif
          socket = accept(server.socket, (struct sockaddr*)&addr, &addrlen);
          if (socket < 0) return;
          ipaddr = addr.sin_addr.s_addr;
#if 1
          /* set short latency */
          int opt_tcp_nodelay = 1;
          setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char *) &opt_tcp_nodelay, sizeof(opt_tcp_nodelay));
#endif
          // set to non-blocking to allow partial read ()
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
          u_long non_blocking_flag = 1;
          ioctlsocket(socket, FIONBIO, &non_blocking_flag);
#else
          fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, 0) | O_NONBLOCK);
#endif
          if(server.Verbose()) (*server.log) << "[" << socket << "] connection accepted\n";
      
          pthread_mutex_lock(&server.mutex);
          server.clients += 1;
          pthread_mutex_unlock(&server.mutex);
      
          if(server.Verbose()) (*server.log) << "Connected clients: " << server.clients << "\n";
      
        }
        HttpServer&        server;
        int                socket;
        uint32_t           ipaddr;
      } launcher(*this);
      
      if (launcher.socket < 0)
        {
          /* FIXME: should investigate the reason... */
          (*err_log) << "Error accepting connection\n";
          continue;
        }
      
      /* Launch the service thread */
      pthread_t client_thread_id;
      pthread_mutex_lock(&mutex);
      if (int err = pthread_create(&client_thread_id, 0, Shuttle::routine, static_cast<void*>(&launcher)))
        {
          (*err_log) << "error in thread creation (" << err << ")\n";
          throw 0;
        }
      client_thread_ids.push_back(client_thread_id);
        
      /* Wait for thread full initialization */
      pthread_mutex_lock(&mutex);
      pthread_mutex_unlock(&mutex);
    }
    
    for(std::vector<pthread_t>::const_iterator it = client_thread_ids.begin(); it != client_thread_ids.end(); it++)
    {
      pthread_join(*it, 0);
    }
  
  // Leaving main processing loop
  if(Verbose()) (*log) << "Cleaning up...\n";
  
  if (this->socket)
  {
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
    closesocket(this->socket);
#else
    close(this->socket);
#endif
  }
  this->socket = 0;
}

} // end of namespace hypapp
} // end of namespace util
} // end of namespace unisim
