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

#ifndef __UNISIM_UTIL_HYPAPP_HYPAPP_HH__
#define __UNISIM_UTIL_HYPAPP_HYPAPP_HH__

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <cstring>
#include <inttypes.h>

namespace unisim {
namespace util {
namespace hypapp {

struct HttpServer;

struct ClientConnection
{
  ClientConnection(HttpServer& _http_server, int _socket) : http_server(_http_server), socket(_socket) {}
  
  template <uintptr_t SZ>
  bool Send(char const (&text)[SZ]) const { return Send( &text[0], SZ-1 ); }
  bool Send( std::string const& text ) const { return Send( &text[0], text.size() ); }
  bool Send(char const* buf, uintptr_t size) const;
  
  HttpServer& http_server;
  int         socket;
};

struct MessageLoop;

struct InputStreamBuffer : std::streambuf
{
  InputStreamBuffer();
  InputStreamBuffer(char const* buffer, std::streamsize length, std::streampos _pos);
  
  void Initialize(char const* _buffer, std::streamsize _length, std::streampos _pos);

protected:
  virtual int_type underflow();
  virtual std::streamsize xsgetn(char* s, std::streamsize n);

private:
  char const *buffer;
  std::streamsize length;
  std::streampos pos;
};

struct OutputStreamBuffer : std::streambuf
{
  OutputStreamBuffer();
  const std::string& str() const { return buffer; }
  void ClearContent() { buffer.clear(); }

protected:
  virtual int_type overflow(int_type c);
  virtual std::streamsize xsputn(const char* s, std::streamsize n);

private:
  std::string buffer;

  void reserve(std::streamsize n);
};

struct HeaderField
{
  HeaderField(char const* _key, char const* _value)
    : key(_key)
    , value(_value)
  {
  }
  
  char const* key;
  char const* value;
};

std::ostream& operator << (std::ostream& os, const HeaderField& f);

struct RequestPart
{
public:
  RequestPart()
    : ibuf(0)
    , header_fields(0)
    , header_field_count(0)
    , content(0)
    , content_length(0)
  {
  }

  unsigned int GetContentLength() const { return content_length; }
  char const* GetContent() const { return content; }

  unsigned int GetHeaderFieldCount() const
  {
    return header_field_count;
  }
  
  HeaderField const *GetHeaderField(unsigned int i) const
  {
    return (i < header_field_count) ? &header_fields[i] : 0;
  }
  
  char const *GetHeaderFieldValue(char const* key) const
  {
    if(header_field_count)
    {
      unsigned int n = header_field_count;
      HeaderField const* header_field = header_fields;
      do
      {
        if(strcasecmp(header_field->key, key) == 0)
        {
          return header_field->value;
        }
      }
      while(++header_field, --n);
    }
    return "";
  }
  
private:
  friend struct MessageLoop;

  char const *ibuf;
  HeaderField const* header_fields;
  unsigned int header_field_count;
  char const *content;
  unsigned int content_length;
};

struct Request
{
  enum request_type_t { NO_REQ = 0, OPTIONS, GET, HEAD, POST };

  request_type_t GetRequestType() const { return request_type; }
  char const* GetRequestURI() const { return uri; }
  char const* GetHost() const { return host; }
  char const* GetContentType() const { return content_type; }
  unsigned int GetContentLength() const { return content_length; }
  char const* GetContent() const { return content; }
  
  unsigned int GetHeaderFieldCount() const
  {
    return header_field_count;
  }
  
  HeaderField const *GetHeaderField(unsigned int i) const
  {
    return (i < header_field_count) ? &header_fields[i] : 0;
  }
  
  char const *GetHeaderFieldValue(char const* key) const
  {
    if(header_field_count)
    {
      unsigned int n = header_field_count;
      HeaderField const* header_field = header_fields;
      do
      {
        if(strcasecmp(header_field->key, key) == 0)
        {
          return header_field->value;
        }
      }
      while(++header_field, --n);
    }
    return "";
  }
  
  unsigned int GetPartCount() const
  {
    return parts.size();
  }
  
  RequestPart const& GetPart(unsigned int i) const
  {
    return parts[i];
  }
  
private:
  Request()
    : header_fields(0)
    , header_field_count(0)
    , request_type(NO_REQ)
    , uri(0)
    , host(0)
    , content_type(0)
    , content_length(0)
    , content(0)
    , parts()
  {
  }
  Request(Request const &) {}
  Request& operator = (Request const&) { return *this; }
  
  friend struct MessageLoop;
  
  HeaderField const* header_fields;
  unsigned int header_field_count;
  request_type_t request_type;
  char const *uri;
  char const *host;
  char const *content_type;
  unsigned int content_length;
  char const *content;
  typedef std::vector<RequestPart> Parts;
  Parts parts;
};

std::ostream& operator << (std::ostream& os, const Request::request_type_t& request_type);
std::ostream& operator << (std::ostream& os, const Request& req);


struct HttpRequestPart : std::istream
{
public:
  HttpRequestPart(const RequestPart& _part)
    : part(_part)
    , content_stream_buffer(part.GetContent(), part.GetContentLength(), 0)
  {
    rdbuf(&content_stream_buffer);
  }

  unsigned int GetContentLength() const { return part.GetContentLength(); }
  char const* GetContent() const { return part.GetContent(); }

  unsigned int GetHeaderFieldCount() const { return part.GetHeaderFieldCount(); }
  HeaderField const *GetHeaderField(unsigned int i) const { return part.GetHeaderField(i); }
  char const *GetHeaderFieldValue(char const* key) const { return part.GetHeaderFieldValue(key); }
  
private:
	const RequestPart& part;
	InputStreamBuffer content_stream_buffer;
};

struct HttpRequest : std::istream
{
public:
  HttpRequest(const Request& req, std::ostream& log = std::cout, std::ostream& warn_log = std::cerr, std::ostream& err_log = std::cerr);
  HttpRequest(const std::string& server_root, const std::string& path, const HttpRequest& http_request);
  ~HttpRequest();
  
  bool IsValid() const { return valid; }
  bool HasQuery() const { return has_query; }
  bool HasFragment() const { return has_fragment; }
  Request::request_type_t GetRequestType() const { return req.GetRequestType(); }
  char const* GetRequestURI() const { return req.GetRequestURI(); }
  char const* GetHost() const { return req.GetHost(); }
  char const* GetContentType() const { return req.GetContentType(); }
  unsigned int GetContentLength() const { return req.GetContentLength(); }
  char const* GetContent() const { return req.GetContent(); }
  char const *GetHeaderFieldValue(char const* key) const { return req.GetHeaderFieldValue(key); }
  const std::string& GetAbsolutePath() const { return abs_path; }
  const std::string& GetServerRoot() const { return server_root; }
  const std::string& GetPath() const { return path; }
  const std::string& GetQuery() const { return query; }
  const std::string& GetFragment() const { return fragment; }
  const std::string& GetDomain() const { return domain; }
  bool HasPort() const { return has_port; }
  unsigned int GetPort() const { return port; }
  unsigned int GetPartCount() const { return parts.size(); }
  HttpRequestPart const& GetPart(unsigned int i) const { return *parts[i]; }

  friend std::ostream& operator << (std::ostream& os, const HttpRequest& http_request);
  
private:

  bool valid;
  bool has_query;
  bool has_fragment;
  const Request& req;
  std::string abs_path;
  std::string server_root;
  std::string path;
  std::string query;
  std::string fragment;
  std::string domain;
  bool has_port;
  unsigned int port;
  InputStreamBuffer content_stream_buffer;
  typedef std::vector<HttpRequestPart *> Parts;
  Parts parts;
  std::ostream& log;
  std::ostream& warn_log;
  std::ostream& err_log;
};

struct HttpResponseHeaderField
{
  HttpResponseHeaderField(const std::string& _key, const std::string& _value)
    : key(_key)
    , value(_value)
  {
  }
  
  std::string key;
  std::string value;
};

struct HttpResponse : public std::ostream
{
  enum StatusCode
  {
    CONTINUE                      = 100,
    SWITCHING_PROTOCOLS           = 101,
    
    // successful
    OK                            = 200,
    CREATED                       = 201,
    ACCEPTED                      = 202,
    NON_AUTHORITATIVE_INFORMATION = 203,
    NO_CONTENT                    = 204,
    RESET_CONTENT                 = 205,
    PARTIAL_CONTENT               = 206,

    // redirection
    MULTIPLE_CHOICES              = 300,
    MOVED_PERMANENTLY             = 301,
    FOUND                         = 302,
    SEE_OTHER                     = 303,
    NOT_MODIFIED                  = 304,
    USE_PROXY                     = 305,
    UNUSED                        = 306,
    TEMPORARY_REDIRECT            = 307,

    // client error
    BAD_REQUEST                   = 400,
    UNAUTHORIZED                  = 401,
    PAYMENT_REQUIRED              = 402,
    FORBIDDEN                     = 403,
    NOT_FOUND                     = 404,
    METHOD_NOT_ALLOWED            = 405,
    NOT_ACCEPTABLE                = 406,
    PROXY_AUTHENTICATION_REQUIRED = 407,
    REQUEST_TIMEOUT               = 408,
    CONFLICT                      = 409,
    GONE                          = 410,
    LENGH_REQUIRED                = 411,
    PRECONDITION_FAILED           = 412,
    REQUEST_ENTITY_TOO_LARGE      = 413,
    UNSUPPORTED_MEDIA_TYPE        = 415,
    REQUEST_RANGE_NOT_SATISFIABLE = 416,
    EXPECTATION_FAILED            = 417,

    // server error
    INTERNAL_SERVER_ERROR         = 500,
    NOT_IMPLEMENTED               = 501,
    BAD_GATEWAY                   = 502,
    SERVICE_UNAVAILABLE           = 503,
    GATEWAY_TIMEOUT               = 504,
    HTTP_VERSION_NOT_SUPPORTED    = 505
  };
  
  HttpResponse();
  HttpResponse& SetStatus(StatusCode _status_code) { status_code = _status_code; return *this; }
  HttpResponse& SetContentType(const std::string& _content_type) { content_type = _content_type; return *this; }
  HttpResponse& EnableCache(bool v = true) { enable_cache = v; return *this; }
  HttpResponse& KeepAlive(bool v = true) { keep_alive = v; return *this; }
  HttpResponse& Allow(const std::string& _allow) { allow = _allow; return *this; }
  HttpResponse& AcceptRanges(const std::string& _accept_ranges) { accept_ranges = _accept_ranges; return *this; }
  HttpResponse& SetHeaderField(const std::string& key, const std::string& value) { header_fields.push_back(HeaderField(key, value)); return *this; } 
  
  const std::string& str() const { return content_stream_buffer.str(); }
  void ClearContent() { content_stream_buffer.ClearContent(); }
  
  bool IsSuccessful() const { return (status_code >= OK) && (status_code <= PARTIAL_CONTENT); }
  bool IsRedirection() const { return (status_code >= MULTIPLE_CHOICES) && (status_code <= TEMPORARY_REDIRECT); }
  bool IsClientError() const { return (status_code >= BAD_REQUEST) && (status_code <= EXPECTATION_FAILED); }
  bool IsServerError() const { return (status_code >= INTERNAL_SERVER_ERROR) && (status_code <= HTTP_VERSION_NOT_SUPPORTED); }
  
  std::string ToString(bool header_only = false) const;
private:
  typedef HttpResponseHeaderField HeaderField;
  typedef std::vector<HttpResponseHeaderField> HeaderFields;
  friend std::ostream& operator << (std::ostream&, const HttpResponse&);
  
  StatusCode status_code;
  std::string content_type;
  bool enable_cache;
  bool keep_alive;
  std::string allow;
  std::string accept_ranges;
  OutputStreamBuffer content_stream_buffer;
  HeaderFields header_fields;
  
  void Print(std::ostream& os, bool header_only) const;
};

std::ostream& operator << (std::ostream& os, const HttpResponse::StatusCode& status_code);
std::ostream& operator << (std::ostream&, const HttpResponse&);

struct MessageLoop
{
  MessageLoop(HttpServer& _http_server, std::ostream& _log = std::cout, std::ostream& _warn_log = std::cout, std::ostream& _err_log = std::cerr)
    : http_server(_http_server), log(_log), warn_log(_warn_log), err_log(_err_log) {}
  virtual ~MessageLoop() {}
  
  void Run(ClientConnection const& conn);
  
  virtual bool SendResponse(Request const& request, ClientConnection const& conn ) = 0;
protected:
  HttpServer& http_server;
  // Log
  std::ostream& log;
  std::ostream& warn_log;
  std::ostream& err_log;
};

struct Form_URL_Encoded_Decoder
{
  bool Decode(const std::string& s, std::ostream& err_log = std::cerr);
  virtual bool FormAssign(const std::string& name, const std::string& value) = 0;
};

struct URI_Encoder
{
  static std::string Encode(const std::string& s);
  static std::string EncodeComponent(const std::string& s);
};

struct HTML_Encoder
{
  static std::string Encode(const std::string& s);
};

struct URL_AbsolutePathDecoder
{
  static bool Decode(const std::string& url, std::string& abs_path, std::ostream& err_log = std::cerr);
};

struct HttpServer
{
  HttpServer();
  HttpServer( int _port, int _maxclients);
  virtual ~HttpServer();

  void SetTCPPort(int _port);
  void SetMaxClients(int _maxclients);
  void SetLog(std::ostream& os);
  void SetWarnLog(std::ostream& os);
  void SetErrLog(std::ostream& os);
  void StartLoopThread();
  void Kill();
  void JoinLoopThread();
  bool Killed() const;
  bool Running() const;
  bool Verbose() const;

  // Content exchange callbacks
  virtual void Serve(ClientConnection const& conn) = 0;
  
  std::ostream& GetLog() const { return *log; }
  std::ostream& GetWarnLog() const { return *warn_log; }
  std::ostream& GetErrLog() const { return *err_log; }

protected:
  // Loop Thread
  pthread_t tid;
  
  // Configuration
  static bool const ALLOW_REUSE_PORT_NUMBER = true;
  int             port;
  int             maxclients;
  
  // State
  pthread_mutex_t mutex;
  int             clients;
  int             socket;
  bool            killed;
  bool            running;
  
  // Log
  bool verbose;
  std::ostream* log;
  std::ostream* warn_log;
  std::ostream* err_log;
  
private:
  void  Init();
  void  LoopThread();
};

} // end of namespace hypapp
} // end of namespace util
} // end of namespace unisim

#endif // __UNISIM_UTIL_HYPAPP_HYPAPP_HH__
