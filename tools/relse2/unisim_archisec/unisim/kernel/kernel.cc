/*
 *  Copyright (c) 2007,
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
 *          Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#if defined(HAVE_UNISIM__KERNEL__SERVICE__CONFIG_HH)
#include "unisim/kernel/config.hh"
#endif

#ifndef BIN_TO_SHARED_DATA_PATH
#error "BIN_TO_SHARED_DATA_PATH is undefined"
#endif

#include "unisim/kernel/kernel.hh"
#include "unisim/kernel/variable/variable.hh"
#include "unisim/kernel/logger/logger_server.hh"
#include "unisim/kernel/logger/logger.hh"
#include "unisim/util/hypapp/hypapp.hh"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <algorithm>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
//#include <limits.h>
//#include <limits>
#if defined(__APPLE_CC__) || defined(linux) || defined(__linux) || defined(__linux__)
#include <dlfcn.h>
#endif

#if !defined(WIN32) && !defined(_WIN32) && !defined(WIN64) && !defined(_WIN64)
#include <signal.h>
#endif

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
#include <windows.h>
#endif

// #if defined(__APPLE_CC__)
// #include <mach-o/dyld.h>
// #endif

#include "unisim/util/backtrace/backtrace.hh"
#include "unisim/util/likely/likely.hh"

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
#include <fcntl.h>
//Note: this is to force opening console and files in binary mode on Windows as on UNIX
int _CRT_fmode = _O_BINARY;
#endif

#ifdef DEBUG_MEMORY_ALLOCATION
void *operator new(std::size_t size)
{
	std::cerr << "malloc(" << size << ")" << std::endl;
	std::cerr << unisim::util::backtrace::BackTrace() << std::endl;
	return malloc(size);
}

void *operator new[](std::size_t size)
{
	std::cerr << "malloc(" << size << ")" << std::endl;
	std::cerr << unisim::util::backtrace::BackTrace() << std::endl;
	return malloc(size);
}

void operator delete(void *storage, std::size_t size)
{
	std::cerr << "free(" << size << ")" << std::endl;
	std::cerr << unisim::util::backtrace::BackTrace() << std::endl;
	free(storage);
}

void operator delete[](void *storage, std::size_t size)
{
	std::cerr << "free(" << size << ")" << std::endl;
	std::cerr << unisim::util::backtrace::BackTrace() << std::endl;
	free(storage);
}
#endif

namespace {

template <typename T> struct DiGraph;

template <typename T>
struct Vertex
{
	typedef std::vector<Vertex<T> *> Successors;
	
	Vertex(const T& value, const std::string& label);
	virtual ~Vertex();
	
	void operator () (Vertex<T> *succ); // make a edge
	Successors& GetSuccessors();
	Vertex<T> *GetSuccessor(const T& value);
	const T& GetValue() const;
	const std::string& GetLabel() const;
private:
	friend struct DiGraph<T>;
	
	int id;
	T value;
	std::string label;
	Successors successors;
	
	void SetId(int id);
	int GetId() const;
};

template <typename T>
Vertex<T>::Vertex(const T& _value, const std::string& _label)
	: id(-1)
	, value(_value)
	, label(_label)
	, successors()
{
}

template <typename T>
Vertex<T>::~Vertex()
{
}

template <typename T>
void Vertex<T>::operator() (Vertex<T> *succ)
{
	for(typename Successors::iterator it = successors.begin(); it != successors.end(); ++it)
	{
		assert((*it) != succ);
	}
	successors.push_back(succ);
}

template <typename T>
Vertex<T> *Vertex<T>::GetSuccessor(const T& value)
{
	for(typename Successors::iterator it = successors.begin(); it != successors.end(); ++it)
	{
		Vertex<T> *succ = *it;
		if(succ->GetValue() == value) return succ;
	}
	
	return 0;
}

template <typename T>
typename Vertex<T>::Successors& Vertex<T>::GetSuccessors()
{
	return successors;
}

template <typename T>
const T& Vertex<T>::GetValue() const
{
	return value;
}

template <typename T>
const std::string& Vertex<T>::GetLabel() const
{
	return label;
}

template <typename T>
void Vertex<T>::SetId(int _id)
{
	id = _id;
}

template <typename T>
int Vertex<T>::GetId() const
{
	return id;
}

template <typename T>
struct DiGraph
{
	typedef std::vector<Vertex<T> *> Vertices;
	
	DiGraph();
	virtual ~DiGraph();
	
	void operator () (Vertex<T> *vertex); // add vertex
	Vertex<T> *operator [] (const T& value); // retrieve vertex
	typename Vertices::size_type Size() const;
	
	template <typename ITERATOR> bool TopologicalSort(ITERATOR it) const;
	
	void WriteGraphviz(std::ostream& os);
private:
	Vertices vertices;
	
	typedef std::map<T, Vertex<T> *> VerticesByValue;
	VerticesByValue vertices_by_value;
};

template <typename T>
DiGraph<T>::DiGraph()
	: vertices()
{
}

template <typename T>
DiGraph<T>::~DiGraph()
{
	for(typename Vertices::iterator it = vertices.begin(); it != vertices.end(); ++it)
	{
		delete *it;
	}
}

template <typename T>
void DiGraph<T>::operator () (Vertex<T> *vertex)
{
	typename VerticesByValue::iterator it = vertices_by_value.find(vertex->GetValue());
	assert(it == vertices_by_value.end());
	vertices_by_value[vertex->GetValue()] = vertex;
	vertex->SetId(vertices.size());
	vertices.push_back(vertex);
}

template <typename T>
Vertex<T> *DiGraph<T>::operator [] (const T& value)
{
	typename VerticesByValue::iterator it = vertices_by_value.find(value);
	return (it != vertices_by_value.end()) ? (*it).second : 0;
}

template <typename T>
typename DiGraph<T>::Vertices::size_type DiGraph<T>::Size() const
{
	return vertices.size();
}

template <typename T>
template <typename ITERATOR>
bool DiGraph<T>::TopologicalSort(ITERATOR it) const
{
	// Kahn's algorithm
	
	typename Vertices::size_type num_vertices = vertices.size(); // number of vertices
	typename Vertices::size_type num_vertices_zero_indegree = num_vertices; // number of vertices with zero indegree
	std::vector<int> indegree(num_vertices, 0);
	
	for(typename Vertices::const_iterator vertex_it = vertices.begin(); vertex_it != vertices.end(); ++vertex_it) 
	{ 
		Vertex<T> *vertex = *vertex_it;
		const typename Vertex<T>::Successors& successors = vertex->GetSuccessors();
		for(typename Vertex<T>::Successors::const_iterator succ_it = successors.begin(); succ_it != successors.end(); ++succ_it)
		{
			Vertex<T> *succ = *succ_it;
			if(indegree[succ->GetId()] == 0)
			{
				--num_vertices_zero_indegree;
			}
			indegree[succ->GetId()]++; 
		}
	}
	
	std::vector<int> s; // Set of all vertices with no incoming edge
	s.reserve(num_vertices_zero_indegree);
	for(typename Vertices::const_iterator vertex_it = vertices.begin(); vertex_it != vertices.end(); ++vertex_it) 
	{ 
		Vertex<T> *vertex = *vertex_it;
		if(indegree[vertex->GetId()] == 0)
		{
			s.push_back(vertex->GetId());
		}
	}
	
	typename Vertices::size_type visited_count = 0; 
	
	while(!s.empty()) 
	{ 
		int u = s.back();
		s.pop_back();
		Vertex<T> *vertex = vertices[u];
		it = vertex; // assign iterator in topological order

		const typename Vertex<T>::Successors& successors = vertex->GetSuccessors();
		for(typename Vertex<T>::Successors::const_iterator succ_it = successors.begin(); succ_it != successors.end(); ++succ_it)
		{
			Vertex<T> *succ = *succ_it;
			if(--indegree[succ->GetId()] == 0)
			{
				s.push_back(succ->GetId());
			}
		}
		
		visited_count++;
	}
	
	return visited_count == vertices.size();
}

template <typename T>
void DiGraph<T>::WriteGraphviz(std::ostream& os)
{
	os << "digraph G {" << std::endl;
	for(typename Vertices::const_iterator vertex_it = vertices.begin(); vertex_it != vertices.end(); ++vertex_it) 
	{ 
		Vertex<T> *u = *vertex_it;
		os << "\tnode_" << u->GetId() << " [label = \"" << u->GetLabel() << "\"]" << std::endl;
	}
	os << "ranksep = 8;" << std::endl;
	for(typename Vertices::const_iterator vertex_it = vertices.begin(); vertex_it != vertices.end(); ++vertex_it) 
	{ 
		Vertex<T> *u = *vertex_it;
		const typename Vertex<T>::Successors& successors = u->GetSuccessors();
		for(typename Vertex<T>::Successors::const_iterator succ_it = successors.begin(); succ_it != successors.end(); ++succ_it)
		{
			Vertex<T> *v = *succ_it;
			os << "\tnode_" << u->GetId() << " -> node_" << v->GetId() << std::endl;
		}
	}
	os << "}" << std::endl;
}

}

namespace unisim {
namespace kernel {

std::string string_to_latex(const char *s, unsigned int cut, const char *style)
{
	static struct
	{
		const char *searchFor;
		const char *replaceBy;
	}
	conversion_table[] =
	{
		{"\n", "\\\\\n"},
		{"é", "\\'e"},
		{"è", "\\`e"},
		{"ê", "\\^e"},
		{"à", "\\`a"},
		{"#", "\\#"},
		{"_", "\\_"},
		{"\t", "~~"},
		{"{", "$\\{$"},
		{"}", "$\\}$"},
		{"&", "\\&"},
		{"--", "{-}{-}"},
		{"->", "$\\rightarrow$"},
		{"<<", "<}\\texttt{<"},
		{">>", ">}\\texttt{>"},
		{"<", "$<$"},
		{">", "$>$"},
		{"%", "\\%"},
		{"$", "\\$"},
		{"//(1)", "\\ding{202}"},
		{"//(2)", "\\ding{203}"},
		{"//(3)", "\\ding{204}"},
		{"//(4)", "\\ding{205}"},
		{"//(5)", "\\ding{206}"},
		{"//(6)", "\\ding{207}"},
		{"//(7)", "\\ding{208}"},
		{"//(8)", "\\ding{209}"},
		{"//(9)", "\\ding{210}"},
		{"/*(1)*/", "\\ding{202}"},
		{"/*(2)*/", "\\ding{203}"},
		{"/*(3)*/", "\\ding{204}"},
		{"/*(4)*/", "\\ding{205}"},
		{"/*(5)*/", "\\ding{206}"},
		{"/*(6)*/", "\\ding{207}"},
		{"/*(7)*/", "\\ding{208}"},
		{"/*(8)*/", "\\ding{209}"},
		{"/*(9)*/", "\\ding{210}"}
	};

	std::string out;
	unsigned int col = 1;
	
	if(style)
	{
		out += "\\";
		out += style;
		out += "{";
	}
	
	while(*s)
	{
		unsigned int i;
		bool found = false;
		
		bool can_cut = (*s == ' ') || (strncmp(s, "::", 2) == 0) || (*s == '/') || (*s == '_') || (*s == '-') || (*s == '.') || (*s == '[');
		
		for(i = 0; i < sizeof(conversion_table)/sizeof(conversion_table[0]); i++)
		{
			int length = strlen(conversion_table[i].searchFor);
			if(strncmp(s, conversion_table[i].searchFor, length) == 0)
			{
				out += conversion_table[i].replaceBy;
				s += length;
				col += length;

				if(cut)
				{
					if(col > cut && can_cut)
					{
						if(style) out += "}";
						out += " \\newline$\\hookrightarrow$";
						if(style)
						{
							out += "\\";
							out += style;
							out += "{";
						}
						col = 1;
					}
				}
				found = true;
			}
		}
		
		if(!found)
		{
			out += *s;
			s++;
			col++;
			if(cut)
			{
				if(col > cut && can_cut)
				{
					if(style) out += "}";
					out += " \\newline$\\hookrightarrow$";
					if(style)
					{
						out += "\\";
						out += style;
						out += "{";
					}
					col = 1;
				}
			}
		}
	}
	
	if(style)
	{
		out += "}";
	}
	return out;
}

bool ResolvePath(const std::string& prefix_dir,
		const std::string& suffix_dir,
		std::string& out_dir) 
{
	std::string unresolved_dir = prefix_dir;
	unresolved_dir += '/';
	unresolved_dir += suffix_dir;
//	char resolved_dir_buf[PATH_MAX + 1];
	char resolved_dir_buf[FILENAME_MAX + 1];

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__APPLE_CC__)
	if ( realpath(unresolved_dir.c_str(), 
				resolved_dir_buf) )
	{
		out_dir = resolved_dir_buf;
		return true;
	}
#elif defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	DWORD length = GetFullPathName(unresolved_dir.c_str(), 
			PATH_MAX + 1, 
			resolved_dir_buf, 
			0);
	if(length > 0)
	{
		resolved_dir_buf[length] = 0;
		out_dir = resolved_dir_buf;
		return true;
	}
#endif
	return false;
}

//=============================================================================
//=                             SignalHandler                                 =
//=============================================================================

class SignalHandler
{
private:
	friend class Simulator;
	
	static void Init();
	static void Fini();
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType);
#else
	static void SigIntHandler(int signum);
	static void SigPipeHandler(int signum);
	static void (*sig_int_handler)(int);
	static void (*prev_sig_int_handler)(int);
	static void (*sig_pipe_handler)(int);
	static void (*prev_sig_pipe_handler)(int);
#endif
};

#if !defined(WIN32) && !defined(_WIN32) && !defined(WIN64) && !defined(_WIN64)
void (*SignalHandler::sig_pipe_handler)(int) = 0;
void (*SignalHandler::prev_sig_pipe_handler)(int) = 0;
void (*SignalHandler::sig_int_handler)(int) = 0;
void (*SignalHandler::prev_sig_int_handler)(int) = 0;
#endif

void SignalHandler::Init()
{
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	SetConsoleCtrlHandler(&SignalHandler::ConsoleCtrlHandler, TRUE);
#else
	sig_int_handler = &SignalHandler::SigIntHandler;
	prev_sig_int_handler = signal(SIGINT, sig_int_handler);
	sig_pipe_handler = &SignalHandler::SigPipeHandler;
	prev_sig_pipe_handler = signal(SIGPIPE, sig_pipe_handler);
#endif
}

void SignalHandler::Fini()
{
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	SetConsoleCtrlHandler(&SignalHandler::ConsoleCtrlHandler, FALSE);
#else
	if(sig_pipe_handler)
	{
		signal(SIGPIPE, prev_sig_pipe_handler);
		sig_pipe_handler = 0;
	}
	if(sig_int_handler)
	{
		signal(SIGINT, prev_sig_int_handler);
		sig_int_handler = 0;
	}
#endif
}

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
BOOL WINAPI SignalHandler::ConsoleCtrlHandler(DWORD dwCtrlType)
{
	bool interrupted = false;
	switch(dwCtrlType)
	{
		case CTRL_C_EVENT:
			std::cerr << "Interrupted by Ctrl-C" << std::endl;
			interrupted = true;
			break;
		case CTRL_BREAK_EVENT:
			std::cerr << "Interrupted by Ctrl-Break" << std::endl;
			interrupted = true;
			break;
		case CTRL_CLOSE_EVENT:
			std::cerr << "Interrupted by a console close" << std::endl;
			interrupted = true;
			break;
		case CTRL_LOGOFF_EVENT:
			std::cerr << "Interrupted because of logoff" << std::endl;
			interrupted = true;
			break;
		case CTRL_SHUTDOWN_EVENT:
			std::cerr << "Interrupted because of shutdown" << std::endl;
			interrupted = true;
			break;
	}
	
	if(interrupted)
	{
		Simulator::Instance()->MTSigInt();
	}
	
	return interrupted ? TRUE : FALSE;
}
#else
void SignalHandler::SigIntHandler(int signum)
{
	std::cerr << "Interrupted by Ctrl-C or SIGINT signal" << std::endl;
	Simulator::Instance()->MTSigInt();
}

void SignalHandler::SigPipeHandler(int signum)
{
	/* do nothing */
}
#endif

//=============================================================================
//=                             VariableBase                                 =
//=============================================================================
	
VariableBase::
VariableBase(const char *_name, Object *_owner, Type _type, const char *_description)
	: name(_owner ? std::string(_owner->GetName()) + std::string(".") + std::string(_name) : std::string(_name) )
	, var_name(std::string(_name))
	, owner(_owner)
	, container(0)
	, description(_description ? std::string(_description) : std::string(""))
	, enumerated_values()
	, type(_type)
	, fmt(FMT_DEFAULT)
	, is_mutable(true)
	, is_visible(true)
	, is_serializable(true)
	, is_modified(false)
	, listener_set()
{
	if(_owner)
	{
		_owner->Add(*this);
	}
	Simulator::Instance()->Register(this);
}

VariableBase::
VariableBase(const char *_name, VariableBase *_container, Type _type, const char *_description)
	: name(_container ? std::string(_container->GetName()) + std::string(".") + std::string(_name) : std::string(_name))
	, var_name(_container ? std::string(_container->GetVarName()) + std::string(".") + std::string(_name) : std::string(_name))
	, owner(0)
	, container(_container)
	, description(_description ? std::string(_description) : std::string(""))
	, enumerated_values()
	, type(_type)
	, fmt(FMT_DEFAULT)
	, is_mutable(true)
	, is_visible(true)
	, is_serializable(true)
	, is_modified(false)
	, listener_set()
{
	Simulator::Instance()->Register(this);
}

VariableBase::
VariableBase()
	: name()
	, owner(0)
	, container(0)
	, description()
	, type(VAR_VOID)
	, fmt(FMT_DEFAULT)
	, is_mutable(false)
	, is_visible(false)
	, is_serializable(false)
	, is_modified(false)
	, listener_set()
{
}

VariableBase::~VariableBase()
{
	if(owner) owner->Remove(*this);
	Simulator::Instance()->Unregister(this);
}

void VariableBase::Initialize()
{
	Simulator::Instance()->Initialize(this);
}

Object *VariableBase::GetOwner() const
{
	return owner;
}

VariableBase *VariableBase::GetContainer() const
{
	return container;
}

const char *VariableBase::GetName() const
{
	return name.c_str();
}

const char *VariableBase::GetVarName() const
{
	return var_name.c_str();
}
	
const char *VariableBase::GetDescription() const
{
	return description.c_str();
}

VariableBase::Type VariableBase::GetType() const
{
	return type;
}

const char *VariableBase::GetTypeName() const
{
	switch(type)
	{
		case VAR_VOID: return "void";
		case VAR_ARRAY: return "array";
		case VAR_PARAMETER: return "parameter";
		case VAR_STATISTIC: return "statistic";
		case VAR_REGISTER: return "register";
		case VAR_SIGNAL: return "signal";
	}
	return "invalid";
}

VariableBase::Format VariableBase::GetFormat() const
{
	return fmt;
}

const char *VariableBase::GetDataTypeName() const
{
	return "";
}

VariableBase::DataType VariableBase::GetDataType() const
{
	return DT_USER;
}

bool VariableBase::HasEnumeratedValues() const {
	return !enumerated_values.empty();
}

bool VariableBase::HasEnumeratedValue(const char * value) const {
	std::vector<std::string>::const_iterator iter;

	for(iter = enumerated_values.begin(); iter != enumerated_values.end(); iter++) {
		if(iter->compare(value) == 0) {
			return true;
		}
	}
	return false;
}

void VariableBase::GetEnumeratedValues(std::vector<std::string> &values) const {
	if(!HasEnumeratedValues()) return;
	for(unsigned int i = 0; i < enumerated_values.size(); i++) {
		values.push_back(enumerated_values[i]);
	}
}

bool VariableBase::AddEnumeratedValue(const char *value) {
	if(HasEnumeratedValue(value)) return false;
	enumerated_values.push_back(std::string(value));
	return true;
}

bool VariableBase::RemoveEnumeratedValue(const char *value) {
	std::vector<std::string>::iterator it;
	for(it = enumerated_values.begin(); it != enumerated_values.end(); it++) {
		if(it->compare(value) == 0) {
			enumerated_values.erase(it);
			return true;
		}
	}
	return false;
}

void VariableBase::SetDescription(const char *_description)
{
	description = _description;
}

void VariableBase::SetFormat(Format _fmt)
{
	fmt = _fmt;
}

bool VariableBase::IsVoid() const
{
	return this == Simulator::Instance()->void_variable;
}

bool VariableBase::IsMutable() const
{
	return is_mutable;
}

bool VariableBase::IsVisible() const
{
	return is_visible;
}

bool VariableBase::IsSerializable() const
{
	return is_serializable;
}

bool VariableBase::IsModified() const
{
	return is_modified;
}

void VariableBase::SetMutable(bool _is_mutable)
{
	is_mutable = _is_mutable;
}

void VariableBase::SetVisible(bool _is_visible)
{
	is_visible = _is_visible;
}

void VariableBase::SetSerializable(bool _is_serializable)
{
	is_serializable = _is_serializable;
}

void VariableBase::SetModified(bool _is_modified)
{
	is_modified = _is_modified;
}

void
VariableBase::AddListener( VariableBaseListener* listener )
{
  listener_set.insert( listener );
}

void
VariableBase::RemoveListener( VariableBaseListener* listener )
{
  listener_set.erase( listener );
}

void
VariableBase::NotifyListeners()
{
  typedef std::set<VariableBaseListener*>::iterator listener_iterator;
  for (listener_iterator itr = listener_set.begin(), end = listener_set.end(); itr != end; ++itr)
    {
      (*itr)->VariableBaseNotify( this );
    }
}

VariableBase::operator bool () const { return false; }
VariableBase::operator signed char () const { return (long long) *this; }
VariableBase::operator short () const { return (long long) *this; }
VariableBase::operator int () const { return (long long) *this; }
VariableBase::operator long () const { return (long long) *this; }
VariableBase::operator long long () const { return 0LL; }
VariableBase::operator unsigned char () const { return (unsigned long long) *this; }
VariableBase::operator unsigned short () const { return (unsigned long long) *this; }
VariableBase::operator unsigned int () const { return (unsigned long long) *this; }
VariableBase::operator unsigned long () const { return (unsigned long long) *this; }
VariableBase::operator unsigned long long () const { return 0ULL; }
VariableBase::operator float () const { return (double) *this; }
VariableBase::operator double () const { return 0.0; }
VariableBase::operator std::string () const { return std::string(); }

VariableBase& VariableBase::operator = (bool value) { NotifyListeners(); return *this; }
VariableBase& VariableBase::operator = (char value) { *this = (long long) value; return *this; }
VariableBase& VariableBase::operator = (short value) { *this = (long long) value; return *this; }
VariableBase& VariableBase::operator = (int value) { *this = (long long) value; return *this; }
VariableBase& VariableBase::operator = (long value) { *this = (long long) value; return *this; }
VariableBase& VariableBase::operator = (long long value) { NotifyListeners(); return *this; }
VariableBase& VariableBase::operator = (unsigned char value) { *this = (unsigned long long) value; return *this; }
VariableBase& VariableBase::operator = (unsigned short value) { *this = (unsigned long long) value; return *this; }
VariableBase& VariableBase::operator = (unsigned int value) { *this = (unsigned long long) value; return *this; }
VariableBase& VariableBase::operator = (unsigned long value) { *this = (unsigned long long) value; return *this; }
VariableBase& VariableBase::operator = (unsigned long long value) { NotifyListeners(); return *this; }
VariableBase& VariableBase::operator = (float value) { *this = (double) value; return *this; }
VariableBase& VariableBase::operator = (double value) { NotifyListeners(); return *this; }
VariableBase& VariableBase::operator = (const char *value) { NotifyListeners(); return *this; }

VariableBase& VariableBase::operator [] (unsigned int index)
{
	if(index >= 0)
	{
		std::cerr << "Subscript out of range" << std::endl;
		return *Simulator::Instance()->void_variable;
	}
	return *this;
}

const VariableBase& VariableBase::operator [] (unsigned int index) const
{
	if(index >= 0)
	{
		std::cerr << "Subscript out of range" << std::endl;
		return *Simulator::Instance()->void_variable;
	}
	return *this;
}

unsigned int VariableBase::GetLength() const
{
	return 0;
}

unsigned int VariableBase::GetBitSize() const { return 0; }

VariableBase& VariableBase::operator = (const VariableBase& variable)
{
	std::string variable_value = (std::string) variable;
	return *this = variable_value.c_str();
}

std::string VariableBase::GetSymbolicValue() const
{
	return IsVisible() ? name : (std::string) *this;
}

void VariableBase::GenerateLatexDocumentation(std::ostream& os) const
{
	os << "\\multicolumn{1}{|p{7.5cm}}{\\textbf{Name:} " << string_to_latex(name.c_str(), 26, "texttt") << "} & \\multicolumn{1}{p{7.5cm}|}{\\textbf{Type:} " << string_to_latex(GetTypeName(), 36, "texttt") << "}\\\\" << std::endl;
	
	if(type == VAR_STATISTIC)
	{
		// symbolically print formula 
		os << "\\multicolumn{1}{|p{7.5cm}}{\\textbf{Statistic:} ";
		os << string_to_latex(GetSymbolicValue().c_str(), 24, "texttt");
	}
	else
	{
		// print variable current value
		os << "\\multicolumn{1}{|p{7.5cm}}{\\textbf{Default:} ";
		os << string_to_latex(((std::string) *this).c_str(), 24, "texttt");
	}
	os << "} & \\multicolumn{1}{p{7.5cm}|}{\\textbf{Data type:} " << string_to_latex(GetDataTypeName(), 36, "texttt") << "}\\\\" << std::endl;
	
	if(HasEnumeratedValues())
	{
		os << "\\multicolumn{2}{|p{15cm}|}{\\textbf{Valid:} ";
		
		std::vector<std::string>::const_iterator enumerated_values_iter;
		for(enumerated_values_iter = enumerated_values.begin(); enumerated_values_iter != enumerated_values.end(); enumerated_values_iter++)
		{
			if(enumerated_values_iter != enumerated_values.begin())
			{
				os << ",~";
			}
			os << string_to_latex((*enumerated_values_iter).c_str(), 0, "texttt");
		}
		os << "}\\\\" << std::endl;
	}
	else
	{
		os << "\\multicolumn{2}{|l|}{}\\\\" << std::endl;
	}
	
	if(!description.empty())
	{
		os << "\\multicolumn{2}{|l|}{}\\\\" << std::endl;
		os << "\\multicolumn{2}{|p{15cm}|}{\\textbf{Description:} \\newline " << string_to_latex(description.c_str()) << ".}\\\\" << std::endl;
	}
	os << "\\hline" << std::endl;
}

VariableBase& VariableBase::GetVoidVariable()
{
	return *Simulator::Instance()->void_variable;
}
        
//=============================================================================
//=                                 Object                                    =
//=============================================================================

Object::Object(const char *_name, Object *_parent, const char *_description)
	: object_name(_parent ? (std::string(_parent->GetName()) + std::string(".") + std::string(_name)) : std::string(_name))
	, object_base_name(std::string(_name))
	, description(_description ? std::string(_description) : std::string(""))
	, parent(_parent)
	, leaf_objects()
	, killed(false)
{
	if(_parent) _parent->Add(*this);
	Simulator::Instance()->Register(this);
}

Object::~Object()
{
	if(parent) parent->Remove(*this);
	Simulator::Instance()->Unregister(this);
}

const char *Object::GetName() const
{
	return object_name.c_str();
}

const char *Object::GetObjectName() const
{
	return object_base_name.c_str();
}

std::string Object::URI() const
{
	return (parent ? parent->URI() : std::string()) + '/' + unisim::util::hypapp::URI_Encoder::EncodeComponent(object_base_name);
}

Object *Object::GetParent() const
{
	return parent;
}

void Object::Add(Object& object)
{
	std::list<Object *>::iterator object_iter;
	for(object_iter = leaf_objects.begin(); object_iter != leaf_objects.end(); object_iter++)
	{
		if(unisim::util::nat_sort::nat_ltstr::Less(object.GetName(), (*object_iter)->GetName()))
		{
			leaf_objects.insert(object_iter, &object);
			return;
		}
	}
	leaf_objects.push_back(&object);
}

void Object::Remove(Object& object)
{
	std::list<Object *>::iterator object_iter;

	for(object_iter = leaf_objects.begin(); object_iter != leaf_objects.end(); object_iter++)
	{
		if(*object_iter == &object)
		{
			leaf_objects.erase(object_iter);
			return;
		}
	}
}

void Object::Add(VariableBase& var)
{
	std::list<VariableBase *>::iterator variable_iter;
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		if(unisim::util::nat_sort::nat_ltstr::Less(var.GetName(), (*variable_iter)->GetName()))
		{
			variables.insert(variable_iter, &var);
			return;
		}
	}
	variables.push_back(&var);
}

void Object::Remove(VariableBase& var)
{
	std::list<VariableBase *>::iterator var_iter;

	for(var_iter = variables.begin(); var_iter != variables.end(); var_iter++)
	{
		if(*var_iter == &var)
		{
			variables.erase(var_iter);
			return;
		}
	}
}

void Object::GetVariables(std::list<VariableBase *>& lst, VariableBase::Type type) const
{
	std::list<VariableBase *>::const_iterator variable_iter;

	lst.clear();
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *variable = *variable_iter;
		if(((type == VariableBase::VAR_VOID) || (variable->GetType() == type)) && variable->IsVisible())
		{
			lst.push_back(*variable_iter);
		}
	}
}

const std::list<Object *>& Object::GetLeafs() const
{
	return leaf_objects;
}

bool Object::BeginSetup()
{
	return true;
}

bool Object::EndSetup()
{
	return true;
}

void Object::SigInt()
{
}

void Object::Kill()
{
	killed = true;
}

void Object::OnDisconnect()
{
//	cerr << "WARNING! Using default OnDisconnect for " << GetName() << std::endl;
}

VariableBase& Object::operator [] (const char *name)
{
	std::string fullname = GetName() + std::string(".") + std::string(name);
	VariableBase *variable = Simulator::Instance()->FindVariable(fullname.c_str());
	return *variable;
}

VariableBase& Object::operator [] (const std::string& name)
{
	std::string fullname = GetName() + std::string(".") + name;
	VariableBase *variable = Simulator::Instance()->FindVariable(fullname.c_str());
	return *variable;
}

Simulator *Object::GetSimulator() const
{
	return Simulator::Instance();
}

const char *Object::GetDescription() const
{
	return description.c_str();
}

void Object::GenerateLatexDocumentation(std::ostream& os, VariableBase::Type variable_type) const
{
	bool header_printed = false;
	
	std::list<VariableBase *>::const_iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *variable = *variable_iter;
		
		if((variable->GetType() == variable_type) && variable->IsVisible())
		{
			if(!header_printed)
			{
				os << "\\multicolumn{2}{|l|}{\\textbf{\\Large " << string_to_latex(GetName()) << "}}\\\\" << std::endl;
				os << "\\hline" << std::endl;
				header_printed = true;
			}
			variable->GenerateLatexDocumentation(os);
		}
	}
	if(header_printed) os << "\\hline" << std::endl;
}

void Object::Stop(int exit_status, bool asynchronous)
{
	Simulator::Instance()->Stop(this, exit_status, asynchronous);
}

void Object::SetDescription(const char *_description)
{
	description = _description;
}

void Object::AddServiceAgent( ServiceAgent const* srv_agent )
{
	if (not srv_agents.insert( srv_agent ).second)
	{
		throw std::runtime_error("Multiple service agent registering");
	}
}

void Object::DoServiceSetup()
{
	for (ServiceAgent const* agent : srv_agents)
		agent->Setup(this);
}


//=============================================================================
//=                                ServiceBase                                =
//=============================================================================

ServiceBase::ServiceBase(const char *name, Object *parent, const char *description)
	: Object(name, parent, description)
	, setup_state( NoSetup )
	, is_connected(false)
{}

/// Check if service setup is needed while ensuring that no concurrent setup is ongoing
bool ServiceBase::NeedServiceSetup() const
{
	switch (SetupState(setup_state))
	{
	case NoSetup:       return true;
	case SetupComplete: return false;
	default: break;
	}

	std::cerr << "ERROR! Cyclic Service Setup in Object \"" << this->GetName() << "\n";
	exit(1);
	return false;
}

//=============================================================================
//=                              ServicePortBase                              =
//=============================================================================

ServicePortBase::ServicePortBase(const char *_name, Object *_owner)
	: name(std::string(_owner->GetName()) + std::string(".") + std::string(_name))
	, owner(_owner)
	, bwd_ports()
	, fwd_port(0)
{
	Simulator::Instance()->Register(this);
}

ServicePortBase::~ServicePortBase()
{
	if(fwd_port)
	{
		fwd_port->Disconnect(this);
	}
	for (auto & bwd_port : bwd_ports)
	{
		bwd_port->fwd_port = 0;
	}
	
	Simulator::Instance()->Unregister(this);
}

const char *ServicePortBase::GetName() const
{
	return name.c_str();
}

void ServicePortBase::Dump(std::ostream& os) const
{
	if(fwd_port)
	{
		os << GetName() << " -> " << fwd_port->GetName() << std::endl;
	}

	for(std::list<ServicePortBase*>::const_iterator port_iter = bwd_ports.begin(); port_iter != bwd_ports.end(); port_iter++)
	{
		os << "# " << (*port_iter)->GetName() << " -> " << GetName() << std::endl;
	}
}

void ServicePortBase::Connect(ServicePortBase* fwd)
{
	if (fwd_port)
	{
		std::cerr << "WARNING! Can't connect " << GetName() << " to "
		          << fwd->GetName() << " because it is already connected to "
		          << fwd_port->GetName() << std::endl;
		return;
	}
#ifdef DEBUG_KERNEL
	std::cerr << GetName() << " -> " << srv_export.GetName() << std::endl;
#endif
	fwd_port = fwd;
	fwd->bwd_ports.push_back(this);
}

void ServicePortBase::Disconnect(ServicePortBase* bwd)
{
	BwdPorts::iterator it = std::find(bwd_ports.begin(), bwd_ports.end(), bwd);
	if(it != bwd_ports.end())
	{
		bwd_ports.erase(it);
	}
}

void
ServicePortBase::SpreadFwd( ServicePortBase::Visitor& visitor )
{
	if(fwd_port)
	{
		fwd_port->SpreadFwd(visitor);
	}
	visitor.Process(*this);
}

void
ServicePortBase::SpreadBwd( ServicePortBase::Visitor& visitor )
{
	for (auto const& bwd_port : bwd_ports)
	{
		bwd_port->SpreadBwd(visitor);
	}
	visitor.Process(*this);
}

//=============================================================================
//=                           ConfigFileHelper                                =
//=============================================================================

ConfigFileHelper::~ConfigFileHelper()
{
}

bool ConfigFileHelper::Match(const char *filename) const
{
	return MatchFilenameByExtension(filename, GetName());
}

bool ConfigFileHelper::MatchFilenameByExtension(const char *filename, const char *extension)
{
	const char *p = filename;
	const char *dot = 0;
	do
	{
		if((p = strchr(p, '.')) != 0)
		{
			dot = p++;
		}
	}
	while(p);
	
	return dot && (strcasecmp(dot + 1, extension) == 0);
}

//=============================================================================
//=                                Simulator                                  =
//=============================================================================

Simulator *Simulator::simulator = 0;

Simulator::CommandLineOption::CommandLineOption(char _short_name, const char *_long_name, const char *_opt_description, const char *_arg_description)
	: short_name(_short_name)
	, long_name(_long_name)
	, arg_description(_arg_description)
	, opt_description(_opt_description)
{
}

char Simulator::CommandLineOption::GetShortName() const
{
	return short_name;
}

const char *Simulator::CommandLineOption::GetLongName() const
{
	return long_name;
}

bool Simulator::CommandLineOption::HasArgument() const
{
	return arg_description != 0;
}

const char *Simulator::CommandLineOption::GetArgumentDescription() const
{
	return arg_description;
}

const char *Simulator::CommandLineOption::GetOptionDescription() const
{
	return opt_description;
}

int Simulator::CommandLineOption::operator == (const char *arg) const
{
	if(arg[0] == '-')
	{
		if(arg[1] == '-')
		{
			return strcmp(arg + 2, long_name) == 0;
		}
		else
		{
			return (arg[2] == 0) && (arg[1] == short_name);
		}
	}
	return 0;
}

Simulator::Simulator(int argc, char **argv, void (*LoadBuiltInConfig)(Simulator *))
	: void_variable(0)
	, shared_data_dir()
	, set_vars()
	, get_config_filenames()
	, default_config_file_format("XML")
	, list_parms(false)
	, generate_doc(false)
	, generate_doc_filename()
	, enable_warning(false)
	, enable_version(false)
	, enable_help(false)
	, warn_get_bin_path(false)
	, warn_get_share_path(false)
	, enable_press_enter_at_exit(false)
	, bin_dir()
	, program_binary()
	, program_name()
	, authors()
	, copyright()
	, description()
	, version()
	, license()
	, schematic()
	, var_program_name(0)
	, var_authors(0)
	, var_copyright(0)
	, var_description(0)
	, var_version(0)
	, var_license(0)
	, var_schematic(0)
	, param_enable_press_enter_at_exit(0)
	, param_default_config_file_format(0)
	, config_file_formats()
	, command_line_options()
	, objects()
	, srv_ports()
	, variables()
	, cmd_args()
	, param_cmd_args(0)
	, mutex()
	, sig_int_thrd()
	, sig_int_thrd_create_mutex()
	, sig_int_thrd_create_cond()
	, sig_int_thrd_mutex()
	, sig_int_thrd_cond()
	, sig_int_cond(false)
	, stop_sig_int_thrd(false)
	, sig_int_thrd_alive(false)
{
	pthread_mutex_init(&mutex, NULL);
	
	pthread_mutex_init(&sig_int_thrd_create_mutex, NULL);
	pthread_mutex_init(&sig_int_thrd_mutex, NULL);
	
	pthread_cond_init(&sig_int_thrd_create_cond, NULL);
	pthread_cond_init(&sig_int_thrd_cond, NULL);
	
	SignalHandler::Init();

	if(LoadBuiltInConfig)
	{
		LoadBuiltInConfig(this);
	}
	
	bool has_share_data_dir_hint = false;
	std::string shared_data_dir_hint;
	
	std::map<std::string, ConfigFileHelper *>::iterator config_file_helper_iter;
	for(config_file_helper_iter = config_file_helpers.begin(); config_file_helper_iter != config_file_helpers.end(); config_file_helper_iter++)
	{
		if(config_file_helper_iter != config_file_helpers.begin())
		{
			config_file_formats += " | ";
		}
		ConfigFileHelper *config_file_helper = (*config_file_helper_iter).second;
		config_file_formats += config_file_helper->GetName();
	}

	command_line_options.push_back(CommandLineOption('s', "set", "set value of parameter 'param' to 'value'", "param=value"));
	if(config_file_helpers.size())
	{
		command_line_options.push_back(CommandLineOption('c', "config", "configures the simulator with the given configuration file", "file"));
		command_line_options.push_back(CommandLineOption('g', "get-config", "get the simulator configuration file (you can use it to create your own configuration. This option can be combined with -c to get a new configuration file with existing variables from another file", "file"));
		command_line_options.push_back(CommandLineOption('f', "default-config-file-format", "set the simulator default configuration file format", config_file_formats.c_str()));
	}
	command_line_options.push_back(CommandLineOption('l', "list", "lists all available parameters, their type, and their current value"));
	command_line_options.push_back(CommandLineOption('w', "warn", "enable printing of kernel warnings"));
	command_line_options.push_back(CommandLineOption('d', "doc", "enable printing a latex documentation", "Latex file"));
	command_line_options.push_back(CommandLineOption('v', "version", "displays the program version information"));
	command_line_options.push_back(CommandLineOption('p', "share-path", "the path that should be used for the share directory (absolute path)", "path"));
	command_line_options.push_back(CommandLineOption('h', "help", "displays this help"));
	
	if(simulator)
	{
		throw std::runtime_error("No more than one instance of unisim::kernel::Simulator is allowed");
	}
	
	simulator = this;
	void_variable = new VariableBase("void", (Object *) 0, VariableBase::VAR_VOID, "unknown variable");
	void_variable->SetMutable(false);
	void_variable->SetVisible(false);
	void_variable->SetSerializable(false);

	var_authors = new variable::Parameter<std::string>("authors", 0, authors, "Authors");
	var_authors->SetMutable(false);
	var_authors->SetVisible(false);
	var_authors->SetSerializable(false);

	var_program_name = new variable::Parameter<std::string>("program-name", 0, program_name, "Program name");
	var_program_name->SetMutable(false);
	var_program_name->SetVisible(false);
	var_program_name->SetSerializable(false);

	var_copyright = new variable::Parameter<std::string>("copyright", 0, copyright, "Copyright");
	var_copyright->SetMutable(false);
	var_copyright->SetVisible(false);
	var_copyright->SetSerializable(false);

	var_version = new variable::Parameter<std::string>("version", 0, version, "Version");
	var_version->SetMutable(false);
	var_version->SetVisible(false);
	var_version->SetSerializable(false);

	var_description = new variable::Parameter<std::string>("description", 0, description, "Description");
	var_description->SetMutable(false);
	var_description->SetVisible(false);
	var_description->SetSerializable(false);

	var_license = new variable::Parameter<std::string>("license", 0, license, "License");
	var_license->SetMutable(false);
	var_license->SetVisible(false);
	var_license->SetSerializable(false);

	var_schematic = new variable::Parameter<std::string>("schematic", 0, schematic, "path to simulator schematic");
	var_schematic->SetMutable(false);
	var_schematic->SetVisible(false);
	var_schematic->SetSerializable(false);

	param_enable_press_enter_at_exit = new variable::Parameter<bool>("enable-press-enter-at-exit", 0, enable_press_enter_at_exit, "Enable/Disable pressing key enter at exit");
	
	param_default_config_file_format = new variable::Parameter<std::string>("default-config-file-format", 0, default_config_file_format, "Default configuration file format (when failed guessing from filename)");
	param_default_config_file_format->SetMutable(false);
	param_default_config_file_format->SetVisible(false);
	param_default_config_file_format->SetSerializable(false);

	// parse command line arguments (first pass)
	char **arg_end = argv + argc;
	
	if(argv)
	{
		int state = 0;
		for(char **arg = argv + 1; arg < arg_end; arg++)
		{
			switch(state)
			{
				case 0:
					// Unless there's an acceptable option entry assume options parsing ends here
					state = -1;
					
					// "--" unconditionally ends option parsing afterwards
					if (strcmp(*arg, "--") == 0)
					{
						arg++;
						break;
					}
					
					for (std::vector<CommandLineOption>::const_iterator cmd_opt_itr = command_line_options.begin(),
																		cmd_opt_end = command_line_options.end();
						cmd_opt_itr != cmd_opt_end; ++cmd_opt_itr)
					{
						if(*cmd_opt_itr == *arg)
						{
							switch(cmd_opt_itr->GetShortName())
							{
								case 's':
									state = 1;
									break;
								case 'c':
									state = 2;
									break;
								case 'f':
									state = 6;
									break;
								case 'g':
									state = 3;
									break;
								case 'l':
									list_parms = true;
									state = 0;
									break;
								case 'v':
									enable_version = true;
									state = 0;
									break;
								case 'h':
									enable_help = true;
									state = 0;
									break;
								case 'w':
									enable_warning = true;
									state = 0;
									break;
								case 'd':
									state = 4;
									break;
								case 'p':
									has_share_data_dir_hint = true;
									state = 5;
									break;
								default:
									break;
							}
							break;
						}
					}
					break;
				
				case 1:
					// skipping set variable
					state = 0;
					break;
				case 2:
					// skipping loading variables
					state = 0;
					break;
				case 3:
					// skipping get config
					state = 0;
					break;
				case 4:
					// skipping generate doc
					state = 0;
					break;
				case 5:
					// getting the share data path
					shared_data_dir_hint = *arg;
					state = 0;
					break;
				case 6:
					// getting the default config file format
					default_config_file_format = *arg;
					state = 0;
					break;
				default:
					std::cerr << "Internal error while parsing command line arguments" << std::endl;
					state = -1;
					break;
			}
			if (state == -1)
			{
				arg_end = arg;
			}
		}
	}

	if ( !has_share_data_dir_hint )
	{
		if(GetBinPath(argv ? argv[0] : 0, bin_dir, program_binary))
		{
// 			 std::cerr << "bin_dir=\"" << bin_dir << "\"" << std::endl;
// 			 std::cerr << "program_binary=\"" << program_binary << "\"" << std::endl;

			if ( GetSharePath(bin_dir, shared_data_dir) )
			{
// 				std::cerr << "shared_data_dir=\"" << shared_data_dir << "\"" << std::endl;
			}
			else
			{
// 				std::cerr << "Could not resolve share data dir path" << std::endl;
				warn_get_share_path = true;
			}
		}
		else
		{
// 			std::cerr << "Could not resolve bin and share data dir paths" << std::endl;
			warn_get_bin_path = true;
			warn_get_share_path = true;
		}
	}
	else
	{
		if ( !ResolvePath(shared_data_dir_hint, std::string(), shared_data_dir) )
		{
// 			std::cerr << "Could not resolve share data dir path" << std::endl;
			warn_get_share_path = true;
		}
		else
		{
// 			std::cerr << "Resolved data dir path: " << shared_data_dir
// 			 	<< std::endl;
		}
	}

	if(argv)
	{
		// parse command line arguments (second pass)
		int state = 0;
		for(char **arg = argv + 1; arg < arg_end; arg++)
		{
			switch(state)
			{
				case 0:
					// Unless there's an acceptable option entry assume options parsing ends here
					state = -1;
					
					// "--" unconditionally ends option parsing afterwards
					if (strcmp(*arg, "--") == 0)
					{
						arg++;
						break;
					}
					
					for (std::vector<CommandLineOption>::const_iterator cmd_opt_itr = command_line_options.begin(),
																		cmd_opt_end = command_line_options.end();
						cmd_opt_itr != cmd_opt_end; ++cmd_opt_itr)
					{
						if(*cmd_opt_itr == *arg)
						{
							switch(cmd_opt_itr->GetShortName())
							{
								case 's':
									state = 1;
									break;
								case 'c':
									state = 2;
									break;
								case 'f':
									state = 6;
									break;
								case 'F':
									state = 7;
									break;
								case 'g':
									state = 3;
									break;
								case 'l':
									list_parms = true;
									state = 0;
									break;
								case 'v':
									enable_version = true;
									state = 0;
									break;
								case 'h':
									enable_help = true;
									state = 0;
									break;
								case 'w':
									enable_warning = true;
									if(!LoadBuiltInConfig)
									{
										std::cerr << "WARNING! No built-in parameters set loaded" << std::endl;
									}
									if(warn_get_bin_path)
									{
										std::cerr << "WARNING! Can't determine binary directory" << std::endl;
									}
									if(warn_get_share_path)
									{
										std::cerr << "WARNING! Can't determine share directory" << std::endl;
										std::cerr << "         Program binary is '" << program_binary << "'" << std::endl;
										std::cerr << "         Binary dir is     '" << bin_dir << "'" << std::endl;
									}
									state = 0;
									break;
								case 'd':
									state = 4;
									break;
								case 'p':
									state = 5;
									break;
								default:
									state = -1;
									break;
							}
						}
					}
					break;
				
				case 1:
					{
						std::string variable_name;
						
						char *p;
						for(p = *arg; *p != 0 && *p != '='; p++)
						{
							variable_name += *p;
						}
						if(*p == '=')
						{
							const char *variable_value = ++p;
							
							SetVariable(variable_name.c_str(), variable_value);
						}
						else if(enable_warning)
						{
							std::cerr << "WARNING! Ignoring " << *arg << std::endl;
						}
					}
					state = 0;
					break;
				case 2:
					if(LoadVariables(*arg, VariableBase::VAR_PARAMETER))
					{
						std::cerr << "variable::Parameters set using file \"" << (*arg) << "\"" << std::endl;
					}
					else if(enable_warning)
					{
						std::cerr << "WARNING! Loading parameters set from file \"" << (*arg) << "\" failed" << std::endl;
					}
					state = 0;
					break;
				case 3:
					get_config_filenames.push_back(*arg);
					state = 0;
					break;
				case 4:
					generate_doc = true;
					generate_doc_filename = *arg;
					state = 0;
					break;
				case 5:
					state = 0;
					break;
				case 6:
					state = 0;
					break;
				case 7:
					state = 0;
					break;
				default:
					std::cerr << "Internal error while parsing command line arguments" << std::endl;
					state = -1;
					break;
			}
			if (state == -1)
			{
				arg_end = arg;
			}
		}
	
		// create on the fly parameters cmd-args[*] that are the remaining parameters
		int cmd_args_dim = argv + argc - arg_end;
		cmd_args.resize(cmd_args_dim);
		param_cmd_args = new variable::ParameterArray<std::string>("cmd-args", 0, &cmd_args[0], cmd_args_dim, "command line arguments");
		for(int i = 0; i < cmd_args_dim; i++)
		{
			(*param_cmd_args)[i] = arg_end[i];
		}
		param_cmd_args->SetVisible(false);
		param_cmd_args->SetMutable(false);
		param_cmd_args->SetSerializable(false);
	}
	
	unisim::kernel::logger::Logger::StaticServerInstance();
}

Simulator::~Simulator()
{
	if(enable_press_enter_at_exit)
	{
		std::cout << "Press Enter to exit..." << std::endl;
		getc(stdin);
	}
	
	if(void_variable)
	{
		delete void_variable;
	}
	
	if(param_cmd_args)
	{
		delete param_cmd_args;
	}
	
	if(var_program_name)
	{
		delete var_program_name;
	}
	
	if(var_authors)
	{
		delete var_authors;
	}
	
	if(var_copyright)
	{
		delete var_copyright;
	}
	
	if(var_version)
	{
		delete var_version;
	}
	
	if(var_license)
	{
		delete var_license;
	}
	
	if(var_schematic)
	{
		delete var_schematic;
	}

	if(var_description)
	{
		delete var_description;
	}

	if(param_enable_press_enter_at_exit)
	{
		delete param_enable_press_enter_at_exit;
	}
	
	if(param_default_config_file_format)
	{
		delete param_default_config_file_format;
	}
	
	std::map<std::string, ConfigFileHelper *>::iterator config_file_helper_iter;
	for(config_file_helper_iter = config_file_helpers.begin(); config_file_helper_iter != config_file_helpers.end(); config_file_helper_iter++)
	{
		ConfigFileHelper *config_file_helper = (*config_file_helper_iter).second;
		delete config_file_helper;
	}
	
	SignalHandler::Fini();
	
	if(!StopSigIntThrd())
	{
		std::cerr << "WARNING! Can't stop SIGINT thread" << std::endl;
	}
	
	unisim::kernel::logger::Logger::ReleaseStaticServiceInstance();
	
	pthread_mutex_destroy(&mutex);
	
	pthread_mutex_destroy(&sig_int_thrd_create_mutex);
	pthread_mutex_destroy(&sig_int_thrd_mutex);
	
	pthread_cond_destroy(&sig_int_thrd_create_cond);
	pthread_cond_destroy(&sig_int_thrd_cond);
}

void Simulator::Version(std::ostream& os) const
{
	os << program_name << " " << version << std::endl;
	os << copyright << std::endl;
	os << "License: " << license << std::endl;
	os << "Authors: " << authors << std::endl;
}

void Simulator::Help(std::ostream& os) const
{
	os << description << std::endl << std::endl;
	os << "Usage: " << program_binary << " [<options>] [...]" << std::endl << std::endl;
	os << "Options:" << std::endl;

	std::vector<CommandLineOption>::const_iterator cmd_opt_itr;
	for(cmd_opt_itr = command_line_options.begin(); cmd_opt_itr != command_line_options.end(); cmd_opt_itr++)
	{
		os << std::endl;
		os << " --" << cmd_opt_itr->GetLongName();
		if(cmd_opt_itr->HasArgument())
		{
			os << " <" << cmd_opt_itr->GetArgumentDescription() << ">";
		}
		os << std::endl;
		os << " -" << cmd_opt_itr->GetShortName();
		if(cmd_opt_itr->HasArgument())
		{
			os << " <" << cmd_opt_itr->GetArgumentDescription() << ">";
		}
		os << std::endl;
		os << "            " << cmd_opt_itr->GetOptionDescription();
		os << std::endl;
	}
}

void Simulator::Register(Object *object)
{
	if(objects.find(object->GetName()) != objects.end())
	{
		std::cerr << "ERROR! Object \"" << object->GetName() << "\" already exists" << std::endl;
		Dump(std::cerr);
		exit(1);
	}
	
	Lock();
	objects[object->GetName()] = object;
	Unlock();
}

void Simulator::Register(VariableBase *variable)
{
	if(variables.find(variable->GetName()) != variables.end())
	{
		std::cerr << "ERROR! Variable \"" << variable->GetName() << "\" already exists" << std::endl;
		exit(1);
	}

	variables[variable->GetName()] = variable;
}

void Simulator::Initialize(VariableBase *variable)
{
	// initialize variable from command line
	std::map<std::string, std::string>::iterator set_var_iter = set_vars.find(variable->GetName());
	
	if(set_var_iter != set_vars.end())
	{
		const char *value = (*set_var_iter).second.c_str();
#ifdef DEBUG_VARIABLES
		std::cerr << variable->GetName() << " <- \"" << value << "\"" << std::endl;
#endif
		*variable = value;
		variable->SetModified(false); // cancel modification flag
		set_vars.erase(set_var_iter);
	}
}

void Simulator::Register(ServicePortBase *srv_port)
{
	if(srv_ports.find(srv_port->GetName()) != srv_ports.end())
	{
		std::cerr << "ERROR! " << (srv_port->IsExport() ? "Export" : "Import") << " \"" << srv_port->GetName() << "\" already exists" << std::endl;
		exit(1);
	}

	srv_ports[srv_port->GetName()] = srv_port;
}

void Simulator::Register(ConfigFileHelper *config_file_helper)
{
	if(config_file_helpers.find(config_file_helper->GetName()) != config_file_helpers.end())
	{
		std::cerr << "ERROR! Configuration file helper \"" << config_file_helper->GetName() << "\" already exists" << std::endl;
		exit(1);
	}

	config_file_helpers[config_file_helper->GetName()] = config_file_helper;
}

void Simulator::Unregister(Object *object)
{
	std::map<std::string, Object *>::iterator object_iter;
	object_iter = objects.find(object->GetName());
	if(object_iter != objects.end())
	{
		Lock();
		objects.erase(object_iter);
		Unlock();
	}
}

void Simulator::Unregister(VariableBase *variable)
{
	std::map<std::string, VariableBase *>::iterator variable_iter;
	variable_iter = variables.find(variable->GetName());
	if(variable_iter != variables.end()) variables.erase(variable_iter);
}

void Simulator::Unregister(ServicePortBase *srv_port)
{
	std::map<std::string, ServicePortBase*>::iterator port_iter = srv_ports.find(srv_port->GetName());
	if(port_iter != srv_ports.end()) srv_ports.erase(port_iter);
}

void Simulator::Dump(std::ostream& os)
{
	os << "OBJECTS:" << std::endl;

	std::map<std::string, Object *>::iterator object_iter;

	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		os << (*object_iter).second->GetName() << std::endl;
	}
	os << std::endl;

	os << "PARAMETERS:" << std::endl;
	std::map<std::string, VariableBase *>::iterator variable_iter;
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		os << (*variable_iter).second->GetName() << " = \"" << ((std::string) *(*variable_iter).second) << "\"" << std::endl;
	}
	os << std::endl;

	std::map<std::string, ServicePortBase *>::iterator port_iter;

	os << "IMPORTS:" << std::endl;

	for(port_iter = srv_ports.begin(); port_iter != srv_ports.end(); port_iter++)
	{
		ServicePortBase& srv_port = *port_iter->second;
		if (srv_port.IsExport()) continue;
		Object *service = srv_port.GetService();
		os << srv_port.GetName();
		if(service) os << " (to " << service->GetName() << ")";
		os << std::endl;
	}
	os << std::endl;

	std::cerr << "EXPORTS:" << std::endl;

	for(port_iter = srv_ports.begin(); port_iter != srv_ports.end(); port_iter++)
	{
		ServicePortBase& srv_port = *port_iter->second;
		if (not srv_port.IsExport()) continue;
		os << srv_port.GetName();
                os << " (from ";
		// TODO: Give client names
                // srv_port.DumpClientNames( os );
                os <<  ")" << std::endl;
	}
	os << std::endl;

	std::cerr << "CONNECTIONS:" << std::endl;
	for(port_iter = srv_ports.begin(); port_iter != srv_ports.end(); port_iter++)
	{
		port_iter->second->Dump(os);
	}
}

void Simulator::DumpVariables(std::ostream &os, VariableBase::Type filter_type) {
/*	switch(filter_type)
	{
		case VariableBase::VAR_VOID:
			os << "Variables:" << std::endl;
			break;
		case VariableBase::VAR_ARRAY:
			os << "Arrays of variables:" << std::endl;
			break;
		case VariableBase::VAR_PARAMETER:
			os << "variable::Parameters:" << std::endl;
			break;
		case VariableBase::VAR_STATISTIC:
			os << "Statistics:" << std::endl;
			break;
		case VariableBase::VAR_REGISTER:
			os << "Registers:" << std::endl;
			break;
	}*/
	
	unsigned int max_name_column_width = 64;
	unsigned int max_value_column_width = 32;
	unsigned int max_variable_name_length = 0;
	unsigned int max_variable_value_length = 0;
	
	std::map<std::string, VariableBase *>::iterator variable_iter;

	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *var = (*variable_iter).second;
		VariableBase::Type var_type = var->GetType();
		if(var->IsVisible() && (filter_type == VariableBase::VAR_VOID || var_type == filter_type))
		{
			const char *name = var->GetName();
			std::string value = (std::string) *var;
			
			unsigned int variable_name_length = strlen(name);
			unsigned int variable_value_length = value.length();
			
			if(variable_name_length > max_variable_name_length) max_variable_name_length = variable_name_length;
			if(variable_value_length > max_variable_value_length) max_variable_value_length = variable_value_length;
		}
	}
	
	if(max_variable_name_length < max_name_column_width) max_name_column_width = max_variable_name_length;
	if(max_variable_value_length < max_value_column_width) max_value_column_width = max_variable_value_length;

	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *var = (*variable_iter).second;
		VariableBase::Type var_type = var->GetType();
		if(var->IsVisible() && (filter_type == VariableBase::VAR_VOID || var_type == filter_type))
		{
			std::stringstream sstr_name;
			std::stringstream sstr_value;
			const char *name = var->GetName();
			std::string value = (std::string) *var;
//			const char *dt = var->GetDataTypeName();
			const char *desc = (*variable_iter).second->GetDescription();
			
			if(strlen(name) <= max_name_column_width)
			{
				sstr_name.width(max_name_column_width);
			}
			sstr_name.setf(std::ios::left);
			sstr_name << name;
			if(value.length() <= max_value_column_width)
			{
				sstr_value.width(max_value_column_width);
			}
			sstr_value.setf(std::ios::left);
			sstr_value << value;
			os << sstr_name.str() << " " << sstr_value.str();
			if(strlen(desc) != 0)
			{
				os << " # " << (*variable_iter).second->GetDescription();
			}
// 			if(strlen(dt) != 0)
// 			{
// 				os << dt;
// 			}
			
			os << std::endl;
		}
	}
}

void Simulator::DumpStatistics(std::ostream &os)
{
	DumpVariables(os, VariableBase::VAR_STATISTIC);
}

void Simulator::DumpParameters(std::ostream &os)
{
	DumpVariables(os, VariableBase::VAR_PARAMETER);
}

void Simulator::DumpRegisters(std::ostream &os)
{
	DumpVariables(os, VariableBase::VAR_REGISTER);
}

ConfigFileHelper *Simulator::GuessConfigFileHelper(const char *filename)
{
	std::map<std::string, ConfigFileHelper *>::iterator config_file_helper_iter;
	for(config_file_helper_iter = config_file_helpers.begin(); config_file_helper_iter != config_file_helpers.end(); config_file_helper_iter++)
	{
		ConfigFileHelper *config_file_helper = (*config_file_helper_iter).second;
		if(config_file_helper->Match(filename)) return config_file_helper;
	}
	return FindConfigFileHelper(default_config_file_format);
}

ConfigFileHelper *Simulator::FindConfigFileHelper(const std::string& config_file_format)
{
	std::map<std::string, ConfigFileHelper *>::iterator config_file_helper_it = config_file_helpers.find(config_file_format);
	
	return (config_file_helper_it != config_file_helpers.end()) ? (*config_file_helper_it).second : 0;
}

bool Simulator::LoadVariables(const char *filename, VariableBase::Type type, const std::string& config_file_format)
{
	ConfigFileHelper *config_file_helper = config_file_format.empty() ? GuessConfigFileHelper(filename) : FindConfigFileHelper(config_file_format);
	if(config_file_helper)
	{
		return config_file_helper->LoadVariables(filename, type);
	}
	
	return false;
}

bool Simulator::LoadVariables(std::istream& is, VariableBase::Type type, const std::string& config_file_format)
{
	ConfigFileHelper *config_file_helper = FindConfigFileHelper(config_file_format);
	if(config_file_helper)
	{
		return config_file_helper->LoadVariables(is, type);
	}
	
	return false;
}

bool Simulator::SaveVariables(const char *filename, VariableBase::Type type, const std::string& config_file_format)
{
	ConfigFileHelper *config_file_helper = config_file_format.empty() ? GuessConfigFileHelper(filename) : FindConfigFileHelper(config_file_format);
	if(config_file_helper)
	{
		return config_file_helper->SaveVariables(filename, type);
	}
	
	return false;
}

bool Simulator::SaveVariables(std::ostream& os, VariableBase::Type type, const std::string& config_file_format)
{
	ConfigFileHelper *config_file_helper = FindConfigFileHelper(config_file_format);
	if(config_file_helper)
	{
		return config_file_helper->SaveVariables(os, type);
	}
	
	return false;
}

Simulator::SetupStatus Simulator::Setup()
{
	if(!StartSigIntThrd())
	{
		std::cerr << "ERROR! Can't start SIGINT thread" << std::endl;
		return ST_ERROR;
	}
	
	if(sig_int_cond) return ST_OK_DONT_START;
		
	if(generate_doc)
	{
		if(generate_doc_filename.empty())
		{
			GenerateLatexDocumentation(std::cerr);
		}
		else
		{
			std::cerr << "Latex documentation generation using file \"" << generate_doc_filename << "\"" << std::endl;
			std::ofstream stream(generate_doc_filename.c_str(), std::ofstream::out);
			GenerateLatexDocumentation(stream);
		}
		return ST_OK_DONT_START;
	}
	
	if(sig_int_cond) return ST_OK_DONT_START;
	
	if(enable_version)
	{
		Version(std::cerr);
		return ST_OK_DONT_START;
	}
	
	if(sig_int_cond) return ST_OK_DONT_START;
	
	if(enable_help)
	{
		Help(std::cerr);
		return ST_OK_DONT_START;
	}
	
	if(sig_int_cond) return ST_OK_DONT_START;

	if(list_parms)
	{
		std::cerr << "Listing parameters..." << std::endl;
		DumpVariables(std::cerr, unisim::kernel::VariableBase::VAR_PARAMETER);
		std::cerr << "Aborting simulation" << std::endl;
		return ST_OK_DONT_START;
	}

	if(sig_int_cond) return ST_OK_DONT_START;
	
	for(std::vector<std::string>::const_iterator get_config_filename_it = get_config_filenames.begin(); get_config_filename_it != get_config_filenames.end(); ++get_config_filename_it)
	{
		const std::string& get_config_filename = *get_config_filename_it;
		if(SaveVariables(get_config_filename.c_str(), VariableBase::VAR_PARAMETER))
		{
			std::cerr << "variable::Parameters saved on file \"" << get_config_filename << "\"" << std::endl;
		}
		else
		{
			std::cerr << "WARNING! Saving parameters set to file \"" << get_config_filename << "\" failed" << std::endl;
		}
	}
	
	if(sig_int_cond) return ST_OK_DONT_START;
	
	if(!get_config_filenames.empty())
	{
		std::cerr << "Aborting simulation" << std::endl;
		return ST_OK_DONT_START;
	}

	if(sig_int_cond) return ST_OK_DONT_START;
	
	std::map<std::string, ServicePortBase *>::iterator port_iter;
	if(enable_warning)
	{
		for(port_iter = srv_ports.begin(); port_iter != srv_ports.end(); port_iter++)
		{
			ServicePortBase& srv_export = *port_iter->second;
			if (srv_export.IsExport() and not srv_export.IsConnected())
			{
				std::cerr << "WARNING! " << srv_export.GetName() << " is unused" << std::endl;
			}
		}
	}

	if(sig_int_cond) return ST_OK_DONT_START;
	
	SetupStatus status = ST_OK_TO_START;
	
	// Call all objects "BeginSetup()"
	std::map<std::string, Object *>::iterator object_iter;
	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		Object *object = (*object_iter).second;
#ifdef DEBUG_KERNEL
		std::cerr << "Simulator:" << object->GetName() << "::BeginSetup()" << std::endl;
#endif
		if(!object->BeginSetup())
		{
			std::cerr << "Simulator: " << object->GetName() << " beginning of setup failed" << std::endl;
			status = ST_ERROR;
			break;
		}
		
		if(sig_int_cond) break;
	}

	// Call all services "DoServiceSetup()"
	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		Object& object = *object_iter->second;
		object.DoServiceSetup();
        }
	
	if(sig_int_cond)
	{
		switch(status)
		{
			case ST_OK_TO_START  : 
			case ST_OK_DONT_START:
			case ST_WARNING      : return ST_OK_DONT_START; 
			case ST_ERROR        : return ST_ERROR;
		}
	}
	
	if(status != ST_ERROR)
	{
		// Call all objects "EndSetup()"
		for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
		{
			Object *object = (*object_iter).second;
#ifdef DEBUG_KERNEL
			std::cerr << "Simulator:" << object->GetName() << "::EndSetup()" << std::endl;
#endif
			if(!object->EndSetup())
			{
				std::cerr << "Simulator: " << object->GetName() << " end of setup failed" << std::endl;
				status = ST_ERROR;
				break;
			}
			if(sig_int_cond) break;
		}
	}

	if(enable_warning)
	{
		// display a warning if some variable values are unused
		std::map<std::string, std::string>::iterator set_var_iter;
		
		for(set_var_iter = set_vars.begin(); set_var_iter != set_vars.end(); set_var_iter++)
		{
			std::cerr << "WARNING! value \"" << (*set_var_iter).second << "\" for variable \"" << (*set_var_iter).first << "\" is unused." << std::endl;
		}
	}

	if(sig_int_cond)
	{
		switch(status)
		{
			case ST_OK_TO_START  : 
			case ST_OK_DONT_START:
			case ST_WARNING      : return ST_OK_DONT_START; 
			case ST_ERROR        : return ST_ERROR;
		}
	}
	
	return status;
}

void Simulator::Stop(Object *object, int exit_status, bool asynchronous)
{
	std::cerr << "WARNING! Stop is not cleanly implemented" << std::endl;
	Kill();
	exit(exit_status);
}

const VariableBase *Simulator::FindVariable(const char *name, VariableBase::Type type) const
{
	std::map<std::string, VariableBase *>::const_iterator variable_iter;
	
	variable_iter = variables.find(name);
	
	if(variable_iter != variables.end() && (type == VariableBase::VAR_VOID || (*variable_iter).second->GetType() == type)) return (*variable_iter).second;
	
	return void_variable;
}

VariableBase *Simulator::FindVariable(const char *name, VariableBase::Type type)
{
	std::map<std::string, VariableBase *>::iterator variable_iter;
	
	variable_iter = variables.find(name);
	
	if(variable_iter != variables.end() && (type == VariableBase::VAR_VOID || (*variable_iter).second->GetType() == type)) return (*variable_iter).second;
	
	return void_variable;
}

const VariableBase *Simulator::FindArray(const char *name) const
{
	return FindVariable(name, VariableBase::VAR_ARRAY);
}

VariableBase *Simulator::FindArray(const char *name)
{
	return FindVariable(name, VariableBase::VAR_ARRAY);
}

const VariableBase *Simulator::FindParameter(const char *name) const
{
	return FindVariable(name, VariableBase::VAR_PARAMETER);
}

VariableBase *Simulator::FindParameter(const char *name)
{
	return FindVariable(name, VariableBase::VAR_PARAMETER);
}

const VariableBase *Simulator::FindRegister(const char *name) const
{
	return FindVariable(name, VariableBase::VAR_REGISTER);
}

VariableBase *Simulator::FindRegister(const char *name)
{
	return FindVariable(name, VariableBase::VAR_REGISTER);
}

const VariableBase *Simulator::FindStatistic(const char *name) const
{
	return FindVariable(name, VariableBase::VAR_STATISTIC);
}

VariableBase *Simulator::FindStatistic(const char *name)
{
	return FindVariable(name, VariableBase::VAR_STATISTIC);
}

void Simulator::GetVariables(std::list<VariableBase *>& lst, VariableBase::Type type)
{
	std::map<std::string, VariableBase *>::iterator variable_iter;

	lst.clear();
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		if((*variable_iter).second->IsVisible() && (type == VariableBase::VAR_VOID || (*variable_iter).second->GetType() == type))
		{
			lst.push_back((*variable_iter).second);
		}
	}
}

void Simulator::GetRootVariables(std::list<VariableBase *>& lst, VariableBase::Type type)
{
	std::map<std::string, VariableBase *>::iterator variable_iter;

	lst.clear();
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *var = (*variable_iter).second;
		if(!var->GetOwner() && var->IsVisible() && (type == VariableBase::VAR_VOID || var->GetType() == type))
		{
			lst.push_back((*variable_iter).second);
		}
	}
}

void Simulator::GetArrays(std::list<VariableBase *>& lst)
{
	GetVariables(lst, VariableBase::VAR_ARRAY);
}

void Simulator::GetParameters(std::list<VariableBase *>& lst)
{
	GetVariables(lst, VariableBase::VAR_PARAMETER);
}

void Simulator::GetRegisters(std::list<VariableBase *>& lst)
{
	GetVariables(lst, VariableBase::VAR_REGISTER);
}

void Simulator::GetSignals(std::list<VariableBase *>& lst)
{
	GetVariables(lst, VariableBase::VAR_SIGNAL);
}

void Simulator::GetStatistics(std::list<VariableBase *>& lst)
{
	GetVariables(lst, VariableBase::VAR_STATISTIC);
}

void Simulator::GetObjects(std::list<Object *>& lst) const
{
	std::map<std::string, Object *>::const_iterator object_iter;

	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		if((*object_iter).second)
		{
			lst.push_back((*object_iter).second);
		}
	}
}

void Simulator::GetRootObjects(std::list<Object *>& lst) const
{
	std::map<std::string, Object *>::const_iterator object_iter;

	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		if((*object_iter).second)
		{
			if(!(*object_iter).second->GetParent())
			{
				// std::cerr << "root: " << (*object_iter).second->GetName() << std::endl;
				lst.push_back((*object_iter).second);
			}
		}
	}
}

Object *Simulator::FindObject(const char *name) const
{
	std::map<std::string, Object *>::const_iterator object_iter = objects.find(name);
	return (object_iter != objects.end()) ? (*object_iter).second : 0;
}

#if defined(__APPLE_CC__) || defined(linux) || defined(__linux) || defined(__linux__)
void FindMyself()
{
	// stupid method to find the path to the executable/library using the dladdr
	//   function under apple and linux
}
#endif

bool Simulator::GetExecutablePath(const char *argv0, std::string& out_executable_path) const
{
#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__APPLE_CC__)
	Dl_info info;
	if ( dladdr((void *)unisim::kernel::FindMyself, &info) != 0 )
	{
//		char bin_path_buf[PATH_MAX + 1];
		char bin_path_buf[FILENAME_MAX + 1];
		char *bin_path_pointer = realpath(info.dli_fname, bin_path_buf);
		if(bin_path_pointer == bin_path_buf)
		{
			out_executable_path = std::string(bin_path_buf);
			return true;
		}
	}
#elif defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	char bin_path_buf[PATH_MAX + 1];
	DWORD bin_path_length;
	bin_path_length = GetModuleFileName(NULL, bin_path_buf, sizeof(bin_path_buf));
	if(bin_path_length > 0)
	{
		bin_path_buf[bin_path_length] = 0;
		out_executable_path = std::string(bin_path_buf);
		return true;
	}
#endif
	if(!argv0) return false;
	
	char *path_buf = getenv("PATH");
	if(path_buf)
	{
		// environment variable PATH is set
		std::string path(path_buf);
		
		size_t pos = 0;
		size_t next_pos = 0;
		do
		{
			next_pos = path.find(':', pos);
			if(next_pos != std::string::npos)
			{
				if(pos != next_pos)
				{
					std::string dir(path.substr(pos, next_pos - pos));
					std::string filename(dir + "/" + argv0);
					if(access(filename.c_str(), X_OK) == 0)
					{
						out_executable_path = filename;
						return true;
					}
				}
				pos = next_pos + 1;
			}
		} while(next_pos != std::string::npos);
		
//		char cwd_path_buf[PATH_MAX];
		char cwd_path_buf[FILENAME_MAX];
		if(getcwd(cwd_path_buf, sizeof(cwd_path_buf)))
		{
			out_executable_path = std::string(cwd_path_buf) + "/" + argv0;
			return true;
		}
	}
	if(access(argv0, X_OK) == 0)
	{
		out_executable_path = std::string(argv0);
		return true;
	}
	return false;
}

bool Simulator::GetBinPath(const char *argv0, std::string& out_bin_dir, std::string& out_bin_program) const
{
	std::string executable_path;
	
	if(!GetExecutablePath(argv0, executable_path)) return false;
	//std::cerr << "executable_path=\"" << executable_path << "\"" << std::endl;
	// compute bin dirname
	const char *start = executable_path.c_str();
	const char *end = start + executable_path.length() - 1;
	while(end != (start - 1) && 
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	      (*end != '\\') &&
#endif
	      (*end != '/'))
	{
		end--;
	}
	
	if(end != (start - 1))
	{
		out_bin_dir.clear();
		const char *p = start;
		while(p != end)
		{
			out_bin_dir += *p;
			p++;
		}
		
		out_bin_program = end + 1;
		return true;
	}
	return false;
}

//#define DEBUG_SEARCH_SHARED_DATA_FILE

bool Simulator::GetSharePath(const std::string& bin_dir, std::string& out_share_dir) const
{
	return ResolvePath(bin_dir, std::string(BIN_TO_SHARED_DATA_PATH), out_share_dir);
}

const std::string& Simulator::GetSharedDataDirectory() const
{
	return shared_data_dir;
}

std::string Simulator::SearchSharedDataFile(const char *filename) const
{
	std::string s(filename);
	if(!s.empty())
	{
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
		std::cerr << "SearchSharedDataFile: Trying \"" << s << "\"";
#endif
		if(access(s.c_str(), F_OK) == 0)
		{
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
			std::cerr << "...found" << std::endl;
#endif
			return s;
		}
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
		std::cerr << "...not found" << std::endl;
#endif

		std::stringstream sstr;
		sstr << shared_data_dir << "/" << filename;
		s = sstr.str();
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
		std::cerr << "SearchSharedDataFile: Trying \"" << s << "\"";
#endif
		if(access(s.c_str(), F_OK) == 0)
		{
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
			std::cerr << "...found" << std::endl;
#endif
			return s;
		}
		
#ifdef DEBUG_SEARCH_SHARED_DATA_FILE
		std::cerr << "...not found" << std::endl;
#endif
	}
	return std::string(filename);
}

std::vector<std::string> const&
Simulator::GetCmdArgs() const
{
	return cmd_args;
}

template <typename T>
T Simulator::GetVariable(const char *variable_name, const T *t) const
{
	return (T) *FindVariable(variable_name);
}

template bool Simulator::GetVariable(const char *, const bool *) const;
template signed char Simulator::GetVariable(const char *, const signed char *) const;
template short Simulator::GetVariable(const char *, const short *) const;
template int Simulator::GetVariable(const char *, const int *) const;
template long Simulator::GetVariable(const char *, const long *) const;
template long long Simulator::GetVariable(const char *, const long long *) const;
template unsigned char Simulator::GetVariable(const char *, const unsigned char *) const;
template unsigned short Simulator::GetVariable(const char *, const unsigned short *) const;
template unsigned int Simulator::GetVariable(const char *, const unsigned int *) const;
template unsigned long Simulator::GetVariable(const char *, const unsigned long *) const;
template float Simulator::GetVariable(const char *, const float *) const;
template double Simulator::GetVariable(const char *, const double *) const;
template std::string Simulator::GetVariable(const char *, const std::string *) const;

void Simulator::SetVariable(const char *variable_name, const char *variable_value)
{
	VariableBase *variable = FindVariable(variable_name);
	if(variable == void_variable)
	{
		std::map<std::string, std::string>::iterator set_vars_it = set_vars.find(std::string(variable_name));
		
		if(set_vars_it != set_vars.end())
		{
			set_vars.erase(set_vars_it);
		}
		set_vars.insert(std::pair<std::string, std::string>(std::string(variable_name), std::string(variable_value)));
	}
	else
	{
		*variable = variable_value;
	}
}

void Simulator::SetVariable(const char *variable_name, bool variable_value)
{
	SetVariable(variable_name, variable_value ? "true" : "false");
}

void Simulator::SetVariable(const char *variable_name, char variable_value)
{
	SetVariable(variable_name, (long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, unsigned char variable_value)
{
	SetVariable(variable_name, (unsigned long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, short variable_value)
{
	SetVariable(variable_name, (long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, unsigned short variable_value)
{
	SetVariable(variable_name, (unsigned long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, int variable_value)
{
	SetVariable(variable_name, (long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, unsigned int variable_value)
{
	SetVariable(variable_name, (unsigned long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, long variable_value)
{
	SetVariable(variable_name, (long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, unsigned long variable_value)
{
	SetVariable(variable_name, (unsigned long long) variable_value);
}

void Simulator::SetVariable(const char *variable_name, unsigned long long variable_value)
{
	std::stringstream sstr;
	sstr << variable_value;
	SetVariable(variable_name, sstr.str().c_str());
}

void Simulator::SetVariable(const char *variable_name, long long variable_value)
{
	std::stringstream sstr;
	sstr << variable_value;
	SetVariable(variable_name, sstr.str().c_str());
}

void Simulator::SetVariable(const char *variable_name, float variable_value)
{
	SetVariable(variable_name, double(variable_value));
}

void Simulator::SetVariable(const char *variable_name, double variable_value)
{
	std::stringstream sstr;
	sstr << variable_value;
	SetVariable(variable_name, sstr.str().c_str());
}

void Simulator::GenerateLatexDocumentation(std::ostream& os) const
{
	std::map<std::string, Object *>::const_iterator object_iter;
	
	os << "This documentation has been automatically generated from the simulator \\texttt{" << string_to_latex(program_name.c_str()) << "} version " << string_to_latex(version.c_str()) << " on " << string_to_latex(__DATE__) << "." << std::endl;

	os << "\\subsection{Introduction}" << std::endl;
	os << string_to_latex(description.c_str()) << ".\\\\" << std::endl;
	os << "Section \\ref{" << program_name << "_licensing} gives licensing informations about the simulator." << std::endl;
	os << "Section \\ref{" << program_name << "_simulated_configuration} shows the set of modules and services that compose the simulator." << std::endl;
	os << "Section \\ref{" << program_name << "_using} shows how to invoke the simulator at the command line prompt." << std::endl;
	os << "Section \\ref{" << program_name << "_configuration} gives the simulator parameters." << std::endl;
	os << "Section \\ref{" << program_name << "_statistics} gives the simulator statistic counters." << std::endl;
	os << "Section \\ref{" << program_name << "_formulas} gives the simulator statistic formulas." << std::endl;

	os << "\\subsection{Licensing}" << std::endl;
	os << "\\label{" << program_name << "_licensing}" << std::endl;
	os << string_to_latex(program_name.c_str()) << " " << string_to_latex(version.c_str()) << "\\\\" << std::endl;
	os << string_to_latex(copyright.c_str()) << "\\\\" << std::endl;
	os << "License: " << string_to_latex(license.c_str()) << "\\\\" << std::endl;
	os << "Authors: " << string_to_latex(authors.c_str()) << "\\\\" << std::endl;
	
	os << "\\subsection{Simulated configuration}" << std::endl;
	os << "\\label{" << program_name << "_simulated_configuration}" << std::endl;
	
	if(!schematic.empty())
	{
		os << "\\begin{figure}[!ht]" << std::endl;
		os << "\t\\begin{center}" << std::endl;
		os << "\t\t\\includegraphics[width=\\textwidth]{" << schematic << "}" << std::endl;
		os << "\t\\end{center}" << std::endl;
		os << "\t\\caption{" << program_name << " simulator schematic.}" << std::endl;
		os << "\\end{figure}" << std::endl;
	}
	
	os << "\\noindent The " << string_to_latex(program_name.c_str()) << " simulator is composed of the following modules and services:" << std::endl;
	os << "\\begin{itemize}\\addtolength{\\itemsep}{-0.40\\baselineskip}" << std::endl;
	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		const char *obj_description = (*object_iter).second->GetDescription();
		os << "\\item \\textbf{" << string_to_latex((*object_iter).second->GetName()) << "}";
		if(*obj_description != 0) // not empty description
		{
			os << ": " << string_to_latex(obj_description);
		}
		os << std::endl;
	}
	os << "\\end{itemize}" << std::endl;

	os << "\\subsection{Using the " << string_to_latex(program_name.c_str()) << " simulator}" << std::endl;
	os << "\\label{" << program_name << "_using}" << std::endl;
	os << "The " << string_to_latex(program_name.c_str()) << " simulator has the following command line options:\\\\" << std::endl;
	os << "~\\\\" << std::endl;
	os << "\\noindent Usage: \\texttt{" << program_binary << " [<options>] [...]}" << std::endl << std::endl;
	os << "\\noindent Options:" << std::endl;
	os << "\\begin{itemize}" << std::endl;

	std::vector<CommandLineOption>::const_iterator cmd_opt_itr;
	for(cmd_opt_itr = command_line_options.begin(); cmd_opt_itr != command_line_options.end(); cmd_opt_itr++)
	{
		os << "\\item \\texttt{";
		os << "--" << string_to_latex(cmd_opt_itr->GetLongName());
		if(cmd_opt_itr->HasArgument())
		{
			os << " $<$" << string_to_latex(cmd_opt_itr->GetArgumentDescription()) << "$>$";
		}
		os << " or -" << cmd_opt_itr->GetShortName();
		if(cmd_opt_itr->HasArgument())
		{
			os << " $<$" << string_to_latex(cmd_opt_itr->GetArgumentDescription()) << "$>$";
		}
		os << "}: " << string_to_latex(cmd_opt_itr->GetOptionDescription());
		os << "" << std::endl;
	}
	os << "\\end{itemize}" << std::endl;

	
	// 	std::stringstream sstr_version;
// 	Version(sstr_version);
// 	os << "\\subsection{Version}" << std::endl;
// 	os << string_to_latex(sstr_version.str().c_str()) << std::endl;
// 	
// 	std::stringstream sstr_help;
// 	Help(sstr_help);
// 	os << "\\subsection{Usage}" << std::endl;
// 	os << string_to_latex(sstr_help.str().c_str(), 80, "texttt") << std::endl;

	std::map<std::string, VariableBase *>::const_iterator variable_iter;
	bool header_printed = false;
	
	//----------------------- Configuration -----------------------
	os << "\\subsection{Configuration}" << std::endl;
	os << "\\label{" << program_name << "_configuration}" << std::endl;
	os << "Simulator configuration (see below) can be modified using command line Options \\texttt{--set $<$param=value$>$} or \\texttt{--config $<$config file$>$}.\\\\" << std::endl;
	os << "~\\\\" << std::endl;
	
	os << "\\tablehead{\\hline}" << std::endl;
	os << "\\tabletail{\\hline}" << std::endl;
	os << "\\begin{supertabular}{|p{7.5cm}|p{7.5cm}|}" << std::endl;
	//os << "\\hline" << std::endl;

	header_printed = false;
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *variable = (*variable_iter).second;
		if((variable->GetType() == VariableBase::VAR_PARAMETER) && !variable->GetOwner() && variable->IsVisible())
		{
			if(!header_printed)
			{
				os << "\\multicolumn{2}{|l|}{\\textbf{\\Large Global}}\\\\" << std::endl;
				os << "\\hline" << std::endl;
				header_printed = true;
			}
			variable->GenerateLatexDocumentation(os);
		}
	}

	if(header_printed) os << "\\hline" << std::endl;

	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		(*object_iter).second->GenerateLatexDocumentation(os, VariableBase::VAR_PARAMETER);
	}

	//os << "\\hline" << std::endl;
	os << "\\end{supertabular}" << std::endl;

	//----------------------- Statistics -----------------------
	os << "\\subsection{Statistics}" << std::endl;
	os << "\\label{" << program_name << "_statistics}" << std::endl;
	os << "Simulation statistic counters are listed below:\\\\" << std::endl;
	os << "~\\\\" << std::endl;
	os << "\\tablehead{\\hline}" << std::endl;
	os << "\\tabletail{\\hline}" << std::endl;
	os << "\\begin{supertabular}{|p{7.5cm}|p{7.5cm}|}" << std::endl;
	//os << "\\hline" << std::endl;

	header_printed = false;
	// Global statistics
	
	for(variable_iter = variables.begin(); variable_iter != variables.end(); variable_iter++)
	{
		VariableBase *variable = (*variable_iter).second;
		if((variable->GetType() == VariableBase::VAR_STATISTIC) && !variable->GetOwner() && variable->IsVisible())
		{
			if(!header_printed)
			{
				os << "\\multicolumn{2}{|l|}{\\textbf{\\Large Global}}\\\\" << std::endl;
				os << "\\hline" << std::endl;
				header_printed = true;
			}
			variable->GenerateLatexDocumentation(os);
		}
	}

	if(header_printed) os << "\\hline" << std::endl;

	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		(*object_iter).second->GenerateLatexDocumentation(os, VariableBase::VAR_STATISTIC);
	}

	//os << "\\hline" << std::endl;
	os << "\\end{supertabular}" << std::endl;
}

bool Simulator::IsWarningEnabled() const
{
	return enable_warning;
}

void Simulator::SigInt()
{
}

void Simulator::Kill()
{
	std::map<std::string, Object *>::iterator object_iter;
	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		Object *object = (*object_iter).second;
		object->Kill();
	}
}

void Simulator::SigIntThrd()
{
	pthread_mutex_lock(&sig_int_thrd_mutex);
	
	do
	{
#ifdef DEBUG_KERNEL
		std::cerr << "Thread that handle SIGINT sleeping" << std::endl;
#endif
		
		do
		{
			pthread_cond_wait(&sig_int_thrd_cond, &sig_int_thrd_mutex);
		}
		while(!sig_int_cond);
		
		sig_int_cond = false;
#ifdef DEBUG_KERNEL
		std::cerr << "Thread that handle SIGINT waking up" << std::endl;
#endif
		
		if(!stop_sig_int_thrd)
		{
			BroadcastSigInt();
		}
	}
	while(!stop_sig_int_thrd);
	
	pthread_mutex_unlock(&sig_int_thrd_mutex);
}

void *Simulator::SigIntThrdEntryPoint(void *_self)
{
	Simulator *self = static_cast<Simulator *>(_self);
	pthread_mutex_lock(&self->sig_int_thrd_create_mutex);
	self->sig_int_thrd_alive = true;
	pthread_cond_signal(&self->sig_int_thrd_create_cond);
	pthread_mutex_unlock(&self->sig_int_thrd_create_mutex);
	
	self->SigIntThrd();
	
	return 0;
}

bool Simulator::StartSigIntThrd()
{
	bool status = true;
	
	if(sig_int_thrd_alive)
	{
		std::cerr << "WARNING! thread that handle SIGINT has already started" << std::endl;
		status = false;
	}
	else
	{
		pthread_attr_t sig_int_thrd_attr;
		pthread_attr_init(&sig_int_thrd_attr);
		
		pthread_mutex_lock(&sig_int_thrd_create_mutex);

		sig_int_thrd_alive = false;

		// Create a thread that handle SIGINT

#ifdef DEBUG_KERNEL
		std::cerr << "Creating thread that handle SIGINT" << std::endl;
#endif
		
		if(pthread_create(&sig_int_thrd, &sig_int_thrd_attr, &Simulator::SigIntThrdEntryPoint, this) == 0)
		{
			// wait for creation of thread that handle SIGINT
			do
			{
				pthread_cond_wait(&sig_int_thrd_create_cond, &sig_int_thrd_create_mutex);
			}
			while(!sig_int_thrd_alive);
			
#ifdef DEBUG_KERNEL
			std::cerr << "Thread that handle SIGINT has started" << std::endl;
#endif
		}
		else
		{
			// can't create thread that handle SIGINT
#ifdef DEBUG_KERNEL
			std::cerr << "ERROR! Can't create thread that handle SIGINT" << std::endl;
#endif
			status = false;
		}
		
		pthread_mutex_unlock(&sig_int_thrd_create_mutex);

		pthread_attr_destroy(&sig_int_thrd_attr);
	}
	
	return status;
}

bool Simulator::StopSigIntThrd()
{
	bool status = true;
	
	if(sig_int_thrd_alive)
	{
		stop_sig_int_thrd = true;
		
#ifdef DEBUG_KERNEL
		std::cerr << "joining thread that handle SIGINT" << std::endl;
#endif

		MTSigInt();
		
		if(pthread_join(sig_int_thrd, NULL) == 0)
		{
			// thread has gracefully exited
#ifdef DEBUG_KERNEL
			std::cerr << "thread that handle SIGINT has gracefully exited" << std::endl;
#endif
			sig_int_thrd_alive = false;
		}
		else
		{
			// can't join communication thread
#ifdef DEBUG_KERNEL
			std::cerr << "ERROR! can't join thread that handle SIGINT" << std::endl;
#endif
			status = false;
		}
	}
	
	return status;
}

void Simulator::MTSigInt()
{
	if(sig_int_thrd_alive)
	{
		pthread_mutex_lock(&sig_int_thrd_mutex);
		sig_int_cond = true;
		pthread_cond_signal(&sig_int_thrd_cond);
		pthread_mutex_unlock(&sig_int_thrd_mutex);
	}
	else
	{
		sig_int_cond = true;
	}
}

void Simulator::BroadcastSigInt()
{
	this->SigInt();
	Lock();
	std::map<std::string, Object *>::iterator object_iter;
	for(object_iter = objects.begin(); object_iter != objects.end(); object_iter++)
	{
		Object *object = (*object_iter).second;
		object->SigInt();
	}
	Unlock();
}

void Simulator::Lock()
{
	pthread_mutex_lock(&mutex);
}

void Simulator::Unlock()
{
	pthread_mutex_unlock(&mutex);
}

} // end of namespace kernel
} // end of namespace unisim
