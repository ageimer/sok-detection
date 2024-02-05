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
 * Authors: Gilles Mouchard (gilles.mouchar@cea.fr)
 *          Yves Lhuillier (yves.lhuillier@cea.fr)
 */

#ifndef __UNISIM_KERNEL_SERVICE_SERVICE_HH__
#define __UNISIM_KERNEL_SERVICE_SERVICE_HH__

#include <unisim/util/inlining/inlining.hh>
#include <unisim/util/nat_sort/nat_sort.hh>
#include <iostream>
#include <string>
#include <list>
#include <map>
#include <set>
#include <vector>
#include <stdint.h>
#include <pthread.h>

#ifdef DEBUG_MEMORY_ALLOCATION
void *operator new(std::size_t size);
void *operator new[](std::size_t size);
void operator delete(void *p, std::size_t size);
void operator delete[](void *p, std::size_t size);
#endif

namespace unisim {
namespace kernel {

namespace variable
{
template <class TYPE> class Parameter;
template <class TYPE> class ParameterArray;
}

class Object;
class VariableBase;
class Simulator;
template <class SERVICE_IF> class Client;
template <class SERVICE_IF> class Service;
class ServicePortBase;
template <class SERVICE_IF> class ServiceImport;
template <class SERVICE_IF> class ServiceExport;
class ServiceAgent;
class ServiceBase;
class SignalHandler;
class ConfigFileHelper;

std::string string_to_latex(const char *s, unsigned int cut = 0, const char *style = 0);

// Service import/export connection operators
template <class SERVICE_IF>
ServiceExport<SERVICE_IF>& operator >> (ServiceImport<SERVICE_IF>& lhs, ServiceExport<SERVICE_IF>& rhs);

template <class SERVICE_IF>
ServiceImport<SERVICE_IF>& operator >> (ServiceImport<SERVICE_IF>& lhs, ServiceImport<SERVICE_IF>& rhs);

template <class SERVICE_IF>
ServiceExport<SERVICE_IF>& operator >> (ServiceExport<SERVICE_IF>& lhs, ServiceExport<SERVICE_IF>& rhs);

// template <class SERVICE_IF>
// ServiceImport<SERVICE_IF>& operator << (ServiceExport<SERVICE_IF>& lhs, ServiceImport<SERVICE_IF>& rhs);

// template <class SERVICE_IF>
// ServiceImport<SERVICE_IF>& operator << (ServiceImport<SERVICE_IF>& lhs, ServiceImport<SERVICE_IF>& rhs);

// template <class SERVICE_IF>
// ServiceExport<SERVICE_IF>& operator << (ServiceExport<SERVICE_IF>& lhs, ServiceExport<SERVICE_IF>& rhs);

//=============================================================================
//=                          VariableBaseListener                             =
//=============================================================================

class VariableBaseListener
{
public:
	virtual void VariableBaseNotify(const VariableBase *var) = 0;
	virtual ~VariableBaseListener() {};
};

//=============================================================================
//=                             VariableBase                                  =
//=============================================================================

class VariableBase
{
public:
	typedef enum { VAR_VOID, VAR_ARRAY, VAR_PARAMETER, VAR_STATISTIC, VAR_REGISTER, VAR_SIGNAL } Type;
	typedef enum { FMT_DEFAULT, FMT_HEX, FMT_DEC } Format;
	typedef enum { DT_USER, DT_BOOL, DT_SCHAR, DT_SHORT, DT_INT, DT_LONG, DT_LONG_LONG, DT_UCHAR, DT_USHORT, DT_UINT, DT_ULONG, DT_ULONG_LONG, DT_FLOAT, DT_DOUBLE, DT_STRING } DataType;

	VariableBase();
	VariableBase(const char *name, Object *owner, Type type, const char *description = 0);
	VariableBase(const char *name, VariableBase *container, Type type, const char *description = 0);
	virtual ~VariableBase();
	
	void Initialize();
	Object *GetOwner() const;
	VariableBase *GetContainer() const;
	static VariableBase &GetVoidVariable();
	const char *GetName() const;
	const char *GetVarName() const;
	const char *GetDescription() const;
	Type GetType() const;
	const char *GetTypeName() const;
	Format GetFormat() const;
	virtual const char *GetDataTypeName() const;
	virtual DataType GetDataType() const;
	bool HasEnumeratedValues() const;
	bool HasEnumeratedValue(const char *value) const;
	void GetEnumeratedValues(std::vector<std::string> &values) const;
	bool AddEnumeratedValue(const char *value);
	bool RemoveEnumeratedValue(const char *value);
	void SetDescription(const char *description);
	void SetFormat(Format fmt);
	bool IsVoid() const;

	virtual operator bool () const;
	operator signed char () const;
	operator short () const;
	operator int () const;
	operator long () const;
	virtual operator long long () const;
	operator unsigned char () const;
	operator unsigned short () const;
	operator unsigned int () const;
	operator unsigned long () const;
	virtual operator unsigned long long () const;
	operator float () const;
	virtual operator double () const;
	virtual operator std::string () const;
	virtual VariableBase& operator = (bool value);
	VariableBase& operator = (char value);
	VariableBase& operator = (short value);
	VariableBase& operator = (int value);
	VariableBase& operator = (long value);
	virtual VariableBase& operator = (long long value);
	VariableBase& operator = (unsigned char value);
	VariableBase& operator = (unsigned short value);
	VariableBase& operator = (unsigned int value);
	VariableBase& operator = (unsigned long value);
	virtual VariableBase& operator = (unsigned long long value);
	VariableBase& operator = (float value);
	virtual VariableBase& operator = (double value);
	virtual VariableBase& operator = (const char * value);

	virtual VariableBase& operator [] (unsigned int index);
	virtual const VariableBase& operator [] (unsigned int index) const;
	virtual unsigned int GetLength() const;
	virtual unsigned int GetBitSize() const;
	
	virtual VariableBase& operator = (const VariableBase& variable);
	virtual std::string GetSymbolicValue() const;
	void GenerateLatexDocumentation(std::ostream& os) const;
	
	bool IsMutable() const;
	bool IsVisible() const;
	bool IsSerializable() const;
	bool IsModified() const;
	virtual void SetMutable(bool is_mutable);
	virtual void SetVisible(bool is_visible);
	virtual void SetSerializable(bool is_serializable);
	virtual void SetModified(bool is_modified);

	void AddListener(VariableBaseListener *listener);
	void RemoveListener(VariableBaseListener *listener);
	void NotifyListeners();

private:
	std::string name;
	std::string var_name;
	Object *owner;
	VariableBase *container;
	std::string description;
	std::vector<std::string> enumerated_values;
	Type type;
	Format fmt;
	bool is_mutable;
	bool is_visible;
	bool is_serializable;
	bool is_modified;
	std::set<VariableBaseListener*> listener_set;
};

//=============================================================================
//=                           ConfigFileHelper                                =
//=============================================================================

class ConfigFileHelper
{
public:
	virtual ~ConfigFileHelper();
	virtual const char *GetName() const = 0;
	virtual bool SaveVariables(const char *filename, VariableBase::Type type = VariableBase::VAR_VOID) = 0;
	virtual bool SaveVariables(std::ostream& os, VariableBase::Type type = VariableBase::VAR_VOID) = 0;
	virtual bool LoadVariables(const char *filename, VariableBase::Type type = VariableBase::VAR_VOID) = 0;
	virtual bool LoadVariables(std::istream& is, VariableBase::Type type = VariableBase::VAR_VOID) = 0;
	virtual bool Match(const char *filename) const;
protected:
	static bool MatchFilenameByExtension(const char *filename, const char *extension);
};

//=============================================================================
//=                                 Simulator                                 =
//=============================================================================

class Simulator
{
public:
	typedef enum
	{
		ST_OK_TO_START = 0,
		ST_OK_DONT_START,
		ST_WARNING,
		ST_ERROR
	} SetupStatus;
	
	static inline Simulator *Instance() { return simulator; }
	
	Simulator(int argc, char **argv,
			void (*LoadBuiltInConfig)(Simulator *simulator) = 0);
	virtual ~Simulator();
	virtual SetupStatus Setup();
	virtual void Stop(Object *object, int exit_status, bool asynchronous = false);

	const VariableBase *FindVariable(const char *name, VariableBase::Type type = VariableBase::VAR_VOID) const;
	VariableBase *FindVariable(const char *name, VariableBase::Type type = VariableBase::VAR_VOID);
	const VariableBase *FindArray(const char *name) const;
	VariableBase *FindArray(const char *name);
	const VariableBase *FindParameter(const char *name) const;
	VariableBase *FindParameter(const char *name);
	const VariableBase *FindRegister(const char *name) const;
	VariableBase *FindRegister(const char *name);
	const VariableBase *FindStatistic(const char *name) const;
	VariableBase *FindStatistic(const char *name);
	Object *FindObject(const char *name) const;

	void GetVariables(std::list<VariableBase *>& lst, VariableBase::Type type = VariableBase::VAR_VOID);
	void GetRootVariables(std::list<VariableBase *>& lst, VariableBase::Type type = VariableBase::VAR_VOID);
	void GetArrays(std::list<VariableBase *>& lst);
	void GetParameters(std::list<VariableBase *>& lst);
	void GetRegisters(std::list<VariableBase *>& lst);
	void GetSignals(std::list<VariableBase *>& lst);
	void GetStatistics(std::list<VariableBase *>& lst);

	void Dump(std::ostream& os);
	void DumpVariables(std::ostream& os, VariableBase::Type filter_type = VariableBase::VAR_VOID);
	void DumpStatistics(std::ostream& os);
	void DumpParameters(std::ostream& os);
	void DumpRegisters(std::ostream& os);

	bool GetExecutablePath(const char *argv0, std::string& out_execute_path) const;
	bool GetBinPath(const char *argv0, std::string& out_bin_dir, std::string& out_bin_program) const;
	bool GetSharePath(const std::string& bin_dir, std::string& out_share_dir) const;
	const std::string& GetSharedDataDirectory() const;
	std::string SearchSharedDataFile(const char *filename) const;
	std::vector<std::string> const& GetCmdArgs() const;

	void GenerateLatexDocumentation(std::ostream& os) const;
	
	virtual double GetSimTime()	{ return (0);	}
	virtual double GetHostTime()	{ return (0);	}

	// ********** The following methods are added by Reda and used by PIMServer *****
	virtual unsigned long long   GetStructuredAddress(unsigned long long logicalAddress) { return (logicalAddress); }
	virtual unsigned long long   GetPhysicalAddress(unsigned long long logicalAddress) { return (logicalAddress); }
	// *******************************************************************************

	bool IsWarningEnabled() const;

	void Register(ConfigFileHelper *config_file_helper);
	
private:
	friend class Object;
	friend class VariableBase;
	template <class TYPE> friend class Variable;
	template <class TYPE> friend class VariableArray;
	friend class ServicePortBase;
	friend class SignalHandler;

	static Simulator *simulator;
	VariableBase *void_variable;
	std::string shared_data_dir;
	std::map<std::string, std::string> set_vars;
	std::vector<std::string> get_config_filenames;
	std::string default_config_file_format;
	bool list_parms;
	bool generate_doc;
	std::string generate_doc_filename;
	bool enable_warning;
	bool enable_version;
	bool enable_help;
	bool warn_get_bin_path;
	bool warn_get_share_path;
	bool enable_press_enter_at_exit;
	std::string bin_dir;
	std::string program_binary;
	std::string program_name;
	std::string authors;
	std::string copyright;
	std::string description;
	std::string version;
	std::string license;
	std::string schematic;
	variable::Parameter<std::string> *var_program_name;
	variable::Parameter<std::string> *var_authors;
	variable::Parameter<std::string> *var_copyright;
	variable::Parameter<std::string> *var_description;
	variable::Parameter<std::string> *var_version;
	variable::Parameter<std::string> *var_license;
	variable::Parameter<std::string> *var_schematic;
	variable::Parameter<bool> *param_enable_press_enter_at_exit;
	variable::Parameter<std::string> *param_default_config_file_format;
	
	void Version(std::ostream& os) const;
	void Help(std::ostream& os) const;
	
	void Register(Object *object);
	void Register(ServicePortBase *srv_port);
	void Register(VariableBase *variable);

	void Unregister(Object *object);
	void Unregister(ServicePortBase *srv_import);
	void Unregister(VariableBase *variable);

	void Initialize(VariableBase *variable);

	ConfigFileHelper *GuessConfigFileHelper(const char *filename);
	ConfigFileHelper *FindConfigFileHelper(const std::string& config_file_format);
public:
	bool LoadVariables(const char *filename, VariableBase::Type type = VariableBase::VAR_VOID, const std::string& config_file_format = std::string());
	bool LoadVariables(std::istream& is, VariableBase::Type type = VariableBase::VAR_VOID, const std::string& config_file_format = std::string());
	bool SaveVariables(const char *filename, VariableBase::Type type = VariableBase::VAR_VOID, const std::string& config_file_format = std::string());
	bool SaveVariables(std::ostream& os, VariableBase::Type type = VariableBase::VAR_VOID, const std::string& config_file_format = std::string());

	void GetObjects(std::list<Object *>& lst) const;
	void GetRootObjects(std::list<Object *>& lst) const;

private:
	class CommandLineOption
	{
	public:
		CommandLineOption(char short_name, const char *long_name, const char *opt_description, const char *arg_description = 0);
		char GetShortName() const;
		const char *GetLongName() const;
		bool HasArgument() const;
		const char *GetArgumentDescription() const;
		const char *GetOptionDescription() const;
		int operator == (const char *arg) const;
	private:
		char short_name;
		const char *long_name;
		const char *arg_description;
		const char *opt_description;
	};

	std::string config_file_formats;
	std::vector<CommandLineOption> command_line_options;

	std::map<std::string, Object *, unisim::util::nat_sort::nat_ltstr> objects;
	std::map<std::string, ServicePortBase *> srv_ports;
	std::map<std::string, VariableBase *, unisim::util::nat_sort::nat_ltstr> variables;
	std::map<std::string, ConfigFileHelper *> config_file_helpers;
	
	std::vector<std::string> cmd_args;
	variable::ParameterArray<std::string> *param_cmd_args;
	
public:
	template <typename T> T GetVariable(const char *variable_name, const T *t = 0) const;
	
	void SetVariable(const char *variable_name, const char *variable_value);
	void SetVariable(const char *variable_name, bool variable_value);
	void SetVariable(const char *variable_name, char variable_value);
	void SetVariable(const char *variable_name, unsigned char variable_value);
	void SetVariable(const char *variable_name, short variable_value);
	void SetVariable(const char *variable_name, unsigned short variable_value);
	void SetVariable(const char *variable_name, int variable_value);
	void SetVariable(const char *variable_name, unsigned int variable_value);
	void SetVariable(const char *variable_name, long variable_value);
	void SetVariable(const char *variable_name, unsigned long variable_value);
	void SetVariable(const char *variable_name, unsigned long long variable_value);
	void SetVariable(const char *variable_name, long long variable_value);
	void SetVariable(const char *variable_name, float variable_value);
	void SetVariable(const char *variable_name, double variable_value);
	
	virtual void SigInt();
	virtual void Kill();
private:
	pthread_mutex_t mutex;
	
	pthread_t sig_int_thrd;
	
	pthread_mutex_t sig_int_thrd_create_mutex;
	pthread_cond_t sig_int_thrd_create_cond;
	
	pthread_mutex_t sig_int_thrd_mutex;
	pthread_cond_t sig_int_thrd_cond;
	
	bool sig_int_cond;
	bool stop_sig_int_thrd;
	bool sig_int_thrd_alive;
	
	void SigIntThrd();
	static void *SigIntThrdEntryPoint(void *self);
	bool StartSigIntThrd();
	bool StopSigIntThrd();
	void MTSigInt();
	
	void BroadcastSigInt();
	void Lock();
	void Unlock();
};

//=============================================================================
//=                                 Object                                    =
//=============================================================================

class Object
{
public:
	Object(Object const&) = delete;
	Object(const char *name, Object *parent = 0, const char *description = 0);
	virtual ~Object();

	virtual void OnDisconnect();
	/** Object initial setup routine. The routine is the first
	 * called, it must not call any import. */
	virtual bool BeginSetup();
	/** Object final setup routine. The routine is called after export
	 * setup, id can call any import. */
	virtual bool EndSetup();
	
	virtual void SigInt();
	virtual void Kill();
	bool Killed() const { return killed; }

	const char *GetName() const;
	const char *GetObjectName() const;
	std::string URI() const;

	void Add(Object& object);
	void Remove(Object& object);
	void Add(VariableBase& var);
	void Remove(VariableBase& var);
	const std::list<Object *>& GetLeafs() const;
	void GetVariables(std::list<VariableBase *>& lst, VariableBase::Type type = VariableBase::VAR_VOID) const;
	Object *GetParent() const;
	void Disconnect();
	VariableBase& operator [] (const char *name);
	VariableBase& operator [] (const std::string& name);
	Simulator *GetSimulator() const;
	void GenerateLatexDocumentation(std::ostream& os, VariableBase::Type variable_type) const;
	const char *GetDescription() const;
	virtual void Stop(int exit_status, bool asynchronous = false);
	void SetDescription(const char *description);
	/** Service setup routine. The routine is called after BeginSetup, it
	 * can call imports (see ServiceImport::RequireSetup) */
	void AddServiceAgent( ServiceAgent const* srv_agent );
	void DoServiceSetup();
	
private:
	std::string object_name;
	std::string object_base_name;
	std::string description;
	Object *parent;
	std::list<VariableBase *> variables;
	std::list<Object *> leaf_objects;
	std::set<ServiceAgent const*> srv_agents;
	bool killed;
};

//=============================================================================
//=                              ServiceInterface                             =
//=============================================================================

class ServiceInterface
{
public:
	virtual ~ServiceInterface() {}
};

//=============================================================================
//=                            Service<SERVICE_IF>                            =
//=============================================================================

// ServiceAgent objects that knows about Services actual types (able to call Setup(Service*))
class ServiceAgent
{
public:
	virtual ~ServiceAgent() {}
	virtual void Setup( Object* ) const = 0;
	virtual ServiceBase* GetBase( Object* ) const = 0;
	
	struct SetupError {};
};

class ServiceBase : virtual public Object
{
public:
	ServiceBase(const char *name, Object *parent, const char *description);
	bool NeedServiceSetup() const;
	bool ServiceIsConnected() const { return is_connected; }
	
protected:
	enum SetupState { NoSetup = 0, SetupStarted, SetupComplete  };
	unsigned setup_state : 2;
	unsigned is_connected : 1;
};

template <class SERVICE_IF>
class Service : public ServiceBase, public SERVICE_IF
{
public:
	Service(const char *name, Object *parent = 0, const char *description = 0);
	virtual void Setup(SERVICE_IF*) {}
	void RequireSetup() { if (NeedServiceSetup()) { Setup(this); setup_state = SetupComplete; } }
};

template <class SERVICE_IF>
Service<SERVICE_IF>::Service(const char *_name, Object *_parent, const char *_description)
	: Object(_name, _parent, _description)
	, ServiceBase(_name, _parent, _description)
{
	static struct DerivedServiceAgent : public ServiceAgent
	{
		void Setup( Object* object ) const override { dynamic_cast<Service<SERVICE_IF>*>(object)->RequireSetup(); }
		ServiceBase* GetBase( Object* object ) const  override { return dynamic_cast<Service<SERVICE_IF>*>(object); }
	} agent;
	this->Object::AddServiceAgent( &agent );
}

//=============================================================================
//=                           Client<SERVICE_IF>                              =
//=============================================================================

template <class SERVICE_IF>
class Client : virtual public Object
{
public:
	Client(const char *name, Object *parent = 0, const char *description = 0);
	virtual ~Client();
};

template <class SERVICE_IF>
Client<SERVICE_IF>::Client(const char *_name, Object *_parent, const char *_description) :
	Object(_name, _parent, _description)
{
}

template <class SERVICE_IF>
Client<SERVICE_IF>::~Client()
{
}

//=============================================================================
//=                              ServicePortBase                              =
//=============================================================================

class ServicePortBase
{
public:
	ServicePortBase(const char *name, Object *owner);
	virtual ~ServicePortBase();

	virtual bool IsConnected() const = 0;
	virtual Object *GetService() const = 0;
	virtual bool IsExport() const = 0;

	const char *GetName() const;
	void Dump(std::ostream& os) const;

	struct Visitor { virtual ~Visitor() {} virtual void Process(ServicePortBase& port) = 0; };
	void SpreadFwd( Visitor& visitor );
	void SpreadBwd( Visitor& visitor );

protected:
	void Connect(ServicePortBase* fwd);
	void Disconnect(ServicePortBase* bwd);

	std::string name;
	Object *owner;
	typedef std::list<ServicePortBase *> BwdPorts;
	BwdPorts bwd_ports;
	ServicePortBase *fwd_port;
};

template <class SERVICE_IF>
class ServicePort : public ServicePortBase
{
public:
	ServicePort(const char *name, Service<SERVICE_IF> *owner);
	ServicePort(const char *name, Client<SERVICE_IF> *owner);
	ServicePort(const char *name, Object *owner);
	virtual ~ServicePort();

	virtual bool IsConnected() const override;

	virtual Service<SERVICE_IF> *GetService() const override;

	operator SERVICE_IF * () const;

	SERVICE_IF *operator -> () const;

	void Bind(ServicePort<SERVICE_IF>& fwd);
	void Bind(Service<SERVICE_IF>& service);

	void RequireSetup() const;

private:
	void SpreadServiceBwd(Service<SERVICE_IF>* service);

protected:
	Service<SERVICE_IF> *service;
	Client<SERVICE_IF> *client;
};

template <class SERVICE_IF>
ServicePort<SERVICE_IF>::ServicePort(const char *_name, Service<SERVICE_IF> *_owner)
	: ServicePortBase(_name, _owner)
	, service(_owner)
	, client(0)
{}

template <class SERVICE_IF>
ServicePort<SERVICE_IF>::ServicePort(const char *_name, Client<SERVICE_IF> *_owner)
	: ServicePortBase(_name, _owner)
	, service(0)
	, client(_owner)
{}

template <class SERVICE_IF>
ServicePort<SERVICE_IF>::ServicePort(const char *_name, Object *_owner)
	: ServicePortBase(_name, _owner)
	, service(0)
	, client(0)
{}

template <class SERVICE_IF>
ServicePort<SERVICE_IF>::~ServicePort()
{
	// Now service/client is no longer available, it needs to be propagated upstream.
	struct ClientAssignment : public Visitor
	{
		void Process(ServicePortBase& port) override
		{
			static_cast<ServicePort<SERVICE_IF>&>(port).client = 0;
		}
	} fwd_visitor;
	
	struct ServiceAssignment : public Visitor
	{
		void Process(ServicePortBase& port) override
		{
			static_cast<ServicePort<SERVICE_IF>&>(port).service = 0;
		}
	} bwd_visitor;
	
	SpreadFwd( fwd_visitor );
	SpreadBwd( bwd_visitor );
}

template <class SERVICE_IF>
bool ServicePort<SERVICE_IF>::IsConnected() const
{
	return service and service->ServiceIsConnected();
}

template <class SERVICE_IF>
Service<SERVICE_IF> *ServicePort<SERVICE_IF>::GetService() const
{
	return service;
}

template <class SERVICE_IF>
ServicePort<SERVICE_IF>::operator SERVICE_IF * () const
{
	return service;
}

template <class SERVICE_IF>
SERVICE_IF *ServicePort<SERVICE_IF>::operator -> () const
{
#ifdef DEBUG_KERNEL
	if(!service)
	{
		std::cerr << "ERROR! " << GetName() << " interface can't be used because it is not bound to a service." << std::endl;
		owner->Object::Stop(-1);
	}
#endif
	return service;
}

template <class SERVICE_IF>
void ServicePort<SERVICE_IF>::RequireSetup() const
{
	if (service)
		service->RequireSetup();
}

template <class SERVICE_IF>
void ServicePort<SERVICE_IF>::Bind(Service<SERVICE_IF>& service)
{
	if (fwd_port)
	{
		std::cerr << "WARNING! Can't connect " << GetName() << " to "
		          << service.GetName() << " because it is already connected to "
		          << fwd_port->GetName() << std::endl;
		return;
	}

	SpreadServiceBwd(&service);
}

template <class SERVICE_IF>
void ServicePort<SERVICE_IF>::Bind(ServicePort<SERVICE_IF>& fwd)
{
	Connect(&fwd);

	if (not fwd.service)
		return;

	SpreadServiceBwd(fwd.service);
}

template <class SERVICE_IF>
void ServicePort<SERVICE_IF>::SpreadServiceBwd(Service<SERVICE_IF>* service)
{
	// Now service is known, it needs to be propagated upstream.
	struct ServiceAssignment : public Visitor
	{
		ServiceAssignment(Service<SERVICE_IF> *srv) : service(srv) {} Service<SERVICE_IF> *service;
		void Process(ServicePortBase& port) override
		{
			static_cast<ServicePort<SERVICE_IF>&>(port).service = service;
		}
	} visitor( service );
	
	SpreadBwd( visitor );
}

//=============================================================================
//=                       ServiceImport<SERVICE_IF>                           =
//=============================================================================

template <class SERVICE_IF>
class ServiceImport : public ServicePort<SERVICE_IF>
{
public:
	ServiceImport(const char *name, Client<SERVICE_IF> *client) : ServicePort<SERVICE_IF>(name, client) {}
	ServiceImport(const char *name, Object *owner) : ServicePort<SERVICE_IF>(name, owner) {}
	virtual bool IsExport() const override { return false; }
};

//=============================================================================
//=                          ServiceExport<SERVICE_IF>                        =
//=============================================================================

template <class SERVICE_IF>
class ServiceExport : public ServicePort<SERVICE_IF>
{
public:
	ServiceExport(const char *name, Service<SERVICE_IF> *service) : ServicePort<SERVICE_IF>(name, service) {}
	ServiceExport(const char *name, Object *owner) : ServicePort<SERVICE_IF>(name, owner) {}
	virtual bool IsExport() const override { return true; }
};

//=============================================================================
//=                                Operators                                  =
//=============================================================================

// (import -> export) ==> export
template <class SERVICE_IF>
ServiceExport<SERVICE_IF>& operator >> (ServiceImport<SERVICE_IF>& lhs, ServiceExport<SERVICE_IF>& rhs)
{
	lhs.Bind(rhs);
	return rhs;
}

// (import1 -> import2) ==> import2
template <class SERVICE_IF>
ServiceImport<SERVICE_IF>& operator >> (ServiceImport<SERVICE_IF>& lhs, ServiceImport<SERVICE_IF>& rhs)
{
	lhs.Bind(rhs);
	return rhs;
}

// (export1 -> export2) ==> export2
template <class SERVICE_IF>
ServiceExport<SERVICE_IF>& operator >> (ServiceExport<SERVICE_IF>& lhs, ServiceExport<SERVICE_IF>& rhs)
{
	lhs.Bind(rhs);
	return rhs;
}

#if __cplusplus >= 201103L

template <typename ITEM>
struct Generator
{
	typedef ITEM Item;
	Generator( char const* _prefix, Object* _parent, char const* _description )
		: prefix(_prefix), parent(_parent), description(_description)
	{}
	char const* prefix;
	Object* parent;
	char const* description;
	Item make_item( std::size_t index )
	{
		return Item(std::string(prefix) + '[' + std::to_string(index) + ']', parent, description);
	}
};

#endif

} // end of namespace kernel
} // end of namespace unisim

#endif // __UNISIM_KERNEL_SERVICE_SERVICE_HH__
