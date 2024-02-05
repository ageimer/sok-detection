#include "aarch64/aarch64dec.hh"

#include <unisim/component/cxx/processor/arm/isa/arm64/decode.hh>
#include <unisim/component/cxx/processor/arm/isa/arm64/disasm.hh>
#include <unisim/util/arithmetic/arithmetic.hh>
#include <iostream>

using unisim::util::arithmetic::RotateRight;
using unisim::util::arithmetic::BitScanReverse;

#include <unisim/component/cxx/processor/arm/isa/arm64/execute.hh>
#include <unisim/component/cxx/processor/arm/execute.hh>


namespace unisim { namespace component { namespace cxx { namespace processor { namespace arm { namespace isa { namespace arm64 {
template <	typename	ARCH>
Operation<	ARCH>::Operation(CodeType _code, uint64_t _addr, const char *_name)
:
encoding(_code),
addr(_addr),
name(_name)
{
}

template <	typename	ARCH>
Operation<	ARCH>::~Operation()
{
}

template <	typename	ARCH>
void Operation<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "; Unknown AARCH64 instruction";
}}
template <	typename	ARCH>
void Operation<	ARCH>::execute( ARCH & cpu)
{
	{ cpu.UndefinedInstruction(this); }}
template <	typename	ARCH>
class OpMsr : public Operation<	ARCH>
{
public:
	OpMsr(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t op2;
	uint8_t crm;
	uint8_t crn;
	uint8_t op1;
	uint8_t op0;
	typename ARCH::SysReg const* sysreg; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdc_www : public Operation<	ARCH>
{
public:
	OpAdc_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdc_xxx : public Operation<	ARCH>
{
public:
	OpAdc_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdcs_www : public Operation<	ARCH>
{
public:
	OpAdcs_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdcs_xxx : public Operation<	ARCH>
{
public:
	OpAdcs_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wsxtb : public Operation<	ARCH>
{
public:
	OpAdd_wsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wsxth : public Operation<	ARCH>
{
public:
	OpAdd_wsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wsxtw : public Operation<	ARCH>
{
public:
	OpAdd_wsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wsxtx : public Operation<	ARCH>
{
public:
	OpAdd_wsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wuxtb : public Operation<	ARCH>
{
public:
	OpAdd_wuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wuxth : public Operation<	ARCH>
{
public:
	OpAdd_wuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wuxtw : public Operation<	ARCH>
{
public:
	OpAdd_wuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wuxtx : public Operation<	ARCH>
{
public:
	OpAdd_wuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xsxtb : public Operation<	ARCH>
{
public:
	OpAdd_xsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xsxth : public Operation<	ARCH>
{
public:
	OpAdd_xsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xsxtw : public Operation<	ARCH>
{
public:
	OpAdd_xsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xsxtx : public Operation<	ARCH>
{
public:
	OpAdd_xsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xuxtb : public Operation<	ARCH>
{
public:
	OpAdd_xuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xuxth : public Operation<	ARCH>
{
public:
	OpAdd_xuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xuxtw : public Operation<	ARCH>
{
public:
	OpAdd_xuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xuxtx : public Operation<	ARCH>
{
public:
	OpAdd_xuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wi : public Operation<	ARCH>
{
public:
	OpAdd_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xi : public Operation<	ARCH>
{
public:
	OpAdd_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wlsl : public Operation<	ARCH>
{
public:
	OpAdd_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wlsr : public Operation<	ARCH>
{
public:
	OpAdd_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_wasr : public Operation<	ARCH>
{
public:
	OpAdd_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xlsl : public Operation<	ARCH>
{
public:
	OpAdd_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xlsr : public Operation<	ARCH>
{
public:
	OpAdd_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdd_xasr : public Operation<	ARCH>
{
public:
	OpAdd_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wsxtb : public Operation<	ARCH>
{
public:
	OpAdds_wsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wsxth : public Operation<	ARCH>
{
public:
	OpAdds_wsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wsxtw : public Operation<	ARCH>
{
public:
	OpAdds_wsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wsxtx : public Operation<	ARCH>
{
public:
	OpAdds_wsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wuxtb : public Operation<	ARCH>
{
public:
	OpAdds_wuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wuxth : public Operation<	ARCH>
{
public:
	OpAdds_wuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wuxtw : public Operation<	ARCH>
{
public:
	OpAdds_wuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wuxtx : public Operation<	ARCH>
{
public:
	OpAdds_wuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xsxtb : public Operation<	ARCH>
{
public:
	OpAdds_xsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xsxth : public Operation<	ARCH>
{
public:
	OpAdds_xsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xsxtw : public Operation<	ARCH>
{
public:
	OpAdds_xsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xsxtx : public Operation<	ARCH>
{
public:
	OpAdds_xsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xuxtb : public Operation<	ARCH>
{
public:
	OpAdds_xuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xuxth : public Operation<	ARCH>
{
public:
	OpAdds_xuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xuxtw : public Operation<	ARCH>
{
public:
	OpAdds_xuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xuxtx : public Operation<	ARCH>
{
public:
	OpAdds_xuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wi : public Operation<	ARCH>
{
public:
	OpAdds_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xi : public Operation<	ARCH>
{
public:
	OpAdds_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wlsl : public Operation<	ARCH>
{
public:
	OpAdds_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wlsr : public Operation<	ARCH>
{
public:
	OpAdds_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_wasr : public Operation<	ARCH>
{
public:
	OpAdds_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xlsl : public Operation<	ARCH>
{
public:
	OpAdds_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xlsr : public Operation<	ARCH>
{
public:
	OpAdds_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdds_xasr : public Operation<	ARCH>
{
public:
	OpAdds_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdr : public Operation<	ARCH>
{
public:
	OpAdr(CodeType code, uint64_t addr);
	uint8_t rd;
	int32_t imm1;
	uint8_t imm0;
	int32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAdrp : public Operation<	ARCH>
{
public:
	OpAdrp(CodeType code, uint64_t addr);
	uint8_t rd;
	int32_t imm1;
	uint8_t imm0;
	int32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_wi : public Operation<	ARCH>
{
public:
	OpAnd_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_xi : public Operation<	ARCH>
{
public:
	OpAnd_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint8_t n;
	uint64_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_wlsl : public Operation<	ARCH>
{
public:
	OpAnd_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_wlsr : public Operation<	ARCH>
{
public:
	OpAnd_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_wasr : public Operation<	ARCH>
{
public:
	OpAnd_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_wror : public Operation<	ARCH>
{
public:
	OpAnd_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_xlsl : public Operation<	ARCH>
{
public:
	OpAnd_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_xlsr : public Operation<	ARCH>
{
public:
	OpAnd_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_xasr : public Operation<	ARCH>
{
public:
	OpAnd_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnd_xror : public Operation<	ARCH>
{
public:
	OpAnd_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_wi : public Operation<	ARCH>
{
public:
	OpAnds_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_xi : public Operation<	ARCH>
{
public:
	OpAnds_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint8_t n;
	uint64_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_wlsl : public Operation<	ARCH>
{
public:
	OpAnds_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_wlsr : public Operation<	ARCH>
{
public:
	OpAnds_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_wasr : public Operation<	ARCH>
{
public:
	OpAnds_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_wror : public Operation<	ARCH>
{
public:
	OpAnds_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_xlsl : public Operation<	ARCH>
{
public:
	OpAnds_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_xlsr : public Operation<	ARCH>
{
public:
	OpAnds_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_xasr : public Operation<	ARCH>
{
public:
	OpAnds_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAnds_xror : public Operation<	ARCH>
{
public:
	OpAnds_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAsr_www : public Operation<	ARCH>
{
public:
	OpAsr_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpAsr_xxx : public Operation<	ARCH>
{
public:
	OpAsr_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpB : public Operation<	ARCH>
{
public:
	OpB(CodeType code, uint64_t addr);
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpB_cond : public Operation<	ARCH>
{
public:
	OpB_cond(CodeType code, uint64_t addr);
	uint8_t cond;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBfm_w : public Operation<	ARCH>
{
public:
	OpBfm_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBfm_x : public Operation<	ARCH>
{
public:
	OpBfm_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_wlsl : public Operation<	ARCH>
{
public:
	OpBic_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_wlsr : public Operation<	ARCH>
{
public:
	OpBic_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_wasr : public Operation<	ARCH>
{
public:
	OpBic_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_wror : public Operation<	ARCH>
{
public:
	OpBic_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_xlsl : public Operation<	ARCH>
{
public:
	OpBic_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_xlsr : public Operation<	ARCH>
{
public:
	OpBic_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_xasr : public Operation<	ARCH>
{
public:
	OpBic_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBic_xror : public Operation<	ARCH>
{
public:
	OpBic_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_wlsl : public Operation<	ARCH>
{
public:
	OpBics_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_wlsr : public Operation<	ARCH>
{
public:
	OpBics_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_wasr : public Operation<	ARCH>
{
public:
	OpBics_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_wror : public Operation<	ARCH>
{
public:
	OpBics_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_xlsl : public Operation<	ARCH>
{
public:
	OpBics_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_xlsr : public Operation<	ARCH>
{
public:
	OpBics_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_xasr : public Operation<	ARCH>
{
public:
	OpBics_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBics_xror : public Operation<	ARCH>
{
public:
	OpBics_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBl : public Operation<	ARCH>
{
public:
	OpBl(CodeType code, uint64_t addr);
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBlr : public Operation<	ARCH>
{
public:
	OpBlr(CodeType code, uint64_t addr);
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBr : public Operation<	ARCH>
{
public:
	OpBr(CodeType code, uint64_t addr);
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpBrk : public Operation<	ARCH>
{
public:
	OpBrk(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCbnz_wlit : public Operation<	ARCH>
{
public:
	OpCbnz_wlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCbnz_xlit : public Operation<	ARCH>
{
public:
	OpCbnz_xlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCbz_wlit : public Operation<	ARCH>
{
public:
	OpCbz_wlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCbz_xlit : public Operation<	ARCH>
{
public:
	OpCbz_xlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmn_wi : public Operation<	ARCH>
{
public:
	OpCcmn_wi(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmn_xi : public Operation<	ARCH>
{
public:
	OpCcmn_xi(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmn_w : public Operation<	ARCH>
{
public:
	OpCcmn_w(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmn_x : public Operation<	ARCH>
{
public:
	OpCcmn_x(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmp_wi : public Operation<	ARCH>
{
public:
	OpCcmp_wi(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmp_xi : public Operation<	ARCH>
{
public:
	OpCcmp_xi(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmp_w : public Operation<	ARCH>
{
public:
	OpCcmp_w(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCcmp_x : public Operation<	ARCH>
{
public:
	OpCcmp_x(CodeType code, uint64_t addr);
	uint8_t v;
	uint8_t c;
	uint8_t z;
	uint8_t n;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpClrex : public Operation<	ARCH>
{
public:
	OpClrex(CodeType code, uint64_t addr);
	uint8_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCls_w : public Operation<	ARCH>
{
public:
	OpCls_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCls_x : public Operation<	ARCH>
{
public:
	OpCls_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpClz_w : public Operation<	ARCH>
{
public:
	OpClz_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpClz_x : public Operation<	ARCH>
{
public:
	OpClz_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsel_w : public Operation<	ARCH>
{
public:
	OpCsel_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsel_x : public Operation<	ARCH>
{
public:
	OpCsel_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsinc_w : public Operation<	ARCH>
{
public:
	OpCsinc_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsinc_x : public Operation<	ARCH>
{
public:
	OpCsinc_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsinv_w : public Operation<	ARCH>
{
public:
	OpCsinv_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsinv_x : public Operation<	ARCH>
{
public:
	OpCsinv_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsneg_w : public Operation<	ARCH>
{
public:
	OpCsneg_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCsneg_x : public Operation<	ARCH>
{
public:
	OpCsneg_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t cond;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpDcps1 : public Operation<	ARCH>
{
public:
	OpDcps1(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpDcps2 : public Operation<	ARCH>
{
public:
	OpDcps2(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpDcps3 : public Operation<	ARCH>
{
public:
	OpDcps3(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpDrps : public Operation<	ARCH>
{
public:
	OpDrps(CodeType code, uint64_t addr);
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpEon_wlsl : public Operation<	ARCH>
{
public:
	OpEon_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_wlsr : public Operation<	ARCH>
{
public:
	OpEon_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_wasr : public Operation<	ARCH>
{
public:
	OpEon_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_wror : public Operation<	ARCH>
{
public:
	OpEon_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_xlsl : public Operation<	ARCH>
{
public:
	OpEon_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_xlsr : public Operation<	ARCH>
{
public:
	OpEon_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_xasr : public Operation<	ARCH>
{
public:
	OpEon_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEon_xror : public Operation<	ARCH>
{
public:
	OpEon_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_wi : public Operation<	ARCH>
{
public:
	OpEor_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_xi : public Operation<	ARCH>
{
public:
	OpEor_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint8_t n;
	uint64_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_wlsl : public Operation<	ARCH>
{
public:
	OpEor_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_wlsr : public Operation<	ARCH>
{
public:
	OpEor_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_wasr : public Operation<	ARCH>
{
public:
	OpEor_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_wror : public Operation<	ARCH>
{
public:
	OpEor_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_xlsl : public Operation<	ARCH>
{
public:
	OpEor_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_xlsr : public Operation<	ARCH>
{
public:
	OpEor_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_xasr : public Operation<	ARCH>
{
public:
	OpEor_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEor_xror : public Operation<	ARCH>
{
public:
	OpEor_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpEret : public Operation<	ARCH>
{
public:
	OpEret(CodeType code, uint64_t addr);
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpExtr_w : public Operation<	ARCH>
{
public:
	OpExtr_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpExtr_x : public Operation<	ARCH>
{
public:
	OpExtr_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpHlt : public Operation<	ARCH>
{
public:
	OpHlt(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpHvc : public Operation<	ARCH>
{
public:
	OpHvc(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdar_w : public Operation<	ARCH>
{
public:
	OpLdar_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdar_x : public Operation<	ARCH>
{
public:
	OpLdar_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdarb_w : public Operation<	ARCH>
{
public:
	OpLdarb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdarh_w : public Operation<	ARCH>
{
public:
	OpLdarh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxp_w : public Operation<	ARCH>
{
public:
	OpLdaxp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxp_x : public Operation<	ARCH>
{
public:
	OpLdaxp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxr_w : public Operation<	ARCH>
{
public:
	OpLdaxr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxr_x : public Operation<	ARCH>
{
public:
	OpLdaxr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxrb_w : public Operation<	ARCH>
{
public:
	OpLdaxrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdaxrh_w : public Operation<	ARCH>
{
public:
	OpLdaxrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdp_w : public Operation<	ARCH>
{
public:
	OpLdp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	int16_t imm;
	uint8_t am;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdp_x : public Operation<	ARCH>
{
public:
	OpLdp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	int16_t imm;
	uint8_t am;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdpsw_xxi : public Operation<	ARCH>
{
public:
	OpLdpsw_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	int16_t imm;
	uint8_t am;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wxi : public Operation<	ARCH>
{
public:
	OpLdr_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wuo : public Operation<	ARCH>
{
public:
	OpLdr_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xxi : public Operation<	ARCH>
{
public:
	OpLdr_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xuo : public Operation<	ARCH>
{
public:
	OpLdr_xuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wlit : public Operation<	ARCH>
{
public:
	OpLdr_wlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xlit : public Operation<	ARCH>
{
public:
	OpLdr_xlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wxwu : public Operation<	ARCH>
{
public:
	OpLdr_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wxxu : public Operation<	ARCH>
{
public:
	OpLdr_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wxws : public Operation<	ARCH>
{
public:
	OpLdr_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_wxxs : public Operation<	ARCH>
{
public:
	OpLdr_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xxwu : public Operation<	ARCH>
{
public:
	OpLdr_xxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xxxu : public Operation<	ARCH>
{
public:
	OpLdr_xxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xxws : public Operation<	ARCH>
{
public:
	OpLdr_xxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdr_xxxs : public Operation<	ARCH>
{
public:
	OpLdr_xxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wxi : public Operation<	ARCH>
{
public:
	OpLdrb_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wuo : public Operation<	ARCH>
{
public:
	OpLdrb_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wxwu : public Operation<	ARCH>
{
public:
	OpLdrb_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wxxu : public Operation<	ARCH>
{
public:
	OpLdrb_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wxws : public Operation<	ARCH>
{
public:
	OpLdrb_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrb_wxxs : public Operation<	ARCH>
{
public:
	OpLdrb_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wxi : public Operation<	ARCH>
{
public:
	OpLdrh_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wuo : public Operation<	ARCH>
{
public:
	OpLdrh_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wxwu : public Operation<	ARCH>
{
public:
	OpLdrh_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wxxu : public Operation<	ARCH>
{
public:
	OpLdrh_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wxws : public Operation<	ARCH>
{
public:
	OpLdrh_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrh_wxxs : public Operation<	ARCH>
{
public:
	OpLdrh_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wxi : public Operation<	ARCH>
{
public:
	OpLdrsb_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wuo : public Operation<	ARCH>
{
public:
	OpLdrsb_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xxi : public Operation<	ARCH>
{
public:
	OpLdrsb_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xuo : public Operation<	ARCH>
{
public:
	OpLdrsb_xuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wxwu : public Operation<	ARCH>
{
public:
	OpLdrsb_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wxxu : public Operation<	ARCH>
{
public:
	OpLdrsb_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wxws : public Operation<	ARCH>
{
public:
	OpLdrsb_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_wxxs : public Operation<	ARCH>
{
public:
	OpLdrsb_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xxwu : public Operation<	ARCH>
{
public:
	OpLdrsb_xxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xxxu : public Operation<	ARCH>
{
public:
	OpLdrsb_xxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xxws : public Operation<	ARCH>
{
public:
	OpLdrsb_xxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsb_xxxs : public Operation<	ARCH>
{
public:
	OpLdrsb_xxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wxi : public Operation<	ARCH>
{
public:
	OpLdrsh_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wuo : public Operation<	ARCH>
{
public:
	OpLdrsh_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xxi : public Operation<	ARCH>
{
public:
	OpLdrsh_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xuo : public Operation<	ARCH>
{
public:
	OpLdrsh_xuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wxwu : public Operation<	ARCH>
{
public:
	OpLdrsh_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wxxu : public Operation<	ARCH>
{
public:
	OpLdrsh_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wxws : public Operation<	ARCH>
{
public:
	OpLdrsh_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_wxxs : public Operation<	ARCH>
{
public:
	OpLdrsh_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xxwu : public Operation<	ARCH>
{
public:
	OpLdrsh_xxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xxxu : public Operation<	ARCH>
{
public:
	OpLdrsh_xxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xxws : public Operation<	ARCH>
{
public:
	OpLdrsh_xxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsh_xxxs : public Operation<	ARCH>
{
public:
	OpLdrsh_xxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xlit : public Operation<	ARCH>
{
public:
	OpLdrsw_xlit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xxi : public Operation<	ARCH>
{
public:
	OpLdrsw_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xuo : public Operation<	ARCH>
{
public:
	OpLdrsw_xuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xxwu : public Operation<	ARCH>
{
public:
	OpLdrsw_xxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xxxu : public Operation<	ARCH>
{
public:
	OpLdrsw_xxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xxws : public Operation<	ARCH>
{
public:
	OpLdrsw_xxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdrsw_xxxs : public Operation<	ARCH>
{
public:
	OpLdrsw_xxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdtr_wbo : public Operation<	ARCH>
{
public:
	OpLdtr_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtr_xbo : public Operation<	ARCH>
{
public:
	OpLdtr_xbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrb_wbo : public Operation<	ARCH>
{
public:
	OpLdtrb_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrh_wbo : public Operation<	ARCH>
{
public:
	OpLdtrh_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrsb_wbo : public Operation<	ARCH>
{
public:
	OpLdtrsb_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrsb_xbo : public Operation<	ARCH>
{
public:
	OpLdtrsb_xbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrsh_wbo : public Operation<	ARCH>
{
public:
	OpLdtrsh_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrsh_xbo : public Operation<	ARCH>
{
public:
	OpLdtrsh_xbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdtrsw_xbo : public Operation<	ARCH>
{
public:
	OpLdtrsw_xbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdxp_w : public Operation<	ARCH>
{
public:
	OpLdxp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdxp_x : public Operation<	ARCH>
{
public:
	OpLdxp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdxr_w : public Operation<	ARCH>
{
public:
	OpLdxr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdxr_x : public Operation<	ARCH>
{
public:
	OpLdxr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdxrb_w : public Operation<	ARCH>
{
public:
	OpLdxrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdxrh_w : public Operation<	ARCH>
{
public:
	OpLdxrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLsl_www : public Operation<	ARCH>
{
public:
	OpLsl_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLsl_xxx : public Operation<	ARCH>
{
public:
	OpLsl_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLsr_www : public Operation<	ARCH>
{
public:
	OpLsr_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLsr_xxx : public Operation<	ARCH>
{
public:
	OpLsr_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMadd_w : public Operation<	ARCH>
{
public:
	OpMadd_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMadd_x : public Operation<	ARCH>
{
public:
	OpMadd_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMov_wi : public Operation<	ARCH>
{
public:
	OpMov_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint16_t imm0;
	uint8_t shift;
	int8_t n;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMov_xi : public Operation<	ARCH>
{
public:
	OpMov_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint16_t imm0;
	uint8_t shift;
	int8_t n;
	uint64_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMovk_w : public Operation<	ARCH>
{
public:
	OpMovk_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint16_t imm;
	uint8_t shift;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMovk_x : public Operation<	ARCH>
{
public:
	OpMovk_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint16_t imm;
	uint8_t shift;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMrs : public Operation<	ARCH>
{
public:
	OpMrs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t op2;
	uint8_t crm;
	uint8_t crn;
	uint8_t op1;
	uint8_t op0;
	typename ARCH::SysReg const* sysreg; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMsub_w : public Operation<	ARCH>
{
public:
	OpMsub_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpMsub_x : public Operation<	ARCH>
{
public:
	OpMsub_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpNop : public Operation<	ARCH>
{
public:
	OpNop(CodeType code, uint64_t addr);
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_wlsl : public Operation<	ARCH>
{
public:
	OpOrn_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_wlsr : public Operation<	ARCH>
{
public:
	OpOrn_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_wasr : public Operation<	ARCH>
{
public:
	OpOrn_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_wror : public Operation<	ARCH>
{
public:
	OpOrn_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_xlsl : public Operation<	ARCH>
{
public:
	OpOrn_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_xlsr : public Operation<	ARCH>
{
public:
	OpOrn_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_xasr : public Operation<	ARCH>
{
public:
	OpOrn_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrn_xror : public Operation<	ARCH>
{
public:
	OpOrn_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_wi : public Operation<	ARCH>
{
public:
	OpOrr_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_xi : public Operation<	ARCH>
{
public:
	OpOrr_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	uint8_t n;
	uint64_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_wlsl : public Operation<	ARCH>
{
public:
	OpOrr_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_xlsl : public Operation<	ARCH>
{
public:
	OpOrr_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_wlsr : public Operation<	ARCH>
{
public:
	OpOrr_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_xlsr : public Operation<	ARCH>
{
public:
	OpOrr_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_wasr : public Operation<	ARCH>
{
public:
	OpOrr_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_xasr : public Operation<	ARCH>
{
public:
	OpOrr_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_wror : public Operation<	ARCH>
{
public:
	OpOrr_wror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpOrr_xror : public Operation<	ARCH>
{
public:
	OpOrr_xror(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrfm_lit : public Operation<	ARCH>
{
public:
	OpPrfm_lit(CodeType code, uint64_t addr);
	uint8_t rt;
	int32_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrefetchMemory_xi : public Operation<	ARCH>
{
public:
	OpPrefetchMemory_xi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrefetchMemory_xws : public Operation<	ARCH>
{
public:
	OpPrefetchMemory_xws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrefetchMemory_xwu : public Operation<	ARCH>
{
public:
	OpPrefetchMemory_xwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrefetchMemory_xx : public Operation<	ARCH>
{
public:
	OpPrefetchMemory_xx(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t opt;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpPrfum : public Operation<	ARCH>
{
public:
	OpPrfum(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRbit_w : public Operation<	ARCH>
{
public:
	OpRbit_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRbit_x : public Operation<	ARCH>
{
public:
	OpRbit_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRet : public Operation<	ARCH>
{
public:
	OpRet(CodeType code, uint64_t addr);
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRev_w : public Operation<	ARCH>
{
public:
	OpRev_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRev_x : public Operation<	ARCH>
{
public:
	OpRev_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRev16_w : public Operation<	ARCH>
{
public:
	OpRev16_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRev16_x : public Operation<	ARCH>
{
public:
	OpRev16_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRev32_x : public Operation<	ARCH>
{
public:
	OpRev32_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRor_www : public Operation<	ARCH>
{
public:
	OpRor_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpRor_xxx : public Operation<	ARCH>
{
public:
	OpRor_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbc_www : public Operation<	ARCH>
{
public:
	OpSbc_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbc_xxx : public Operation<	ARCH>
{
public:
	OpSbc_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbcs_www : public Operation<	ARCH>
{
public:
	OpSbcs_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbcs_xxx : public Operation<	ARCH>
{
public:
	OpSbcs_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbfm_w : public Operation<	ARCH>
{
public:
	OpSbfm_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSbfm_x : public Operation<	ARCH>
{
public:
	OpSbfm_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSdiv_www : public Operation<	ARCH>
{
public:
	OpSdiv_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSdiv_xxx : public Operation<	ARCH>
{
public:
	OpSdiv_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSmaddl_xw : public Operation<	ARCH>
{
public:
	OpSmaddl_xw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSmc : public Operation<	ARCH>
{
public:
	OpSmc(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpSmsubl_xw : public Operation<	ARCH>
{
public:
	OpSmsubl_xw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSmulh : public Operation<	ARCH>
{
public:
	OpSmulh(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlr_w : public Operation<	ARCH>
{
public:
	OpStlr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlr_x : public Operation<	ARCH>
{
public:
	OpStlr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlrb_w : public Operation<	ARCH>
{
public:
	OpStlrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlrh_w : public Operation<	ARCH>
{
public:
	OpStlrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxp_w : public Operation<	ARCH>
{
public:
	OpStlxp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxp_x : public Operation<	ARCH>
{
public:
	OpStlxp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxr_w : public Operation<	ARCH>
{
public:
	OpStlxr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxr_x : public Operation<	ARCH>
{
public:
	OpStlxr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxrb_w : public Operation<	ARCH>
{
public:
	OpStlxrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStlxrh_w : public Operation<	ARCH>
{
public:
	OpStlxrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStp_w : public Operation<	ARCH>
{
public:
	OpStp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	int16_t imm;
	uint8_t am;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStp_x : public Operation<	ARCH>
{
public:
	OpStp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	int16_t imm;
	uint8_t am;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wxi : public Operation<	ARCH>
{
public:
	OpStr_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wuo : public Operation<	ARCH>
{
public:
	OpStr_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xxi : public Operation<	ARCH>
{
public:
	OpStr_xxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xuo : public Operation<	ARCH>
{
public:
	OpStr_xuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wxwu : public Operation<	ARCH>
{
public:
	OpStr_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wxxu : public Operation<	ARCH>
{
public:
	OpStr_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wxws : public Operation<	ARCH>
{
public:
	OpStr_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_wxxs : public Operation<	ARCH>
{
public:
	OpStr_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xxwu : public Operation<	ARCH>
{
public:
	OpStr_xxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xxxu : public Operation<	ARCH>
{
public:
	OpStr_xxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xxws : public Operation<	ARCH>
{
public:
	OpStr_xxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStr_xxxs : public Operation<	ARCH>
{
public:
	OpStr_xxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wxi : public Operation<	ARCH>
{
public:
	OpStrb_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wuo : public Operation<	ARCH>
{
public:
	OpStrb_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wxwu : public Operation<	ARCH>
{
public:
	OpStrb_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wxxu : public Operation<	ARCH>
{
public:
	OpStrb_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wxws : public Operation<	ARCH>
{
public:
	OpStrb_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrb_wxxs : public Operation<	ARCH>
{
public:
	OpStrb_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wxi : public Operation<	ARCH>
{
public:
	OpStrh_wxi(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t am;
	int16_t imm;
	Reject reject; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wuo : public Operation<	ARCH>
{
public:
	OpStrh_wuo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wxwu : public Operation<	ARCH>
{
public:
	OpStrh_wxwu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wxxu : public Operation<	ARCH>
{
public:
	OpStrh_wxxu(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	char const* format;   uint8_t shift; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wxws : public Operation<	ARCH>
{
public:
	OpStrh_wxws(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStrh_wxxs : public Operation<	ARCH>
{
public:
	OpStrh_wxxs(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t s;
	uint8_t rm;
	uint8_t shift;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSttr_wbo : public Operation<	ARCH>
{
public:
	OpSttr_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpSttr_xbo : public Operation<	ARCH>
{
public:
	OpSttr_xbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpSttrb_wbo : public Operation<	ARCH>
{
public:
	OpSttrb_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpSttrh_wbo : public Operation<	ARCH>
{
public:
	OpSttrh_wbo(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	int16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpStxp_w : public Operation<	ARCH>
{
public:
	OpStxp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStxp_x : public Operation<	ARCH>
{
public:
	OpStxp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStxr_w : public Operation<	ARCH>
{
public:
	OpStxr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStxr_x : public Operation<	ARCH>
{
public:
	OpStxr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStxrb_w : public Operation<	ARCH>
{
public:
	OpStxrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpStxrh_w : public Operation<	ARCH>
{
public:
	OpStxrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rt2;
	uint8_t rs;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wsxtb : public Operation<	ARCH>
{
public:
	OpSub_wsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wsxth : public Operation<	ARCH>
{
public:
	OpSub_wsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wsxtw : public Operation<	ARCH>
{
public:
	OpSub_wsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wsxtx : public Operation<	ARCH>
{
public:
	OpSub_wsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wuxtb : public Operation<	ARCH>
{
public:
	OpSub_wuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wuxth : public Operation<	ARCH>
{
public:
	OpSub_wuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wuxtw : public Operation<	ARCH>
{
public:
	OpSub_wuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wuxtx : public Operation<	ARCH>
{
public:
	OpSub_wuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xsxtb : public Operation<	ARCH>
{
public:
	OpSub_xsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xsxth : public Operation<	ARCH>
{
public:
	OpSub_xsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xsxtw : public Operation<	ARCH>
{
public:
	OpSub_xsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xsxtx : public Operation<	ARCH>
{
public:
	OpSub_xsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xuxtb : public Operation<	ARCH>
{
public:
	OpSub_xuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xuxth : public Operation<	ARCH>
{
public:
	OpSub_xuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xuxtw : public Operation<	ARCH>
{
public:
	OpSub_xuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xuxtx : public Operation<	ARCH>
{
public:
	OpSub_xuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wi : public Operation<	ARCH>
{
public:
	OpSub_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xi : public Operation<	ARCH>
{
public:
	OpSub_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wlsl : public Operation<	ARCH>
{
public:
	OpSub_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wlsr : public Operation<	ARCH>
{
public:
	OpSub_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_wasr : public Operation<	ARCH>
{
public:
	OpSub_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xlsl : public Operation<	ARCH>
{
public:
	OpSub_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xlsr : public Operation<	ARCH>
{
public:
	OpSub_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSub_xasr : public Operation<	ARCH>
{
public:
	OpSub_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wuxtb : public Operation<	ARCH>
{
public:
	OpSubs_wuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wuxth : public Operation<	ARCH>
{
public:
	OpSubs_wuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wuxtw : public Operation<	ARCH>
{
public:
	OpSubs_wuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wuxtx : public Operation<	ARCH>
{
public:
	OpSubs_wuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wsxtb : public Operation<	ARCH>
{
public:
	OpSubs_wsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wsxth : public Operation<	ARCH>
{
public:
	OpSubs_wsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wsxtw : public Operation<	ARCH>
{
public:
	OpSubs_wsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wsxtx : public Operation<	ARCH>
{
public:
	OpSubs_wsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xuxtb : public Operation<	ARCH>
{
public:
	OpSubs_xuxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xuxth : public Operation<	ARCH>
{
public:
	OpSubs_xuxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xuxtw : public Operation<	ARCH>
{
public:
	OpSubs_xuxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xuxtx : public Operation<	ARCH>
{
public:
	OpSubs_xuxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xsxtb : public Operation<	ARCH>
{
public:
	OpSubs_xsxtb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xsxth : public Operation<	ARCH>
{
public:
	OpSubs_xsxth(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xsxtw : public Operation<	ARCH>
{
public:
	OpSubs_xsxtw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xsxtx : public Operation<	ARCH>
{
public:
	OpSubs_xsxtx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	Reject reject;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wi : public Operation<	ARCH>
{
public:
	OpSubs_wi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xi : public Operation<	ARCH>
{
public:
	OpSubs_xi(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint16_t imm0;
	uint8_t shl12;
	uint32_t imm;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wlsl : public Operation<	ARCH>
{
public:
	OpSubs_wlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wlsr : public Operation<	ARCH>
{
public:
	OpSubs_wlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_wasr : public Operation<	ARCH>
{
public:
	OpSubs_wasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xlsl : public Operation<	ARCH>
{
public:
	OpSubs_xlsl(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xlsr : public Operation<	ARCH>
{
public:
	OpSubs_xlsr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSubs_xasr : public Operation<	ARCH>
{
public:
	OpSubs_xasr(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imm;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSvc : public Operation<	ARCH>
{
public:
	OpSvc(CodeType code, uint64_t addr);
	uint16_t imm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpTb : public Operation<	ARCH>
{
public:
	OpTb(CodeType code, uint64_t addr);
	uint8_t rt;
	int16_t imm;
	uint8_t pos0;
	uint8_t bitval;
	uint8_t pos1;
	unsigned pos;   char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUbfm_w : public Operation<	ARCH>
{
public:
	OpUbfm_w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUbfm_x : public Operation<	ARCH>
{
public:
	OpUbfm_x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t imms;
	uint8_t immr;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUdiv_www : public Operation<	ARCH>
{
public:
	OpUdiv_www(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUdiv_xxx : public Operation<	ARCH>
{
public:
	OpUdiv_xxx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUmaddl_xw : public Operation<	ARCH>
{
public:
	OpUmaddl_xw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUmsubl_xw : public Operation<	ARCH>
{
public:
	OpUmsubl_xw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpUmulh : public Operation<	ARCH>
{
public:
	OpUmulh(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t ra;
	uint8_t rm;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32b : public Operation<	ARCH>
{
public:
	OpCrc32b(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32h : public Operation<	ARCH>
{
public:
	OpCrc32h(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32w : public Operation<	ARCH>
{
public:
	OpCrc32w(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32x : public Operation<	ARCH>
{
public:
	OpCrc32x(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32cb : public Operation<	ARCH>
{
public:
	OpCrc32cb(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32ch : public Operation<	ARCH>
{
public:
	OpCrc32ch(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32cw : public Operation<	ARCH>
{
public:
	OpCrc32cw(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCrc32cx : public Operation<	ARCH>
{
public:
	OpCrc32cx(CodeType code, uint64_t addr);
	uint8_t rd;
	uint8_t rn;
	uint8_t rm;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCas_w : public Operation<	ARCH>
{
public:
	OpCas_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCas_x : public Operation<	ARCH>
{
public:
	OpCas_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCasb_w : public Operation<	ARCH>
{
public:
	OpCasb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCash_w : public Operation<	ARCH>
{
public:
	OpCash_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCasp_w : public Operation<	ARCH>
{
public:
	OpCasp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpCasp_x : public Operation<	ARCH>
{
public:
	OpCasp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t l;
	uint8_t rs;
	uint8_t a;
	char const* format; virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSwp_w : public Operation<	ARCH>
{
public:
	OpSwp_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t l;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSwp_x : public Operation<	ARCH>
{
public:
	OpSwp_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t l;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpSwpb_w : public Operation<	ARCH>
{
public:
	OpSwpb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t l;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpSwph_w : public Operation<	ARCH>
{
public:
	OpSwph_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t l;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
private:
};

template <	typename	ARCH>
class OpLdstadd_w : public Operation<	ARCH>
{
public:
	OpLdstadd_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstadd_x : public Operation<	ARCH>
{
public:
	OpLdstadd_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstaddb_w : public Operation<	ARCH>
{
public:
	OpLdstaddb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstaddh_w : public Operation<	ARCH>
{
public:
	OpLdstaddh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstclr_w : public Operation<	ARCH>
{
public:
	OpLdstclr_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstclr_x : public Operation<	ARCH>
{
public:
	OpLdstclr_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstclrb_w : public Operation<	ARCH>
{
public:
	OpLdstclrb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstclrh_w : public Operation<	ARCH>
{
public:
	OpLdstclrh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdsteor_w : public Operation<	ARCH>
{
public:
	OpLdsteor_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdsteor_x : public Operation<	ARCH>
{
public:
	OpLdsteor_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdsteorb_w : public Operation<	ARCH>
{
public:
	OpLdsteorb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdsteorh_w : public Operation<	ARCH>
{
public:
	OpLdsteorh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstset_w : public Operation<	ARCH>
{
public:
	OpLdstset_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstset_x : public Operation<	ARCH>
{
public:
	OpLdstset_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsetb_w : public Operation<	ARCH>
{
public:
	OpLdstsetb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstseth_w : public Operation<	ARCH>
{
public:
	OpLdstseth_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmax_w : public Operation<	ARCH>
{
public:
	OpLdstsmax_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmax_x : public Operation<	ARCH>
{
public:
	OpLdstsmax_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmaxb_w : public Operation<	ARCH>
{
public:
	OpLdstsmaxb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmaxh_w : public Operation<	ARCH>
{
public:
	OpLdstsmaxh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmin_w : public Operation<	ARCH>
{
public:
	OpLdstsmin_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsmin_x : public Operation<	ARCH>
{
public:
	OpLdstsmin_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsminb_w : public Operation<	ARCH>
{
public:
	OpLdstsminb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstsminh_w : public Operation<	ARCH>
{
public:
	OpLdstsminh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumax_w : public Operation<	ARCH>
{
public:
	OpLdstumax_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumax_x : public Operation<	ARCH>
{
public:
	OpLdstumax_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumaxb_w : public Operation<	ARCH>
{
public:
	OpLdstumaxb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumaxh_w : public Operation<	ARCH>
{
public:
	OpLdstumaxh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumin_w : public Operation<	ARCH>
{
public:
	OpLdstumin_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstumin_x : public Operation<	ARCH>
{
public:
	OpLdstumin_x(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstuminb_w : public Operation<	ARCH>
{
public:
	OpLdstuminb_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
class OpLdstuminh_w : public Operation<	ARCH>
{
public:
	OpLdstuminh_w(CodeType code, uint64_t addr);
	uint8_t rt;
	uint8_t rn;
	uint8_t rs;
	uint8_t r;
	uint8_t a;
	virtual
	void disasm( ARCH & cpu,
	std::ostream& sink );
	virtual
	void execute( ARCH & cpu );
private:
};

template <	typename	ARCH>
void OpMsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sysreg->DisasmWrite(op0, op1, crn, crm, op2, rt, sink);
}}
template <	typename	ARCH>
void OpMsr<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.CheckSystemAccess(op1);

		sysreg->Write(op0, op1, crn, crm, op2, cpu, cpu.GetGZR(rt));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMsr(CodeType code, uint64_t addr)
{
	return new OpMsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdc_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adc\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpAdc_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2 + U32(cpu.GetCarry());
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdc_www(CodeType code, uint64_t addr)
{
	return new OpAdc_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdc_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adc\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpAdc_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2 + U64(cpu.GetCarry());
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdc_xxx(CodeType code, uint64_t addr)
{
	return new OpAdc_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdcs_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adcs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpAdcs_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		BOOL carry( cpu.GetCarry() );
		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2 + U32(carry);
		cpu.SetGZR(rd, res);

		BOOL n = S32(res) < S32(0), z = res == U32(0);
		if (cpu.Test(carry))
		cpu.SetNZCV( n, z, op1 >= ~op2, n xor (S32(op1) <  S32(~op2)) );
		else
		cpu.SetNZCV( n, z, op1 >  ~op2, n xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdcs_www(CodeType code, uint64_t addr)
{
	return new OpAdcs_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdcs_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adcs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpAdcs_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		BOOL carry( cpu.GetCarry() );
		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2 + U64(carry);
		cpu.SetGZR(rd, res);

		BOOL n = S64(res) < S64(0), z = res == U64(0);
		if (cpu.Test(carry))
		cpu.SetNZCV( n, z, op1 >= ~op2, n xor (S64(op1) <  S64(~op2)) );
		else
		cpu.SetNZCV( n, z, op1 >  ~op2, n xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdcs_xxx(CodeType code, uint64_t addr)
{
	return new OpAdcs_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wsxtb(CodeType code, uint64_t addr)
{
	return new OpAdd_wsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wsxth(CodeType code, uint64_t addr)
{
	return new OpAdd_wsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wsxtw(CodeType code, uint64_t addr)
{
	return new OpAdd_wsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wsxtx(CodeType code, uint64_t addr)
{
	return new OpAdd_wsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wuxtb(CodeType code, uint64_t addr)
{
	return new OpAdd_wuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wuxth(CodeType code, uint64_t addr)
{
	return new OpAdd_wuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wuxtw(CodeType code, uint64_t addr)
{
	return new OpAdd_wuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_wuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wuxtx(CodeType code, uint64_t addr)
{
	return new OpAdd_wuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xsxtb(CodeType code, uint64_t addr)
{
	return new OpAdd_xsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xsxth(CodeType code, uint64_t addr)
{
	return new OpAdd_xsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xsxtw(CodeType code, uint64_t addr)
{
	return new OpAdd_xsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xsxtx(CodeType code, uint64_t addr)
{
	return new OpAdd_xsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xuxtb(CodeType code, uint64_t addr)
{
	return new OpAdd_xuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xuxth(CodeType code, uint64_t addr)
{
	return new OpAdd_xuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xuxtw(CodeType code, uint64_t addr)
{
	return new OpAdd_xuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdd_xuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xuxtx(CodeType code, uint64_t addr)
{
	return new OpAdd_xuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpAdd_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGSR(rn)), op2(imm), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wi(CodeType code, uint64_t addr)
{
	return new OpAdd_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpAdd_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGSR(rn)), op2(imm), res = op1 + op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xi(CodeType code, uint64_t addr)
{
	return new OpAdd_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAdd_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wlsl(CodeType code, uint64_t addr)
{
	return new OpAdd_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdd_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wlsr(CodeType code, uint64_t addr)
{
	return new OpAdd_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdd_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_wasr(CodeType code, uint64_t addr)
{
	return new OpAdd_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAdd_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xlsl(CodeType code, uint64_t addr)
{
	return new OpAdd_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdd_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xlsr(CodeType code, uint64_t addr)
{
	return new OpAdd_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdd_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "add\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdd_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdd_xasr(CodeType code, uint64_t addr)
{
	return new OpAdd_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wsxtb(CodeType code, uint64_t addr)
{
	return new OpAdds_wsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wsxth(CodeType code, uint64_t addr)
{
	return new OpAdds_wsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wsxtw(CodeType code, uint64_t addr)
{
	return new OpAdds_wsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wsxtx(CodeType code, uint64_t addr)
{
	return new OpAdds_wsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wuxtb(CodeType code, uint64_t addr)
{
	return new OpAdds_wuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wuxth(CodeType code, uint64_t addr)
{
	return new OpAdds_wuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wuxtw(CodeType code, uint64_t addr)
{
	return new OpAdds_wuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_wuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wuxtx(CodeType code, uint64_t addr)
{
	return new OpAdds_wuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xsxtb(CodeType code, uint64_t addr)
{
	return new OpAdds_xsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xsxth(CodeType code, uint64_t addr)
{
	return new OpAdds_xsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xsxtw(CodeType code, uint64_t addr)
{
	return new OpAdds_xsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xsxtx(CodeType code, uint64_t addr)
{
	return new OpAdds_xsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U8(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xuxtb(CodeType code, uint64_t addr)
{
	return new OpAdds_xuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U16(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xuxth(CodeType code, uint64_t addr)
{
	return new OpAdds_xuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U32(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xuxtw(CodeType code, uint64_t addr)
{
	return new OpAdds_xuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpAdds_xuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U64(cpu.GetGZR(rm))) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xuxtx(CodeType code, uint64_t addr)
{
	return new OpAdds_xuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpAdds_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGSR(rn)), op2(imm), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wi(CodeType code, uint64_t addr)
{
	return new OpAdds_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpAdds_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGSR(rn)), op2(imm), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xi(CodeType code, uint64_t addr)
{
	return new OpAdds_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAdds_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wlsl(CodeType code, uint64_t addr)
{
	return new OpAdds_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdds_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wlsr(CodeType code, uint64_t addr)
{
	return new OpAdds_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "adds\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdds_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_wasr(CodeType code, uint64_t addr)
{
	return new OpAdds_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAdds_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xlsl(CodeType code, uint64_t addr)
{
	return new OpAdds_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdds_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xlsr(CodeType code, uint64_t addr)
{
	return new OpAdds_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdds_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmn\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "adds\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAdds_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 + op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdds_xasr(CodeType code, uint64_t addr)
{
	return new OpAdds_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adr\t" << DisasmGZXR(rd) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpAdr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		cpu.SetGZR(rd, cpu.GetPC() + U64(imm));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdr(CodeType code, uint64_t addr)
{
	return new OpAdr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAdrp<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "adrp\t" << DisasmGZXR(rd) << ", 0x" << std::hex << ((this->GetAddr() + (uint64_t(imm)<<12)) & uint64_t(-1<<12));
}}
template <	typename	ARCH>
void OpAdrp<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		cpu.SetGZR(rd, (cpu.GetPC() + (U64(imm)<<12)) & U64(-1<<12));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAdrp(CodeType code, uint64_t addr)
{
	return new OpAdrp<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGSWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpAnd_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGZR(rn)), op2(imm), res = op1 & op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_wi(CodeType code, uint64_t addr)
{
	return new OpAnd_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGSXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpAnd_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGZR(rn)), op2(imm), res = op1 & op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_xi(CodeType code, uint64_t addr)
{
	return new OpAnd_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAnd_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_wlsl(CodeType code, uint64_t addr)
{
	return new OpAnd_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_wlsr(CodeType code, uint64_t addr)
{
	return new OpAnd_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_wasr(CodeType code, uint64_t addr)
{
	return new OpAnd_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_wror(CodeType code, uint64_t addr)
{
	return new OpAnd_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAnd_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_xlsl(CodeType code, uint64_t addr)
{
	return new OpAnd_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_xlsr(CodeType code, uint64_t addr)
{
	return new OpAnd_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_xasr(CodeType code, uint64_t addr)
{
	return new OpAnd_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnd_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "and\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnd_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 & op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnd_xror(CodeType code, uint64_t addr)
{
	return new OpAnd_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZWR(rn) << ", " << DisasmI(imm,16);
		else
		sink << "ands\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpAnds_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1(cpu.GetGZR(rn)), op2(imm), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_wi(CodeType code, uint64_t addr)
{
	return new OpAnds_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZXR(rn) << ", " << DisasmI(imm,16);
		else
		sink << "ands\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpAnds_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1(cpu.GetGZR(rn)), op2(imm), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_xi(CodeType code, uint64_t addr)
{
	return new OpAnds_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "ands\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAnds_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_wlsl(CodeType code, uint64_t addr)
{
	return new OpAnds_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_wlsr(CodeType code, uint64_t addr)
{
	return new OpAnds_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_wasr(CodeType code, uint64_t addr)
{
	return new OpAnds_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_wror(CodeType code, uint64_t addr)
{
	return new OpAnds_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "ands\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpAnds_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_xlsl(CodeType code, uint64_t addr)
{
	return new OpAnds_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_xlsr(CodeType code, uint64_t addr)
{
	return new OpAnds_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_xasr(CodeType code, uint64_t addr)
{
	return new OpAnds_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAnds_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "tst\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "ands\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpAnds_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 & op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAnds_xror(CodeType code, uint64_t addr)
{
	return new OpAnds_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAsr_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "asr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpAsr_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( S32(op1) >> (op2 & U32(0b11111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAsr_www(CodeType code, uint64_t addr)
{
	return new OpAsr_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpAsr_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "asr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpAsr_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( S64(op1) >> (op2 & U64(0b111111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpAsr_xxx(CodeType code, uint64_t addr)
{
	return new OpAsr_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpB<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "b\t0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpB<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpB(CodeType code, uint64_t addr)
{
	return new OpB<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpB_cond<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "b." << DisasmCond(cond) << "\t0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpB_cond<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		if (CheckCondition(cpu, cond))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpB_cond(CodeType code, uint64_t addr)
{
	return new OpB_cond<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBfm_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms < immr)
		sink << "bfi\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(-immr&31) << ", " << DisasmI(imms+1);
		else
		sink << "bfxil\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpBfm_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		unsigned l = (imms ^ 31), r = (l + immr) & 31;
		uint32_t mask = (uint32_t(int32_t(-1)) << l) >> r;

		U32 src( cpu.GetGZR(rn) ), bf( (src << l) >> r ), dst( cpu.GetGZR(rd) ), res( (dst & U32(~mask)) | bf );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBfm_w(CodeType code, uint64_t addr)
{
	return new OpBfm_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBfm_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms < immr)
		sink << "bfi\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(-immr&63) << ", " << DisasmI(imms+1);
		else
		sink << "bfxil\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpBfm_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		unsigned l = (imms ^ 63), r = (l + immr) & 63;
		uint64_t mask = (uint64_t(int64_t(-1)) << l) >> r;

		U64 src( cpu.GetGZR(rn) ), bf( (src << l) >> r ), res( (cpu.GetGZR(rd) & U64(~mask)) | bf );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBfm_x(CodeType code, uint64_t addr)
{
	return new OpBfm_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpBic_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_wlsl(CodeType code, uint64_t addr)
{
	return new OpBic_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_wlsr(CodeType code, uint64_t addr)
{
	return new OpBic_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_wasr(CodeType code, uint64_t addr)
{
	return new OpBic_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_wror(CodeType code, uint64_t addr)
{
	return new OpBic_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpBic_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_xlsl(CodeType code, uint64_t addr)
{
	return new OpBic_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_xlsr(CodeType code, uint64_t addr)
{
	return new OpBic_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_xasr(CodeType code, uint64_t addr)
{
	return new OpBic_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBic_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bic\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBic_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBic_xror(CodeType code, uint64_t addr)
{
	return new OpBic_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpBics_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_wlsl(CodeType code, uint64_t addr)
{
	return new OpBics_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_wlsr(CodeType code, uint64_t addr)
{
	return new OpBics_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_wasr(CodeType code, uint64_t addr)
{
	return new OpBics_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), res == U32(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_wror(CodeType code, uint64_t addr)
{
	return new OpBics_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpBics_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_xlsl(CodeType code, uint64_t addr)
{
	return new OpBics_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_xlsr(CodeType code, uint64_t addr)
{
	return new OpBics_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_xasr(CodeType code, uint64_t addr)
{
	return new OpBics_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBics_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bics\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpBics_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 & ~op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), res == U64(0), BOOL(false), BOOL(false) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBics_xror(CodeType code, uint64_t addr)
{
	return new OpBics_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "bl\t0x" << std::hex << (this->GetAddr()+int64_t(imm));
}}
template <	typename	ARCH>
void OpBl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 target_addr( cpu.GetPC() + U64(S64(imm)) );
		U64 return_addr( cpu.GetNPC() );
		cpu.SetGZR(30, return_addr);
		cpu.BranchTo( target_addr, ARCH::B_CALL );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBl(CodeType code, uint64_t addr)
{
	return new OpBl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBlr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "blr\t" << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpBlr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 target_addr( cpu.GetGZR(rn) );
		U64 return_addr( cpu.GetNPC() );
		cpu.SetGZR(30, return_addr);
		cpu.BranchTo( target_addr, ARCH::B_CALL );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBlr(CodeType code, uint64_t addr)
{
	return new OpBlr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "br\t" << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpBr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 target_addr( cpu.GetGZR(rn) );
		cpu.BranchTo( target_addr, ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBr(CodeType code, uint64_t addr)
{
	return new OpBr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpBrk<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "brk\t" << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpBrk<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.SoftwareBreakpoint( imm );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpBrk(CodeType code, uint64_t addr)
{
	return new OpBrk<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCbnz_wlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cbnz\t" << DisasmGZWR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpCbnz_wlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U32 op1( cpu.GetGZR(rt) );

		if (cpu.Test( op1 != U32(0) ))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCbnz_wlit(CodeType code, uint64_t addr)
{
	return new OpCbnz_wlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCbnz_xlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cbnz\t" << DisasmGZXR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpCbnz_xlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rt) );

		if (cpu.Test( op1 != U64(0) ))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCbnz_xlit(CodeType code, uint64_t addr)
{
	return new OpCbnz_xlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCbz_wlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cbz\t" << DisasmGZWR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpCbz_wlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U32 op1( cpu.GetGZR(rt) );

		if (cpu.Test( op1 == U32(0) ))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCbz_wlit(CodeType code, uint64_t addr)
{
	return new OpCbz_wlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCbz_xlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cbz\t" << DisasmGZXR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpCbz_xlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rt) );

		if (cpu.Test( op1 == U64(0) ))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCbz_xlit(CodeType code, uint64_t addr)
{
	return new OpCbz_xlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmn_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmn\t" << DisasmGZWR(rn) << ", " << DisasmI(imm,16) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmn_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U32 op1( cpu.GetGZR(rn) ), op2( imm ), res = op1 + op2;
			cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmn_wi(CodeType code, uint64_t addr)
{
	return new OpCcmn_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmn_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmn\t" << DisasmGZXR(rn) << ", " << DisasmI(imm,16) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmn_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U64 op1( cpu.GetGZR(rn) ), op2( imm ), res = op1 + op2;
			cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmn_xi(CodeType code, uint64_t addr)
{
	return new OpCcmn_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmn_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmn\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmn_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2;
			cpu.SetNZCV( S32(res) < S32(0), res == U32(0), op1 > ~op2, (S32(res) < S32(0)) xor (S32(op1) <= S32(~op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmn_w(CodeType code, uint64_t addr)
{
	return new OpCcmn_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmn_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmn\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmn_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 + op2;
			cpu.SetNZCV( S64(res) < S64(0), res == U64(0), op1 > ~op2, (S64(res) < S64(0)) xor (S64(op1) <= S64(~op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmn_x(CodeType code, uint64_t addr)
{
	return new OpCcmn_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmp_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmp\t" << DisasmGZWR(rn) << ", " << DisasmI(imm,16) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmp_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U32 op1( cpu.GetGZR(rn) ), op2( imm ), res = op1 - op2;
			cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmp_wi(CodeType code, uint64_t addr)
{
	return new OpCcmp_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmp_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmp\t" << DisasmGZXR(rn) << ", " << DisasmI(imm,16) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmp_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U64 op1( cpu.GetGZR(rn) ), op2( imm ), res = op1 - op2;
			cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmp_xi(CodeType code, uint64_t addr)
{
	return new OpCcmp_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmp\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2;
			cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmp_w(CodeType code, uint64_t addr)
{
	return new OpCcmp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCcmp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ccmp\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmI((n<<3)|(z<<2)|(c<<1)|(v<<0),16) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCcmp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		if (CheckCondition(cpu, cond))
		{
			U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2;
			cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
		}
		else
		cpu.SetNZCV( BOOL(n==1), BOOL(z==1), BOOL(c==1), BOOL(v==1) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCcmp_x(CodeType code, uint64_t addr)
{
	return new OpCcmp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpClrex<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "clrex\t" << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpClrex<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.ClearExclusiveLocal();
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpClrex(CodeType code, uint64_t addr)
{
	return new OpClrex<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCls_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cls\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
}}
template <	typename	ARCH>
void OpCls_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 val( cpu.GetGZR(rn) );
		val = val ^ U32(S32(val) >> 1);

		if (cpu.Test( val == U32(0) ))
		val = U32(31);
		else
		val = U32(30) - BitScanReverse( val );

		cpu.SetGZR(rd, val);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCls_w(CodeType code, uint64_t addr)
{
	return new OpCls_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCls_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cls\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpCls_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 val( cpu.GetGZR(rn) );
		val = val ^ U64(S64(val) >> 1);

		if (cpu.Test( val == U64(0) ))
		val = U64(63);
		else
		val = U64(62) - BitScanReverse( val );

		cpu.SetGZR(rd, val);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCls_x(CodeType code, uint64_t addr)
{
	return new OpCls_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpClz_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "clz\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
}}
template <	typename	ARCH>
void OpClz_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 val( cpu.GetGZR(rn) );
		if (cpu.Test( val == U32(0) ))
		val = U32(32);
		else
		val = U32(31) - BitScanReverse( val );

		cpu.SetGZR(rd, val);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpClz_w(CodeType code, uint64_t addr)
{
	return new OpClz_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpClz_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "clz\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpClz_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 val( cpu.GetGZR(rn) );
		if (cpu.Test( val == U64(0) ))
		val = U64(64);
		else
		val = U64(63) - BitScanReverse( val );

		cpu.SetGZR(rd, val);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpClz_x(CodeType code, uint64_t addr)
{
	return new OpClz_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsel_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "csel\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsel_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res;
		if (CheckCondition(cpu, cond))
		res = U32(cpu.GetGZR(rn));
		else
		res = U32(cpu.GetGZR(rm));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsel_w(CodeType code, uint64_t addr)
{
	return new OpCsel_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsel_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "csel\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsel_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res;
		if (CheckCondition(cpu, cond))
		res = cpu.GetGZR(rn);
		else
		res = cpu.GetGZR(rm);
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsel_x(CodeType code, uint64_t addr)
{
	return new OpCsel_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsinc_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		if (rn != 31)
		sink << "cinc\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "cset\t" << DisasmGZWR(rd) << ", " << DisasmCond(cond^1);
		else
		sink << "csinc\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsinc_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res;
		if (CheckCondition(cpu, cond))
		res = U32(cpu.GetGZR(rn));
		else
		res = U32(cpu.GetGZR(rm)) + U32(1);
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsinc_w(CodeType code, uint64_t addr)
{
	return new OpCsinc_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsinc_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		if (rn != 31)
		sink << "cinc\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "cset\t" << DisasmGZXR(rd) << ", " << DisasmCond(cond^1);
		else
		sink << "csinc\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsinc_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res;
		if (CheckCondition(cpu, cond))
		res = cpu.GetGZR(rn);
		else
		res = cpu.GetGZR(rm) + U64(1);
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsinc_x(CodeType code, uint64_t addr)
{
	return new OpCsinc_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsinv_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		if (rn != 31)
		sink << "cinv\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "csetm\t" << DisasmGZWR(rd) << ", " << DisasmCond(cond^1);
		else
		sink << "csinv\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsinv_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res;
		if (CheckCondition(cpu, cond))
		res = U32(cpu.GetGZR(rn));
		else
		res = ~U32(cpu.GetGZR(rm));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsinv_w(CodeType code, uint64_t addr)
{
	return new OpCsinv_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsinv_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		if (rn != 31)
		sink << "cinv\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "csetm\t" << DisasmGZXR(rd) << ", " << DisasmCond(cond^1);
		else
		sink << "csinv\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsinv_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res;
		if (CheckCondition(cpu, cond))
		res = cpu.GetGZR(rn);
		else
		res = ~(cpu.GetGZR(rm));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsinv_x(CodeType code, uint64_t addr)
{
	return new OpCsinv_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsneg_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		sink << "cneg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "csneg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsneg_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res;
		if (CheckCondition(cpu, cond))
		res = U32(cpu.GetGZR(rn));
		else
		res = -U32(cpu.GetGZR(rm));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsneg_w(CodeType code, uint64_t addr)
{
	return new OpCsneg_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCsneg_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if ((rn == rm) and (cond < 0b1110))
		sink << "cneg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmCond(cond^1);
		else
		sink << "csneg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmCond(cond);
}}
template <	typename	ARCH>
void OpCsneg_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res;
		if (CheckCondition(cpu, cond))
		res = cpu.GetGZR(rn);
		else
		res = -(cpu.GetGZR(rm));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCsneg_x(CodeType code, uint64_t addr)
{
	return new OpCsneg_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpDcps1<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "dcps1\t" << DisasmI(imm,16);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpDcps1(CodeType code, uint64_t addr)
{
	return new OpDcps1<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpDcps2<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "dcps2\t" << DisasmI(imm,16);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpDcps2(CodeType code, uint64_t addr)
{
	return new OpDcps2<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpDcps3<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "dcps3\t" << DisasmI(imm,16);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpDcps3(CodeType code, uint64_t addr)
{
	return new OpDcps3<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpDrps<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "drps";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpDrps(CodeType code, uint64_t addr)
{
	return new OpDrps<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpEon_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_wlsl(CodeType code, uint64_t addr)
{
	return new OpEon_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_wlsr(CodeType code, uint64_t addr)
{
	return new OpEon_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_wasr(CodeType code, uint64_t addr)
{
	return new OpEon_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_wror(CodeType code, uint64_t addr)
{
	return new OpEon_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpEon_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_xlsl(CodeType code, uint64_t addr)
{
	return new OpEon_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_xlsr(CodeType code, uint64_t addr)
{
	return new OpEon_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_xasr(CodeType code, uint64_t addr)
{
	return new OpEon_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEon_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eon\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEon_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 ^ ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEon_xror(CodeType code, uint64_t addr)
{
	return new OpEon_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGSWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpEor_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGZR(rn)), op2(imm), res = op1 ^ op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_wi(CodeType code, uint64_t addr)
{
	return new OpEor_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGSXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpEor_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGZR(rn)), op2(imm), res = op1 ^ op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_xi(CodeType code, uint64_t addr)
{
	return new OpEor_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpEor_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_wlsl(CodeType code, uint64_t addr)
{
	return new OpEor_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_wlsr(CodeType code, uint64_t addr)
{
	return new OpEor_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_wasr(CodeType code, uint64_t addr)
{
	return new OpEor_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_wror(CodeType code, uint64_t addr)
{
	return new OpEor_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpEor_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_xlsl(CodeType code, uint64_t addr)
{
	return new OpEor_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_xlsr(CodeType code, uint64_t addr)
{
	return new OpEor_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_xasr(CodeType code, uint64_t addr)
{
	return new OpEor_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEor_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eor\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpEor_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 ^ op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEor_xror(CodeType code, uint64_t addr)
{
	return new OpEor_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpEret<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "eret";
}}
template <	typename	ARCH>
void OpEret<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.ExceptionReturn();
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpEret(CodeType code, uint64_t addr)
{
	return new OpEret<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpExtr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == rm)
		sink << "ror\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(imms);
		else
		sink << "extr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmI(imms);
}}
template <	typename	ARCH>
void OpExtr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( ((op1 << 1) << (imms ^ 31)) | (op2 >> imms) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpExtr_w(CodeType code, uint64_t addr)
{
	return new OpExtr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpExtr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == rm)
		sink << "ror\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(imms);
		else
		sink << "extr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmI(imms);
}}
template <	typename	ARCH>
void OpExtr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( ((op1 << 1) << (imms ^ 63)) | (op2 >> imms) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpExtr_x(CodeType code, uint64_t addr)
{
	return new OpExtr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpHlt<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "hlt\t" << DisasmI(imm,16);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpHlt(CodeType code, uint64_t addr)
{
	return new OpHlt<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpHvc<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "hvc\t" << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpHvc<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.CallHypervisor( imm );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpHvc(CodeType code, uint64_t addr)
{
	return new OpHvc<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdar_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldar\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdar_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdar_w(CodeType code, uint64_t addr)
{
	return new OpLdar_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdar_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldar\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdar_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdar_x(CodeType code, uint64_t addr)
{
	return new OpLdar_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdarb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldarb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdarb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdarb_w(CodeType code, uint64_t addr)
{
	return new OpLdarb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdarh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldarh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdarh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdarh_w(CodeType code, uint64_t addr)
{
	return new OpLdarh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxp\t" << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		cpu.SetExclusiveMonitors( addr, 8 );
		U32 data0( cpu.MemRead32( addr + U64(0) ) ),
		data1( cpu.MemRead32( addr + U64(4) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxp_w(CodeType code, uint64_t addr)
{
	return new OpLdaxp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxp\t" << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		cpu.SetExclusiveMonitors( addr, 16 );
		U64 data0( cpu.MemRead64( addr + U64(0) ) ),
		data1( cpu.MemRead64( addr + U64(8) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxp_x(CodeType code, uint64_t addr)
{
	return new OpLdaxp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 4 );
		cpu.SetGZR(rt, cpu.MemRead32( addr ));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxr_w(CodeType code, uint64_t addr)
{
	return new OpLdaxr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 8 );
		cpu.SetGZR(rt, cpu.MemRead64( addr ));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxr_x(CodeType code, uint64_t addr)
{
	return new OpLdaxr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 1 );
		cpu.SetGZR(rt, U64(cpu.MemRead8( addr )));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxrb_w(CodeType code, uint64_t addr)
{
	return new OpLdaxrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdaxrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldaxrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdaxrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 2 );
		cpu.SetGZR(rt, U64(cpu.MemRead16( addr )));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdaxrh_w(CodeType code, uint64_t addr)
{
	return new OpLdaxrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "n") << "p\t" << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		/* TODO: catch Non-temporal hint (am == 0) */
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U32 data0( cpu.MemRead32( addr + U64(0) ) ),
		data1( cpu.MemRead32( addr + U64(4) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdp_w(CodeType code, uint64_t addr)
{
	return new OpLdp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "n") << "p\t" << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		/* TODO: catch Non-temporal hint (am == 0) */
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U64 data0( cpu.MemRead64( addr + U64(0) ) ),
		data1( cpu.MemRead64( addr + U64(8) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdp_x(CodeType code, uint64_t addr)
{
	return new OpLdp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdpsw_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldpsw\t" << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdpsw_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S32 data0( cpu.MemRead32( addr + U64(0) ) ),
		data1( cpu.MemRead32( addr + U64(4) ) );
		cpu.SetGZR(rt,  U64(data0));
		cpu.SetGZR(rt2, U64(data1));
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdpsw_xxi(CodeType code, uint64_t addr)
{
	return new OpLdpsw_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "r\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdr_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wxi(CodeType code, uint64_t addr)
{
	return new OpLdr_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdr_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wuo(CodeType code, uint64_t addr)
{
	return new OpLdr_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "r\t" << DisasmGZXR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdr_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xxi(CodeType code, uint64_t addr)
{
	return new OpLdr_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdr_xuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xuo(CodeType code, uint64_t addr)
{
	return new OpLdr_xuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpLdr_wlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 addr( cpu.GetPC() + U64(S64(imm)) );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wlit(CodeType code, uint64_t addr)
{
	return new OpLdr_wlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpLdr_xlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 addr( cpu.GetPC() + U64(S64(imm)) );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xlit(CodeType code, uint64_t addr)
{
	return new OpLdr_xlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wxwu(CodeType code, uint64_t addr)
{
	return new OpLdr_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wxxu(CodeType code, uint64_t addr)
{
	return new OpLdr_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wxws(CodeType code, uint64_t addr)
{
	return new OpLdr_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_wxxs(CodeType code, uint64_t addr)
{
	return new OpLdr_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_xxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xxwu(CodeType code, uint64_t addr)
{
	return new OpLdr_xxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_xxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xxxu(CodeType code, uint64_t addr)
{
	return new OpLdr_xxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_xxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xxws(CodeType code, uint64_t addr)
{
	return new OpLdr_xxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdr_xxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdr_xxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.MemRead64(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdr_xxxs(CodeType code, uint64_t addr)
{
	return new OpLdr_xxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rb\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrb_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wxi(CodeType code, uint64_t addr)
{
	return new OpLdrb_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrb_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wuo(CodeType code, uint64_t addr)
{
	return new OpLdrb_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrb_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wxwu(CodeType code, uint64_t addr)
{
	return new OpLdrb_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrb_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wxxu(CodeType code, uint64_t addr)
{
	return new OpLdrb_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrb_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wxws(CodeType code, uint64_t addr)
{
	return new OpLdrb_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrb_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrb_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrb_wxxs(CodeType code, uint64_t addr)
{
	return new OpLdrb_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rh\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrh_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wxi(CodeType code, uint64_t addr)
{
	return new OpLdrh_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrh_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, typename ARCH::U32(data));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wuo(CodeType code, uint64_t addr)
{
	return new OpLdrh_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrh_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wxwu(CodeType code, uint64_t addr)
{
	return new OpLdrh_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrh_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wxxu(CodeType code, uint64_t addr)
{
	return new OpLdrh_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrh_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wxws(CodeType code, uint64_t addr)
{
	return new OpLdrh_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrh_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrh_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrh_wxxs(CodeType code, uint64_t addr)
{
	return new OpLdrh_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rsb\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrsb_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8  S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, U32(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wxi(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8  S8;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		S8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, U32(S32(data)));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wuo(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rsb\t" << DisasmGZXR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrsb_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8  S8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, U64(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xxi(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_xuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8  S8;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		S8 data( cpu.MemRead8(addr) );
		cpu.SetGZR(rt, U64(S64(data)));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xuo(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wxwu(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wxxu(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wxws(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_wxxs(CodeType code, uint64_t addr)
{
	return new OpLdrsb_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_xxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xxwu(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_xxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xxxu(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_xxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xxws(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsb_xxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsb_xxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S8(cpu.MemRead8(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsb_xxxs(CodeType code, uint64_t addr)
{
	return new OpLdrsb_xxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rsh\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrsh_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, U32(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wxi(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		S16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, U32(S32(data)));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wuo(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rsh\t" << DisasmGZXR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrsh_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, U64(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xxi(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_xuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		S16 data( cpu.MemRead16(addr) );
		cpu.SetGZR(rt, U64(S64(data)));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xuo(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wxwu(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wxxu(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wxws(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( S32(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_wxxs(CodeType code, uint64_t addr)
{
	return new OpLdrsh_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_xxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xxwu(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_xxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xxxu(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_xxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xxws(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsh_xxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsh_xxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S16(cpu.MemRead16(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsh_xxxs(CodeType code, uint64_t addr)
{
	return new OpLdrsh_xxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xlit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpLdrsw_xlit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;

		U64 addr( cpu.GetPC() + U64(S64(imm)) );
		U64 data( S64(S32( cpu.MemRead32(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xlit(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xlit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ld" << (am ? "" : "u") << "rsw\t" << DisasmGZXR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpLdrsw_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32  S32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		S32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, U64(data));
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xxi(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpLdrsw_xuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32  S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		S32 data( cpu.MemRead32(addr) );
		cpu.SetGZR(rt, U64(S64(data)));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xuo(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsw_xxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S32(cpu.MemRead32(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xxwu(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsw_xxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S32(cpu.MemRead32(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xxxu(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsw_xxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S32(cpu.MemRead32(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xxws(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdrsw_xxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpLdrsw_xxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( S64(S32(cpu.MemRead32(addr))) );
		cpu.SetGZR(rt, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdrsw_xxxs(CodeType code, uint64_t addr)
{
	return new OpLdrsw_xxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtr_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtr_wbo(CodeType code, uint64_t addr)
{
	return new OpLdtr_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtr_xbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtr_xbo(CodeType code, uint64_t addr)
{
	return new OpLdtr_xbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrb_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrb_wbo(CodeType code, uint64_t addr)
{
	return new OpLdtrb_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrh_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrh_wbo(CodeType code, uint64_t addr)
{
	return new OpLdtrh_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrsb_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrsb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrsb_wbo(CodeType code, uint64_t addr)
{
	return new OpLdtrsb_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrsb_xbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrsb\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrsb_xbo(CodeType code, uint64_t addr)
{
	return new OpLdtrsb_xbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrsh_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrsh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrsh_wbo(CodeType code, uint64_t addr)
{
	return new OpLdtrsh_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrsh_xbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrsh\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrsh_xbo(CodeType code, uint64_t addr)
{
	return new OpLdtrsh_xbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdtrsw_xbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldtrsw\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdtrsw_xbo(CodeType code, uint64_t addr)
{
	return new OpLdtrsw_xbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxp\t" << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		cpu.SetExclusiveMonitors( addr, 8 );
		U32 data0( cpu.MemRead32( addr + U64(0) ) ),
		data1( cpu.MemRead32( addr + U64(4) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxp_w(CodeType code, uint64_t addr)
{
	return new OpLdxp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxp\t" << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		cpu.SetExclusiveMonitors( addr, 16 );
		U64 data0( cpu.MemRead64( addr + U64(0) ) ),
		data1( cpu.MemRead64( addr + U64(8) ) );
		cpu.SetGZR(rt,  data0);
		cpu.SetGZR(rt2, data1);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxp_x(CodeType code, uint64_t addr)
{
	return new OpLdxp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 4 );
		cpu.SetGZR(rt, cpu.MemRead32( addr ));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxr_w(CodeType code, uint64_t addr)
{
	return new OpLdxr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 8 );
		cpu.SetGZR(rt, cpu.MemRead64( addr ));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxr_x(CodeType code, uint64_t addr)
{
	return new OpLdxr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 1 );
		cpu.SetGZR(rt, U64(cpu.MemRead8( addr )));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxrb_w(CodeType code, uint64_t addr)
{
	return new OpLdxrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdxrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ldxrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdxrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		cpu.SetExclusiveMonitors( addr, 2 );
		cpu.SetGZR(rt, U64(cpu.MemRead16( addr )));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdxrh_w(CodeType code, uint64_t addr)
{
	return new OpLdxrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLsl_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "lsl\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpLsl_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( op1 << (op2 & U32(0b11111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLsl_www(CodeType code, uint64_t addr)
{
	return new OpLsl_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLsl_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "lsl\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpLsl_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( op1 << (op2 & U64(0b111111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLsl_xxx(CodeType code, uint64_t addr)
{
	return new OpLsl_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLsr_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "lsr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpLsr_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( op1 >> (op2 & U32(0b11111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLsr_www(CodeType code, uint64_t addr)
{
	return new OpLsr_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLsr_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "lsr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpLsr_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( op1 >> (op2 & U64(0b111111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLsr_xxx(CodeType code, uint64_t addr)
{
	return new OpLsr_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMadd_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "mul\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "madd\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZWR(ra);
}}
template <	typename	ARCH>
void OpMadd_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), acc( cpu.GetGZR(ra) ), res( acc + op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMadd_w(CodeType code, uint64_t addr)
{
	return new OpMadd_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMadd_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "mul\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
		else
		sink << "madd\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpMadd_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( cpu.GetGZR(ra) + op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMadd_x(CodeType code, uint64_t addr)
{
	return new OpMadd_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMov_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "mov\t" << DisasmGZWR(rd) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpMov_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.SetGZR(rd, typename ARCH::U64(imm));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMov_wi(CodeType code, uint64_t addr)
{
	return new OpMov_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMov_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "mov\t" << DisasmGZXR(rd) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpMov_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.SetGZR(rd, typename ARCH::U64(imm));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMov_xi(CodeType code, uint64_t addr)
{
	return new OpMov_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMovk_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "movk\t" << DisasmGZWR(rd) << ", " << DisasmI(imm,16) << DisasmINZ(", lsl ",shift);
}}
template <	typename	ARCH>
void OpMovk_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 src( cpu.GetGZR(rd) ), mask( ~(uint32_t(0xffff) << shift) ), res( (src & mask) | (U32(imm) << shift) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMovk_w(CodeType code, uint64_t addr)
{
	return new OpMovk_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMovk_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "movk\t" << DisasmGZXR(rd) << ", " << DisasmI(imm,16) << DisasmINZ(", lsl ",shift);
}}
template <	typename	ARCH>
void OpMovk_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 src( cpu.GetGZR(rd) ), mask( ~(uint64_t(0xffff) << shift) ), res( (src & mask) | (U64(imm) << shift) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMovk_x(CodeType code, uint64_t addr)
{
	return new OpMovk_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMrs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sysreg->DisasmRead(op0, op1, crn, crm, op2, rt, sink);
}}
template <	typename	ARCH>
void OpMrs<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.CheckSystemAccess(op1);

		cpu.SetGZR(rt, sysreg->Read(op0, op1, crn, crm, op2, cpu));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMrs(CodeType code, uint64_t addr)
{
	return new OpMrs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMsub_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "mneg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "msub\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZWR(ra);
}}
template <	typename	ARCH>
void OpMsub_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), acc( cpu.GetGZR(ra) ), res( acc - op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMsub_w(CodeType code, uint64_t addr)
{
	return new OpMsub_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpMsub_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "mneg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
		else
		sink << "msub\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpMsub_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( cpu.GetGZR(ra) - op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpMsub_x(CodeType code, uint64_t addr)
{
	return new OpMsub_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpNop<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "nop";
}}
template <	typename	ARCH>
void OpNop<	ARCH>::execute( ARCH & cpu)
{
	{
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpNop(CodeType code, uint64_t addr)
{
	return new OpNop<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "orn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpOrn_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_wlsl(CodeType code, uint64_t addr)
{
	return new OpOrn_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_wlsr(CodeType code, uint64_t addr)
{
	return new OpOrn_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_wasr(CodeType code, uint64_t addr)
{
	return new OpOrn_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_wror(CodeType code, uint64_t addr)
{
	return new OpOrn_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "orn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpOrn_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_xlsl(CodeType code, uint64_t addr)
{
	return new OpOrn_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_xlsr(CodeType code, uint64_t addr)
{
	return new OpOrn_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_xasr(CodeType code, uint64_t addr)
{
	return new OpOrn_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrn_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mvn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "orn\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrn_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 | ~op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrn_xror(CodeType code, uint64_t addr)
{
	return new OpOrn_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGSWR(rd) << ", " << DisasmI(imm,16);
		else
		sink << "orr\t" << DisasmGSWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpOrr_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGZR(rn)), op2(imm), res = op1 | op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_wi(CodeType code, uint64_t addr)
{
	return new OpOrr_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGSXR(rd) << ", " << DisasmI(imm,16);
		else
		sink << "orr\t" << DisasmGSXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpOrr_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGZR(rn)), op2(imm), res = op1 | op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_xi(CodeType code, uint64_t addr)
{
	return new OpOrr_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "orr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpOrr_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_wlsl(CodeType code, uint64_t addr)
{
	return new OpOrr_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "orr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpOrr_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_xlsl(CodeType code, uint64_t addr)
{
	return new OpOrr_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_wlsr(CodeType code, uint64_t addr)
{
	return new OpOrr_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_xlsr(CodeType code, uint64_t addr)
{
	return new OpOrr_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_wasr(CodeType code, uint64_t addr)
{
	return new OpOrr_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_xasr(CodeType code, uint64_t addr)
{
	return new OpOrr_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_wror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_wror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( RotateRight(U32(cpu.GetGZR(rm)), imm) ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_wror(CodeType code, uint64_t addr)
{
	return new OpOrr_wror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpOrr_xror<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "mov\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
		else
		sink << "orr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", ror " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpOrr_xror<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( RotateRight(U64(cpu.GetGZR(rm)), imm) ), res = op1 | op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpOrr_xror(CodeType code, uint64_t addr)
{
	return new OpOrr_xror<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrfm_lit<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "prfm\t" << DisasmI(rt,16) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpPrfm_lit<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		cpu.PrefetchMemory( rt, cpu.GetPC() + U64(S64(imm)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrfm_lit(CodeType code, uint64_t addr)
{
	return new OpPrfm_lit<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrefetchMemory_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "PrefetchMemory\t" << DisasmI(rt,16) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpPrefetchMemory_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		cpu.PrefetchMemory( rt, cpu.GetGSR(rn) + U64(imm) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrefetchMemory_xi(CodeType code, uint64_t addr)
{
	return new OpPrefetchMemory_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrefetchMemory_xws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "PrefetchMemory\t" << DisasmI(rt,16) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpPrefetchMemory_xws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		cpu.PrefetchMemory( rt, cpu.GetGSR(rn) + U64(S64(S32(cpu.GetGZR(rm))) << shift));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrefetchMemory_xws(CodeType code, uint64_t addr)
{
	return new OpPrefetchMemory_xws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrefetchMemory_xwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "PrefetchMemory\t" << DisasmI(rt,16) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpPrefetchMemory_xwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		cpu.PrefetchMemory( rt, cpu.GetGSR(rn) + (U64(U32(cpu.GetGZR(rm))) << shift) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrefetchMemory_xwu(CodeType code, uint64_t addr)
{
	return new OpPrefetchMemory_xwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrefetchMemory_xx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "PrefetchMemory\t" << DisasmI(rt,16) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm);
		if (opt) sink << ",sxtx" << DisasmINZ(" ", shift) << "]";
		else     sink << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpPrefetchMemory_xx<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.PrefetchMemory( rt, cpu.GetGSR(rn) + (cpu.GetGZR(rm) << shift) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrefetchMemory_xx(CodeType code, uint64_t addr)
{
	return new OpPrefetchMemory_xx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpPrfum<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "prfum\t" << DisasmI(rt,16) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpPrfum<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		cpu.PrefetchMemory( rt, cpu.GetGSR(rn) + U64(imm) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpPrfum(CodeType code, uint64_t addr)
{
	return new OpPrfum<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRbit_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rbit\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
}}
template <	typename	ARCH>
void OpRbit_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res( cpu.GetGZR(rn) );
		uint32_t const masks[] = {0x55555555, 0x33333333, 0x0f0f0f0f, 0x00ff00ff, 0x0000ffff};

		for (unsigned i = 0; i < 5; ++i) {
			unsigned shift = (1<<i);
			U32 mask = U32(masks[i]);
			res = ((res >> shift) & mask) | ((res & mask) << shift);
		}

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRbit_w(CodeType code, uint64_t addr)
{
	return new OpRbit_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRbit_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rbit\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpRbit_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res( cpu.GetGZR(rn) );
		uint64_t const masks[] = {0x5555555555555555ull, 0x3333333333333333ull, 0x0f0f0f0f0f0f0f0full, 0x00ff00ff00ff00ffull, 0x0000ffff0000ffffull, 0x00000000ffffffffull};

		for (unsigned i = 0; i < 6; ++i) {
			unsigned shift = (1<<i);
			U64 mask = U64(masks[i]);
			res = ((res >> shift) & mask) | ((res & mask) << shift);
		}

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRbit_x(CodeType code, uint64_t addr)
{
	return new OpRbit_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRet<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 30)
		sink << "ret";
		else
		sink << "ret\t" << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpRet<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.BranchTo( cpu.GetGZR(rn), ARCH::B_RET );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRet(CodeType code, uint64_t addr)
{
	return new OpRet<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRev_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rev\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
}}
template <	typename	ARCH>
void OpRev_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 const msk( 0xff );
		U32 src( cpu.GetGZR(rn) ), res( ((src << 24) & (msk << 24)) | ((src << 8) & (msk << 16)) | ((src >> 8) & (msk << 8)) | ((src >> 24) & (msk << 0)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRev_w(CodeType code, uint64_t addr)
{
	return new OpRev_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRev_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rev\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpRev_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 const msk( 0xff );
		U64 src( cpu.GetGZR(rn) ), res( ((src << 56) & (msk << 56)) | ((src << 40) & (msk << 48)) | ((src << 24) & (msk << 40)) | ((src << 8) & (msk << 32)) | ((src >> 8) & (msk << 24)) | ((src >> 24) & (msk << 16)) | ((src >> 40) & (msk << 8)) | ((src >> 56) & (msk << 0)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRev_x(CodeType code, uint64_t addr)
{
	return new OpRev_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRev16_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rev16\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
}}
template <	typename	ARCH>
void OpRev16_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 res( cpu.GetGZR(rn) );
		uint32_t const masks[] = {0x00ff00ff};

		for (unsigned i = 0; i < 1; ++i) {
			unsigned shift = (8<<i);
			U32 mask = U32(masks[i]);
			res = ((res >> shift) & mask) | ((res & mask) << shift);
		}

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRev16_w(CodeType code, uint64_t addr)
{
	return new OpRev16_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRev16_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rev16\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpRev16_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res( cpu.GetGZR(rn) );
		uint64_t const masks[] = {0x00ff00ff00ff00ffull};

		for (unsigned i = 0; i < 1; ++i) {
			unsigned shift = (8<<i);
			U64 mask = U64(masks[i]);
			res = ((res >> shift) & mask) | ((res & mask) << shift);
		}

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRev16_x(CodeType code, uint64_t addr)
{
	return new OpRev16_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRev32_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "rev32\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
}}
template <	typename	ARCH>
void OpRev32_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 res( cpu.GetGZR(rn) );
		uint64_t const masks[] = {0x00ff00ff00ff00ffull, 0x0000ffff0000ffffull};

		for (unsigned i = 0; i < 2; ++i) {
			unsigned shift = (8<<i);
			U64 mask = U64(masks[i]);
			res = ((res >> shift) & mask) | ((res & mask) << shift);
		}

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRev32_x(CodeType code, uint64_t addr)
{
	return new OpRev32_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRor_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ror\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpRor_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( RotateRight(op1, op2 & U32(0b11111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRor_www(CodeType code, uint64_t addr)
{
	return new OpRor_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpRor_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "ror\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpRor_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( RotateRight(op1, op2 & U64(0b111111)) );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpRor_xxx(CodeType code, uint64_t addr)
{
	return new OpRor_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbc_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "ngc\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm);
		else
		sink << "sbc\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpSbc_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::BOOL BOOL;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2 - U32(not BOOL(cpu.GetCarry()));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbc_www(CodeType code, uint64_t addr)
{
	return new OpSbc_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbc_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "ngc\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm);
		else
		sink << "sbc\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpSbc_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::BOOL BOOL;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2 - U64(not BOOL(cpu.GetCarry()));
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbc_xxx(CodeType code, uint64_t addr)
{
	return new OpSbc_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbcs_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "ngcs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm);
		else
		sink << "sbcs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpSbcs_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::BOOL BOOL;

		BOOL borrow( not BOOL(cpu.GetCarry()) );
		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2 - U32(borrow);
		cpu.SetGZR(rd, res);

		BOOL n = S32(res) < S32(0), z = res == U32(0);
		if (cpu.Test(borrow))
		cpu.SetNZCV( n, z, op1 >  op2, n xor (S32(op1) <= S32(op2)) );
		else
		cpu.SetNZCV( n, z, op1 >= op2, n xor (S32(op1) <  S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbcs_www(CodeType code, uint64_t addr)
{
	return new OpSbcs_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbcs_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "ngcs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm);
		else
		sink << "sbcs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpSbcs_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::BOOL BOOL;

		BOOL borrow( not BOOL(cpu.GetCarry()) );
		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = op1 - op2 - U64(borrow);
		cpu.SetGZR(rd, res);

		BOOL n = S64(res) < S64(0), z = res == U64(0);
		if (cpu.Test(borrow))
		cpu.SetNZCV( n, z, op1 >  op2, n xor (S64(op1) <= S64(op2)) );
		else
		cpu.SetNZCV( n, z, op1 >= op2, n xor (S64(op1) <  S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbcs_xxx(CodeType code, uint64_t addr)
{
	return new OpSbcs_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbfm_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms == 0b11111)
		sink << "asr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(immr);
		else if (imms < immr)
		sink << "sbfiz\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(-immr&31) << ", " << DisasmI(imms+1);
		else if ((immr == 0) and (imms == 0b00111))
		sink << "sxtb\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
		else if ((immr == 0) and (imms == 0b01111))
		sink << "sxth\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
		else
		sink << "sbfx\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpSbfm_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		unsigned l = (imms ^ 31), r = (l + immr) & 31;

		U32 src( cpu.GetGZR(rn) ), res( S32(src << l) >> r );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbfm_w(CodeType code, uint64_t addr)
{
	return new OpSbfm_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSbfm_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms == 0b111111)
		sink << "asr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(immr);
		else if (imms < immr)
		sink << "sbfiz\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(-immr&63) << ", " << DisasmI(imms+1);
		else if ((immr == 0) and (imms == 0b000111))
		sink << "sxtb\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
		else if ((immr == 0) and (imms == 0b001111))
		sink << "sxth\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
		else if ((immr == 0) and (imms == 0b011111))
		sink << "sxtw\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
		else
		sink << "sbfx\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpSbfm_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;
		unsigned l = (imms ^ 63), r = (l + immr) & 63;

		U64 src( cpu.GetGZR(rn) ), res( S64(src << l) >> r );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSbfm_x(CodeType code, uint64_t addr)
{
	return new OpSbfm_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSdiv_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sdiv\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpSdiv_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		S32 const zero(0);
		S32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = cpu.Test(op2 == zero) ? zero : (op1 / op2);
		cpu.SetGZR(rd, U32(res));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSdiv_www(CodeType code, uint64_t addr)
{
	return new OpSdiv_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSdiv_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sdiv\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpSdiv_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		S64 const zero(0);
		S64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = cpu.Test(op2 == zero) ? zero : (op1 / op2);
		cpu.SetGZR(rd, U64(res));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSdiv_xxx(CodeType code, uint64_t addr)
{
	return new OpSdiv_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSmaddl_xw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "smull\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "smaddl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpSmaddl_xw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		S64 op1( S32( cpu.GetGZR(rn) ) ), op2( S32( cpu.GetGZR(rm) ) ), op3( cpu.GetGZR(ra ) ), res( op3 + (op1 * op2) );
		cpu.SetGZR(rd, U64(res));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSmaddl_xw(CodeType code, uint64_t addr)
{
	return new OpSmaddl_xw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSmc<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "smc\t" << DisasmI(imm,16);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSmc(CodeType code, uint64_t addr)
{
	return new OpSmc<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSmsubl_xw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "smnegl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "smsubl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpSmsubl_xw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		S64 op1( S32( cpu.GetGZR(rn) ) ), op2( S32( cpu.GetGZR(rm) ) ), op3( cpu.GetGZR(ra ) ), res( op3 - (op1 * op2) );
		cpu.SetGZR(rd, U64(res));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSmsubl_xw(CodeType code, uint64_t addr)
{
	return new OpSmsubl_xw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSmulh<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "smulh\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpSmulh<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		S64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( SignedMultiplyHigh64( cpu, op1, op2 ) );

		cpu.SetGZR(rd, U64(res));
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSmulh(CodeType code, uint64_t addr)
{
	return new OpSmulh<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlr_w(CodeType code, uint64_t addr)
{
	return new OpStlr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlr_x(CodeType code, uint64_t addr)
{
	return new OpStlr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlrb_w(CodeType code, uint64_t addr)
{
	return new OpStlrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlrh_w(CodeType code, uint64_t addr)
{
	return new OpStlrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxp\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		if (cpu.ExclusiveMonitorsPass(addr, 8)) {
			cpu.MemWrite32( addr + U64(0), data0 );
			cpu.MemWrite32( addr + U64(4), data1 );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxp_w(CodeType code, uint64_t addr)
{
	return new OpStlxp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxp\t" << DisasmGZWR(rs) << ", " << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		if (cpu.ExclusiveMonitorsPass(addr, 16)) {
			cpu.MemWrite64( addr + U64(0), data0 );
			cpu.MemWrite64( addr + U64(8), data1 );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxp_x(CodeType code, uint64_t addr)
{
	return new OpStlxp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxr\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 4)) {
			cpu.MemWrite32( addr, U32(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxr_w(CodeType code, uint64_t addr)
{
	return new OpStlxr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxr\t" << DisasmGZWR(rs) << ", " << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 8)) {
			cpu.MemWrite64( addr, cpu.GetGZR(rt) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxr_x(CodeType code, uint64_t addr)
{
	return new OpStlxr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxrb\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8  U8;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 1)) {
			cpu.MemWrite8( addr, U8(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxrb_w(CodeType code, uint64_t addr)
{
	return new OpStlxrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStlxrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stlxrh\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStlxrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 2)) {
			cpu.MemWrite16( addr, U16(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStlxrh_w(CodeType code, uint64_t addr)
{
	return new OpStlxrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "n") << "p\t" << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		/* TODO: catch Non-temporal hint (am == 0) */
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U32 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		cpu.MemWrite32( addr + U64(0), data0 );
		cpu.MemWrite32( addr + U64(4), data1 );
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStp_w(CodeType code, uint64_t addr)
{
	return new OpStp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "n") << "p\t" << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		/* TODO: catch Non-temporal hint (am == 0) */
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U64 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		cpu.MemWrite64( addr + U64(0), data0 );
		cpu.MemWrite64( addr + U64(8), data1 );
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStp_x(CodeType code, uint64_t addr)
{
	return new OpStp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "u") << "r\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStr_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wxi(CodeType code, uint64_t addr)
{
	return new OpStr_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpStr_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wuo(CodeType code, uint64_t addr)
{
	return new OpStr_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "u") << "r\t" << DisasmGZXR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStr_xxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xxi(CodeType code, uint64_t addr)
{
	return new OpStr_xxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpStr_xuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xuo(CodeType code, uint64_t addr)
{
	return new OpStr_xuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wxwu(CodeType code, uint64_t addr)
{
	return new OpStr_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpStr_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wxxu(CodeType code, uint64_t addr)
{
	return new OpStr_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wxws(CodeType code, uint64_t addr)
{
	return new OpStr_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U32 data( cpu.GetGZR(rt) );
		cpu.MemWrite32(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_wxxs(CodeType code, uint64_t addr)
{
	return new OpStr_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_xxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xxwu(CodeType code, uint64_t addr)
{
	return new OpStr_xxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpStr_xxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xxxu(CodeType code, uint64_t addr)
{
	return new OpStr_xxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_xxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xxws(CodeType code, uint64_t addr)
{
	return new OpStr_xxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStr_xxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "str\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStr_xxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U64 data( cpu.GetGZR(rt) );
		cpu.MemWrite64(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStr_xxxs(CodeType code, uint64_t addr)
{
	return new OpStr_xxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "u") << "rb\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStrb_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wxi(CodeType code, uint64_t addr)
{
	return new OpStrb_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpStrb_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wuo(CodeType code, uint64_t addr)
{
	return new OpStrb_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrb_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U8 U8;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wxwu(CodeType code, uint64_t addr)
{
	return new OpStrb_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpStrb_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U8 U8;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wxxu(CodeType code, uint64_t addr)
{
	return new OpStrb_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrb_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U8 U8;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wxws(CodeType code, uint64_t addr)
{
	return new OpStrb_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrb_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrb_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U8 U8;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U8 data( cpu.GetGZR(rt) );
		cpu.MemWrite8(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrb_wxxs(CodeType code, uint64_t addr)
{
	return new OpStrb_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wxi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "st" << (am ? "" : "u") << "rh\t" << DisasmGZWR(rt) << ", " << DisasmMemoryRI(rn,imm,am);
}}
template <	typename	ARCH>
void OpStrh_wxi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) ), oaddr( addr + U64(imm) );
		addr = (am == 1 ? addr : oaddr);
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
		if (am & 1)
		cpu.SetGSR(rn, oaddr);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wxi(CodeType code, uint64_t addr)
{
	return new OpStrh_wxi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wuo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}
template <	typename	ARCH>
void OpStrh_wuo<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) + U64(imm) );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wuo(CodeType code, uint64_t addr)
{
	return new OpStrh_wuo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wxwu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",uxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrh_wxwu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wxwu(CodeType code, uint64_t addr)
{
	return new OpStrh_wxwu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wxxu<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << DisasmINZ(",lsl ",shift) << "]";
}}
template <	typename	ARCH>
void OpStrh_wxxu<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 offset( U64(U64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wxxu(CodeType code, uint64_t addr)
{
	return new OpStrh_wxxu<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wxws<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZWR(rm) << ",sxtw" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrh_wxws<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S32(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wxws(CodeType code, uint64_t addr)
{
	return new OpStrh_wxws<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStrh_wxxs<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "strh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmGZXR(rm) << ",sxtx" << DisasmINZ(" ", shift) << "]";
}}
template <	typename	ARCH>
void OpStrh_wxxs<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 offset( S64(S64(cpu.GetGZR(rm))) << shift ), addr( cpu.GetGSR(rn) + offset );
		U16 data( cpu.GetGZR(rt) );
		cpu.MemWrite16(addr, data);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStrh_wxxs(CodeType code, uint64_t addr)
{
	return new OpStrh_wxxs<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSttr_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sttr\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSttr_wbo(CodeType code, uint64_t addr)
{
	return new OpSttr_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSttr_xbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sttr\t" << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSttr_xbo(CodeType code, uint64_t addr)
{
	return new OpSttr_xbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSttrb_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sttrb\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSttrb_wbo(CodeType code, uint64_t addr)
{
	return new OpSttrb_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSttrh_wbo<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sttrh\t" << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "," << DisasmI(imm) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSttrh_wbo(CodeType code, uint64_t addr)
{
	return new OpSttrh_wbo<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxp\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", " << DisasmGZWR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		if (cpu.ExclusiveMonitorsPass(addr, 8)) {
			cpu.MemWrite32( addr + U64(0), data0 );
			cpu.MemWrite32( addr + U64(4), data1 );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxp_w(CodeType code, uint64_t addr)
{
	return new OpStxp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxp\t" << DisasmGZWR(rs) << ", " << DisasmGZXR(rt) << ", " << DisasmGZXR(rt2) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 data0( cpu.GetGZR(rt) ), data1( cpu.GetGZR(rt2) );
		if (cpu.ExclusiveMonitorsPass(addr, 16)) {
			cpu.MemWrite64( addr + U64(0), data0 );
			cpu.MemWrite64( addr + U64(8), data1 );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxp_x(CodeType code, uint64_t addr)
{
	return new OpStxp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxr\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 4)) {
			cpu.MemWrite32( addr, U32(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxr_w(CodeType code, uint64_t addr)
{
	return new OpStxr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxr\t" << DisasmGZWR(rs) << ", " << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 8)) {
			cpu.MemWrite64( addr, cpu.GetGZR(rt) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxr_x(CodeType code, uint64_t addr)
{
	return new OpStxr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxrb\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8  U8;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 1)) {
			cpu.MemWrite8( addr, U8(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxrb_w(CodeType code, uint64_t addr)
{
	return new OpStxrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpStxrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "stxrh\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpStxrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr = cpu.GetGSR(rn);
		if (cpu.ExclusiveMonitorsPass(addr, 2)) {
			cpu.MemWrite16( addr, U16(cpu.GetGZR(rt)) );
			cpu.SetGZR(rs, U64(0));
			} else {
			cpu.SetGZR(rs, U64(1));
		}
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpStxrh_w(CodeType code, uint64_t addr)
{
	return new OpStxrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wsxtb(CodeType code, uint64_t addr)
{
	return new OpSub_wsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wsxth(CodeType code, uint64_t addr)
{
	return new OpSub_wsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wsxtw(CodeType code, uint64_t addr)
{
	return new OpSub_wsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wsxtx(CodeType code, uint64_t addr)
{
	return new OpSub_wsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wuxtb(CodeType code, uint64_t addr)
{
	return new OpSub_wuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wuxth(CodeType code, uint64_t addr)
{
	return new OpSub_wuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wuxtw(CodeType code, uint64_t addr)
{
	return new OpSub_wuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_wuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wuxtx(CodeType code, uint64_t addr)
{
	return new OpSub_wuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xsxtb(CodeType code, uint64_t addr)
{
	return new OpSub_xsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xsxth(CodeType code, uint64_t addr)
{
	return new OpSub_xsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xsxtw(CodeType code, uint64_t addr)
{
	return new OpSub_xsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xsxtx(CodeType code, uint64_t addr)
{
	return new OpSub_xsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xuxtb(CodeType code, uint64_t addr)
{
	return new OpSub_xuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xuxth(CodeType code, uint64_t addr)
{
	return new OpSub_xuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xuxtw(CodeType code, uint64_t addr)
{
	return new OpSub_xuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSub_xuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xuxtx(CodeType code, uint64_t addr)
{
	return new OpSub_xuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpSub_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGSR(rn)), op2(imm), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wi(CodeType code, uint64_t addr)
{
	return new OpSub_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "sub\t" << DisasmGSXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpSub_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGSR(rn)), op2(imm), res = op1 - op2;
		cpu.SetGSR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xi(CodeType code, uint64_t addr)
{
	return new OpSub_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "sub\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpSub_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wlsl(CodeType code, uint64_t addr)
{
	return new OpSub_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "sub\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSub_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wlsr(CodeType code, uint64_t addr)
{
	return new OpSub_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "sub\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSub_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_wasr(CodeType code, uint64_t addr)
{
	return new OpSub_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "sub\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpSub_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xlsl(CodeType code, uint64_t addr)
{
	return new OpSub_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "sub\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSub_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xlsr(CodeType code, uint64_t addr)
{
	return new OpSub_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSub_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rn == 31)
		sink << "neg\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "sub\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSub_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSub_xasr(CodeType code, uint64_t addr)
{
	return new OpSub_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wuxtb(CodeType code, uint64_t addr)
{
	return new OpSubs_wuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wuxth(CodeType code, uint64_t addr)
{
	return new OpSubs_wuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wuxtw(CodeType code, uint64_t addr)
{
	return new OpSubs_wuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGSR(rn) ), op2( U32(U64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wuxtx(CodeType code, uint64_t addr)
{
	return new OpSubs_wuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wsxtb(CodeType code, uint64_t addr)
{
	return new OpSubs_wsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wsxth(CodeType code, uint64_t addr)
{
	return new OpSubs_wsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wsxtw(CodeType code, uint64_t addr)
{
	return new OpSubs_wsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmGZWR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_wsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGSR(rn) ), op2( S32(S64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wsxtx(CodeType code, uint64_t addr)
{
	return new OpSubs_wsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xuxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xuxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xuxtb(CodeType code, uint64_t addr)
{
	return new OpSubs_xuxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xuxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xuxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xuxth(CodeType code, uint64_t addr)
{
	return new OpSubs_xuxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xuxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", uxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xuxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xuxtw(CodeType code, uint64_t addr)
{
	return new OpSubs_xuxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xuxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", uxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xuxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGSR(rn) ), op2( U64(U64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xuxtx(CodeType code, uint64_t addr)
{
	return new OpSubs_xuxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xsxtb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtb" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xsxtb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S8(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xsxtb(CodeType code, uint64_t addr)
{
	return new OpSubs_xsxtb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xsxth<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxth" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xsxth<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S16(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xsxth(CodeType code, uint64_t addr)
{
	return new OpSubs_xsxth<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xsxtw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZWR(rm) << ", sxtw" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xsxtw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S32(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xsxtw(CodeType code, uint64_t addr)
{
	return new OpSubs_xsxtw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xsxtx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmGZXR(rm) << ", sxtx" << DisasmINZ(" ", imm);
}}
template <	typename	ARCH>
void OpSubs_xsxtx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGSR(rn) ), op2( S64(S64(cpu.GetGZR(rm))) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xsxtx(CodeType code, uint64_t addr)
{
	return new OpSubs_xsxtx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGSWR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpSubs_wi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U32 U32;

		U32 op1(cpu.GetGSR(rn)), op2(imm), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wi(CodeType code, uint64_t addr)
{
	return new OpSubs_wi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xi<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGSXR(rn) << ", " << DisasmI(imm,16/*?*/);
}}
template <	typename	ARCH>
void OpSubs_xi<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 op1(cpu.GetGSR(rn)), op2(imm), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xi(CodeType code, uint64_t addr)
{
	return new OpSubs_xi<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpSubs_wlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wlsl(CodeType code, uint64_t addr)
{
	return new OpSubs_wlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSubs_wlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( U32(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wlsr(CodeType code, uint64_t addr)
{
	return new OpSubs_wlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_wasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "subs\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSubs_wasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;

		U32 op1( cpu.GetGZR(rn) ), op2( S32(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S32(res) < S32(0), op1 == op2, op1 >= op2, (S32(res) < S32(0)) xor (S32(op1) < S32(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_wasr(CodeType code, uint64_t addr)
{
	return new OpSubs_wasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xlsl<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << DisasmINZ(", lsl ",imm);
}}
template <	typename	ARCH>
void OpSubs_xlsl<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) << imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xlsl(CodeType code, uint64_t addr)
{
	return new OpSubs_xlsl<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xlsr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", lsr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSubs_xlsr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xlsr(CodeType code, uint64_t addr)
{
	return new OpSubs_xlsr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSubs_xasr<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (rd == 31)
		sink << "cmp\t" << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else if (rn == 31)
		sink << "negs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
		else
		sink << "subs\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm) << ", asr " << DisasmI(imm);
}}
template <	typename	ARCH>
void OpSubs_xasr<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 op1( cpu.GetGZR(rn) ), op2( S64(cpu.GetGZR(rm)) >> imm ), res = op1 - op2;
		cpu.SetGZR(rd, res);
		cpu.SetNZCV( S64(res) < S64(0), op1 == op2, op1 >= op2, (S64(res) < S64(0)) xor (S64(op1) < S64(op2)) );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSubs_xasr(CodeType code, uint64_t addr)
{
	return new OpSubs_xasr<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSvc<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "svc\t" << DisasmI(imm,16);
}}
template <	typename	ARCH>
void OpSvc<	ARCH>::execute( ARCH & cpu)
{
	{
		cpu.CallSupervisor( imm );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSvc(CodeType code, uint64_t addr)
{
	return new OpSvc<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpTb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "tb" << (bitval?"nz\t":"z\t");
		if (not pos1)  sink << DisasmGZWR(rt);
		else           sink << DisasmGZXR(rt);
		sink << ", " << DisasmI(pos) << ", 0x" << std::hex << (this->GetAddr()+imm);
}}
template <	typename	ARCH>
void OpTb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::S64 S64;

		U64 operand( cpu.GetGZR(rt) );
		if (cpu.Test( ((operand >> pos) & U64(1)) == U64(bitval) ))
		cpu.BranchTo( cpu.GetPC() + U64(S64(imm)), ARCH::B_JMP );
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpTb(CodeType code, uint64_t addr)
{
	return new OpTb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUbfm_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms == 0b11111)
		sink << "lsr\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(immr);
		else if (immr == (imms+1))
		sink << "lsl\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(31-imms);
		else if (imms < immr)
		sink << "ubfiz\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(-immr&31) << ", " << DisasmI(imms+1);
		else if ((immr == 0) and (imms == 0b111))
		sink << "uxtb\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
		else if ((immr == 0) and (imms == 0b1111))
		sink << "uxth\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn);
		else
		sink << "ubfx\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpUbfm_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		unsigned l = (imms ^ 31), r = (l + immr) & 31;

		U32 src( cpu.GetGZR(rn) ), res( (src << l) >> r );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUbfm_w(CodeType code, uint64_t addr)
{
	return new OpUbfm_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUbfm_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (imms == 0b111111)
		sink << "lsr\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(immr);
		else if (immr == (imms+1))
		sink << "lsl\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(63-imms);
		else if (imms < immr)
		sink << "ubfiz\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(-immr&63) << ", " << DisasmI(imms+1);
		// else if ((immr == 0) and (imms == 0b111))
		//   sink << "uxtb\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
		// else if ((immr == 0) and (imms == 0b1111))
		//   sink << "uxth\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn);
		else
		sink << "ubfx\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmI(immr) << ", " << DisasmI(imms+1-immr);
}}
template <	typename	ARCH>
void OpUbfm_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		unsigned l = (imms ^ 63), r = (l + immr) & 63;

		U64 src( cpu.GetGZR(rn) ), res( (src << l) >> r );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUbfm_x(CodeType code, uint64_t addr)
{
	return new OpUbfm_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUdiv_www<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "udiv\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpUdiv_www<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 const zero(0);
		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = cpu.Test(op2 == zero) ? zero : (op1 / op2);
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUdiv_www(CodeType code, uint64_t addr)
{
	return new OpUdiv_www<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUdiv_xxx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "udiv\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpUdiv_xxx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 const zero(0);
		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res = cpu.Test(op2 == zero) ? zero : (op1 / op2);
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUdiv_xxx(CodeType code, uint64_t addr)
{
	return new OpUdiv_xxx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUmaddl_xw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "umull\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "umaddl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpUmaddl_xw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;

		U64 op1( U32(cpu.GetGZR(rn)) ), op2( U32(cpu.GetGZR(rm)) ), res( cpu.GetGZR(ra) + op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUmaddl_xw(CodeType code, uint64_t addr)
{
	return new OpUmaddl_xw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUmsubl_xw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		if (ra == 31)
		sink << "umnegl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
		else
		sink << "umsubl\t" << DisasmGZXR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm) << ", " << DisasmGZXR(ra);
}}
template <	typename	ARCH>
void OpUmsubl_xw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;
		typedef typename ARCH::U32 U32;

		U64 op1( U32(cpu.GetGZR(rn)) ), op2( U32(cpu.GetGZR(rm)) ), res( cpu.GetGZR(ra) - op1*op2 );
		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUmsubl_xw(CodeType code, uint64_t addr)
{
	return new OpUmsubl_xw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpUmulh<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "umulh\t" << DisasmGZXR(rd) << ", " << DisasmGZXR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpUmulh<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( UnsignedMultiplyHigh64( cpu, op1, op2 ) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpUmulh(CodeType code, uint64_t addr)
{
	return new OpUmulh<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32b<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32b\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32b<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U8(cpu.GetGZR(rm)) ), res( PolyMod2<U32,8>(op1 ^ op2, 0xedb88320) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32b(CodeType code, uint64_t addr)
{
	return new OpCrc32b<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32h<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32h\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32h<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U16(cpu.GetGZR(rm)) ), res( PolyMod2<U32,16>(op1 ^ op2, 0xedb88320) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32h(CodeType code, uint64_t addr)
{
	return new OpCrc32h<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32w\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( PolyMod2<U32,32>(op1 ^ op2, 0xedb88320) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32w(CodeType code, uint64_t addr)
{
	return new OpCrc32w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32x\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpCrc32x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 op1( U32(cpu.GetGZR(rn)) ), op2( cpu.GetGZR(rm) ), res( PolyMod2<U32,64>(op1 ^ op2, 0xedb88320) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32x(CodeType code, uint64_t addr)
{
	return new OpCrc32x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32cb<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32cb\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32cb<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U8(cpu.GetGZR(rm)) ), res( PolyMod2<U32,8>(op1 ^ op2, 0x82f63b78) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32cb(CodeType code, uint64_t addr)
{
	return new OpCrc32cb<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32ch<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32ch\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32ch<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( U16(cpu.GetGZR(rm)) ), res( PolyMod2<U32,16>(op1 ^ op2, 0x82f63b78) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32ch(CodeType code, uint64_t addr)
{
	return new OpCrc32ch<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32cw<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32cw\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZWR(rm);
}}
template <	typename	ARCH>
void OpCrc32cw<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;

		U32 op1( cpu.GetGZR(rn) ), op2( cpu.GetGZR(rm) ), res( PolyMod2<U32,32>(op1 ^ op2, 0x82f63b78) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32cw(CodeType code, uint64_t addr)
{
	return new OpCrc32cw<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCrc32cx<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "crc32cx\t" << DisasmGZWR(rd) << ", " << DisasmGZWR(rn) << ", " << DisasmGZXR(rm);
}}
template <	typename	ARCH>
void OpCrc32cx<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 op1( U32(cpu.GetGZR(rn)) ), op2( cpu.GetGZR(rm) ), res( PolyMod2<U32,64>(op1 ^ op2, 0x82f63b78) );

		cpu.SetGZR(rd, res);
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCrc32cx(CodeType code, uint64_t addr)
{
	return new OpCrc32cx<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCas_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cas" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCas_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 comparevalue( cpu.GetGZR(rs) );

		/*BEG ATOMIC*/
		U32 data( cpu.MemRead32(addr) );

		if (cpu.Test(data == comparevalue))
		cpu.MemWrite32(addr, U32(cpu.GetGZR(rt)));
		cpu.SetGZR(rs, data);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCas_w(CodeType code, uint64_t addr)
{
	return new OpCas_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCas_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cas" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZXR(rs) << ", " << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCas_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 comparevalue( cpu.GetGZR(rs) );

		/*BEG ATOMIC*/
		U64 data( cpu.MemRead64(addr) );

		if (cpu.Test(data == comparevalue))
		cpu.MemWrite64(addr, cpu.GetGZR(rt));
		cpu.SetGZR(rs, data);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCas_x(CodeType code, uint64_t addr)
{
	return new OpCas_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCasb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cas" << (&"a"[!a]) << (&"l"[!l]) << "b\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCasb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U8 comparevalue( cpu.GetGZR(rs) );

		/*BEG ATOMIC*/
		U8 data( cpu.MemRead8(addr) );

		if (cpu.Test(data == comparevalue))
		cpu.MemWrite8(addr, U8(cpu.GetGZR(rt)));
		cpu.SetGZR(rs, typename ARCH::U32(data));
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCasb_w(CodeType code, uint64_t addr)
{
	return new OpCasb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCash_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "cas" << (&"a"[!a]) << (&"l"[!l]) << "h\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCash_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U16 comparevalue( cpu.GetGZR(rs) );

		/*BEG ATOMIC*/
		U16 data( cpu.MemRead16(addr) );

		if (cpu.Test(data == comparevalue))
		cpu.MemWrite16(addr, U16(cpu.GetGZR(rt)));
		cpu.SetGZR(rs, typename ARCH::U32(data));
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCash_w(CodeType code, uint64_t addr)
{
	return new OpCash_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCasp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "casp" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rs|1) << ", " << DisasmGZWR(rt) << ", " << DisasmGZWR(rt|1) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCasp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U32 comparevalue0( cpu.GetGZR(rs+0) ),
		comparevalue1( cpu.GetGZR(rs+1) );

		/*BEG ATOMIC*/
		U32 data0( cpu.MemRead32(addr+U64(0)) ),
		data1( cpu.MemRead32(addr+U64(4)) );

		if (cpu.Test(data0 == comparevalue0 and data1 == comparevalue1))
		{
			cpu.MemWrite32(addr+U64(0), U32(cpu.GetGZR(rt+0)));
			cpu.MemWrite32(addr+U64(4), U32(cpu.GetGZR(rt+1)));
		}
		cpu.SetGZR(rs+0, data0);
		cpu.SetGZR(rs+1, data1);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCasp_w(CodeType code, uint64_t addr)
{
	return new OpCasp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpCasp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "casp" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZXR(rs) << ", " << DisasmGZXR(rs|1) << ", " << DisasmGZXR(rt) << ", " << DisasmGZXR(rt|1) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpCasp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );
		U64 comparevalue0( cpu.GetGZR(rs+0) ),
		comparevalue1( cpu.GetGZR(rs+1) );

		/*BEG ATOMIC*/
		U64 data0( cpu.MemRead64(addr+U64(0)) ),
		data1( cpu.MemRead64(addr+U64(8)) );

		if (cpu.Test(data0 == comparevalue0 and data1 == comparevalue1))
		{
			cpu.MemWrite64(addr+U64(0), cpu.GetGZR(rt+0));
			cpu.MemWrite64(addr+U64(8), cpu.GetGZR(rt+1));
		}
		cpu.SetGZR(rs+0, data0);
		cpu.SetGZR(rs+1, data1);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpCasp_x(CodeType code, uint64_t addr)
{
	return new OpCasp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSwp_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "swp" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpSwp_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 data( cpu.MemRead32(addr) );
		cpu.MemWrite32(addr, U32(cpu.GetGZR(rs)));
		cpu.SetGZR(rt, data);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSwp_w(CodeType code, uint64_t addr)
{
	return new OpSwp_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSwp_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "swp" << (&"a"[!a]) << (&"l"[!l]) << "\t" << DisasmGZXR(rs) << ", " << DisasmGZXR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpSwp_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 data( cpu.MemRead64(addr) );
		cpu.MemWrite64(addr, cpu.GetGZR(rs));
		cpu.SetGZR(rt, data);
		/*END ATOMIC*/
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSwp_x(CodeType code, uint64_t addr)
{
	return new OpSwp_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSwpb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "swp" << (&"a"[!a]) << (&"l"[!l]) << "b\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSwpb_w(CodeType code, uint64_t addr)
{
	return new OpSwpb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpSwph_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		sink << "swp" << (&"a"[!a]) << (&"l"[!l]) << "h\t" << DisasmGZWR(rs) << ", " << DisasmGZWR(rt) << ", [" << DisasmGSXR(rn) << "]";
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpSwph_w(CodeType code, uint64_t addr)
{
	return new OpSwph_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstadd_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "add" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstadd_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( oldval + U32(cpu.GetGZR(rs)) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstadd_w(CodeType code, uint64_t addr)
{
	return new OpLdstadd_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstadd_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "add" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstadd_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( oldval + U64(cpu.GetGZR(rs)) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstadd_x(CodeType code, uint64_t addr)
{
	return new OpLdstadd_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstaddb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "add" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstaddb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( oldval + U8(cpu.GetGZR(rs)) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstaddb_w(CodeType code, uint64_t addr)
{
	return new OpLdstaddb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstaddh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "add" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstaddh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( oldval + U16(cpu.GetGZR(rs)) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstaddh_w(CodeType code, uint64_t addr)
{
	return new OpLdstaddh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstclr_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "clr" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstclr_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( oldval & ~U32(cpu.GetGZR(rs)) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstclr_w(CodeType code, uint64_t addr)
{
	return new OpLdstclr_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstclr_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "clr" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstclr_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( oldval & ~U64(cpu.GetGZR(rs)) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstclr_x(CodeType code, uint64_t addr)
{
	return new OpLdstclr_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstclrb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "clr" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstclrb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( oldval & ~U8(cpu.GetGZR(rs)) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstclrb_w(CodeType code, uint64_t addr)
{
	return new OpLdstclrb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstclrh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "clr" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstclrh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( oldval & ~U16(cpu.GetGZR(rs)) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstclrh_w(CodeType code, uint64_t addr)
{
	return new OpLdstclrh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdsteor_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "eor" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdsteor_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( oldval ^ U32(cpu.GetGZR(rs)) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdsteor_w(CodeType code, uint64_t addr)
{
	return new OpLdsteor_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdsteor_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "eor" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdsteor_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( oldval ^ U64(cpu.GetGZR(rs)) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdsteor_x(CodeType code, uint64_t addr)
{
	return new OpLdsteor_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdsteorb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "eor" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdsteorb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( oldval ^ U8(cpu.GetGZR(rs)) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdsteorb_w(CodeType code, uint64_t addr)
{
	return new OpLdsteorb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdsteorh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "eor" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdsteorh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( oldval ^ U16(cpu.GetGZR(rs)) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdsteorh_w(CodeType code, uint64_t addr)
{
	return new OpLdsteorh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstset_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "set" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstset_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( oldval | U32(cpu.GetGZR(rs)) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstset_w(CodeType code, uint64_t addr)
{
	return new OpLdstset_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstset_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "set" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstset_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( oldval | U64(cpu.GetGZR(rs)) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstset_x(CodeType code, uint64_t addr)
{
	return new OpLdstset_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsetb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "set" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsetb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( oldval | U8(cpu.GetGZR(rs)) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsetb_w(CodeType code, uint64_t addr)
{
	return new OpLdstsetb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstseth_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "set" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstseth_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( oldval | U16(cpu.GetGZR(rs)) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstseth_w(CodeType code, uint64_t addr)
{
	return new OpLdstseth_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmax_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smax" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmax_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( U32(Maximum(S32(oldval), S32(cpu.GetGZR(rs)))) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmax_w(CodeType code, uint64_t addr)
{
	return new OpLdstsmax_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmax_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smax" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmax_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( U64(Maximum(S64(oldval), S64(cpu.GetGZR(rs)))) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmax_x(CodeType code, uint64_t addr)
{
	return new OpLdstsmax_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmaxb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smax" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmaxb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( U8(Maximum(S8(oldval), S8(cpu.GetGZR(rs)))) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmaxb_w(CodeType code, uint64_t addr)
{
	return new OpLdstsmaxb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmaxh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smax" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmaxh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( U16(Maximum(S16(oldval), S16(cpu.GetGZR(rs)))) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmaxh_w(CodeType code, uint64_t addr)
{
	return new OpLdstsmaxh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmin_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smin" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmin_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::S32 S32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( U32(Minimum(S32(oldval), S32(cpu.GetGZR(rs)))) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmin_w(CodeType code, uint64_t addr)
{
	return new OpLdstsmin_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsmin_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smin" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsmin_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::S64 S64;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( U64(Minimum(S64(oldval), S64(cpu.GetGZR(rs)))) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsmin_x(CodeType code, uint64_t addr)
{
	return new OpLdstsmin_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsminb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smin" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsminb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::S8 S8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( U8(Minimum(S8(oldval), S8(cpu.GetGZR(rs)))) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsminb_w(CodeType code, uint64_t addr)
{
	return new OpLdstsminb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstsminh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "smin" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstsminh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::S16 S16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( U16(Minimum(S16(oldval), S16(cpu.GetGZR(rs)))) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstsminh_w(CodeType code, uint64_t addr)
{
	return new OpLdstsminh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumax_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umax" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumax_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( Maximum(oldval, U32(cpu.GetGZR(rs))) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumax_w(CodeType code, uint64_t addr)
{
	return new OpLdstumax_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumax_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umax" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumax_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( Maximum(oldval, U64(cpu.GetGZR(rs))) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumax_x(CodeType code, uint64_t addr)
{
	return new OpLdstumax_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumaxb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umax" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumaxb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( Maximum(oldval, U8(cpu.GetGZR(rs))) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumaxb_w(CodeType code, uint64_t addr)
{
	return new OpLdstumaxb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumaxh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umax" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumaxh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( Maximum(oldval, U16(cpu.GetGZR(rs))) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumaxh_w(CodeType code, uint64_t addr)
{
	return new OpLdstumaxh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumin_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umin" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumin_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U32 U32;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U32 oldval( cpu.MemRead32(addr) ), newval( Minimum(oldval, U32(cpu.GetGZR(rs))) );
		cpu.MemWrite32(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumin_w(CodeType code, uint64_t addr)
{
	return new OpLdstumin_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstumin_x<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umin" << (&"a"[!a]) << (&"l"[!r]) << "\t" << DisasmGZXR(rs);
		if (ld)
		sink << ", " << DisasmGZXR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstumin_x<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U64 oldval( cpu.MemRead64(addr) ), newval( Minimum(oldval, U64(cpu.GetGZR(rs))) );
		cpu.MemWrite64(addr, newval);
		cpu.SetGZR(rt, oldval);
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstumin_x(CodeType code, uint64_t addr)
{
	return new OpLdstumin_x<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstuminb_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umin" << (&"a"[!a]) << (&"l"[!r]) << "b\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstuminb_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U8 U8;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U8 oldval( cpu.MemRead8(addr) ), newval( Minimum(oldval, U8(cpu.GetGZR(rs))) );
		cpu.MemWrite8(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstuminb_w(CodeType code, uint64_t addr)
{
	return new OpLdstuminb_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
void OpLdstuminh_w<	ARCH>::disasm( ARCH & cpu,
std::ostream& sink)
{
	{
		bool ld = rt != 31 or a;
		sink << (ld ? "ld" : "st") << "umin" << (&"a"[!a]) << (&"l"[!r]) << "h\t" << DisasmGZWR(rs);
		if (ld)
		sink << ", " << DisasmGZWR(rt);
		sink << ", [" << DisasmGSXR(rn) << "]";
}}
template <	typename	ARCH>
void OpLdstuminh_w<	ARCH>::execute( ARCH & cpu)
{
	{
		typedef typename ARCH::U16 U16;
		typedef typename ARCH::U64 U64;

		U64 addr( cpu.GetGSR(rn) );

		/*BEG ATOMIC*/
		U16 oldval( cpu.MemRead16(addr) ), newval( Minimum(oldval, U16(cpu.GetGZR(rs))) );
		cpu.MemWrite16(addr, newval);
		cpu.SetGZR(rt, typename ARCH::U32(oldval));
		/*END ATOMIC*/;
}}

template <	typename	ARCH>
static Operation<	ARCH> *DecodeOpLdstuminh_w(CodeType code, uint64_t addr)
{
	return new OpLdstuminh_w<	ARCH>(code, addr);
}

template <	typename	ARCH>
OpMsr<	ARCH>::OpMsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "msr")
{
	rt = uint8_t(code & 0x1f);
	op2 = uint8_t((code >> 5) & 0x7);
	crm = uint8_t((code >> 8) & 0xf);
	crn = uint8_t((code >> 12) & 0xf);
	op1 = uint8_t((code >> 16) & 0x7);
	op0 = uint8_t((code >> 19) & 0x3);
	sysreg = ARCH::GetSystemRegister(op0, op1, crn, crm, op2);
}

template <	typename	ARCH>
OpAdc_www<	ARCH>::OpAdc_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adc_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1458";
}

template <	typename	ARCH>
OpAdc_xxx<	ARCH>::OpAdc_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adc_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1612";
}

template <	typename	ARCH>
OpAdcs_www<	ARCH>::OpAdcs_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adcs_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1459";
}

template <	typename	ARCH>
OpAdcs_xxx<	ARCH>::OpAdcs_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adcs_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1613";
}

template <	typename	ARCH>
OpAdd_wsxtb<	ARCH>::OpAdd_wsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,375";
}

template <	typename	ARCH>
OpAdd_wsxth<	ARCH>::OpAdd_wsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,379";
}

template <	typename	ARCH>
OpAdd_wsxtw<	ARCH>::OpAdd_wsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,383";
}

template <	typename	ARCH>
OpAdd_wsxtx<	ARCH>::OpAdd_wsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,387";
}

template <	typename	ARCH>
OpAdd_wuxtb<	ARCH>::OpAdd_wuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,391";
}

template <	typename	ARCH>
OpAdd_wuxth<	ARCH>::OpAdd_wuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,395";
}

template <	typename	ARCH>
OpAdd_wuxtw<	ARCH>::OpAdd_wuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,399";
}

template <	typename	ARCH>
OpAdd_wuxtx<	ARCH>::OpAdd_wuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,403";
}

template <	typename	ARCH>
OpAdd_xsxtb<	ARCH>::OpAdd_xsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,407";
}

template <	typename	ARCH>
OpAdd_xsxth<	ARCH>::OpAdd_xsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,411";
}

template <	typename	ARCH>
OpAdd_xsxtw<	ARCH>::OpAdd_xsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,415";
}

template <	typename	ARCH>
OpAdd_xsxtx<	ARCH>::OpAdd_xsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,431";
}

template <	typename	ARCH>
OpAdd_xuxtb<	ARCH>::OpAdd_xuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,419";
}

template <	typename	ARCH>
OpAdd_xuxth<	ARCH>::OpAdd_xuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,423";
}

template <	typename	ARCH>
OpAdd_xuxtw<	ARCH>::OpAdd_xuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,427";
}

template <	typename	ARCH>
OpAdd_xuxtx<	ARCH>::OpAdd_xuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,438";
}

template <	typename	ARCH>
OpAdd_wi<	ARCH>::OpAdd_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,24";
}

template <	typename	ARCH>
OpAdd_xi<	ARCH>::OpAdd_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,33";
}

template <	typename	ARCH>
OpAdd_wlsl<	ARCH>::OpAdd_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,182";
}

template <	typename	ARCH>
OpAdd_wlsr<	ARCH>::OpAdd_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,194";
}

template <	typename	ARCH>
OpAdd_wasr<	ARCH>::OpAdd_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,170";
}

template <	typename	ARCH>
OpAdd_xlsl<	ARCH>::OpAdd_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,122";
}

template <	typename	ARCH>
OpAdd_xlsr<	ARCH>::OpAdd_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,134";
}

template <	typename	ARCH>
OpAdd_xasr<	ARCH>::OpAdd_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "add_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,110";
}

template <	typename	ARCH>
OpAdds_wsxtb<	ARCH>::OpAdds_wsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,376";
}

template <	typename	ARCH>
OpAdds_wsxth<	ARCH>::OpAdds_wsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,380";
}

template <	typename	ARCH>
OpAdds_wsxtw<	ARCH>::OpAdds_wsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,384";
}

template <	typename	ARCH>
OpAdds_wsxtx<	ARCH>::OpAdds_wsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,388";
}

template <	typename	ARCH>
OpAdds_wuxtb<	ARCH>::OpAdds_wuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,392";
}

template <	typename	ARCH>
OpAdds_wuxth<	ARCH>::OpAdds_wuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,396";
}

template <	typename	ARCH>
OpAdds_wuxtw<	ARCH>::OpAdds_wuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,400";
}

template <	typename	ARCH>
OpAdds_wuxtx<	ARCH>::OpAdds_wuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,404";
}

template <	typename	ARCH>
OpAdds_xsxtb<	ARCH>::OpAdds_xsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,408";
}

template <	typename	ARCH>
OpAdds_xsxth<	ARCH>::OpAdds_xsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,412";
}

template <	typename	ARCH>
OpAdds_xsxtw<	ARCH>::OpAdds_xsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,416";
}

template <	typename	ARCH>
OpAdds_xsxtx<	ARCH>::OpAdds_xsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,432";
}

template <	typename	ARCH>
OpAdds_xuxtb<	ARCH>::OpAdds_xuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,420";
}

template <	typename	ARCH>
OpAdds_xuxth<	ARCH>::OpAdds_xuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,424";
}

template <	typename	ARCH>
OpAdds_xuxtw<	ARCH>::OpAdds_xuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,428";
}

template <	typename	ARCH>
OpAdds_xuxtx<	ARCH>::OpAdds_xuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,436";
}

template <	typename	ARCH>
OpAdds_wi<	ARCH>::OpAdds_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,23";
}

template <	typename	ARCH>
OpAdds_xi<	ARCH>::OpAdds_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,32";
}

template <	typename	ARCH>
OpAdds_wlsl<	ARCH>::OpAdds_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,183";
}

template <	typename	ARCH>
OpAdds_wlsr<	ARCH>::OpAdds_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,204";
}

template <	typename	ARCH>
OpAdds_wasr<	ARCH>::OpAdds_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,180";
}

template <	typename	ARCH>
OpAdds_xlsl<	ARCH>::OpAdds_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,128";
}

template <	typename	ARCH>
OpAdds_xlsr<	ARCH>::OpAdds_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,144";
}

template <	typename	ARCH>
OpAdds_xasr<	ARCH>::OpAdds_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adds_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,120";
}

template <	typename	ARCH>
OpAdr<	ARCH>::OpAdr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adr")
{
	rd = uint8_t(code & 0x1f);
	imm1 = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	imm0 = uint8_t((code >> 29) & 0x3);
	imm = imm1|imm0;
	format = "base,2";
}

template <	typename	ARCH>
OpAdrp<	ARCH>::OpAdrp(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "adrp")
{
	rd = uint8_t(code & 0x1f);
	imm1 = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	imm0 = uint8_t((code >> 29) & 0x3);
	imm = imm1|imm0;
	format = "base,1";
}

template <	typename	ARCH>
OpAnd_wi<	ARCH>::OpAnd_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	imm = DecodeBitMasks(0,imms,immr).wmask;
	format = "base,71";
}

template <	typename	ARCH>
OpAnd_xi<	ARCH>::OpAnd_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	n = uint8_t((code >> 22) & 0x1);
	imm = DecodeBitMasks(n,imms,immr).wmask;
	format = "base,26";
}

template <	typename	ARCH>
OpAnd_wlsl<	ARCH>::OpAnd_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,187";
}

template <	typename	ARCH>
OpAnd_wlsr<	ARCH>::OpAnd_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,195";
}

template <	typename	ARCH>
OpAnd_wasr<	ARCH>::OpAnd_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,171";
}

template <	typename	ARCH>
OpAnd_wror<	ARCH>::OpAnd_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,206";
}

template <	typename	ARCH>
OpAnd_xlsl<	ARCH>::OpAnd_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,123";
}

template <	typename	ARCH>
OpAnd_xlsr<	ARCH>::OpAnd_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,135";
}

template <	typename	ARCH>
OpAnd_xasr<	ARCH>::OpAnd_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,111";
}

template <	typename	ARCH>
OpAnd_xror<	ARCH>::OpAnd_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "and_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,146";
}

template <	typename	ARCH>
OpAnds_wi<	ARCH>::OpAnds_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	imm = DecodeBitMasks(0,imms,immr).wmask;
	format = "base,73";
}

template <	typename	ARCH>
OpAnds_xi<	ARCH>::OpAnds_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	n = uint8_t((code >> 22) & 0x1);
	imm = DecodeBitMasks(n,imms,immr).wmask;
	format = "base,29";
}

template <	typename	ARCH>
OpAnds_wlsl<	ARCH>::OpAnds_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,184";
}

template <	typename	ARCH>
OpAnds_wlsr<	ARCH>::OpAnds_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,205";
}

template <	typename	ARCH>
OpAnds_wasr<	ARCH>::OpAnds_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,181";
}

template <	typename	ARCH>
OpAnds_wror<	ARCH>::OpAnds_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,213";
}

template <	typename	ARCH>
OpAnds_xlsl<	ARCH>::OpAnds_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,130";
}

template <	typename	ARCH>
OpAnds_xlsr<	ARCH>::OpAnds_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,145";
}

template <	typename	ARCH>
OpAnds_xasr<	ARCH>::OpAnds_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,121";
}

template <	typename	ARCH>
OpAnds_xror<	ARCH>::OpAnds_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ands_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,153";
}

template <	typename	ARCH>
OpAsr_www<	ARCH>::OpAsr_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "asr_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1460";
}

template <	typename	ARCH>
OpAsr_xxx<	ARCH>::OpAsr_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "asr_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1614";
}

template <	typename	ARCH>
OpB<	ARCH>::OpB(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "b")
{
	imm = ((int32_t)((code & 0x3ffffff) << 6) >> 6) << 2;
	format = "base,3";
}

template <	typename	ARCH>
OpB_cond<	ARCH>::OpB_cond(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "b_cond")
{
	cond = uint8_t(code & 0xf);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,20";
}

template <	typename	ARCH>
OpBfm_w<	ARCH>::OpBfm_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bfm_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x1f);
	immr = uint8_t((code >> 16) & 0x1f);
	format = "base,162";
}

template <	typename	ARCH>
OpBfm_x<	ARCH>::OpBfm_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bfm_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	format = "base,90";
}

template <	typename	ARCH>
OpBic_wlsl<	ARCH>::OpBic_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,188";
}

template <	typename	ARCH>
OpBic_wlsr<	ARCH>::OpBic_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,196";
}

template <	typename	ARCH>
OpBic_wasr<	ARCH>::OpBic_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,172";
}

template <	typename	ARCH>
OpBic_wror<	ARCH>::OpBic_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,207";
}

template <	typename	ARCH>
OpBic_xlsl<	ARCH>::OpBic_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,124";
}

template <	typename	ARCH>
OpBic_xlsr<	ARCH>::OpBic_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,136";
}

template <	typename	ARCH>
OpBic_xasr<	ARCH>::OpBic_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,112";
}

template <	typename	ARCH>
OpBic_xror<	ARCH>::OpBic_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bic_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,147";
}

template <	typename	ARCH>
OpBics_wlsl<	ARCH>::OpBics_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,189";
}

template <	typename	ARCH>
OpBics_wlsr<	ARCH>::OpBics_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,197";
}

template <	typename	ARCH>
OpBics_wasr<	ARCH>::OpBics_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,173";
}

template <	typename	ARCH>
OpBics_wror<	ARCH>::OpBics_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,208";
}

template <	typename	ARCH>
OpBics_xlsl<	ARCH>::OpBics_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,125";
}

template <	typename	ARCH>
OpBics_xlsr<	ARCH>::OpBics_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,137";
}

template <	typename	ARCH>
OpBics_xasr<	ARCH>::OpBics_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,113";
}

template <	typename	ARCH>
OpBics_xror<	ARCH>::OpBics_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bics_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,148";
}

template <	typename	ARCH>
OpBl<	ARCH>::OpBl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "bl")
{
	imm = ((int32_t)((code & 0x3ffffff) << 6) >> 6) << 2;
	format = "base,4";
}

template <	typename	ARCH>
OpBlr<	ARCH>::OpBlr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "blr")
{
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2886";
}

template <	typename	ARCH>
OpBr<	ARCH>::OpBr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "br")
{
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2887";
}

template <	typename	ARCH>
OpBrk<	ARCH>::OpBrk(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "brk")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,573";
}

template <	typename	ARCH>
OpCbnz_wlit<	ARCH>::OpCbnz_wlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cbnz_wlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,12";
}

template <	typename	ARCH>
OpCbnz_xlit<	ARCH>::OpCbnz_xlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cbnz_xlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,15";
}

template <	typename	ARCH>
OpCbz_wlit<	ARCH>::OpCbz_wlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cbz_wlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,13";
}

template <	typename	ARCH>
OpCbz_xlit<	ARCH>::OpCbz_xlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cbz_xlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,16";
}

template <	typename	ARCH>
OpCcmn_wi<	ARCH>::OpCcmn_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmn_wi")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	imm = uint8_t((code >> 16) & 0x1f);
	format = "base,366";
}

template <	typename	ARCH>
OpCcmn_xi<	ARCH>::OpCcmn_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmn_xi")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	imm = uint8_t((code >> 16) & 0x1f);
	format = "base,370";
}

template <	typename	ARCH>
OpCcmn_w<	ARCH>::OpCcmn_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmn_w")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,368";
}

template <	typename	ARCH>
OpCcmn_x<	ARCH>::OpCcmn_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmn_x")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,372";
}

template <	typename	ARCH>
OpCcmp_wi<	ARCH>::OpCcmp_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmp_wi")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	imm = uint8_t((code >> 16) & 0x1f);
	format = "base,367";
}

template <	typename	ARCH>
OpCcmp_xi<	ARCH>::OpCcmp_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmp_xi")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	imm = uint8_t((code >> 16) & 0x1f);
	format = "base,371";
}

template <	typename	ARCH>
OpCcmp_w<	ARCH>::OpCcmp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmp_w")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,369";
}

template <	typename	ARCH>
OpCcmp_x<	ARCH>::OpCcmp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ccmp_x")
{
	v = uint8_t(code & 0x1);
	c = uint8_t((code >> 1) & 0x1);
	z = uint8_t((code >> 2) & 0x1);
	n = uint8_t((code >> 3) & 0x1);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,373";
}

template <	typename	ARCH>
OpClrex<	ARCH>::OpClrex(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "clrex")
{
	imm = uint8_t((code >> 8) & 0xf);
	format = "base,2942";
}

template <	typename	ARCH>
OpCls_w<	ARCH>::OpCls_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cls_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2615";
}

template <	typename	ARCH>
OpCls_x<	ARCH>::OpCls_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cls_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2655";
}

template <	typename	ARCH>
OpClz_w<	ARCH>::OpClz_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "clz_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2616";
}

template <	typename	ARCH>
OpClz_x<	ARCH>::OpClz_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "clz_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2654";
}

template <	typename	ARCH>
OpCsel_w<	ARCH>::OpCsel_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csel_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,291";
}

template <	typename	ARCH>
OpCsel_x<	ARCH>::OpCsel_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csel_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,327";
}

template <	typename	ARCH>
OpCsinc_w<	ARCH>::OpCsinc_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csinc_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,292";
}

template <	typename	ARCH>
OpCsinc_x<	ARCH>::OpCsinc_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csinc_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,328";
}

template <	typename	ARCH>
OpCsinv_w<	ARCH>::OpCsinv_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csinv_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,293";
}

template <	typename	ARCH>
OpCsinv_x<	ARCH>::OpCsinv_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csinv_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,329";
}

template <	typename	ARCH>
OpCsneg_w<	ARCH>::OpCsneg_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csneg_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,294";
}

template <	typename	ARCH>
OpCsneg_x<	ARCH>::OpCsneg_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "csneg_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	cond = uint8_t((code >> 12) & 0xf);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,330";
}

template <	typename	ARCH>
OpDcps1<	ARCH>::OpDcps1(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "dcps1")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,578";
}

template <	typename	ARCH>
OpDcps2<	ARCH>::OpDcps2(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "dcps2")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,579";
}

template <	typename	ARCH>
OpDcps3<	ARCH>::OpDcps3(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "dcps3")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,580";
}

template <	typename	ARCH>
OpDrps<	ARCH>::OpDrps(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "drps")
{
	format = "base,2946";
}

template <	typename	ARCH>
OpEon_wlsl<	ARCH>::OpEon_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,190";
}

template <	typename	ARCH>
OpEon_wlsr<	ARCH>::OpEon_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,198";
}

template <	typename	ARCH>
OpEon_wasr<	ARCH>::OpEon_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,174";
}

template <	typename	ARCH>
OpEon_wror<	ARCH>::OpEon_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,209";
}

template <	typename	ARCH>
OpEon_xlsl<	ARCH>::OpEon_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,126";
}

template <	typename	ARCH>
OpEon_xlsr<	ARCH>::OpEon_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,138";
}

template <	typename	ARCH>
OpEon_xasr<	ARCH>::OpEon_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,114";
}

template <	typename	ARCH>
OpEon_xror<	ARCH>::OpEon_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eon_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,149";
}

template <	typename	ARCH>
OpEor_wi<	ARCH>::OpEor_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	imm = DecodeBitMasks(0,imms,immr).wmask;
	format = "base,72";
}

template <	typename	ARCH>
OpEor_xi<	ARCH>::OpEor_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	n = uint8_t((code >> 22) & 0x1);
	imm = DecodeBitMasks(n,imms,immr).wmask;
	format = "base,27";
}

template <	typename	ARCH>
OpEor_wlsl<	ARCH>::OpEor_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,191";
}

template <	typename	ARCH>
OpEor_wlsr<	ARCH>::OpEor_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,199";
}

template <	typename	ARCH>
OpEor_wasr<	ARCH>::OpEor_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,175";
}

template <	typename	ARCH>
OpEor_wror<	ARCH>::OpEor_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,210";
}

template <	typename	ARCH>
OpEor_xlsl<	ARCH>::OpEor_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,127";
}

template <	typename	ARCH>
OpEor_xlsr<	ARCH>::OpEor_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,139";
}

template <	typename	ARCH>
OpEor_xasr<	ARCH>::OpEor_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,115";
}

template <	typename	ARCH>
OpEor_xror<	ARCH>::OpEor_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eor_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,150";
}

template <	typename	ARCH>
OpEret<	ARCH>::OpEret(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "eret")
{
	format = "base,2947";
}

template <	typename	ARCH>
OpExtr_w<	ARCH>::OpExtr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "extr_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,165";
}

template <	typename	ARCH>
OpExtr_x<	ARCH>::OpExtr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "extr_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,109";
}

template <	typename	ARCH>
OpHlt<	ARCH>::OpHlt(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "hlt")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,574";
}

template <	typename	ARCH>
OpHvc<	ARCH>::OpHvc(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "hvc")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,575";
}

template <	typename	ARCH>
OpLdar_w<	ARCH>::OpLdar_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldar_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2622";
}

template <	typename	ARCH>
OpLdar_x<	ARCH>::OpLdar_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldar_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2656";
}

template <	typename	ARCH>
OpLdarb_w<	ARCH>::OpLdarb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldarb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2623";
}

template <	typename	ARCH>
OpLdarh_w<	ARCH>::OpLdarh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldarh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2624";
}

template <	typename	ARCH>
OpLdaxp_w<	ARCH>::OpLdaxp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,220";
}

template <	typename	ARCH>
OpLdaxp_x<	ARCH>::OpLdaxp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,243";
}

template <	typename	ARCH>
OpLdaxr_w<	ARCH>::OpLdaxr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,226";
}

template <	typename	ARCH>
OpLdaxr_x<	ARCH>::OpLdaxr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,245";
}

template <	typename	ARCH>
OpLdaxrb_w<	ARCH>::OpLdaxrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,227";
}

template <	typename	ARCH>
OpLdaxrh_w<	ARCH>::OpLdaxrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldaxrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,228";
}

template <	typename	ARCH>
OpLdp_w<	ARCH>::OpLdp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	imm = ((int16_t)(((code >> 15) & 0x7f) << 9) >> 9) << 2;
	am = uint8_t((code >> 23) & 0x3);
	reject = (rt == rt2) or (am & 1 and (rt == rn or rt2 == rn) and rn != 31);
}

template <	typename	ARCH>
OpLdp_x<	ARCH>::OpLdp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	imm = ((int16_t)(((code >> 15) & 0x7f) << 9) >> 9) << 3;
	am = uint8_t((code >> 23) & 0x3);
	reject = (rt == rt2) or (am & 1 and (rt == rn or rt2 == rn) and rn != 31);
}

template <	typename	ARCH>
OpLdpsw_xxi<	ARCH>::OpLdpsw_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldpsw_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	imm = ((int16_t)(((code >> 15) & 0x7f) << 9) >> 9) << 2;
	am = uint8_t((code >> 23) & 0x3);
	reject = (rt == rt2) or (am == 0) or (am & 1 and (rt == rn or rt2 == rn) and rn != 31);
}

template <	typename	ARCH>
OpLdr_wxi<	ARCH>::OpLdr_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdr_wuo<	ARCH>::OpLdr_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 2;
	format = "base,82";
}

template <	typename	ARCH>
OpLdr_xxi<	ARCH>::OpLdr_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdr_xuo<	ARCH>::OpLdr_xuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 3;
	format = "base,104";
}

template <	typename	ARCH>
OpLdr_wlit<	ARCH>::OpLdr_wlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,14";
}

template <	typename	ARCH>
OpLdr_xlit<	ARCH>::OpLdr_xlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,17";
}

template <	typename	ARCH>
OpLdr_wxwu<	ARCH>::OpLdr_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,623";
}

template <	typename	ARCH>
OpLdr_wxxu<	ARCH>::OpLdr_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1596";
	shift = s*2;
}

template <	typename	ARCH>
OpLdr_wxws<	ARCH>::OpLdr_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,615";
}

template <	typename	ARCH>
OpLdr_wxxs<	ARCH>::OpLdr_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,631";
}

template <	typename	ARCH>
OpLdr_xxwu<	ARCH>::OpLdr_xxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,644";
}

template <	typename	ARCH>
OpLdr_xxxu<	ARCH>::OpLdr_xxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1661";
	shift = s*3;
}

template <	typename	ARCH>
OpLdr_xxws<	ARCH>::OpLdr_xxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,639";
}

template <	typename	ARCH>
OpLdr_xxxs<	ARCH>::OpLdr_xxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldr_xxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,649";
}

template <	typename	ARCH>
OpLdrb_wxi<	ARCH>::OpLdrb_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrb_wuo<	ARCH>::OpLdrb_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff);
	format = "base,83";
}

template <	typename	ARCH>
OpLdrb_wxwu<	ARCH>::OpLdrb_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,624";
}

template <	typename	ARCH>
OpLdrb_wxxu<	ARCH>::OpLdrb_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1597";
	shift = s*0;
}

template <	typename	ARCH>
OpLdrb_wxws<	ARCH>::OpLdrb_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,616";
}

template <	typename	ARCH>
OpLdrb_wxxs<	ARCH>::OpLdrb_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrb_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,632";
}

template <	typename	ARCH>
OpLdrh_wxi<	ARCH>::OpLdrh_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrh_wuo<	ARCH>::OpLdrh_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 1;
	format = "base,84";
}

template <	typename	ARCH>
OpLdrh_wxwu<	ARCH>::OpLdrh_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,625";
}

template <	typename	ARCH>
OpLdrh_wxxu<	ARCH>::OpLdrh_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1598";
	shift = s*1;
}

template <	typename	ARCH>
OpLdrh_wxws<	ARCH>::OpLdrh_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,617";
}

template <	typename	ARCH>
OpLdrh_wxxs<	ARCH>::OpLdrh_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrh_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,633";
}

template <	typename	ARCH>
OpLdrsb_wxi<	ARCH>::OpLdrsb_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrsb_wuo<	ARCH>::OpLdrsb_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff);
	format = "base,85";
}

template <	typename	ARCH>
OpLdrsb_xxi<	ARCH>::OpLdrsb_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrsb_xuo<	ARCH>::OpLdrsb_xuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff);
	format = "base,105";
}

template <	typename	ARCH>
OpLdrsb_wxwu<	ARCH>::OpLdrsb_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,626";
}

template <	typename	ARCH>
OpLdrsb_wxxu<	ARCH>::OpLdrsb_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1599";
	shift = s*0;
}

template <	typename	ARCH>
OpLdrsb_wxws<	ARCH>::OpLdrsb_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,618";
}

template <	typename	ARCH>
OpLdrsb_wxxs<	ARCH>::OpLdrsb_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,634";
}

template <	typename	ARCH>
OpLdrsb_xxwu<	ARCH>::OpLdrsb_xxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,645";
}

template <	typename	ARCH>
OpLdrsb_xxxu<	ARCH>::OpLdrsb_xxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1662";
	shift = s*0;
}

template <	typename	ARCH>
OpLdrsb_xxws<	ARCH>::OpLdrsb_xxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,640";
}

template <	typename	ARCH>
OpLdrsb_xxxs<	ARCH>::OpLdrsb_xxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsb_xxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,650";
}

template <	typename	ARCH>
OpLdrsh_wxi<	ARCH>::OpLdrsh_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrsh_wuo<	ARCH>::OpLdrsh_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 1;
	format = "base,86";
}

template <	typename	ARCH>
OpLdrsh_xxi<	ARCH>::OpLdrsh_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrsh_xuo<	ARCH>::OpLdrsh_xuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 1;
	format = "base,106";
}

template <	typename	ARCH>
OpLdrsh_wxwu<	ARCH>::OpLdrsh_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,627";
}

template <	typename	ARCH>
OpLdrsh_wxxu<	ARCH>::OpLdrsh_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1600";
	shift = s*1;
}

template <	typename	ARCH>
OpLdrsh_wxws<	ARCH>::OpLdrsh_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,619";
}

template <	typename	ARCH>
OpLdrsh_wxxs<	ARCH>::OpLdrsh_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,635";
}

template <	typename	ARCH>
OpLdrsh_xxwu<	ARCH>::OpLdrsh_xxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,646";
}

template <	typename	ARCH>
OpLdrsh_xxxu<	ARCH>::OpLdrsh_xxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1663";
	shift = s*1;
}

template <	typename	ARCH>
OpLdrsh_xxws<	ARCH>::OpLdrsh_xxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,641";
}

template <	typename	ARCH>
OpLdrsh_xxxs<	ARCH>::OpLdrsh_xxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsh_xxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,651";
}

template <	typename	ARCH>
OpLdrsw_xlit<	ARCH>::OpLdrsw_xlit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xlit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,18";
}

template <	typename	ARCH>
OpLdrsw_xxi<	ARCH>::OpLdrsw_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpLdrsw_xuo<	ARCH>::OpLdrsw_xuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 2;
	format = "base,107";
}

template <	typename	ARCH>
OpLdrsw_xxwu<	ARCH>::OpLdrsw_xxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,647";
}

template <	typename	ARCH>
OpLdrsw_xxxu<	ARCH>::OpLdrsw_xxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1664";
	shift = s*2;
}

template <	typename	ARCH>
OpLdrsw_xxws<	ARCH>::OpLdrsw_xxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,642";
}

template <	typename	ARCH>
OpLdrsw_xxxs<	ARCH>::OpLdrsw_xxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldrsw_xxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,652";
}

template <	typename	ARCH>
OpLdtr_wbo<	ARCH>::OpLdtr_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtr_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,297";
}

template <	typename	ARCH>
OpLdtr_xbo<	ARCH>::OpLdtr_xbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtr_xbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,334";
}

template <	typename	ARCH>
OpLdtrb_wbo<	ARCH>::OpLdtrb_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrb_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,298";
}

template <	typename	ARCH>
OpLdtrh_wbo<	ARCH>::OpLdtrh_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrh_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,299";
}

template <	typename	ARCH>
OpLdtrsb_wbo<	ARCH>::OpLdtrsb_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrsb_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,300";
}

template <	typename	ARCH>
OpLdtrsb_xbo<	ARCH>::OpLdtrsb_xbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrsb_xbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,335";
}

template <	typename	ARCH>
OpLdtrsh_wbo<	ARCH>::OpLdtrsh_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrsh_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,301";
}

template <	typename	ARCH>
OpLdtrsh_xbo<	ARCH>::OpLdtrsh_xbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrsh_xbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,336";
}

template <	typename	ARCH>
OpLdtrsw_xbo<	ARCH>::OpLdtrsw_xbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldtrsw_xbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,337";
}

template <	typename	ARCH>
OpLdxp_w<	ARCH>::OpLdxp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,221";
}

template <	typename	ARCH>
OpLdxp_x<	ARCH>::OpLdxp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,244";
}

template <	typename	ARCH>
OpLdxr_w<	ARCH>::OpLdxr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,229";
}

template <	typename	ARCH>
OpLdxr_x<	ARCH>::OpLdxr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,246";
}

template <	typename	ARCH>
OpLdxrb_w<	ARCH>::OpLdxrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,230";
}

template <	typename	ARCH>
OpLdxrh_w<	ARCH>::OpLdxrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldxrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,231";
}

template <	typename	ARCH>
OpLsl_www<	ARCH>::OpLsl_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "lsl_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1467";
}

template <	typename	ARCH>
OpLsl_xxx<	ARCH>::OpLsl_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "lsl_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1615";
}

template <	typename	ARCH>
OpLsr_www<	ARCH>::OpLsr_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "lsr_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1468";
}

template <	typename	ARCH>
OpLsr_xxx<	ARCH>::OpLsr_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "lsr_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1616";
}

template <	typename	ARCH>
OpMadd_w<	ARCH>::OpMadd_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "madd_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,166";
}

template <	typename	ARCH>
OpMadd_x<	ARCH>::OpMadd_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "madd_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,241";
}

template <	typename	ARCH>
OpMov_wi<	ARCH>::OpMov_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "mov_wi")
{
	rd = uint8_t(code & 0x1f);
	imm0 = uint16_t((code >> 5) & 0xffff);
	shift = uint8_t((code >> 21) & 0x1) << 4;
	n = ((int8_t)(((code >> 30) & 0x1) << 7) >> 7);
	imm = (uint32_t(imm0) << shift)^~int32_t(n);
	format = "base,19";
}

template <	typename	ARCH>
OpMov_xi<	ARCH>::OpMov_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "mov_xi")
{
	rd = uint8_t(code & 0x1f);
	imm0 = uint16_t((code >> 5) & 0xffff);
	shift = uint8_t((code >> 21) & 0x3) << 4;
	n = ((int8_t)(((code >> 30) & 0x1) << 7) >> 7);
	imm = (uint64_t(imm0) << shift)^~int64_t(n);
	format = "base,7";
}

template <	typename	ARCH>
OpMovk_w<	ARCH>::OpMovk_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "movk_w")
{
	rd = uint8_t(code & 0x1f);
	imm = uint16_t((code >> 5) & 0xffff);
	shift = uint8_t((code >> 21) & 0x1) << 4;
	format = "base,69";
}

template <	typename	ARCH>
OpMovk_x<	ARCH>::OpMovk_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "movk_x")
{
	rd = uint8_t(code & 0x1f);
	imm = uint16_t((code >> 5) & 0xffff);
	shift = uint8_t((code >> 21) & 0x3) << 4;
	format = "base,25";
}

template <	typename	ARCH>
OpMrs<	ARCH>::OpMrs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "mrs")
{
	rt = uint8_t(code & 0x1f);
	op2 = uint8_t((code >> 5) & 0x7);
	crm = uint8_t((code >> 8) & 0xf);
	crn = uint8_t((code >> 12) & 0xf);
	op1 = uint8_t((code >> 16) & 0x7);
	op0 = uint8_t((code >> 19) & 0x3);
	sysreg = ARCH::GetSystemRegister(op0, op1, crn, crm, op2);
}

template <	typename	ARCH>
OpMsub_w<	ARCH>::OpMsub_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "msub_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,167";
}

template <	typename	ARCH>
OpMsub_x<	ARCH>::OpMsub_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "msub_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,242";
}

template <	typename	ARCH>
OpNop<	ARCH>::OpNop(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "nop")
{
	format = "base,2948";
}

template <	typename	ARCH>
OpOrn_wlsl<	ARCH>::OpOrn_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,185";
}

template <	typename	ARCH>
OpOrn_wlsr<	ARCH>::OpOrn_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,200";
}

template <	typename	ARCH>
OpOrn_wasr<	ARCH>::OpOrn_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,176";
}

template <	typename	ARCH>
OpOrn_wror<	ARCH>::OpOrn_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,211";
}

template <	typename	ARCH>
OpOrn_xlsl<	ARCH>::OpOrn_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,131";
}

template <	typename	ARCH>
OpOrn_xlsr<	ARCH>::OpOrn_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,140";
}

template <	typename	ARCH>
OpOrn_xasr<	ARCH>::OpOrn_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,116";
}

template <	typename	ARCH>
OpOrn_xror<	ARCH>::OpOrn_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orn_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,151";
}

template <	typename	ARCH>
OpOrr_wi<	ARCH>::OpOrr_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	imm = DecodeBitMasks(0,imms,immr).wmask;
	format = "base,70";
}

template <	typename	ARCH>
OpOrr_xi<	ARCH>::OpOrr_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	n = uint8_t((code >> 22) & 0x1);
	imm = DecodeBitMasks(n,imms,immr).wmask;
	format = "base,28";
}

template <	typename	ARCH>
OpOrr_wlsl<	ARCH>::OpOrr_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,193";
}

template <	typename	ARCH>
OpOrr_xlsl<	ARCH>::OpOrr_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,132";
}

template <	typename	ARCH>
OpOrr_wlsr<	ARCH>::OpOrr_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,203";
}

template <	typename	ARCH>
OpOrr_xlsr<	ARCH>::OpOrr_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,143";
}

template <	typename	ARCH>
OpOrr_wasr<	ARCH>::OpOrr_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,179";
}

template <	typename	ARCH>
OpOrr_xasr<	ARCH>::OpOrr_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,119";
}

template <	typename	ARCH>
OpOrr_wror<	ARCH>::OpOrr_wror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_wror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,212";
}

template <	typename	ARCH>
OpOrr_xror<	ARCH>::OpOrr_xror(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "orr_xror")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,152";
}

template <	typename	ARCH>
OpPrfm_lit<	ARCH>::OpPrfm_lit(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "prfm_lit")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int32_t)(((code >> 5) & 0x7ffff) << 13) >> 13) << 2;
	format = "base,8";
}

template <	typename	ARCH>
OpPrefetchMemory_xi<	ARCH>::OpPrefetchMemory_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "PrefetchMemory_xi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 3;
	format = "base,34";
}

template <	typename	ARCH>
OpPrefetchMemory_xws<	ARCH>::OpPrefetchMemory_xws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "PrefetchMemory_xws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,581";
}

template <	typename	ARCH>
OpPrefetchMemory_xwu<	ARCH>::OpPrefetchMemory_xwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "PrefetchMemory_xwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,582";
}

template <	typename	ARCH>
OpPrefetchMemory_xx<	ARCH>::OpPrefetchMemory_xx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "PrefetchMemory_xx")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	opt = uint8_t((code >> 15) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,583";
}

template <	typename	ARCH>
OpPrfum<	ARCH>::OpPrfum(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "prfum")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,258";
}

template <	typename	ARCH>
OpRbit_w<	ARCH>::OpRbit_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rbit_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2617";
}

template <	typename	ARCH>
OpRbit_x<	ARCH>::OpRbit_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rbit_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2617";
}

template <	typename	ARCH>
OpRet<	ARCH>::OpRet(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ret")
{
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2888";
}

template <	typename	ARCH>
OpRev_w<	ARCH>::OpRev_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rev_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2618";
}

template <	typename	ARCH>
OpRev_x<	ARCH>::OpRev_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rev_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2653";
}

template <	typename	ARCH>
OpRev16_w<	ARCH>::OpRev16_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rev16_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2619";
}

template <	typename	ARCH>
OpRev16_x<	ARCH>::OpRev16_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rev16_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2651";
}

template <	typename	ARCH>
OpRev32_x<	ARCH>::OpRev32_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "rev32_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	format = "base,2652";
}

template <	typename	ARCH>
OpRor_www<	ARCH>::OpRor_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ror_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1469";
}

template <	typename	ARCH>
OpRor_xxx<	ARCH>::OpRor_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ror_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1617";
}

template <	typename	ARCH>
OpSbc_www<	ARCH>::OpSbc_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbc_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1472";
}

template <	typename	ARCH>
OpSbc_xxx<	ARCH>::OpSbc_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbc_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1620";
}

template <	typename	ARCH>
OpSbcs_www<	ARCH>::OpSbcs_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbcs_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1473";
}

template <	typename	ARCH>
OpSbcs_xxx<	ARCH>::OpSbcs_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbcs_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1619";
}

template <	typename	ARCH>
OpSbfm_w<	ARCH>::OpSbfm_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbfm_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x1f);
	immr = uint8_t((code >> 16) & 0x1f);
	format = "base,163";
}

template <	typename	ARCH>
OpSbfm_x<	ARCH>::OpSbfm_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sbfm_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	format = "base,91";
}

template <	typename	ARCH>
OpSdiv_www<	ARCH>::OpSdiv_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sdiv_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1470";
}

template <	typename	ARCH>
OpSdiv_xxx<	ARCH>::OpSdiv_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sdiv_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1470";
}

template <	typename	ARCH>
OpSmaddl_xw<	ARCH>::OpSmaddl_xw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "smaddl_xw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,235";
}

template <	typename	ARCH>
OpSmc<	ARCH>::OpSmc(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "smc")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,576";
}

template <	typename	ARCH>
OpSmsubl_xw<	ARCH>::OpSmsubl_xw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "smsubl_xw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,236";
}

template <	typename	ARCH>
OpSmulh<	ARCH>::OpSmulh(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "smulh")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,239";
}

template <	typename	ARCH>
OpStlr_w<	ARCH>::OpStlr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,232";
}

template <	typename	ARCH>
OpStlr_x<	ARCH>::OpStlr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,247";
}

template <	typename	ARCH>
OpStlrb_w<	ARCH>::OpStlrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,233";
}

template <	typename	ARCH>
OpStlrh_w<	ARCH>::OpStlrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,234";
}

template <	typename	ARCH>
OpStlxp_w<	ARCH>::OpStlxp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,168";
}

template <	typename	ARCH>
OpStlxp_x<	ARCH>::OpStlxp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,222";
}

template <	typename	ARCH>
OpStlxr_w<	ARCH>::OpStlxr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,214";
}

template <	typename	ARCH>
OpStlxr_x<	ARCH>::OpStlxr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,224";
}

template <	typename	ARCH>
OpStlxrb_w<	ARCH>::OpStlxrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,215";
}

template <	typename	ARCH>
OpStlxrh_w<	ARCH>::OpStlxrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stlxrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,216";
}

template <	typename	ARCH>
OpStp_w<	ARCH>::OpStp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	imm = ((int16_t)(((code >> 15) & 0x7f) << 9) >> 9) << 2;
	am = uint8_t((code >> 23) & 0x3);
	reject = am & 1 and (rt == rn or rt2 == rn) and rn != 31;
}

template <	typename	ARCH>
OpStp_x<	ARCH>::OpStp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	imm = ((int16_t)(((code >> 15) & 0x7f) << 9) >> 9) << 3;
	am = uint8_t((code >> 23) & 0x3);
	reject = am & 1 and (rt == rn or rt2 == rn) and rn != 31;
}

template <	typename	ARCH>
OpStr_wxi<	ARCH>::OpStr_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpStr_wuo<	ARCH>::OpStr_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 2;
	format = "base,87";
}

template <	typename	ARCH>
OpStr_xxi<	ARCH>::OpStr_xxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpStr_xuo<	ARCH>::OpStr_xuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 3;
	format = "base,108";
}

template <	typename	ARCH>
OpStr_wxwu<	ARCH>::OpStr_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,628";
}

template <	typename	ARCH>
OpStr_wxxu<	ARCH>::OpStr_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1601";
	shift = s*2;
}

template <	typename	ARCH>
OpStr_wxws<	ARCH>::OpStr_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,620";
}

template <	typename	ARCH>
OpStr_wxxs<	ARCH>::OpStr_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*2;
	format = "base,636";
}

template <	typename	ARCH>
OpStr_xxwu<	ARCH>::OpStr_xxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,648";
}

template <	typename	ARCH>
OpStr_xxxu<	ARCH>::OpStr_xxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1665";
	shift = s*3;
}

template <	typename	ARCH>
OpStr_xxws<	ARCH>::OpStr_xxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,643";
}

template <	typename	ARCH>
OpStr_xxxs<	ARCH>::OpStr_xxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "str_xxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*3;
	format = "base,653";
}

template <	typename	ARCH>
OpStrb_wxi<	ARCH>::OpStrb_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpStrb_wuo<	ARCH>::OpStrb_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff);
	format = "base,88";
}

template <	typename	ARCH>
OpStrb_wxwu<	ARCH>::OpStrb_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,629";
}

template <	typename	ARCH>
OpStrb_wxxu<	ARCH>::OpStrb_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1602";
	shift = s*0;
}

template <	typename	ARCH>
OpStrb_wxws<	ARCH>::OpStrb_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,621";
}

template <	typename	ARCH>
OpStrb_wxxs<	ARCH>::OpStrb_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strb_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*0;
	format = "base,637";
}

template <	typename	ARCH>
OpStrh_wxi<	ARCH>::OpStrh_wxi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wxi")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	am = uint8_t((code >> 10) & 0x3);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	reject = am == 2 or (am & 1 and rn == rt and rn != 31);
}

template <	typename	ARCH>
OpStrh_wuo<	ARCH>::OpStrh_wuo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wuo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint16_t((code >> 10) & 0xfff) << 1;
	format = "base,89";
}

template <	typename	ARCH>
OpStrh_wxwu<	ARCH>::OpStrh_wxwu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wxwu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,630";
}

template <	typename	ARCH>
OpStrh_wxxu<	ARCH>::OpStrh_wxxu(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wxxu")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1603";
	shift = s*1;
}

template <	typename	ARCH>
OpStrh_wxws<	ARCH>::OpStrh_wxws(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wxws")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,622";
}

template <	typename	ARCH>
OpStrh_wxxs<	ARCH>::OpStrh_wxxs(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "strh_wxxs")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	s = uint8_t((code >> 12) & 0x1);
	rm = uint8_t((code >> 16) & 0x1f);
	shift = s*1;
	format = "base,638";
}

template <	typename	ARCH>
OpSttr_wbo<	ARCH>::OpSttr_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sttr_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,302";
}

template <	typename	ARCH>
OpSttr_xbo<	ARCH>::OpSttr_xbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sttr_xbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,338";
}

template <	typename	ARCH>
OpSttrb_wbo<	ARCH>::OpSttrb_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sttrb_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,303";
}

template <	typename	ARCH>
OpSttrh_wbo<	ARCH>::OpSttrh_wbo(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sttrh_wbo")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = ((int16_t)(((code >> 12) & 0x1ff) << 7) >> 7);
	format = "base,304";
}

template <	typename	ARCH>
OpStxp_w<	ARCH>::OpStxp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,169";
}

template <	typename	ARCH>
OpStxp_x<	ARCH>::OpStxp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,223";
}

template <	typename	ARCH>
OpStxr_w<	ARCH>::OpStxr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,217";
}

template <	typename	ARCH>
OpStxr_x<	ARCH>::OpStxr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,225";
}

template <	typename	ARCH>
OpStxrb_w<	ARCH>::OpStxrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,218";
}

template <	typename	ARCH>
OpStxrh_w<	ARCH>::OpStxrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "stxrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rt2 = uint8_t((code >> 10) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	format = "base,219";
}

template <	typename	ARCH>
OpSub_wsxtb<	ARCH>::OpSub_wsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,377";
}

template <	typename	ARCH>
OpSub_wsxth<	ARCH>::OpSub_wsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,381";
}

template <	typename	ARCH>
OpSub_wsxtw<	ARCH>::OpSub_wsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,385";
}

template <	typename	ARCH>
OpSub_wsxtx<	ARCH>::OpSub_wsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,389";
}

template <	typename	ARCH>
OpSub_wuxtb<	ARCH>::OpSub_wuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,393";
}

template <	typename	ARCH>
OpSub_wuxth<	ARCH>::OpSub_wuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,397";
}

template <	typename	ARCH>
OpSub_wuxtw<	ARCH>::OpSub_wuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,402";
}

template <	typename	ARCH>
OpSub_wuxtx<	ARCH>::OpSub_wuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,405";
}

template <	typename	ARCH>
OpSub_xsxtb<	ARCH>::OpSub_xsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,409";
}

template <	typename	ARCH>
OpSub_xsxth<	ARCH>::OpSub_xsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,413";
}

template <	typename	ARCH>
OpSub_xsxtw<	ARCH>::OpSub_xsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,417";
}

template <	typename	ARCH>
OpSub_xsxtx<	ARCH>::OpSub_xsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,433";
}

template <	typename	ARCH>
OpSub_xuxtb<	ARCH>::OpSub_xuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,421";
}

template <	typename	ARCH>
OpSub_xuxth<	ARCH>::OpSub_xuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,425";
}

template <	typename	ARCH>
OpSub_xuxtw<	ARCH>::OpSub_xuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,429";
}

template <	typename	ARCH>
OpSub_xuxtx<	ARCH>::OpSub_xuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,435";
}

template <	typename	ARCH>
OpSub_wi<	ARCH>::OpSub_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,21";
}

template <	typename	ARCH>
OpSub_xi<	ARCH>::OpSub_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,30";
}

template <	typename	ARCH>
OpSub_wlsl<	ARCH>::OpSub_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,186";
}

template <	typename	ARCH>
OpSub_wlsr<	ARCH>::OpSub_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,201";
}

template <	typename	ARCH>
OpSub_wasr<	ARCH>::OpSub_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,177";
}

template <	typename	ARCH>
OpSub_xlsl<	ARCH>::OpSub_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,129";
}

template <	typename	ARCH>
OpSub_xlsr<	ARCH>::OpSub_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,141";
}

template <	typename	ARCH>
OpSub_xasr<	ARCH>::OpSub_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "sub_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,117";
}

template <	typename	ARCH>
OpSubs_wuxtb<	ARCH>::OpSubs_wuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,394";
}

template <	typename	ARCH>
OpSubs_wuxth<	ARCH>::OpSubs_wuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,398";
}

template <	typename	ARCH>
OpSubs_wuxtw<	ARCH>::OpSubs_wuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,401";
}

template <	typename	ARCH>
OpSubs_wuxtx<	ARCH>::OpSubs_wuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,406";
}

template <	typename	ARCH>
OpSubs_wsxtb<	ARCH>::OpSubs_wsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,378";
}

template <	typename	ARCH>
OpSubs_wsxth<	ARCH>::OpSubs_wsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,382";
}

template <	typename	ARCH>
OpSubs_wsxtw<	ARCH>::OpSubs_wsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,386";
}

template <	typename	ARCH>
OpSubs_wsxtx<	ARCH>::OpSubs_wsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,390";
}

template <	typename	ARCH>
OpSubs_xuxtb<	ARCH>::OpSubs_xuxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xuxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,422";
}

template <	typename	ARCH>
OpSubs_xuxth<	ARCH>::OpSubs_xuxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xuxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,426";
}

template <	typename	ARCH>
OpSubs_xuxtw<	ARCH>::OpSubs_xuxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xuxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,430";
}

template <	typename	ARCH>
OpSubs_xuxtx<	ARCH>::OpSubs_xuxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xuxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,437";
}

template <	typename	ARCH>
OpSubs_xsxtb<	ARCH>::OpSubs_xsxtb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xsxtb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,410";
}

template <	typename	ARCH>
OpSubs_xsxth<	ARCH>::OpSubs_xsxth(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xsxth")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,414";
}

template <	typename	ARCH>
OpSubs_xsxtw<	ARCH>::OpSubs_xsxtw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xsxtw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,418";
}

template <	typename	ARCH>
OpSubs_xsxtx<	ARCH>::OpSubs_xsxtx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xsxtx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x7);
	rm = uint8_t((code >> 16) & 0x1f);
	reject = imm >= 5;
	format = "base,434";
}

template <	typename	ARCH>
OpSubs_wi<	ARCH>::OpSubs_wi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,22";
}

template <	typename	ARCH>
OpSubs_xi<	ARCH>::OpSubs_xi(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xi")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm0 = uint16_t((code >> 10) & 0xfff);
	shl12 = uint8_t((code >> 22) & 0x1);
	imm = shl12 ? (imm0 << 12) : imm0;
	format = "base,31";
}

template <	typename	ARCH>
OpSubs_wlsl<	ARCH>::OpSubs_wlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,192";
}

template <	typename	ARCH>
OpSubs_wlsr<	ARCH>::OpSubs_wlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,202";
}

template <	typename	ARCH>
OpSubs_wasr<	ARCH>::OpSubs_wasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_wasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,178";
}

template <	typename	ARCH>
OpSubs_xlsl<	ARCH>::OpSubs_xlsl(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xlsl")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,133";
}

template <	typename	ARCH>
OpSubs_xlsr<	ARCH>::OpSubs_xlsr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xlsr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,142";
}

template <	typename	ARCH>
OpSubs_xasr<	ARCH>::OpSubs_xasr(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "subs_xasr")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imm = uint8_t((code >> 10) & 0x3f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,118";
}

template <	typename	ARCH>
OpSvc<	ARCH>::OpSvc(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "svc")
{
	imm = uint16_t((code >> 5) & 0xffff);
	format = "base,577";
}

template <	typename	ARCH>
OpTb<	ARCH>::OpTb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "tb")
{
	rt = uint8_t(code & 0x1f);
	imm = ((int16_t)(((code >> 5) & 0x3fff) << 2) >> 2) << 2;
	pos0 = uint8_t((code >> 19) & 0x1f);
	bitval = uint8_t((code >> 24) & 0x1);
	pos1 = uint8_t((code >> 31) & 0x1) << 5;
	pos = pos1|pos0;
	format = "base,5";
}

template <	typename	ARCH>
OpUbfm_w<	ARCH>::OpUbfm_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ubfm_w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x1f);
	immr = uint8_t((code >> 16) & 0x1f);
	format = "base,164";
}

template <	typename	ARCH>
OpUbfm_x<	ARCH>::OpUbfm_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ubfm_x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	imms = uint8_t((code >> 10) & 0x3f);
	immr = uint8_t((code >> 16) & 0x3f);
	format = "base,92";
}

template <	typename	ARCH>
OpUdiv_www<	ARCH>::OpUdiv_www(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "udiv_www")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1471";
}

template <	typename	ARCH>
OpUdiv_xxx<	ARCH>::OpUdiv_xxx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "udiv_xxx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,1618";
}

template <	typename	ARCH>
OpUmaddl_xw<	ARCH>::OpUmaddl_xw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "umaddl_xw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,237";
}

template <	typename	ARCH>
OpUmsubl_xw<	ARCH>::OpUmsubl_xw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "umsubl_xw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,238";
}

template <	typename	ARCH>
OpUmulh<	ARCH>::OpUmulh(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "umulh")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	ra = uint8_t((code >> 10) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
	format = "base,240";
}

template <	typename	ARCH>
OpCrc32b<	ARCH>::OpCrc32b(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32b")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32h<	ARCH>::OpCrc32h(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32h")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32w<	ARCH>::OpCrc32w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32w")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32x<	ARCH>::OpCrc32x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32x")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32cb<	ARCH>::OpCrc32cb(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32cb")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32ch<	ARCH>::OpCrc32ch(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32ch")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32cw<	ARCH>::OpCrc32cw(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32cw")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCrc32cx<	ARCH>::OpCrc32cx(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "crc32cx")
{
	rd = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rm = uint8_t((code >> 16) & 0x1f);
}

template <	typename	ARCH>
OpCas_w<	ARCH>::OpCas_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cas_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 16) & 0x1f);
	a = uint8_t((code >> 22) & 0x1);
}

template <	typename	ARCH>
OpCas_x<	ARCH>::OpCas_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cas_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 16) & 0x1f);
	a = uint8_t((code >> 22) & 0x1);
}

template <	typename	ARCH>
OpCasb_w<	ARCH>::OpCasb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "casb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 16) & 0x1f);
	a = uint8_t((code >> 22) & 0x1);
}

template <	typename	ARCH>
OpCash_w<	ARCH>::OpCash_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "cash_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 16) & 0x1f);
	a = uint8_t((code >> 22) & 0x1);
}

template <	typename	ARCH>
OpCasp_w<	ARCH>::OpCasp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "casp_w")
{
	rt = uint8_t((code >> 1) & 0xf) << 1;
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 17) & 0xf) << 1;
	a = uint8_t((code >> 22) & 0x1);
}

template <	typename	ARCH>
OpCasp_x<	ARCH>::OpCasp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "casp_x")
{
	rt = uint8_t((code >> 1) & 0xf) << 1;
	rn = uint8_t((code >> 5) & 0x1f);
	l = uint8_t((code >> 15) & 0x1);
	rs = uint8_t((code >> 17) & 0xf) << 1;
	a = uint8_t((code >> 22) & 0x1);
	format = "base,1919";
}

template <	typename	ARCH>
OpSwp_w<	ARCH>::OpSwp_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "swp_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	l = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpSwp_x<	ARCH>::OpSwp_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "swp_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	l = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpSwpb_w<	ARCH>::OpSwpb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "swpb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	l = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpSwph_w<	ARCH>::OpSwph_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "swph_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	l = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstadd_w<	ARCH>::OpLdstadd_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstadd_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstadd_x<	ARCH>::OpLdstadd_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstadd_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstaddb_w<	ARCH>::OpLdstaddb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstaddb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstaddh_w<	ARCH>::OpLdstaddh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstaddh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstclr_w<	ARCH>::OpLdstclr_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstclr_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstclr_x<	ARCH>::OpLdstclr_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstclr_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstclrb_w<	ARCH>::OpLdstclrb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstclrb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstclrh_w<	ARCH>::OpLdstclrh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstclrh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdsteor_w<	ARCH>::OpLdsteor_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldsteor_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdsteor_x<	ARCH>::OpLdsteor_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldsteor_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdsteorb_w<	ARCH>::OpLdsteorb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldsteorb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdsteorh_w<	ARCH>::OpLdsteorh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldsteorh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstset_w<	ARCH>::OpLdstset_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstset_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstset_x<	ARCH>::OpLdstset_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstset_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsetb_w<	ARCH>::OpLdstsetb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsetb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstseth_w<	ARCH>::OpLdstseth_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstseth_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmax_w<	ARCH>::OpLdstsmax_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmax_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmax_x<	ARCH>::OpLdstsmax_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmax_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmaxb_w<	ARCH>::OpLdstsmaxb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmaxb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmaxh_w<	ARCH>::OpLdstsmaxh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmaxh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmin_w<	ARCH>::OpLdstsmin_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmin_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsmin_x<	ARCH>::OpLdstsmin_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsmin_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsminb_w<	ARCH>::OpLdstsminb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsminb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstsminh_w<	ARCH>::OpLdstsminh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstsminh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumax_w<	ARCH>::OpLdstumax_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumax_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumax_x<	ARCH>::OpLdstumax_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumax_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumaxb_w<	ARCH>::OpLdstumaxb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumaxb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumaxh_w<	ARCH>::OpLdstumaxh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumaxh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumin_w<	ARCH>::OpLdstumin_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumin_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstumin_x<	ARCH>::OpLdstumin_x(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstumin_x")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstuminb_w<	ARCH>::OpLdstuminb_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstuminb_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
OpLdstuminh_w<	ARCH>::OpLdstuminh_w(CodeType code, uint64_t addr) : Operation<	ARCH>(code, addr, "ldstuminh_w")
{
	rt = uint8_t(code & 0x1f);
	rn = uint8_t((code >> 5) & 0x1f);
	rs = uint8_t((code >> 16) & 0x1f);
	r = uint8_t((code >> 22) & 0x1);
	a = uint8_t((code >> 23) & 0x1);
}

template <	typename	ARCH>
DecodeTableEntry<	ARCH>::DecodeTableEntry(CodeType opcode, CodeType opcode_mask, Operation<	ARCH> *(*decode)(CodeType, uint64_t))
{
	this->opcode = opcode;
	this->opcode_mask = opcode_mask;
	this->decode = decode;
}

template <	typename	ARCH>
Decoder<	ARCH>::Decoder()

{
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78207000UL, 0xff20fc00UL, DecodeOpLdstuminh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38207000UL, 0xff20fc00UL, DecodeOpLdstuminb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8207000UL, 0xff20fc00UL, DecodeOpLdstumin_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8207000UL, 0xff20fc00UL, DecodeOpLdstumin_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78206000UL, 0xff20fc00UL, DecodeOpLdstumaxh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38206000UL, 0xff20fc00UL, DecodeOpLdstumaxb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8206000UL, 0xff20fc00UL, DecodeOpLdstumax_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8206000UL, 0xff20fc00UL, DecodeOpLdstumax_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78205000UL, 0xff20fc00UL, DecodeOpLdstsminh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38205000UL, 0xff20fc00UL, DecodeOpLdstsminb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8205000UL, 0xff20fc00UL, DecodeOpLdstsmin_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8205000UL, 0xff20fc00UL, DecodeOpLdstsmin_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78204000UL, 0xff20fc00UL, DecodeOpLdstsmaxh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38204000UL, 0xff20fc00UL, DecodeOpLdstsmaxb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8204000UL, 0xff20fc00UL, DecodeOpLdstsmax_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8204000UL, 0xff20fc00UL, DecodeOpLdstsmax_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78203000UL, 0xff20fc00UL, DecodeOpLdstseth_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38203000UL, 0xff20fc00UL, DecodeOpLdstsetb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8203000UL, 0xff20fc00UL, DecodeOpLdstset_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8203000UL, 0xff20fc00UL, DecodeOpLdstset_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78202000UL, 0xff20fc00UL, DecodeOpLdsteorh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38202000UL, 0xff20fc00UL, DecodeOpLdsteorb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8202000UL, 0xff20fc00UL, DecodeOpLdsteor_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8202000UL, 0xff20fc00UL, DecodeOpLdsteor_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78201000UL, 0xff20fc00UL, DecodeOpLdstclrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38201000UL, 0xff20fc00UL, DecodeOpLdstclrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8201000UL, 0xff20fc00UL, DecodeOpLdstclr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8201000UL, 0xff20fc00UL, DecodeOpLdstclr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78200000UL, 0xff20fc00UL, DecodeOpLdstaddh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38200000UL, 0xff20fc00UL, DecodeOpLdstaddb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8200000UL, 0xff20fc00UL, DecodeOpLdstadd_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8200000UL, 0xff20fc00UL, DecodeOpLdstadd_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78208000UL, 0xff20fc00UL, DecodeOpSwph_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38208000UL, 0xff20fc00UL, DecodeOpSwpb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8208000UL, 0xff20fc00UL, DecodeOpSwp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8208000UL, 0xff20fc00UL, DecodeOpSwp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48207c00UL, 0xffa17c01UL, DecodeOpCasp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8207c00UL, 0xffa17c01UL, DecodeOpCasp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48a07c00UL, 0xffa07c00UL, DecodeOpCash_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a07c00UL, 0xffa07c00UL, DecodeOpCasb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8a07c00UL, 0xffa07c00UL, DecodeOpCas_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88a07c00UL, 0xffa07c00UL, DecodeOpCas_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac05c00UL, 0xffe0fc00UL, DecodeOpCrc32cx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac05800UL, 0xffe0fc00UL, DecodeOpCrc32cw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac05400UL, 0xffe0fc00UL, DecodeOpCrc32ch<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac05000UL, 0xffe0fc00UL, DecodeOpCrc32cb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac04c00UL, 0xffe0fc00UL, DecodeOpCrc32x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac04800UL, 0xffe0fc00UL, DecodeOpCrc32w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac04400UL, 0xffe0fc00UL, DecodeOpCrc32h<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac04000UL, 0xffe0fc00UL, DecodeOpCrc32b<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9bc00000UL, 0xffe08000UL, DecodeOpUmulh<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ba08000UL, 0xffe08000UL, DecodeOpUmsubl_xw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ba00000UL, 0xffe08000UL, DecodeOpUmaddl_xw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac00800UL, 0xffe0fc00UL, DecodeOpUdiv_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac00800UL, 0xffe0fc00UL, DecodeOpUdiv_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd3400000UL, 0xffc00000UL, DecodeOpUbfm_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x53000000UL, 0xffe08000UL, DecodeOpUbfm_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x36000000UL, 0x7e000000UL, DecodeOpTb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4000001UL, 0xffe0001fUL, DecodeOpSvc<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb800000UL, 0xffe00000UL, DecodeOpSubs_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb400000UL, 0xffe00000UL, DecodeOpSubs_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb000000UL, 0xffe00000UL, DecodeOpSubs_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b800000UL, 0xffe08000UL, DecodeOpSubs_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b400000UL, 0xffe08000UL, DecodeOpSubs_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b000000UL, 0xffe08000UL, DecodeOpSubs_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf1000000UL, 0xff800000UL, DecodeOpSubs_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x71000000UL, 0xff800000UL, DecodeOpSubs_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb20e000UL, 0xffe0e000UL, DecodeOpSubs_xsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb20c000UL, 0xffe0e000UL, DecodeOpSubs_xsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb20a000UL, 0xffe0e000UL, DecodeOpSubs_xsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb208000UL, 0xffe0e000UL, DecodeOpSubs_xsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb206000UL, 0xffe0e000UL, DecodeOpSubs_xuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb204000UL, 0xffe0e000UL, DecodeOpSubs_xuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb202000UL, 0xffe0e000UL, DecodeOpSubs_xuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeb200000UL, 0xffe0e000UL, DecodeOpSubs_xuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b20e000UL, 0xffe0e000UL, DecodeOpSubs_wsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b20c000UL, 0xffe0e000UL, DecodeOpSubs_wsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b20a000UL, 0xffe0e000UL, DecodeOpSubs_wsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b208000UL, 0xffe0e000UL, DecodeOpSubs_wsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b206000UL, 0xffe0e000UL, DecodeOpSubs_wuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b204000UL, 0xffe0e000UL, DecodeOpSubs_wuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b202000UL, 0xffe0e000UL, DecodeOpSubs_wuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6b200000UL, 0xffe0e000UL, DecodeOpSubs_wuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb800000UL, 0xffe00000UL, DecodeOpSub_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb400000UL, 0xffe00000UL, DecodeOpSub_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb000000UL, 0xffe00000UL, DecodeOpSub_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b800000UL, 0xffe08000UL, DecodeOpSub_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b400000UL, 0xffe08000UL, DecodeOpSub_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b000000UL, 0xffe08000UL, DecodeOpSub_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd1000000UL, 0xff800000UL, DecodeOpSub_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x51000000UL, 0xff800000UL, DecodeOpSub_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb206000UL, 0xffe0e000UL, DecodeOpSub_xuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb204000UL, 0xffe0e000UL, DecodeOpSub_xuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb202000UL, 0xffe0e000UL, DecodeOpSub_xuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb200000UL, 0xffe0e000UL, DecodeOpSub_xuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb20e000UL, 0xffe0e000UL, DecodeOpSub_xsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb20c000UL, 0xffe0e000UL, DecodeOpSub_xsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb20a000UL, 0xffe0e000UL, DecodeOpSub_xsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcb208000UL, 0xffe0e000UL, DecodeOpSub_xsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b206000UL, 0xffe0e000UL, DecodeOpSub_wuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b204000UL, 0xffe0e000UL, DecodeOpSub_wuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b202000UL, 0xffe0e000UL, DecodeOpSub_wuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b200000UL, 0xffe0e000UL, DecodeOpSub_wuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b20e000UL, 0xffe0e000UL, DecodeOpSub_wsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b20c000UL, 0xffe0e000UL, DecodeOpSub_wsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b20a000UL, 0xffe0e000UL, DecodeOpSub_wsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4b208000UL, 0xffe0e000UL, DecodeOpSub_wsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48000000UL, 0xffe08000UL, DecodeOpStxrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8000000UL, 0xffe08000UL, DecodeOpStxrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8000000UL, 0xffe08000UL, DecodeOpStxr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88000000UL, 0xffe08000UL, DecodeOpStxr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8200000UL, 0xffe08000UL, DecodeOpStxp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88200000UL, 0xffe08000UL, DecodeOpStxp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78000800UL, 0xffe00c00UL, DecodeOpSttrh_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38000800UL, 0xffe00c00UL, DecodeOpSttrb_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8000800UL, 0xffe00c00UL, DecodeOpSttr_xbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8000800UL, 0xffe00c00UL, DecodeOpSttr_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7820e800UL, 0xffe0ec00UL, DecodeOpStrh_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7820c800UL, 0xffe0ec00UL, DecodeOpStrh_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78206800UL, 0xffe0ec00UL, DecodeOpStrh_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78204800UL, 0xffe0ec00UL, DecodeOpStrh_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x79000000UL, 0xffc00000UL, DecodeOpStrh_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78000000UL, 0xffe00000UL, DecodeOpStrh_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3820e800UL, 0xffe0ec00UL, DecodeOpStrb_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3820c800UL, 0xffe0ec00UL, DecodeOpStrb_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38206800UL, 0xffe0ec00UL, DecodeOpStrb_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38204800UL, 0xffe0ec00UL, DecodeOpStrb_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x39000000UL, 0xffc00000UL, DecodeOpStrb_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38000000UL, 0xffe00000UL, DecodeOpStrb_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf820e800UL, 0xffe0ec00UL, DecodeOpStr_xxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf820c800UL, 0xffe0ec00UL, DecodeOpStr_xxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8206800UL, 0xffe0ec00UL, DecodeOpStr_xxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8204800UL, 0xffe0ec00UL, DecodeOpStr_xxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb820e800UL, 0xffe0ec00UL, DecodeOpStr_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb820c800UL, 0xffe0ec00UL, DecodeOpStr_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8206800UL, 0xffe0ec00UL, DecodeOpStr_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8204800UL, 0xffe0ec00UL, DecodeOpStr_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf9000000UL, 0xffc00000UL, DecodeOpStr_xuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8000000UL, 0xffe00000UL, DecodeOpStr_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb9000000UL, 0xffc00000UL, DecodeOpStr_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8000000UL, 0xffe00000UL, DecodeOpStr_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa8000000UL, 0xfe400000UL, DecodeOpStp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x28000000UL, 0xfe400000UL, DecodeOpStp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48008000UL, 0xffe08000UL, DecodeOpStlxrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8008000UL, 0xffe08000UL, DecodeOpStlxrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8008000UL, 0xffe08000UL, DecodeOpStlxr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88008000UL, 0xffe08000UL, DecodeOpStlxr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8208000UL, 0xffe08000UL, DecodeOpStlxp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88208000UL, 0xffe08000UL, DecodeOpStlxp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48808000UL, 0xffe08000UL, DecodeOpStlrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8808000UL, 0xffe08000UL, DecodeOpStlrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8808000UL, 0xffe08000UL, DecodeOpStlr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88808000UL, 0xffe08000UL, DecodeOpStlr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9b400000UL, 0xffe08000UL, DecodeOpSmulh<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9b208000UL, 0xffe08000UL, DecodeOpSmsubl_xw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4000003UL, 0xffe0001fUL, DecodeOpSmc<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9b200000UL, 0xffe08000UL, DecodeOpSmaddl_xw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac00c00UL, 0xffe0fc00UL, DecodeOpSdiv_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac00c00UL, 0xffe0fc00UL, DecodeOpSdiv_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x93400000UL, 0xffc00000UL, DecodeOpSbfm_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x13000000UL, 0xffe08000UL, DecodeOpSbfm_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xfa000000UL, 0xffe0fc00UL, DecodeOpSbcs_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7a000000UL, 0xffe0fc00UL, DecodeOpSbcs_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xda000000UL, 0xffe0fc00UL, DecodeOpSbc_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5a000000UL, 0xffe0fc00UL, DecodeOpSbc_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac02c00UL, 0xffe0fc00UL, DecodeOpRor_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac02c00UL, 0xffe0fc00UL, DecodeOpRor_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac00800UL, 0xfffffc00UL, DecodeOpRev32_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac00400UL, 0xfffffc00UL, DecodeOpRev16_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5ac00400UL, 0xfffffc00UL, DecodeOpRev16_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac00c00UL, 0xfffffc00UL, DecodeOpRev_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5ac00800UL, 0xfffffc00UL, DecodeOpRev_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd65f0000UL, 0xfffffc1fUL, DecodeOpRet<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac00000UL, 0xfffffc00UL, DecodeOpRbit_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5ac00000UL, 0xfffffc00UL, DecodeOpRbit_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8800000UL, 0xffe00c00UL, DecodeOpPrfum<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8a06800UL, 0xffe06c00UL, DecodeOpPrefetchMemory_xx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8a04800UL, 0xffe0ec00UL, DecodeOpPrefetchMemory_xwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8a0c800UL, 0xffe0ec00UL, DecodeOpPrefetchMemory_xws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf9800000UL, 0xffc00000UL, DecodeOpPrefetchMemory_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd8000000UL, 0xff000000UL, DecodeOpPrfm_lit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaac00000UL, 0xffe00000UL, DecodeOpOrr_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2ac00000UL, 0xffe08000UL, DecodeOpOrr_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa800000UL, 0xffe00000UL, DecodeOpOrr_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2a800000UL, 0xffe08000UL, DecodeOpOrr_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa400000UL, 0xffe00000UL, DecodeOpOrr_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2a400000UL, 0xffe08000UL, DecodeOpOrr_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa000000UL, 0xffe00000UL, DecodeOpOrr_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2a000000UL, 0xffe08000UL, DecodeOpOrr_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb2000000UL, 0xff800000UL, DecodeOpOrr_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x32000000UL, 0xffc00000UL, DecodeOpOrr_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaae00000UL, 0xffe00000UL, DecodeOpOrn_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaaa00000UL, 0xffe00000UL, DecodeOpOrn_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa600000UL, 0xffe00000UL, DecodeOpOrn_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa200000UL, 0xffe00000UL, DecodeOpOrn_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2ae00000UL, 0xffe08000UL, DecodeOpOrn_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2aa00000UL, 0xffe08000UL, DecodeOpOrn_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2a600000UL, 0xffe08000UL, DecodeOpOrn_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2a200000UL, 0xffe08000UL, DecodeOpOrn_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd503201fUL, 0xffffffffUL, DecodeOpNop<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9b008000UL, 0xffe08000UL, DecodeOpMsub_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1b008000UL, 0xffe08000UL, DecodeOpMsub_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd5200000UL, 0xffe00000UL, DecodeOpMrs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf2800000UL, 0xff800000UL, DecodeOpMovk_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x72800000UL, 0xffc00000UL, DecodeOpMovk_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x92800000UL, 0xbf800000UL, DecodeOpMov_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x12800000UL, 0xbfc00000UL, DecodeOpMov_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9b000000UL, 0xffe08000UL, DecodeOpMadd_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1b000000UL, 0xffe08000UL, DecodeOpMadd_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac02400UL, 0xffe0fc00UL, DecodeOpLsr_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac02400UL, 0xffe0fc00UL, DecodeOpLsr_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac02000UL, 0xffe0fc00UL, DecodeOpLsl_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac02000UL, 0xffe0fc00UL, DecodeOpLsl_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48400000UL, 0xffe08000UL, DecodeOpLdxrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8400000UL, 0xffe08000UL, DecodeOpLdxrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8400000UL, 0xffe08000UL, DecodeOpLdxr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88400000UL, 0xffe08000UL, DecodeOpLdxr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8600000UL, 0xffe08000UL, DecodeOpLdxp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88600000UL, 0xffe08000UL, DecodeOpLdxp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8800800UL, 0xffe00c00UL, DecodeOpLdtrsw_xbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78800800UL, 0xffe00c00UL, DecodeOpLdtrsh_xbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78c00800UL, 0xffe00c00UL, DecodeOpLdtrsh_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38800800UL, 0xffe00c00UL, DecodeOpLdtrsb_xbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38c00800UL, 0xffe00c00UL, DecodeOpLdtrsb_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78400800UL, 0xffe00c00UL, DecodeOpLdtrh_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38400800UL, 0xffe00c00UL, DecodeOpLdtrb_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8400800UL, 0xffe00c00UL, DecodeOpLdtr_xbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8400800UL, 0xffe00c00UL, DecodeOpLdtr_wbo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8a0e800UL, 0xffe0ec00UL, DecodeOpLdrsw_xxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8a0c800UL, 0xffe0ec00UL, DecodeOpLdrsw_xxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8a06800UL, 0xffe0ec00UL, DecodeOpLdrsw_xxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8a04800UL, 0xffe0ec00UL, DecodeOpLdrsw_xxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb9800000UL, 0xffc00000UL, DecodeOpLdrsw_xuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8800000UL, 0xffe00000UL, DecodeOpLdrsw_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x98000000UL, 0xff000000UL, DecodeOpLdrsw_xlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78a0e800UL, 0xffe0ec00UL, DecodeOpLdrsh_xxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78a0c800UL, 0xffe0ec00UL, DecodeOpLdrsh_xxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78a06800UL, 0xffe0ec00UL, DecodeOpLdrsh_xxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78a04800UL, 0xffe0ec00UL, DecodeOpLdrsh_xxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78e0e800UL, 0xffe0ec00UL, DecodeOpLdrsh_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78e0c800UL, 0xffe0ec00UL, DecodeOpLdrsh_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78e06800UL, 0xffe0ec00UL, DecodeOpLdrsh_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78e04800UL, 0xffe0ec00UL, DecodeOpLdrsh_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x79800000UL, 0xffc00000UL, DecodeOpLdrsh_xuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78800000UL, 0xffe00000UL, DecodeOpLdrsh_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x79c00000UL, 0xffc00000UL, DecodeOpLdrsh_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78c00000UL, 0xffe00000UL, DecodeOpLdrsh_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38a0e800UL, 0xffe0ec00UL, DecodeOpLdrsb_xxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38a0c800UL, 0xffe0ec00UL, DecodeOpLdrsb_xxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38a06800UL, 0xffe0ec00UL, DecodeOpLdrsb_xxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38a04800UL, 0xffe0ec00UL, DecodeOpLdrsb_xxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38e0e800UL, 0xffe0ec00UL, DecodeOpLdrsb_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38e0c800UL, 0xffe0ec00UL, DecodeOpLdrsb_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38e06800UL, 0xffe0ec00UL, DecodeOpLdrsb_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38e04800UL, 0xffe0ec00UL, DecodeOpLdrsb_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x39800000UL, 0xffc00000UL, DecodeOpLdrsb_xuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38800000UL, 0xffe00000UL, DecodeOpLdrsb_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x39c00000UL, 0xffc00000UL, DecodeOpLdrsb_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38c00000UL, 0xffe00000UL, DecodeOpLdrsb_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7860e800UL, 0xffe0ec00UL, DecodeOpLdrh_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7860c800UL, 0xffe0ec00UL, DecodeOpLdrh_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78606800UL, 0xffe0ec00UL, DecodeOpLdrh_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78604800UL, 0xffe0ec00UL, DecodeOpLdrh_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x79400000UL, 0xffc00000UL, DecodeOpLdrh_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x78400000UL, 0xffe00000UL, DecodeOpLdrh_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3860e800UL, 0xffe0ec00UL, DecodeOpLdrb_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3860c800UL, 0xffe0ec00UL, DecodeOpLdrb_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38606800UL, 0xffe0ec00UL, DecodeOpLdrb_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38604800UL, 0xffe0ec00UL, DecodeOpLdrb_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x39400000UL, 0xffc00000UL, DecodeOpLdrb_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x38400000UL, 0xffe00000UL, DecodeOpLdrb_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf860e800UL, 0xffe0ec00UL, DecodeOpLdr_xxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf860c800UL, 0xffe0ec00UL, DecodeOpLdr_xxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8606800UL, 0xffe0ec00UL, DecodeOpLdr_xxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8604800UL, 0xffe0ec00UL, DecodeOpLdr_xxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb860e800UL, 0xffe0ec00UL, DecodeOpLdr_wxxs<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb860c800UL, 0xffe0ec00UL, DecodeOpLdr_wxws<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8606800UL, 0xffe0ec00UL, DecodeOpLdr_wxxu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8604800UL, 0xffe0ec00UL, DecodeOpLdr_wxwu<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x58000000UL, 0xff000000UL, DecodeOpLdr_xlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x18000000UL, 0xff000000UL, DecodeOpLdr_wlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf9400000UL, 0xffc00000UL, DecodeOpLdr_xuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf8400000UL, 0xffe00000UL, DecodeOpLdr_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb9400000UL, 0xffc00000UL, DecodeOpLdr_wuo<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb8400000UL, 0xffe00000UL, DecodeOpLdr_wxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x68400000UL, 0xfe400000UL, DecodeOpLdpsw_xxi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa8400000UL, 0xfe400000UL, DecodeOpLdp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x28400000UL, 0xfe400000UL, DecodeOpLdp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48408000UL, 0xffe08000UL, DecodeOpLdaxrh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8408000UL, 0xffe08000UL, DecodeOpLdaxrb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8408000UL, 0xffe08000UL, DecodeOpLdaxr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88408000UL, 0xffe08000UL, DecodeOpLdaxr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8608000UL, 0xffe08000UL, DecodeOpLdaxp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88608000UL, 0xffe08000UL, DecodeOpLdaxp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x48dffc00UL, 0xfffffc00UL, DecodeOpLdarh_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8dffc00UL, 0xfffffc00UL, DecodeOpLdarb_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xc8dffc00UL, 0xfffffc00UL, DecodeOpLdar_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x88dffc00UL, 0xfffffc00UL, DecodeOpLdar_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4000002UL, 0xffe0001fUL, DecodeOpHvc<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4400000UL, 0xffe0001fUL, DecodeOpHlt<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x93c00000UL, 0xffe00000UL, DecodeOpExtr_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x13800000UL, 0xffe08000UL, DecodeOpExtr_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd69f03e0UL, 0xffffffffUL, DecodeOpEret<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcac00000UL, 0xffe00000UL, DecodeOpEor_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xca800000UL, 0xffe00000UL, DecodeOpEor_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xca400000UL, 0xffe00000UL, DecodeOpEor_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xca000000UL, 0xffe00000UL, DecodeOpEor_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4ac00000UL, 0xffe08000UL, DecodeOpEor_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4a800000UL, 0xffe08000UL, DecodeOpEor_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4a400000UL, 0xffe08000UL, DecodeOpEor_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4a000000UL, 0xffe08000UL, DecodeOpEor_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd2000000UL, 0xff800000UL, DecodeOpEor_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x52000000UL, 0xffc00000UL, DecodeOpEor_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcae00000UL, 0xffe00000UL, DecodeOpEon_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xcaa00000UL, 0xffe00000UL, DecodeOpEon_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xca600000UL, 0xffe00000UL, DecodeOpEon_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xca200000UL, 0xffe00000UL, DecodeOpEon_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4ae00000UL, 0xffe08000UL, DecodeOpEon_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4aa00000UL, 0xffe08000UL, DecodeOpEon_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4a600000UL, 0xffe08000UL, DecodeOpEon_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x4a200000UL, 0xffe08000UL, DecodeOpEon_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd6bf03e0UL, 0xffffffffUL, DecodeOpDrps<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4a00003UL, 0xffe0001fUL, DecodeOpDcps3<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4a00002UL, 0xffe0001fUL, DecodeOpDcps2<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4a00001UL, 0xffe0001fUL, DecodeOpDcps1<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xda800400UL, 0xffe00c00UL, DecodeOpCsneg_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5a800400UL, 0xffe00c00UL, DecodeOpCsneg_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xda800000UL, 0xffe00c00UL, DecodeOpCsinv_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5a800000UL, 0xffe00c00UL, DecodeOpCsinv_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9a800400UL, 0xffe00c00UL, DecodeOpCsinc_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1a800400UL, 0xffe00c00UL, DecodeOpCsinc_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9a800000UL, 0xffe00c00UL, DecodeOpCsel_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1a800000UL, 0xffe00c00UL, DecodeOpCsel_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac01000UL, 0xfffffc00UL, DecodeOpClz_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5ac01000UL, 0xfffffc00UL, DecodeOpClz_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xdac01400UL, 0xfffffc00UL, DecodeOpCls_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x5ac01400UL, 0xfffffc00UL, DecodeOpCls_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd503305fUL, 0xfffff0ffUL, DecodeOpClrex<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xfa400000UL, 0xffe00c10UL, DecodeOpCcmp_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7a400000UL, 0xffe00c10UL, DecodeOpCcmp_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xfa400800UL, 0xffe00c10UL, DecodeOpCcmp_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x7a400800UL, 0xffe00c10UL, DecodeOpCcmp_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xba400000UL, 0xffe00c10UL, DecodeOpCcmn_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3a400000UL, 0xffe00c10UL, DecodeOpCcmn_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xba400800UL, 0xffe00c10UL, DecodeOpCcmn_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3a400800UL, 0xffe00c10UL, DecodeOpCcmn_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb4000000UL, 0xff000000UL, DecodeOpCbz_xlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x34000000UL, 0xff000000UL, DecodeOpCbz_wlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb5000000UL, 0xff000000UL, DecodeOpCbnz_xlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x35000000UL, 0xff000000UL, DecodeOpCbnz_wlit<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd4200000UL, 0xffe0001fUL, DecodeOpBrk<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd61f0000UL, 0xfffffc1fUL, DecodeOpBr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd63f0000UL, 0xfffffc1fUL, DecodeOpBlr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x94000000UL, 0xfc000000UL, DecodeOpBl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeae00000UL, 0xffe00000UL, DecodeOpBics_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeaa00000UL, 0xffe00000UL, DecodeOpBics_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xea600000UL, 0xffe00000UL, DecodeOpBics_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xea200000UL, 0xffe00000UL, DecodeOpBics_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6ae00000UL, 0xffe08000UL, DecodeOpBics_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6aa00000UL, 0xffe08000UL, DecodeOpBics_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6a600000UL, 0xffe08000UL, DecodeOpBics_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6a200000UL, 0xffe08000UL, DecodeOpBics_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8ae00000UL, 0xffe00000UL, DecodeOpBic_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8aa00000UL, 0xffe00000UL, DecodeOpBic_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a600000UL, 0xffe00000UL, DecodeOpBic_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a200000UL, 0xffe00000UL, DecodeOpBic_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xae00000UL, 0xffe08000UL, DecodeOpBic_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xaa00000UL, 0xffe08000UL, DecodeOpBic_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa600000UL, 0xffe08000UL, DecodeOpBic_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa200000UL, 0xffe08000UL, DecodeOpBic_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb3400000UL, 0xffc00000UL, DecodeOpBfm_x<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x33000000UL, 0xffe08000UL, DecodeOpBfm_w<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x54000000UL, 0xff000010UL, DecodeOpB_cond<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x14000000UL, 0xfc000000UL, DecodeOpB<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9ac02800UL, 0xffe0fc00UL, DecodeOpAsr_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1ac02800UL, 0xffe0fc00UL, DecodeOpAsr_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xeac00000UL, 0xffe00000UL, DecodeOpAnds_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xea800000UL, 0xffe00000UL, DecodeOpAnds_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xea400000UL, 0xffe00000UL, DecodeOpAnds_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xea000000UL, 0xffe00000UL, DecodeOpAnds_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6ac00000UL, 0xffe08000UL, DecodeOpAnds_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6a800000UL, 0xffe08000UL, DecodeOpAnds_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6a400000UL, 0xffe08000UL, DecodeOpAnds_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x6a000000UL, 0xffe08000UL, DecodeOpAnds_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xf2000000UL, 0xff800000UL, DecodeOpAnds_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x72000000UL, 0xffc00000UL, DecodeOpAnds_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8ac00000UL, 0xffe00000UL, DecodeOpAnd_xror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a800000UL, 0xffe00000UL, DecodeOpAnd_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a400000UL, 0xffe00000UL, DecodeOpAnd_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8a000000UL, 0xffe00000UL, DecodeOpAnd_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xac00000UL, 0xffe08000UL, DecodeOpAnd_wror<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa800000UL, 0xffe08000UL, DecodeOpAnd_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa400000UL, 0xffe08000UL, DecodeOpAnd_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xa000000UL, 0xffe08000UL, DecodeOpAnd_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x92000000UL, 0xff800000UL, DecodeOpAnd_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x12000000UL, 0xffc00000UL, DecodeOpAnd_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x90000000UL, 0x9f000000UL, DecodeOpAdrp<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x10000000UL, 0x9f000000UL, DecodeOpAdr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab800000UL, 0xffe00000UL, DecodeOpAdds_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab400000UL, 0xffe00000UL, DecodeOpAdds_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab000000UL, 0xffe00000UL, DecodeOpAdds_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b800000UL, 0xffe08000UL, DecodeOpAdds_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b400000UL, 0xffe08000UL, DecodeOpAdds_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b000000UL, 0xffe08000UL, DecodeOpAdds_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb1000000UL, 0xff800000UL, DecodeOpAdds_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x31000000UL, 0xff800000UL, DecodeOpAdds_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab206000UL, 0xffe0e000UL, DecodeOpAdds_xuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab204000UL, 0xffe0e000UL, DecodeOpAdds_xuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab202000UL, 0xffe0e000UL, DecodeOpAdds_xuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab200000UL, 0xffe0e000UL, DecodeOpAdds_xuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab20e000UL, 0xffe0e000UL, DecodeOpAdds_xsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab20c000UL, 0xffe0e000UL, DecodeOpAdds_xsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab20a000UL, 0xffe0e000UL, DecodeOpAdds_xsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xab208000UL, 0xffe0e000UL, DecodeOpAdds_xsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b206000UL, 0xffe0e000UL, DecodeOpAdds_wuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b204000UL, 0xffe0e000UL, DecodeOpAdds_wuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b202000UL, 0xffe0e000UL, DecodeOpAdds_wuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b200000UL, 0xffe0e000UL, DecodeOpAdds_wuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b20e000UL, 0xffe0e000UL, DecodeOpAdds_wsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b20c000UL, 0xffe0e000UL, DecodeOpAdds_wsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b20a000UL, 0xffe0e000UL, DecodeOpAdds_wsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x2b208000UL, 0xffe0e000UL, DecodeOpAdds_wsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b800000UL, 0xffe00000UL, DecodeOpAdd_xasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b400000UL, 0xffe00000UL, DecodeOpAdd_xlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b000000UL, 0xffe00000UL, DecodeOpAdd_xlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb800000UL, 0xffe08000UL, DecodeOpAdd_wasr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb400000UL, 0xffe08000UL, DecodeOpAdd_wlsr<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb000000UL, 0xffe08000UL, DecodeOpAdd_wlsl<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x91000000UL, 0xff800000UL, DecodeOpAdd_xi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x11000000UL, 0xff800000UL, DecodeOpAdd_wi<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b206000UL, 0xffe0e000UL, DecodeOpAdd_xuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b204000UL, 0xffe0e000UL, DecodeOpAdd_xuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b202000UL, 0xffe0e000UL, DecodeOpAdd_xuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b200000UL, 0xffe0e000UL, DecodeOpAdd_xuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b20e000UL, 0xffe0e000UL, DecodeOpAdd_xsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b20c000UL, 0xffe0e000UL, DecodeOpAdd_xsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b20a000UL, 0xffe0e000UL, DecodeOpAdd_xsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x8b208000UL, 0xffe0e000UL, DecodeOpAdd_xsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb206000UL, 0xffe0e000UL, DecodeOpAdd_wuxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb204000UL, 0xffe0e000UL, DecodeOpAdd_wuxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb202000UL, 0xffe0e000UL, DecodeOpAdd_wuxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb200000UL, 0xffe0e000UL, DecodeOpAdd_wuxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb20e000UL, 0xffe0e000UL, DecodeOpAdd_wsxtx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb20c000UL, 0xffe0e000UL, DecodeOpAdd_wsxtw<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb20a000UL, 0xffe0e000UL, DecodeOpAdd_wsxth<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xb208000UL, 0xffe0e000UL, DecodeOpAdd_wsxtb<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xba000000UL, 0xffe0fc00UL, DecodeOpAdcs_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x3a000000UL, 0xffe0fc00UL, DecodeOpAdcs_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x9a000000UL, 0xffe0fc00UL, DecodeOpAdc_xxx<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0x1a000000UL, 0xffe0fc00UL, DecodeOpAdc_www<	ARCH>));
	decode_table.push_back(DecodeTableEntry<	ARCH>(0xd5000000UL, 0xffe00000UL, DecodeOpMsr<	ARCH>));
}

template <	typename	ARCH>
Decoder<	ARCH>::~Decoder()
{
}

template <	typename	ARCH>
Operation<	ARCH> *Decoder<	ARCH>::NCDecode(uint64_t addr, CodeType code)
{
	Operation<	ARCH> *operation;
	unsigned int count = decode_table.size();
	unsigned int idx;
	for(idx = 0; idx < count; idx++)
	{
		if((code & decode_table[idx].opcode_mask) == decode_table[idx].opcode)
		{
			operation = decode_table[idx].decode(code, addr);
			return operation;
		}
	}
	operation = new Operation<	ARCH>(code, addr, "???");
	return operation;
}

} } } } } } }
