PIN_ROOT := ../../../Abacus-artifact/Intel-Pin-Archive/
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
TARGET := ia32

include ../makefile.benchmarks
include makefile.rules
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

pintool: dir
	$(MAKE) tools
