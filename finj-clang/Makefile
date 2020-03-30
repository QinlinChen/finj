build_dir := ./build
install_prefix := /tmp/finj

# find finjcore
finjcore_include_dirs := ../finj-core/include
finjcore_srcs := $(abspath $(shell find ../finj-core/src/ -name "*.c"))

# find genhook
genhook_bin := ../tools/genhook.py

# files to generate 
llvmrt_data := ./data/finj-llvm-rt.data
gens := finj-llvm-rt.c

# define finj-llvm-rt
finjllvmrt_lib := $(build_dir)/libfinjllvm.a
finjllvmrt_include_dirs := $(finjcore_include_dirs)
finjllvmrt_src := finj-llvm-rt.c $(finjcore_srcs)

# intermediate files of finj-llvm-rt
obj_dir := $(build_dir)/obj
objs := $(finjllvmrt_src:%.c=$(obj_dir)/%.o)

# define finj-pass
finjpass_lib := $(build_dir)/libfinjpass.so
finjpass_src := FINJPass.cpp

# define finj-clang
finjclang_bin := $(build_dir)/finj-clang
finjclangxx_bin := $(build_dir)/finj-clang++
finjclang_src := finj-clang.c

# compile options
CC=clang
CXX=clang++

LLVM_CONFIG ?= llvm-config

CFLAGS ?= -O3
CFLAGS += -Wall -g
CXXFLAGS ?= -O3
CXXFLAGS += -Wall -g

CLANG_CFL := `$(LLVM_CONFIG) --cxxflags` $(CXXFLAGS)
CLANG_LFL := `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

AR := ar
ARFLAGS := rcs

all: $(gens) $(finjllvmrt_lib) $(finjpass_lib) $(finjclang_bin) $(finjclangxx_bin)

$(gens):%:%.temp $(llvmrt_data) $(genhook_bin)
	@echo + generate $@
	@python3 $(genhook_bin) -d $(llvmrt_data) -i $< -o $@

$(finjllvmrt_lib): $(objs)
	@echo + AR $(notdir $@)
	@$(AR) $(ARFLAGS) $@ $^

$(obj_dir)/%.o: %.c
	@echo + CC $(notdir $<)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(addprefix -I, $(finjllvmrt_include_dirs)) -MMD -c -o $@ $<

-include $(objs:.o/.d)

$(finjpass_lib): $(finjpass_src)
	@echo + CXX $(notdir $@)
	@$(CXX) $(CLANG_CFL) -fno-rtti -fPIC -shared $< -o $@ $(CLANG_LFL)

$(finjclang_bin): $(finjclang_src)
	@echo + CC $(notdir $@)
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(finjclangxx_bin): $(finjclang_bin)
	@echo + ln $(notdir $@)
	@ln -srf $(finjclang_bin) $(finjclangxx_bin)

.PHONY: clean

clean:
	-rm -f $(gens)
	-rm -rf $(build_dir)