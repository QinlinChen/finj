build_dir      := ./build
install_prefix := $$HOME/finj

# find finjcore
finjcore_include_dirs := ../finj-core/include
finjcore_srcs         := $(abspath $(shell find ../finj-core/src/ -name "*.c"))

# find genhook and define files to generate
genhook_bin := ../tools/genhook.py
hook_data   := ./data/hook.data
gens        := include/finj/hook.h src/hook.c

# define project target, includes, and sources
finjhook_lib          := $(build_dir)/libfinjhook.so
finjhook_include_dirs := ./include $(finjcore_include_dirs)
finjhook_srcs         := src/hook.c $(finjcore_srcs)

# intermediate files
obj_dir := $(build_dir)/obj
objs    := $(finjhook_srcs:%.c=$(obj_dir)/%.o)

# compile options
CC     := gcc
CFLAGS += -O2 -Wall -Werror $(addprefix -I, $(finjhook_include_dirs))
LD     := gcc

all: $(gens) $(finjhook_lib)

$(gens):%:%.temp $(hook_data) $(genhook_bin)
	@echo + generate $@
	@python3 $(genhook_bin) -d $(hook_data) -i $< -o $@

$(finjhook_lib): $(objs)
	@echo + LD $(notdir $@)
	@$(LD) -shared -o $@ $^

$(obj_dir)/%.o: %.c
	@echo + CC $(notdir $<)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -fPIC -MMD -c -o $@ $<

-include $(objs:.o/.d)

.PHONY: clean test install

clean:
	-rm -f $(gens)
	-rm -rf $(build_dir)

test_bin := $(build_dir)/test/main
test_srcs := test/main.c

test: $(test_bin)
	@cat /dev/null > /tmp/finj.log
	$(test_bin)
	@sleep 1
	@echo "-------------- /tmp/finj.log -----------------"
	@cat /tmp/finj.log
	@echo "----------------------------------------------"

$(test_bin): $(test_srcs) $(gens) $(finjhook_lib)
	@echo + CCLD $(test_bin)
	@mkdir -p $(dir $(test_bin))
	@$(CC) $(CFLAGS) -o $(test_bin) $(test_srcs) $(finjhook_lib)

install: all
	@mkdir -p $(install_prefix)
	@mkdir -p $(install_prefix)/lib
	@mkdir -p $(install_prefix)/include
	@cp $(finjhook_lib) $(install_prefix)/lib
	@for include_dir in $(finjhook_include_dirs); do \
		cp -r $$include_dir $(install_prefix); \
	done