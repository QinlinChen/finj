build_dir := ./build

# find finjcore
finjcore_include_dirs := ../finj-core/include
finjcore_srcs := $(abspath $(shell find ../finj-core/src/ -name "*.c"))

# find genhook
genhook_bin := ../tools/genhook.py

# define project target, includes, and sources
finjhook_lib := $(build_dir)/libfinjhook.so
finjhook_include_dirs := ./include
finjhook_srcs := src/hook.c $(finjcore_srcs)

# compile options
CC := gcc
CFLAGS += -O2 -Wall -Werror $(addprefix -I, $(finjcore_include_dirs) $(finjhook_include_dirs))
LD := gcc

# files to generate
hook_data := ./data/hook.data
gens := include/finj/hook.h src/hook.c

# intermediate files
obj_dir := $(build_dir)/obj
objs := $(finjhook_srcs:%.c=$(obj_dir)/%.o)

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

.PHONY: clean test

clean:
	-rm -f $(gens)
	-rm -rf $(build_dir)

test_bin := $(build_dir)/test/main
test_srcs := test/main.c

test: $(test_bin)
	@cat /dev/null > /tmp/finj.log
	@echo "------------------- result -------------------"
	$(test_bin)
	@echo "----------------------------------------------"

$(test_bin): $(test_srcs) all
	@echo + CCLD $(test_bin)
	@mkdir -p $(dir $(test_bin))
	@$(CC) $(CFLAGS) -o $(test_bin) $(test_srcs) $(finjhook_lib)
