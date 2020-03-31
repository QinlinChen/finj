build_dir      := ./build
install_prefix := /tmp/finj

# define project target, includes, and sources
finjcore_lib          := $(build_dir)/libfinjcore.so
finjcore_include_dirs := ./include
finjcore_srcs         := $(shell find src/ -name "*.c")

# compile options
CC     := gcc
CFLAGS += -O2 -Wall -Werror -fPIC $(addprefix -I, $(finjcore_include_dirs))
LD     := gcc

# intermediate files
obj_dir := $(build_dir)/obj
objs    := $(finjcore_srcs:%.c=$(obj_dir)/%.o)

$(finjcore_lib): $(objs)
	@echo + LD $(notdir $@)
	@$(LD) -shared -o $@ $^

$(obj_dir)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -MMD -c -o $@ $<

-include $(objs:.o/.d)

.PHONY: clean count install

clean:
	-rm -rf $(build_dir)

count:
	@find . -name "*.[ch]" | xargs cat | wc -l

install: $(finjcore_lib)
	@mkdir -p $(install_prefix)
	@mkdir -p $(install_prefix)/lib
	@cp $(finjcore_lib) $(install_prefix)/lib
	@for include_dir in $(finjcore_include_dirs); do \
		cp -r $$include_dir $(install_prefix); \
	done