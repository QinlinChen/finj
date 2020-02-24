MODULES = genhook src
export BUILD_DIR := $(shell pwd)/build
export BIN := libfinj.a

all:
	@for subdir in $(MODULES); do \
		$(MAKE) -C $$subdir; \
	done

.PHONY: clean test

clean:
	$(MAKE) -C genhook clean
	-rm -rf $(BUILD_DIR)

test:
	$(MAKE) -C test