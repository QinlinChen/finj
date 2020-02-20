TARGET := main

CC := gcc
LD := gcc
CFLAGS += -O2 -Wall -Werror
LDFLAGS +=

BUILD_DIR := ./build
OBJ_DIR := $(BUILD_DIR)/obj

SRCS := $(shell find . -path $(BUILD_DIR) -prune -o -name "*.c" -print)
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

$(TARGET): $(OBJS)
	@echo + LD $@
	@$(LD) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -c -o $@ $<

-include $(OBJS:.o/.d)

.PHONY: clean test

clean:
	-rm -rf $(BUILD_DIR)
	-rm $(TARGET)

test: $(TARGET)
	echo > /tmp/ctest.log
	./$(TARGET)