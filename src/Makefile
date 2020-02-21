ifndef BUILD_DIR
$(error BUILD_DIR undefined)
endif

TARGET := libfinj.a

CC := gcc
CFLAGS += -O2 -Wall -Werror
AR := ar
ARFLAGS := rc

OBJ_DIR := $(BUILD_DIR)/obj

SRCS := $(shell find . -path $(BUILD_DIR) -prune -o -name "*.c" -print)
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	@echo $(BUILD_DIR)
	@echo + AR $@
	@$(AR) $(ARFLAGS) $@ $^

$(OBJ_DIR)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -c -o $@ $<

-include $(OBJS:.o/.d)

.PHONY: clean test

clean:
	-rm -rf $(BUILD_DIR)
