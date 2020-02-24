ifndef BUILD_DIR
$(error BUILD_DIR undefined)
endif

ifndef BIN
$(error BIN undefined)
endif

CC := gcc
CFLAGS += -O2 -Wall -Werror
AR := ar
ARFLAGS := rc

OBJ_DIR := $(BUILD_DIR)/obj
SRCS := $(shell find . -path $(BUILD_DIR) -prune -o -name "*.c" -print)
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

$(BUILD_DIR)/$(BIN): $(OBJS)
	@echo + AR $@
	@$(AR) $(ARFLAGS) $@ $^

$(OBJ_DIR)/%.o: %.c
	@echo + CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -c -o $@ $<

-include $(OBJS:.o/.d)
