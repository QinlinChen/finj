ifndef BUILD_DIR
$(error BUILD_DIR undefined)
endif

CC := gcc
CFLAGS += -O2 -Wall -Werror -I ../src
LDFLAGS := -L $(BUILD_DIR) -lfinj

TEST_BUILD_DIR := $(BUILD_DIR)/test
TEST := main

all:
	@echo + CCLD $(TEST)
	@mkdir -p $(TEST_BUILD_DIR)
	@$(CC) $(CFLAGS) -o $(TEST_BUILD_DIR)/$(TEST) $(TEST).c $(LDFLAGS)
	@echo > /tmp/finj.log
	@echo "------------------- result -------------------"
	$(TEST_BUILD_DIR)/$(TEST)
	@echo "----------------------------------------------"

.PHONY: clean

clean:
	-rm -rf $(TEST_BUILD_DIR)
