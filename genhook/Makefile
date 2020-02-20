HOOK_DATA := ./data/hook.data
TEMPLATES := hook.c hook.h unhook.h
TEMPLATES_IN_DIR := ./templates
TEMPLATES_OUT_DIR := ../src/hook

TEMPLATES_IN := $(addprefix $(TEMPLATES_IN_DIR)/,$(TEMPLATES))
TEMPLATES_OUT := $(addprefix $(TEMPLATES_OUT_DIR)/,$(TEMPLATES))

.DEFAULT_GOAL := generate

.PHONY: generate clean

generate: $(TEMPLATES_OUT)

$(TEMPLATES_OUT): $(TEMPLATES_IN) $(HOOK_DATA) genhook.py
	python3 genhook.py -i $(TEMPLATES_IN_DIR) -o $(TEMPLATES_OUT_DIR) \
		-d $(HOOK_DATA) $(TEMPLATES)

clean:
	-rm $(TEMPLATES_OUT)
