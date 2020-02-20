SUB_DIR = genhook src

all:
	@for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir; \
	done

.PHONY: clean

clean:
	@for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done