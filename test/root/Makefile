# Tests that require root. They plant or corrupt oorunner-owned state under
# /var/run/oo, or exercise init paths, so they cannot run as the unprivileged
# user the main suite uses. Run with `make test-root` as root.
#
# Tests run sequentially: several run `oo init`, which recursively chowns the
# whole runtime tree, so they must not overlap with other namespace tests.

BIN := ../../oo
FLAGS := -vvvvv

export BIN
export FLAGS

FAILED_LIST := failed.diff
TRACE_LOG := trace.log
INPUT_FILES := $(wildcard input/*.test)

TEST_NAMES := $(INPUT_FILES:input/%.test=%)

.NOTPARALLEL:

%: expected/%.out
	tmp=$$(mktemp); \
	sh input/$@.test 2>"$$tmp" | \
	bash ../comparator.sh $< >> $(FAILED_LIST); \
	rc=$$?; \
	( flock 9; printf "===== %s =====\n" $@; cat "$$tmp"; ) 9>> $(TRACE_LOG).lock >> $(TRACE_LOG); \
	rm -f "$$tmp"; \
	if [ $$rc -eq 0 ]; then \
		printf "	%-42s ok\n" $@; \
	else \
		printf "	%-42s FAILED :c\n" $@; \
	fi

setup_and_run_tests:
	if [ "$$(id -u)" != "0" ]; then \
		printf "Not running as root. Skipping root tests.\n" >&2; \
	else \
		$(MAKE) run_tests; \
	fi

clean:
	@rm -f $(FAILED_LIST) $(TRACE_LOG) $(TRACE_LOG).lock

test: $(BIN)
	$(MAKE) -B clean
	$(MAKE) -B setup_and_run_tests
	if test -s $(FAILED_LIST); then cat $(FAILED_LIST); exit 1; fi

run_tests: $(TEST_NAMES)

refill:
	for f in $(TEST_NAMES); do \
		printf "	%-42s $$f.out\n" $$f.test; \
		sh input/$$f.test > expected/$$f.out 2>&1; \
	done || true

.PHONY: test clean run_tests refill setup_and_run_tests
