BIN := ../oo

FAILED_LIST := failed.diff
INPUT_FILES := $(wildcard input/*.test)

TEST_NAMES := $(INPUT_FILES:input/%.test=%)

%: expected/%.out
	bash input/$@.test 2>&1 | \
	bash compare.sh $< >> $(FAILED_LIST) && \
	printf "	%-42s ok\n" $@ || \
	printf "	%-42s FAILED :c\n" $@

# Ensure file capabilities are set on the binary before any test runs.
# Without them all namespace operations will fail with EPERM.
setup:
	@if ! getcap $(BIN) 2>/dev/null | grep -q cap_sys_admin; then \
		printf "capabilities not set on %s\nrun: sudo %s init\n" $(BIN) $(BIN) >&2; \
		exit 1; \
	fi
	@BIN_DIR=$$(dirname $$(readlink -f $(BIN))); \
	if findmnt -n -o OPTIONS --target "$$BIN_DIR" 2>/dev/null | grep -q nosuid; then \
		printf "binary is on a nosuid mount; kernel ignores file capabilities\ncopy binary to a non-nosuid path and re-run\n" >&2; \
		exit 1; \
	fi

clean:
	@rm -f $(FAILED_LIST)

test: $(BIN) setup
	@$(MAKE) -B clean
	@$(MAKE) -B run_tests
	cat $(FAILED_LIST)

run_tests: $(TEST_NAMES)

refill: setup
	for f in $(TEST_NAMES); do \
		printf "	%-42s $$f.out\n" $$f.test; \
		bash input/$$f.test > expected/$$f.out 2>&1; \
	done || true

.PHONY: test clean run_tests setup refill
