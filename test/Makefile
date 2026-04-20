BIN := ../oo
FLAGS := -vvvvv

FAILED_LIST := failed.diff
INPUT_FILES := $(wildcard input/*.test)

TEST_NAMES := $(INPUT_FILES:input/%.test=%)

%: expected/%.out
	sh input/$@.test 2>&1 | \
	bash comparator.sh $< >> $(FAILED_LIST) && \
	printf "	%-42s ok\n" $@ || \
	printf "	%-42s FAILED :c\n" $@

setup_and_run_tests:
	if ! getcap $(BIN) 2>/dev/null | grep -q cap_sys_admin; then \
		printf "Capabilities not set. Skipping tests.\n" $(BIN) >&2; \
	else \
		$(MAKE) run_tests; \
	fi

clean:
	@rm -f $(FAILED_LIST)

test: $(BIN)
	$(MAKE) -B clean
	$(MAKE) -B setup_and_run_tests
	test -f $(FAILED_LIST) && cat $(FAILED_LIST) || true

run_tests: $(TEST_NAMES)

refill: setup
	for f in $(TEST_NAMES); do \
		printf "	%-42s $$f.out\n" $$f.test; \
		sh input/$$f.test > expected/$$f.out 2>&1; \
	done || true

.PHONY: test clean run_tests setup refill
