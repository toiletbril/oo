DIFF_FLAGS := -u

ifeq ($(OS), Windows_NT)
BIN := ../oo.exe
DIFF_FLAGS += -w
else
BIN := ../oo
endif

FAILED_LIST := failed.diff
INPUT_FILES := $(wildcard input/*.test)

TEST_NAMES := $(INPUT_FILES:input/%.test=%)

%: expected/%.out
	bash input/$@.test 2>&1 | \
	diff $(DIFF_FLAGS) $< - >> $(FAILED_LIST) && \
	printf "	%-42s ok\n" $@ || \
	printf "	%-42s FAILED :c\n" $@

clean:
	@rm -f $(FAILED_LIST)

test: $(BIN)
	@$(MAKE) -B clean
	@$(MAKE) -B run_tests
	cat $(FAILED_LIST)

run_tests: $(TEST_NAMES)

refill:
	for f in $(TEST_NAMES); do \
		printf "	%-42s $$f.out\n" $$f.test; \
		bash input/$$f.test > expected/$$f.out 2>&1; \
	done || true

.PHONY: test clean run_tests refill
