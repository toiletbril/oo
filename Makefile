ifndef VERBOSE
MAKEFLAGS += -s
endif

MAKE := $(MAKE) -j$(shell nproc)

all: oo test

oo:
	echo Creating oo...
	$(MAKE) -C src oo

install:
	echo Installing...
	$(MAKE) -C src install

uninstall:
	echo Uninstalling...
	$(MAKE) -C src uninstall

tidy:
	echo Launching '$$'CLANG_TIDY...
	$(MAKE) -C src tidy

fmt:
	echo Launching '$$'CLANG_FMT...
	$(MAKE) -C src fmt

test: oo
	echo Launching tests...
	$(MAKE) -C test test

test-root: oo
	echo Launching root tests...
	$(MAKE) -C test/root test

refill: oo
	echo Refilling tests...
	$(MAKE) -C test refill

refill_tests: refill

clean:
	echo Cleaning up...
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C test/root clean

.PHONY: all oo install uninstall tidy fmt test test-root refill_tests clean
