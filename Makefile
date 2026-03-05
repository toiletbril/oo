ifndef VERBOSE
MAKEFLAGS += -s
endif

all: oo test

oo:
	echo Creating oo...
	$(MAKE) -C src oo

install:
	echo Installing...
	$(MAKE) -C src install

tidy:
	echo Launching '$$'CLANG_TIDY...
	$(MAKE) -C src tidy

fmt:
	echo Launching '$$'CLANG_FMT...
	$(MAKE) -C src fmt

test: oo
	echo Launching tests...
	$(MAKE) -C test test

refill: oo
	echo Refilling tests...
	$(MAKE) -C test refill

refill_tests: refill

clean:
	echo Cleaning up...
	$(MAKE) -C src clean
	$(MAKE) -C test clean

.PHONY: all oo install tidy fmt test refill_tests clean
