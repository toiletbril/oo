# make MODE=dbg/asan/rel/prof
MODE ?= dbg

SOURCES := $(wildcard *.cc)
HEADERS := $(wildcard *.hh)

DIRS := $(wildcard */.)

SOURCES += $(wildcard */**.cc)
HEADERS += $(wildcard */**.hh)

# Translate a list of <...>.cpp files to a list of paths like
# o/$MODE/<...>.o.
OBJECTS := $(SOURCES:%.cc=o/$(MODE)/%.o)

ifneq ($(shell uname -s),Linux)
$(error This program does not make sense on any OS but Linux.)
endif

OUT := ../oo
OO_VERSION := $(shell cat ../VERSION)
OS_INFO := $(shell uname -rvom || echo "<no uname>")
COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo "<no git>")

# Remember CXXFLAGS passed to us from CLI.
ENVCXXFLAGS := $(CXXFLAGS)
override undefine CXXFLAGS

DEFINES := \
	-D_FORTIFY_SOURCE=2 \
	-DCOMPILER_COMMAND="\"$(CXX)\"" \
	-DOS_INFO="\"$(OS_INFO)\"" \
	-DCOMMIT_HASH="\"$(COMMIT_HASH)\"" \
	-DBUILD_MODE="\"$(MODE)\"" \
	-DENVCXXFLAGS="\"$(ENVCXXFLAGS)\"" \
	-DOO_VERSION="\"$(OO_VERSION)\""

WARNINGS := \
	-Wall \
	-Wextra \
	-Wdouble-promotion \
	-Werror \
	-Wno-format \
	-Wno-unused \
	-Wno-unused-parameter \
	-Wno-unused-command-line-argument \
	-Wno-deprecated \
	-Wno-date-time \
	-Wno-unknown-warning-option

CXXFLAGS := \
	-std=c++23 \
	-fno-exceptions \
	-Bsymbolic \
	-fno-semantic-interposition \
	-fno-strict-aliasing \
	$(WARNINGS) \
	$(DEFINES) \
	$(ENVCXXFLAGS)

# Speed up the linking a bit.
ifneq ($(shell which mold > /dev/null 2>&1),)
USE_LD := -fuse-ld=mold
else ifneq ($(shell which lld > /dev/null 2>&1),)
USE_LD := -fuse-ld=lld
else
USE_LD :=
endif

ifeq ($(MODE), rel)
CXXFLAGS += \
	-s \
	-DNDEBUG \
	-O2
else ifeq ($(MODE), dbg)
CXXFLAGS += \
	-fno-omit-frame-pointer \
	-fsanitize=undefined \
	-g3 \
	-Og
else ifeq ($(MODE), asan)
CXXFLAGS += \
	-fno-omit-frame-pointer \
	-g3 \
	-fsanitize=undefined \
	-fsanitize=address \
	-Og
else ifeq ($(MODE), prof)
CXXFLAGS += \
	-g3 \
	-O3
else
$(error Invalid MODE=$(MODE). Available modes are "dbg", "asan", "rel", "prof")
endif

# Libraries.
CXXFLAGS += -lcap

# Making objects in o/$MODE/<...>.o
o/$(MODE)/%.o: %.cc %.hh
	printf "\t%-42s $@\n" $<
	$(CXX) $(CXXFLAGS) -c $< -o $(CWD)$@

# Linking.
$(OUT): $(OBJECTS)
	printf "\t$(OBJECTS) <-> $(OUT)\n"
	$(CXX) $(CXXFLAGS) $(USE_LD) $(OBJECTS) -o $@

dirs: $(DIRS)
	mkdir -p o/$(MODE)/
	mkdir -p o/$(MODE)/$<

oo: dirs
	$(MAKE) $(OUT)

install: oo
	install -m 755 $(OUT) /usr/local/bin/oo
	echo "Installed in '/usr/local/bin/oo'."

CLANG_TIDY ?= clang-tidy

tidy:
	echo "	CLANG_TIDY $(SOURCES) $(HEADERS)"
	$(CLANG_TIDY) $(SOURCES) $(HEADERS) --extra-arg=-std=c++23 --header-filter="*.hpp"

CLANG_FORMAT ?= clang-format

fmt:
	echo "	CLANG_FORMAT -i $(SOURCES) $(HEADERS)"
	$(CLANG_FORMAT) -i $(SOURCES) $(HEADERS)

clean:
	rm -rf ./o ../oo ../oo.exe
	rm -rf ../perf*

.PHONY: dirs oo install tidy fmt clean
