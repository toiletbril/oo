# make MODE=dbg/rel/prof/cosmo/cosmo_dbg
MODE ?= dbg

SOURCES := $(wildcard *.cc)
HEADERS := $(wildcard *.hh)

DIRS := $(wildcard */.)

SOURCES += $(wildcard */**.cc)
HEADERS += $(wildcard */**.hh)

# Translate a list of <...>.cpp files to a list of paths like
# o/$MODE/<...>.o.
OBJECTS := $(SOURCES:%.cc=o/$(MODE)/%.o)

ifeq ($(OS), Windows_NT)
OUT := ../oo.exe
DEVNULL := "NUL"
else
OUT := ../oo
DEVNULL := "/dev/null"
endif

OO_VERSION := $(shell cat ../VERSION)

ifeq ($(MODE), cosmo)
CXX := cosmoc++
else ifeq ($(MODE), cosmo_dbg)
CXX := cosmoc++
else ifeq ($(OS), Windows_NT)
CXX := clang++
endif

ifeq ($(MODE), cosmo)
OS_INFO := "unknown-cosmo"
else ifeq ($(MODE), cosmo_dbg)
OS_INFO := "unknown-cosmo-dbg"
else
OS_INFO := $(shell uname -rvom || echo "<no uname>")
endif

COMMIT_HASH := $(shell git rev-parse HEAD || echo "<no git>")

# Remember CXXFLAGS passed to us from CLI.
ENVCXXFLAGS := $(CXXFLAGS)
override undefine CXXFLAGS

DEFINES := \
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
	-Wno-unknown-warning-option \
	-Wno-error=maybe-uninitialized

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
ifneq ($(shell which mold > $(DEVNULL) 2>&1),)
USE_LD := -fuse-ld=mold
else ifneq ($(shell which lld > $(DEVNULL) 2>&1),)
USE_LD := -fuse-ld=lld
else
USE_LD :=
endif

ifeq ($(MODE), rel)
CXXFLAGS += \
	-s \
	-DNDEBUG \
	-O3
else ifeq ($(MODE), dbg)
CXXFLAGS += \
	-fno-omit-frame-pointer \
	-g3 \
	-O0
ifneq ($(OS), Windows_NT)
ifneq ($(MODE), cosmo)
CXXFLAGS += \
	-fsanitize=address \
	-fsanitize=undefined
endif
endif
else ifeq ($(MODE), cosmo)
CXXFLAGS += \
	-mcosmo \
	-mtiny \
	-fexceptions \
	-g \
	-DNDEBUG \
	-O3
ifneq ($(CXX), cosmoc++)
$(error Your CXX is "$(CXX)" instead of "cosmoc++" for MODE=cosmo)
endif
else ifeq ($(MODE), cosmo_dbg)
CXXFLAGS += \
	-mcosmo \
	-mdbg \
	-fexceptions \
	-g3
ifneq ($(CXX), cosmoc++)
$(error Your CXX is "$(CXX)" instead of "cosmoc++" for MODE=cosmo_dbg)
endif
else ifeq ($(MODE), prof)
CXXFLAGS += \
	-g3 \
	-O3
else
$(error Invalid MODE=$(MODE). Available modes are "dbg", "rel", "prof", "cosmo")
endif

# Missing Windows libraries.
ifeq ($(OS), Windows_NT)
CXXFLAGS += \
	-luserenv \
	-ladvapi32
else
# Linux libraries
CXXFLAGS += \
	-lcap
endif

# Making objects in o/$MODE/<...>.o
o/$(MODE)/%.o: %.cc
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
ifneq ($(OS), Windows_NT)
	install -m 755 $(OUT) /usr/local/bin/oo
	echo "Installed in '/usr/local/bin/oo'."
else
	$(error Unable to figure out install directory for Windows. \
			Please put '$(realpath ..)' in your PATH manually)
endif

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
	rm -rf ../*.ilk ../*.pdb ../*.lib # Windows
	rm -rf ../oo.com.dbg ../oo.aarch64.elf # Cosmopolitan
	rm -rf ../perf*

.PHONY: dirs oo install tidy fmt clean
