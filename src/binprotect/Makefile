# subdirectories
INCDIRS=include
ROOTDIR?=.
BINDIR:=$(ROOTDIR)/bin
TMPDIRS:=$(BINDIR)

# files
SOURCES=$(wildcard *.cpp)
EXECUTABLE=$(BINDIR)/binprotect

# flags
CC=g++
CPPFLAGS:=$(CPPFLAGS) -Wall -std=c++11 -I$(INCDIRS) -I../../lib/build/include
LDFLAGS:=$(LDFLAGS) -L../../lib/build/lib -lpatchAPI -lparseAPI -linstructionAPI -lsymtabAPI -lsymLite -ldynDwarf -ldynElf -lcommon -lelf -ldwarf -ldyninstAPI -lpcontrol -lstackwalk

# tools
ECHO=@echo

.PHONY: clean distclean

all: $(SOURCES) $(EXECUTABLE) | $(TMPDIRS)

$(EXECUTABLE): $(SOURCES) | $(TMPDIRS)
	$(CC) $(CPPFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

distclean: clean
	rm -rf $(BINDIR)

clean:
	rm -rf $(EXECUTABLE)

$(TMPDIRS):
	mkdir -p $(BINDIR)
