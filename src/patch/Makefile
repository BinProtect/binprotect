# flags
CC=g++
CPPFLAGS:=$(CPPFLAGS) -Wall -fPIC -std=c++11
LDFLAGS:=$(LDFLAGS) -shared -ldl

# tools
ECHO=@echo

#subdirs
ROOTDIR?=.
BINDIR=$(ROOTDIR)/patches
TMPDIRS=$(BINDIR)

# files
SOURCES=$(wildcard *.cpp)
EXECUTABLE=$(BINDIR)/libbinprotect.so

.PHONY: clean distclean

all: $(SOURCES) $(EXECUTABLE) | $(TMPDIRS)

$(EXECUTABLE): $(SOURCES) | $(TMPDIRS)
	$(CC) $(CPPFLAGS) $(SOURCES) -o $@ $(LDFLAGS)

distclean: clean

clean:
	rm -rf $(EXECUTABLE)

$(TMPDIRS):
	mkdir -p $(BINDIR)
