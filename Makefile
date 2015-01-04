# tools and flags
CC=g++
CFLAGS=
LDFLAGS=
ECHO=@echo
MAKE=make

# subdirectories
ROOTDIR=$(shell pwd)
SUBDIRS=src
CLEANDIRS=$(SUBDIRS:%=clean-%)
BUILDDIRS=$(SUBDIRS:%=build-%)
#LIBDIRS=lib/DyninstAPI-8.1.2

BINDIR=$(ROOTDIR)/bin
PATCHDIR=$(ROOTDIR)/patches
MUTATEEDIR=$(ROOTDIR)/mutatee
TMPDIRS=$(BINDIR) $(PATCHDIR) $(MUTATEEDIR)

export ROOTDIR

.PHONY: clean distclean
.PHONY: subdirs $(CLEANDIRS)
.PHONY: subdirs $(BUILDDIRS)
.PHONY: lib

all: $(BUILDDIRS) | $(TMPDIRS)

$(BUILDDIRS): | $(TMPDIRS)
	$(MAKE) -C $(@:build-%=%) all

distclean: clean 
	rm -rf ./bin
	rm -rf ./mutatee
	rm -rf ./patches

clean: $(CLEANDIRS)
	$(ECHO) "cleaning up (clean)"

$(CLEANDIRS):
	$(MAKE) -C $(@:clean-%=%) clean

lib:
	cd $(LIBDIRS) && ./configure --prefix=$(ROOTDIR)/lib/build
	$(MAKE) -j2 -C $(LIBDIRS) && $(MAKE) -C $(LIBDIRS) install

$(TMPDIRS):
	mkdir -p $(BINDIR)
	mkdir -p $(PATCHDIR)
	mkdir -p $(MUTATEEDIR)
