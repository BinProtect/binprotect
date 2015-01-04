# tools and flags
CC=gcc
CFLAGS=
LDFLAGS=
ECHO=@echo
MAKE=make

# subdirectories
SUBDIRS=binprotect patch
CLEANDIRS=$(SUBDIRS:%=clean-%)
BUILDDIRS=$(SUBDIRS:%=build-%)

.PHONY: clean distclean
.PHONY: subdirs $(CLEANDIRS)
.PHONY: subdirs $(BUILDDIRS)

all: $(BUILDDIRS)

$(BUILDDIRS):
	$(MAKE) -C $(@:build-%=%) all

distclean: clean

clean: $(CLEANDIRS)
	$(ECHO) cleaning up

$(CLEANDIRS):
	$(MAKE) -C $(@:clean-%=%) clean

