#!/usr/bin/make -f
# This is more a convenience since you can drive the project entirely from
# cargo for most cases. It also provides a simple way to use existing
# source build based packaging systems.

# Project constants
PROJECT := $(shell grep ^name Cargo.toml|sed -e s/\"\s*$$// -e s/^.*\"//)
VERSION := $(shell grep ^version Cargo.toml|sed -e s/\"\s*$$// -e s/^.*\"//)
BINS := paths fdsum

all:		build
required:	Cargo.lock

# Define or override env
sinclude custom.mk

.PHONY:	all config install

install:	release
	@install -d -m 755 $(DESTDIR)$(BINDIR)
	@install -d -m 755 $(DESTDIR)$(MANDIR)/man1
	@for name in $(BINS) ; do \
		install -s -m 755 $(RELEASE)/$${name} $(DESTDIR)$(BINDIR) ;\
		install -m 644 src/man/$${name}.1 $(DESTDIR)$(MANDIR)/man1 ;\
 	done

version:
	@echo $(PROJECT) $(VERSION) $(DESTDIR)

# Can override existing targets
sinclude .make/*.mk
