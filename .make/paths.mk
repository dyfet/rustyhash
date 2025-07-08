# Copyright (C) 2023 Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Testing paths can be set for debug
ifdef WORKINGDIR
TEST_PREFIX := $(WORKINGDIR)
else
ifdef LOCALSTATEDIR
TEST_PREFIX := $(LOCALSTATEDIR)/lib/$(PROJECT)
else
TEST_PREFIX := $(TESTDIR)
endif
endif

ifdef SYSCONFDIR
TEST_CONFIG := $(SYSCONFDIR)
else
TEST_CONFIG := $(TESTDIR)
endif

ifdef LOGPREFIXDIR
TEST_LOGDIR := $(LOGPREFIX)
else
ifdef LOCALSTATEDIR
TEST_LOGDIR := $(LOCALSTATEDIR)/log
else
TEST_LOGDIR := $(TESTDIR)
endif
endif

ifdef APPDATADIR
TEST_APPDIR := $(APPDATADIR)
else
ifdef DATADIR
TEST_APPDIR := $(DATADIR)/$(PROJECT)
else
ifdef PREFIX
TEST_APPDIR := $(PREFIX)/share/$(PROJECT)
else
TEST_APPDIR := $(TESTDIR)
endif
endif
endif

ifeq ($(OS),Windows_NT)
ifndef  PREFIX
PREFIX := "C:\\Program Files\\Calypso"
endif

ifndef  SYSCONFDIR
SYSCONFDIR := "C:\\ProgramData\\Calypso"
endif

ifndef  WORKINGDIR
WORKINGDIR := "C:\\ProgramData\\Calypso"
endif

ifndef  LOCALSTATEDIR
LOCALSTATEDIR := "C:\\ProgramData\\Calypso"
endif
endif

ifndef  DESTDIR
DESTDIR =
endif

ifndef  PREFIX
PREFIX := /usr/local
endif

ifndef  BINDIR
BINDIR := $(PREFIX)/bin
endif

ifndef  SBINDIR
SBINDIR := $(PREFIX)/sbin
endif

ifndef  LIBDIR
LIBDIR := $(PREFIX)/lib
endif


ifndef  LIBDATADIR
LIBDATADIR := $(PREFIX)/lib
endif

ifndef  DATADIR
DATADIR := $(PREFIX)/share
endif

ifndef  MANDIR
MANDIR := $(DATADIR)/man
endif

ifndef  LOCALSTATEDIR
LOCALSTATEDIR := $(PREFIX)/var
endif

ifndef  SYSCONFDIR
SYSCONFDIR := $(PREFIX)/etc
endif

ifndef  LOGPREFIXDIR
LOGPREFIXDIR := $(LOCALSTATEDIR)/log
endif

ifndef  WORKINGDIR
WORKINGDIR := $(LOCALSTATEDIR)/lib/$(PROJECT)
endif

ifndef  APPDATADIR
APPDATADIR := $(DATADIR)/$(PROJECT)
endif

export WORKINGDIR APPDATADIR LOGPREFIXDIR SYSCONFDIR LOCALSTATEDIR DATADIR



