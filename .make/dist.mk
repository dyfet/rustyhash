# Copyright (C) 2023 Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

.PHONY: dist distclean

dist:	required
	@rm -f $(PROJECT)-*.tar.gz $(PROJECT)-*.tar
	@git archive -o $(PROJECT)-$(VERSION).tar --format tar --prefix=$(PROJECT)-$(VERSION)/ v$(VERSION) 2>/dev/null || git archive -o $(PROJECT)-$(VERSION).tar --format tar --prefix=$(PROJECT)-$(VERSION)/ HEAD
	@gzip $(PROJECT)-$(VERSION).tar

distclean:	clean
	@rm -f Cargo.lock go.sum
	@if test -f go.mod ; then ( echo "module $(PROJECT)" ; echo ; echo "$(GOVER)" ) > go.mod ; fi
	@if test -f Cargo.toml ; then cargo generate-lockfile ; fi
