# Copyright (C) 2023 Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

.PHONY: build debug release clean test lint audit

TARGET := $(CURDIR)/target
export PATH := $(TARGET)/debug:${PATH}

build:	required
	@cargo build

release:	required
	@cargo build --release

test:	required
	@cargo test --release

clean:
	@rm -f $(PROJECT)-*.tar.gz
	@cargo clean

lint:	required
	@cargo check

audit:	required
	@cargo audit

debug:	build

Cargo.lock:
	@cargo generate-lockfile
