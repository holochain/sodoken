# sodoken Makefile

.PHONY: all test static

SHELL = /usr/bin/env sh -eu

all: test

test: static
	cargo build --all-targets --all-features
	RUST_BACKTRACE=1 cargo test --all-features

static:
	cargo fmt -- --check
	cargo clippy --all-features -- -Dwarnings
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi
