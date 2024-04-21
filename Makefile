# sodoken Makefile

.PHONY: all static test

SHELL = /usr/bin/env sh -eu

all: static test

test:
	cargo build --all-targets --all-features
	RUST_BACKTRACE=1 cargo test --all-features

static:
	cargo fmt -- --check
	cargo clippy --all-features -- -Dwarnings
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi
