BIN := cnet

.PHONY: build run sudo-run dev release check fmt clippy test clean install

build:
	cargo build

release:
	cargo build --release

run:
	cargo run --release

# Packet capture needs raw-socket privileges; build first, then run the binary as root.
sudo-run: release
	sudo ./target/release/$(BIN)

dev:
	cargo run

check:
	cargo check

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

test:
	cargo test

clean:
	cargo clean

install:
	cargo install --path .
