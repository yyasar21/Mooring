# Mooring — single entry point for humans, agents and CI.
SHELL := /bin/bash
.DEFAULT_GOAL := help
PURE := --workspace --exclude mooring-app

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

setup: ## install toolchain helpers (once per machine)
	rustup component add clippy rustfmt
	cargo install --locked cargo-deny cargo-audit cargo-fuzz tauri-cli@^2 2>/dev/null || true
	pnpm install
	command -v lefthook >/dev/null && lefthook install || echo "install lefthook: brew install lefthook"
	command -v gitleaks >/dev/null || echo "install gitleaks: brew install gitleaks"

dev: ## run the desktop app with hot reload
	pnpm --filter @mooring/desktop build
	cargo tauri dev

fmt: ## format rust
	cargo fmt --all

lint: ## rust + ts lint, no changes
	cargo fmt --all -- --check
	cargo clippy $(PURE) --all-targets -- -D warnings
	pnpm lint
	pnpm typecheck
	@! grep -rn "invoke(" apps/desktop/src --include=*.ts --include=*.tsx | grep -v "src/lib/ipc.ts" || (echo "invoke() outside lib/ipc.ts (ADR-0003)"; exit 1)

test: ## unit tests (pure crates + ui)
	cargo test $(PURE)
	pnpm test

test-vectors: ## verify mooring-vault vectors with the reference age CLI (needs `age`)
	python3 tests/vectors/verify_age_export.py

audit: ## dependency + secret scanning
	cargo deny check
	cargo audit
	pnpm audit --audit-level=high || true
	gitleaks detect --no-banner --redact

check: lint test audit ## everything CI runs

app-check: ## clippy + tests including the Tauri crate (needs the OS WebView toolchain)
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

e2e-ipc: ## A1 E2E flow + hostile IPC input through the command layer (needs the WebView toolchain)
	cargo test -p mooring-app --test e2e_flow

e2e: ## Playwright E2E through tauri-driver (A1+)
	pnpm --filter @mooring/desktop exec playwright test tests/e2e

fuzz: ## run every fuzz target for 60 s each (A1+)
	@for t in $$(cargo fuzz list 2>/dev/null); do cargo fuzz run $$t -- -max_total_time=60; done

bundle: ## unsigned local bundles
	cargo tauri build

sbom: ## CycloneDX SBOMs into build/
	mkdir -p build && cargo cyclonedx --format json --override-filename build/sbom-cargo 2>/dev/null || echo "cargo install cargo-cyclonedx"
	pnpm dlx @cyclonedx/cyclonedx-npm --output-file build/sbom-npm.json >/dev/null 2>&1 || true

.PHONY: help setup dev fmt lint test test-vectors audit check app-check e2e-ipc e2e fuzz bundle sbom
