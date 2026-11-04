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

e2e: ## Playwright UI flows against the Vite dev server + mock transport (apps/desktop/e2e)
	node --test --test-concurrency=1 --test-reporter=spec apps/desktop/e2e/flows.e2e.mjs

fuzz: ## run every fuzz target for 60 s each (A1+)
	@cd fuzz && for t in $$(cargo +nightly fuzz list 2>/dev/null); do cargo +nightly fuzz run $$t -- -max_total_time=60; done

bundle: ## unsigned local bundles
	cargo tauri build

sbom: ## CycloneDX SBOMs into build/
	mkdir -p build && cargo cyclonedx --format json --override-filename build/sbom-cargo 2>/dev/null || echo "cargo install cargo-cyclonedx"
	pnpm dlx @cyclonedx/cyclonedx-npm --output-file build/sbom-npm.json >/dev/null 2>&1 || true

bump: ## set VERSION=x.y.z in Cargo/tauri/package.json + roll CHANGELOG (no commit)
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=x.y.z"; exit 1; }
	scripts/release/bump-version.sh "$(VERSION)"

release: ## bump, commit and tag vVERSION on a clean main; push the tag to start CI (docs/release.md)
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=x.y.z"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree not clean"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "release from main only"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null || { echo "tag v$(VERSION) exists"; exit 1; }
	scripts/release/bump-version.sh "$(VERSION)"
	git add -u
	git commit -m "chore(release): v$(VERSION)"
	git tag -a "v$(VERSION)" -m "Mooring v$(VERSION)"
	@echo "tagged v$(VERSION). Start the pipeline with:  git push origin main v$(VERSION)"

verify-release: ## verify a published release: make verify-release TAG=vX.Y.Z
	@test -n "$(TAG)" || { echo "usage: make verify-release TAG=vX.Y.Z"; exit 1; }
	scripts/release/verify-release.sh "$(TAG)"

icons: ## regenerate src-tauri/icons from packaging/icon.svg
	scripts/release/gen-icons.sh

.PHONY: help setup dev fmt lint test test-vectors audit check app-check e2e-ipc e2e fuzz bundle sbom bump release verify-release icons
