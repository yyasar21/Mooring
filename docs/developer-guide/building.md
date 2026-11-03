# Building Mooring

## Toolchain

| Tool | Version | Why |
| --- | --- | --- |
| Rust | 1.89 or newer (`rust-version` in `Cargo.toml`), stable | Core crates and the Tauri shell |
| Node.js | 22 or newer | UI build |
| pnpm | 10 (`packageManager: pnpm@10.28.0`, via Corepack) | Workspace package manager |
| Tauri CLI | 2.x | `cargo tauri dev` / `build` (installed by `make setup`) |
| cargo-deny, cargo-audit | latest | `make audit` (installed by `make setup`) |
| gitleaks | 8.x | Secret scanning in `make audit` and the pre-commit hook |
| lefthook | latest | Git hooks: fmt, clippy, eslint, gitleaks, Conventional Commits |
| `age` CLI | 1.x, optional | `make test-vectors` |
| Python 3 | optional | `make test-vectors` driver |

The pure crates (`cargo test --workspace --exclude mooring-app`) need only Rust. The desktop
app (`mooring-app`, in `src-tauri/`) additionally needs the platform WebView toolchain below.

## macOS

```bash
xcode-select --install                                   # Apple command line tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
brew install node@22 lefthook gitleaks age
corepack enable                                          # provides the pinned pnpm
git clone https://github.com/yyasar21/Mooring.git && cd Mooring
make setup
make dev
```

On Intel Macs Homebrew may build some formulae from source; that is slow but works. For a
universal binary later: `rustup target add aarch64-apple-darwin x86_64-apple-darwin`.

## Windows 10/11

1. Install **Visual Studio 2022 Build Tools** with the *Desktop development with C++*
   workload (MSVC and a Windows SDK).
2. **WebView2** is preinstalled on Windows 11; on Windows 10 install the Evergreen runtime
   from Microsoft.
3. In PowerShell:

```powershell
winget install --id Rustlang.Rustup
winget install --id OpenJS.NodeJS.LTS
winget install --id Git.Git
winget install --id GnuWin32.Make           # or use Git Bash's make / run the cargo and pnpm commands directly
winget install --id Gitleaks.Gitleaks
corepack enable
rustup default stable-x86_64-pc-windows-msvc
git clone https://github.com/yyasar21/Mooring.git; cd Mooring
make setup
make dev
```

The Makefile uses bash; run it from Git Bash, or call the commands each target lists
(`cargo`, `pnpm`) directly from PowerShell.

## Linux

### Debian / Ubuntu (22.04 or newer)

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config curl file \
  libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Node.js 22 from your preferred source (NodeSource, nvm, distro backports), then:
corepack enable
```

### Fedora / RHEL 9+

```bash
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config curl file \
  webkit2gtk4.1-devel libappindicator-gtk3-devel librsvg2-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo dnf install -y nodejs   # must be 22+; use a module stream or nvm otherwise
corepack enable
```

Then, on any distribution:

```bash
git clone https://github.com/yyasar21/Mooring.git && cd Mooring
make setup
make dev
```

Install `gitleaks` and `lefthook` from their release pages or your package manager;
`make setup` prints a hint when they are missing.

The clipboard uses X11 directly (no C library); on pure Wayland it goes through XWayland.

## Make targets

| Target | What it does |
| --- | --- |
| `make setup` | rustfmt/clippy components, cargo-deny, cargo-audit, cargo-fuzz, Tauri CLI, `pnpm install`, lefthook hooks |
| `make dev` | Build the UI and run the app with hot reload |
| `make check` | `lint` + `test` + `audit` — everything CI runs |
| `make app-check` | clippy and tests including `mooring-app` (needs the WebView toolchain) |
| `make bundle` | Unsigned local installers under `target/release/bundle/` |
| `make sbom` | CycloneDX SBOMs for cargo and npm into `build/` |

See [testing](testing.md) for the test targets.

## The `age` git pin

The vault's portable export uses the [`age`](https://github.com/str4d/rage) crate. The
crates.io release 0.12.1 depends on `ml-kem 0.2`, while russh 0.65 needs `ml-kem 0.3`, and both
cannot be in one build. The root `Cargo.toml` therefore patches `age` to a reviewed commit of
the official repository:

```toml
[patch.crates-io]
age = { git = "https://github.com/str4d/rage", rev = "b5b68c4" }
```

- `Cargo.lock` pins the full commit hash; `deny.toml` allows exactly this one git source.
- The first build fetches it from GitHub, so offline builds need a warm cargo cache
  (`cargo fetch`).
- Do not move the pin without a security review. It is removed as soon as `age` 0.13 is
  published (accepted risk **R-AGE-PIN** in the [threat model](../security/threat-model.md)).

## Release builds

Signed and notarized release builds are produced by CI only. See
[release process](release-process.md).
