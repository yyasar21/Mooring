# GitHub repository setup

A checklist for the maintainer to make `yyasar21/Mooring` discoverable and safe to open up.
These settings live in GitHub, not in the repository, so they have to be set by hand.

## 1. About box

Repository → ⚙ next to **About**.

**Description** (shown in search results, keep under 350 characters):

> Secure, open source remote access manager for SSH, RDP, VNC, Kubernetes and vSphere.
> Encrypted Argon2id + XChaCha20-Poly1305 vault, hash-chained audit log, Rust + Tauri.
> macOS, Windows, Linux.

**Website**: leave empty until GitHub Pages is live, then set it to the Pages URL (see §7).
Tick **Releases**; untick **Packages** and **Deployments** unless used.

**Topics** (add exactly these; GitHub allows 20):

```text
remote-access ssh-client rdp vnc kubernetes vsphere remote-desktop-manager tauri rust
security credential-manager open-source cross-platform macos windows linux
```

Optional extras if you want to use the remaining four slots: `sftp`, `terminal`,
`royal-ts-alternative`, `password-vault`.

## 2. Social preview

Settings → General → **Social preview** → upload an image.

- Size **1280 × 640 px** (2:1), PNG, under 1 MB.
- Start from `docs/assets/hero.png` (1440 × 860): crop to the tree and terminal area, or scale
  it to 1280 px wide and place it on a 1280 × 640 canvas in the dark background colour
  `#03070a`.
- Leave a 40 px safe margin; add the wordmark "Mooring" and one line such as
  "Secure remote access manager — SSH · RDP · VNC · Kubernetes · vSphere" in large type, so it
  reads at small sizes on social sites.
- Use only demo data (`example.test` hosts). Save the file as
  `docs/assets/social-preview.png` so it can be updated later.

## 3. Features

Settings → General → **Features**:

- ✅ **Issues** (templates and forms are in `.github/ISSUE_TEMPLATE/`).
- ✅ **Discussions** — create categories *Announcements* (maintainers only), *Q&A*
  (answerable), *Ideas*, *Show and tell*. Pin a welcome post linking the roadmap.
- ❌ **Wiki** — documentation lives in `docs/`.
- ✅ **Sponsorships** only if you keep `.github/FUNDING.yml`; delete the file otherwise.
- Pull requests: allow **squash merging** only, default message "Pull request title and
  description"; enable **Always suggest updating pull request branches** and
  **Automatically delete head branches**.

## 4. Security

Settings → **Code security**:

- ✅ **Private vulnerability reporting** (required for the flow in `SECURITY.md`).
- ✅ **Dependency graph**, **Dependabot alerts**, **Dependabot security updates**
  (version updates come from `.github/dependabot.yml`).
- ✅ **Secret scanning** and **Push protection**.
- ✅ **Code scanning**: the `security` workflow already uploads Semgrep SARIF; optionally also
  enable CodeQL default setup for JavaScript/TypeScript and Actions.
- Settings → Actions → General: **Workflow permissions** = *Read repository contents*;
  untick *Allow GitHub Actions to create and approve pull requests*. Require approval for
  workflows from first-time contributors.

## 5. Branch protection

Settings → **Rules → Rulesets** → new branch ruleset for `main`:

- Restrict deletions; block force pushes.
- Require a pull request before merging: 1 approval, dismiss stale approvals, require review
  from **Code Owners** (`.github/CODEOWNERS`), require conversation resolution.
- Require status checks to pass, branch up to date. Add after the first CI run:
  `check (macos-14)`, `check (windows-2022)`, `check (ubuntu-22.04)`, `rust-deps`,
  `npm-deps`, `secrets`, `semgrep`, `unsafe-audit`, `age-cli` (test vectors). Check names
  in the Actions tab after the first run; they change if the workflows change.
- Require signed commits (optional but recommended) and linear history.
- Add yourself to the bypass list only if you need emergency merges.

Add a tag ruleset for `v*`: restrict creation, update and deletion to maintainers.

## 6. Releases

- Releases are created by the release workflow from `v*` tags; see `docs/release.md`.
- Create the Homebrew tap repository `yyasar21/homebrew-mooring` before the first release.
- Store signing secrets as **environment secrets** in a `release` environment with required
  reviewers, not as repository secrets.
- Mark `v0.x` releases as *pre-release* until the A4 exit criteria are met.

## 7. GitHub Pages (later)

When the docs are ready for a site: Settings → Pages → *GitHub Actions* as source, build
`docs/` with a static site generator (mdBook or MkDocs Material both work with the current
Markdown), and set the About **Website** field to the Pages URL. Add a custom domain only with
DNS you control and enforce HTTPS.

## 8. Launch checklist

Before announcing:

- [ ] Repository public, About box, topics and social preview set.
- [ ] CI, security and test-vector badges green on `main`.
- [ ] Private vulnerability reporting enabled; `SECURITY.md` links work.
- [ ] Discussions open with a pinned welcome post.
- [ ] README renders correctly (Mermaid diagram, screenshots, tables) on github.com and on
      mobile.
- [ ] At least a few `good first issue` and `help wanted` issues exist (for example: fuzz
      targets, importer formats, translations of the user guide).
- [ ] Pre-release status is stated clearly; no claim of features that are only planned.

Where to announce (one at a time, a few days apart, answer every comment):

- [ ] **Hacker News** — "Show HN: Mooring – open source, security-first remote access
      manager in Rust/Tauri". Post on a weekday morning US time; first comment explains the
      motivation, the vault design and what works today.
- [ ] **r/rust** — focus on the Rust side: `forbid(unsafe)`, russh, RustCrypto, the `age` pin
      story, Tauri IPC hardening.
- [ ] **r/selfhosted** — focus on local-first, no account, no telemetry, planned self-hosted
      sync.
- [ ] Also suitable: r/sysadmin, r/devops, r/homelab, Lobsters (`rust`, `security` tags),
      the Tauri Discord showcase channel.
- [ ] **Awesome lists** — open PRs once there is a release:
      `awesome-tauri` (Applications), `awesome-rust` (Applications → System tools),
      `awesome-selfhosted` only if it fits their criteria (it is a desktop client, so likely
      not), `awesome-sysadmin` (Remote desktop / SSH clients), `awesome-ssh`.
- [ ] Add Mooring to alternative-software directories (AlternativeTo as an alternative to
      Royal TS, Remote Desktop Manager, mRemoteNG, Termius).

After launch: watch issues and Discussions daily for the first two weeks, label and respond
quickly, and turn recurring questions into FAQ entries.
