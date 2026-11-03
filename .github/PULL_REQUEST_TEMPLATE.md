<!-- markdownlint-disable-next-line MD041 -->
## Summary

<!-- What does this change and why? Link the issue: "Closes #123". -->

## Type

- [ ] `feat` — new capability
- [ ] `fix` — bug fix
- [ ] `security` — security hardening
- [ ] `docs` / `test` / `refactor` / `build` / `ci` / `chore`

## Test evidence

<!-- Commands you ran and their result. New behaviour needs a new test. -->

```text
make check
```

- [ ] `make check` is green locally
- [ ] Tested on: macOS / Windows / Linux (strike out the ones you did not test)
- [ ] New or changed behaviour is covered by a test that fails without the change

## Security checklist

- [ ] No secret can reach the UI, a log line, an error message, a test fixture or git
- [ ] New or changed Tauri commands validate and cap their input and return `IpcError`
- [ ] No change to capabilities or CSP, or the change is explained below
- [ ] No new dependency, or it is justified below (purpose, license, maintenance, `unsafe`)
- [ ] Parsers of untrusted input have size caps and tests (and a fuzz target where required)
- [ ] No `unsafe`, no custom cryptography
- [ ] Examples use placeholders (`example.test`, `<your-host>`), not real hosts or users

<!-- Explain any unchecked item here. -->

## Documentation

- [ ] User guide / developer guide updated if behaviour changed
- [ ] ADR added or amended for a design decision
- [ ] `CHANGELOG.md` updated under `Unreleased`

## Screenshots

<!-- For UI changes: dark and light theme, using demo data only. -->
