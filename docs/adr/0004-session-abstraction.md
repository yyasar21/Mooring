# ADR-0004: Session abstraction

Status: Accepted · 2026-11-03

## Context
SSH, RDP, VNC, Kubernetes exec and vSphere console must share tabs, audit, reconnect and
input handling without the UI knowing the protocol.

## Decision
`mooring_core::session::Session`:
```rust
#[async_trait]
pub trait Session: Send {
    fn protocol(&self) -> Protocol;
    async fn send(&mut self, input: SessionInput) -> Result<()>;
    async fn next_event(&mut self) -> Result<Option<SessionEvent>>;
    async fn close(&mut self) -> Result<()>;
}
```
- `ConnectParams` carries `ConnectSecret` (password / private key / none) for the handshake
  only; its `Debug` is redacted and it is dropped after `connect`.
- Events (`Connected`, `Bytes`, `Frame`, `Prompt`, `Closed`) stream to the UI through a Tauri
  channel; the UI never polls. Frames are RGBA rectangles; A2 moves to a shared buffer.
- `Prompt` carries a stable id so TOFU host-key / certificate decisions and keyboard-interactive
  auth round-trip through the UI without the protocol crate blocking on UI code.

## Alternatives considered
- One enum per protocol with a giant match in the Tauri layer: no shared reconnect/audit
  logic. Rejected.
- Channels only (no trait): loses the ability to unit-test a protocol crate in isolation.

## Security consequences
Secret material enters a protocol crate exactly once and is zeroized after the handshake.
Protocol crates never receive the vault; the Tauri layer resolves credentials.

## Test plan
Stub crates compile against the trait (A0). A1 adds an SSH integration test against
`<lab-host>` (`MOORING_LAB_HOST`), `#[ignore]`d by default.
