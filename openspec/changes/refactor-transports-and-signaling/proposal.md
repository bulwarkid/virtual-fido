# Change: Refactor Transports and Signaling

## Why
The current `mac/` directory mixes DriverKit and VirtualHID implementations and is separate from the `transport/` package. This makes the codebase harder to maintain and test. Additionally, automation relies on signal files or AppleScript, which is brittle; a stream-based (stdin/stdout) signaling interface is more robust.

## What Changes
- **MODIFIED**: Refactor transport architecture to move macOS drivers into `transport/dkit` and `transport/vhid`.
- **ADDED**: Stream-based signaling interface for `promptApprover` to handle `insert`, `remove`, and `touch` (activate) commands via stdin/stdout.
- **ADDED**: Cross-platform support for Online/Offline flows (e.g., macOS Relay to Linux Vault and vice-versa).
- **ADDED**: Comprehensive test matrix for full and air-gapped modes across all supported OSs.

## Impact
- **Affected specs**: `architecture`
- **Affected code**: `mac/`, `transport/`, `cmd/virtual-fido/main.go`
- **BREAKING**: Changes to internal package structure for macOS drivers.
