## 1. Setup
- [x] 1.1 Create new transport subdirectories: `transport/dkit`, `transport/vhid`

## 2. Refactor macOS Drivers
- [x] 2.1 Move `mac/mac.go` and related DKIT logic to `transport/dkit`
- [x] 2.2 Move `mac/mac_hidvirtual.go` and related VHID logic to `transport/vhid`
- [x] 2.3 Refactor imports and references in `transport/transport_darwin.go`
- [x] 2.4 Align VHID build flags and files with `//go:build darwin` conventions

## 3. Signaling Interface
- [ ] 3.1 Refactor `promptApprover` in `main.go` to listen for signaling commands on stdin
- [ ] 3.2 Implement `insert`, `remove`, and `touch` (activate) commands
- [ ] 3.3 Ensure stdout feedback for automated scripts

## 4. Verification
- [ ] 4.1 Create `test/matrix.md` with full mode and *-only modes
- [ ] 4.2 Verify build on macOS/Linux with new structure
- [ ] 4.3 Verify signaling via piped input
- [ ] 4.4 Verify cross-platform Online/Offline flow (macOS Relay -> Linux Vault)
