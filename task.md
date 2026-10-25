# Task: Virtual FIDO Modernization

- [x] Audit the codebase and create a comprehensive architecture report

- [x] Setup `specs/` directory and integrate with OpenSpec/Alloy
    - [x] Initialize OpenSpec structure
    - [x] Move architecture report and diagrams to specs
    - [x] Establish test baseline and coverage metrics
- [x] Task 1: Refactor Transports (UNIFIED LAYER)
    - [x] Move `mac/` (DriverKit) to `transport/dkit`
    - [x] Move `mac/` (VirtualHID) to `transport/vhid`
    - [x] Align `VHID` usage with `UHID` (`//go:build darwin`)
- [/] Task 2: Signaling Interface & Operational Modes
    - [x] Refactor `promptApprover` for stream-based signaling (Full/Relay/Vault support)
    - [ ] Verify Full Mode for macOS/Linux
    - [ ] Verify Online/Offline cross-platform flows (macOS <-> Linux)
- [ ] Task 3: (POSTPONED) PureGo Migration
    - [ ] Map `CoreHID` and `libobjc` symbols with `purego`
    - [ ] Re-implement `VirtualFIDODevice` logic in Go
- [x] Task 4: Verification and Test Matrix
    - [x] Create a comprehensive test matrix for full mode, `online-only`, and `offline-only`
    - [x] Convert `run_headless_test.sh` to Python
    - [x] Verify basic integration with `runOnlineDarwin`