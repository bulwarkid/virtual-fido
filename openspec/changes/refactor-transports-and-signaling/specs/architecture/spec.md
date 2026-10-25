## MODIFIED Requirements

### Requirement: Cross-platform HID Emulation
The system SHALL provide a way to emulate HID reports across Linux and macOS via a unified transport architecture.

#### Scenario: Linux UHID Initialization
- **WHEN** running on Linux
- **THEN** the system SHALL attempt to use `/dev/uhid` for HID injection via the `transport/uhid` package.

#### Scenario: macOS CoreHID Initialization
- **WHEN** running on macOS 15+
- **THEN** the system SHALL attempt to use the `CoreHID` framework via the `transport/vhid` package.

## ADDED Requirements

### Requirement: Stream-based Signaling Interface
The system SHALL support and expose a stream-based signaling interface (stdin/stdout) for automated control.

#### Scenario: Activation via Signaling
- **WHEN** a `touch` command is received on stdin
- **THEN** the system SHALL approve the pending FIDO operation.

#### Scenario: Removal via Signaling
- **WHEN** a `remove` command is received on stdin
- **THEN** the system SHALL gracefully stop the virtual HID device.
