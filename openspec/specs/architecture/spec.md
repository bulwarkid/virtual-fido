# Capability: Architecture

## Requirements

### Requirement: Cross-platform HID Emulation
The system SHALL provide a way to emulate HID reports across Linux and macOS, adhering to the [Detailed HID Transport Spec](../transport/hid.md).

#### Scenario: Linux UHID Initialization
- **WHEN** running on Linux
- **THEN** the system SHALL attempt to use `/dev/uhid` for HID injection.

#### Scenario: macOS CoreHID Initialization
- **WHEN** running on macOS 15+
- **THEN** the system SHALL attempt to use the `CoreHID` framework for user-space HID emulation.

### Requirement: Protocol Isolation
The FIDO protocol logic (CTAP/U2F) MUST be isolated from the HID transport layer.

#### Scenario: Protocol Message Handling
- **WHEN** a HID report is received
- **THEN** it SHALL be passed to the `CTAPHIDServer` for processing, regardless of the transport used.

### Requirement: Seed-based Key Derivation
All cryptographic keys MUST be derived from a single 32-byte master seed.

#### Scenario: Stateless Key Recovery
- **WHEN** the same 32-byte seed is loaded
- **THEN** the system SHALL derive the same credential keys.

### Requirement: FIDO 2.1 Compliance
The system SHALL implement the FIDO 2.1 (CTAP 2.1) protocol as the baseline for modern WebAuthn operations.

#### Scenario: User Verification (UV)
- **WHEN** a FIDO operation is approved by the user
- **THEN** the system SHALL set the `User Verified` (UV) bit in the authenticator data.

#### Scenario: Discoverable Credentials (Resident Keys)
- **WHEN** a `makeCredential` request specifies `residentKey: required` or `preferred`
- **THEN** the system SHALL provide support for discoverable credentials, allowing stateless recovery via the 32-byte seed even when no `allowList` is provided in `getAssertion`.

### Requirement: User Approval for FIDO Operations
Operations that change state or perform authentication MUST require user approval.

#### Scenario: Sign-in Approval
- **WHEN** a `getAssertion` (login) request is received
- **THEN** the system SHALL prompt the user for approval before signing.
