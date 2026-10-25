# Project Context

## Purpose
`virtual-fido` is a cross-platform virtual FIDO2/U2F authenticator that allows using a computer as a security key. It emulates HID reports at the OS level to provide a hardware-less security key experience.

## Tech Stack
- **Primary**: Go (Golang)
- **Secondary**: Swift (currently being migrated to Go via `purego`), C, Objective-C
- **Protocols**: FIDO 2.1 (CTAP 2.1), U2F (CTAP 1.0)
- **HID Drivers**: UHID (Linux), DriverKit/CoreHID (macOS), USB-over-IP (Cross-platform)

## Project Conventions

### Code Style
All code MUST follow the [Style Guide](styleguide.md). Key constraints include:
- 80 character line limit.
- Tabs are 8 spaces.
- Present-tense commit messages with subsystem prefix.

### Architecture Patterns
- **Protocol Separation**: FIDO protocol logic is isolated from HID transport logic.
- **Seed-based Derivation**: All keys are derived from a single 32-byte seed.

### Testing Strategy

- **Unit Tests**: Package-level tests run via `go test ./...`. Current baseline coverage:
    - `crypto`: 81.7% (Excellent - covers hashing, AES, RSA, ECDSA)
    - `usb`: 74.1% (Good - covers descriptors and HID reports)
    - `ctap_hid`: 63.2% (Moderate - covers message fragmentation)
    - `cose`: 52.2% (Moderate - covers COSE key types)
    - `u2f`: 44.6% (Low/Moderate - basic registration)
    - `ctap`: 32.0% (Low - core protocol flows)
    - `util`: 16.2% (Low - request buffering)
- **E2E Tests**: Browser-based WebAuthn orchestration tests using Playwright.

### Git Workflow
Commit messages should follow the `subsystem: short description` format.

## Domain Context
Deep knowledge of FIDO, WebAuthn, CBOR, COSE, and HID report descriptors is required for Core modifications.

## Important Constraints
- **Security**: Private keys are ephemeral or derived; never stored in plaintext.
- **Compatibility**: Must support macOS 15+ (CoreHID) and modern Linux kernels (UHID).

## External Dependencies
- `github.com/bulwarkid/virtual-fido` (This repo)
- System frameworks: `CoreHID`, `IOKit`, `Foundation` (macOS).
