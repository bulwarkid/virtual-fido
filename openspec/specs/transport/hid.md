# Capability: HID Transport Specification

## Overview
This specification defines the low-level HID (Human Interface Device) report structure and transport behaviors required for the Virtual FIDO device to remain compliant with FIDO CTAP (Client to Authenticator Protocol) and WebAuthn standards.

## HID Report Descriptor
The device SHALL advertise a HID Report Descriptor for a U2F Authenticator.

### Descriptor Structure (Usage Page 0xF1D0)
| Item | Value | Description |
| :--- | :--- | :--- |
| **Usage Page** | `0x06, 0xD0, 0xF1` | FIDO Alliance |
| **Usage** | `0x09, 0x01` | U2F Authenticator device |
| **Collection** | `0xA1, 0x01` | Application |
| **Input Usage** | `0x09, 0x20` | Input Report Data |
| **Logical Min** | `0x15, 0x00` | 0 |
| **Logical Max** | `0x26, 0xFF, 0x00` | 255 |
| **Report Size** | `0x75, 0x08` | 8 bits |
| **Report Count** | `0x95, 0x40` | 64 bytes |
| **Input Type** | `0x81, 0x02` | Data, Var, Abs |
| **Output Usage** | `0x09, 0x21` | Output Report Data |
| **Report Count** | `0x95, 0x40` | 64 bytes |
| **Output Type** | `0x91, 0x02` | Data, Var, Abs |
| **End Collection** | `0xC0` | |

## Transport Requirements

### Requirement: Fixed Report Size
All messages exchanged over the HID transport MUST be exactly **64 bytes**.
- **Input (Device -> Host)**: Reports MUST be padded with zeros if smaller than 64 bytes.
- **Output (Host -> Device)**: The transport layer MUST handle exactly 64-byte chunks.

### Requirement: macOS Pacing
On macOS guest environments utilizing `CoreHID`, the transport layer MUST implement a pacing mechanism.
- **Minimum Inter-report Delay**: 20 milliseconds.
- **Rationale**: Prevents "Resource Busy" errors and kernel-side dropouts in virtualization environments.

## Compliance Reference
- **FIDO CTAP HID Protocol**: [FIDO Alliance Specifications](https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html)
- **WebAuthn**: [W3C Recommendation](https://www.w3.org/TR/webauthn/)
