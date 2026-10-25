# Protocol: FIDO 2.1 (CTAP 2.1)

## Overview
This document specifies the FIDO 2.1 (CTAP 2.1) protocol support in `virtual-fido`. The project aims to provide a robust, cross-platform virtual authenticator that satisfies the requirements of modern WebAuthn Relying Parties, particularly regarding Passkeys.

## Supported Versions
The authenticator reports the following versions in discovery:
- `FIDO_2_1` (Baseline for modern WebAuthn)
- `FIDO_2_0` (Legacy FIDO2)
- `U2F_V2` (Legacy U2F)

## Core 2.1 Features

### 1. User Verification (UV)
The authenticator treats user interaction with the virtual device (e.g., approval signal) as "User Verification". 
- **Internal UV**: The internal UV bit in `authData` is always set to `1` upon user approval of a request.
- **Site Expectation**: This satisfies sites that require `userVerification: required`.

### 2. Discoverable Credentials (Resident Keys)
The authenticator supports "Discoverable Credentials" (formerly known as Resident Keys).
- **Storage**: Credentials are deriveable from the 32-byte seed and the RP ID.
- **Lookup**: When a `getAssertion` request is received without an `allowList`, the authenticator performs a deterministic lookup based on the RP ID and a default identity.
- **Satisfies**: `residentKey: required` or `preferred`.

### 3. Credential Management (Basic)
The authenticator handles the Credential Management command code (`0x0b`) by logging it and returning a graceful error instead of panicking, ensuring compatibility with browsers that probe for these capabilities.

## Technical Alignment

### discovery (getInfo)
| Option | Value | Description |
| --- | --- | --- |
| `rk` | `true` | Supports resident keys / discoverable credentials. |
| `uv` | `true` | Supports built-in user verification. |
| `up` | `true` | Supports user presence. |
| `plat` | `false` | Reports as a roaming authenticator (external key). |

### Error Codes
The implementation follows FIDO 2.1 error code mapping, specifically:
- `ctap1ErrInvalidCommand (0x01)` for unsupported commands.
- `ctap2ErrOperationDenied (0x27)` for user-rejected approvals.
- `ctap2ErrNoCredentials (0x2e)` for empty lookup results.
