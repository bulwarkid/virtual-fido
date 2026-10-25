# Test Matrix: Operational Modes

This matrix defines the required test scenarios for each operational mode of `virtual-fido`.

| Mode | Transport | Logic Location | Goal | Key Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Full Mode** | UHID (Linux) / VHID (macOS) | Local | Local authenticator | Browser registration/login success. |
| **Online-only (Relay)** | VHID/UHID | Remote (Relay) | Bridging to air-gap | Hex blob generation on stdin/stdout. |
| **Offline-only (Vault)** | None (stdin) | Local (Vault) | Secure key storage | Processing hex blobs and signing. |

## Test Scenarios

### 1. Full Mode Registration (macOS)
- **Setup**: `just build-vhid`
- **Execution**: `./virtual-fido run --transport darwin`
- **Action**: Perform WebAuthn registration on `webauthn.io`.
- **Expected**: `promptApprover` triggers; registration success.

### 2. Air-gap Relay (Online-only)
- **Setup**: `runOnlineDarwin`
- **Execution**: `./virtual-fido online-only --transport darwin`
- **Expected**: System waits for HID reports; prints hex blobs to stdout.

### 3. Air-gap Vault (Offline-only)
- **Setup**: `offlineOnlyCmd`
- **Execution**: `./virtual-fido offline-only --seed-file seed.txt`
- **Action**: Paste hex blob from Relay.
- **Expected**: `promptApprover` triggers; returns signature hex blob.

### 4. Signaling Interface (Automation)
- **Execution**: `echo "touch" | ./virtual-fido run --always-approve`
- **Expected**: Pending requests are auto-approved via the stream command.
