# Virtual FIDO

> Also check out [Bulwark Passkey](https://bulwark.id), a passkey manager based on VirtualFIDO that is currently in beta!

Virtual FIDO is a virtual USB device that implements the FIDO 2.1 (CTAP 2.1) and U2F (CTAP 1.0) protocols (like a YubiKey) to support passkeys, 2FA, and WebAuthn. Please note that this software is still in beta and under active development.

## Features

-   Support for both Windows and Linux through USB/IP (Mac support coming later)
-   Pure Go UHID transport on Linux (no usbip dependency)
-   Native macOS support via CoreHID (macOS 15+)
-   Full FIDO 2.1 compliance (Resident Keys, User Verification)
-   Connect using both U2F and FIDO 2.1 protocols for both normal 2FA and WebAuthn
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (example provided: terminal-based)

## How it works

Virtual FIDO creates a virtual HID authenticator. On Linux you can choose:

- USB/IP server over local TCP to attach a virtual USB device (depends on `usbip` binary), or
- UHID (pure Go, no usbip) which creates a local `/dev/uhid` device.

Both expose U2F and CTAP2 over CTAPHID. In the demo, credentials created by the virtual device are stored in a local file, and approvals are done using the terminal.

## Demo Usage

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.

### Windows

Run `go run ./cmd/demo start` to attach the USB device. Run `go run ./cmd/demo --help` to see more commands, such as to list or delete credentials from the file.

### Linux

Note that this tool requires elevated permissions.

#### usbip (depends on external binary)
1. Run `sudo modprobe vhci-hcd` to load the necessary drivers.
2. Run `sudo go run ./cmd/demo start` to start up the USB device server. Authenticate when `sudo` prompts you; this is necessary to attach the device.

#### UHID (pure Go, self-contained, Linux only)
1. Ensure `/dev/uhid` is accessible (usually requires root).
2. Use `virtual_fido.StartUHID(ctx, client, "Virtual FIDO")` in your own program to run without usbip.
   (The demo CLI still uses usbip by default, pass `--transport uhid` to use UHID.)
