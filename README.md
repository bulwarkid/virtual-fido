# Virtual FIDO

> **Note**: Virtual FIDO is currently in beta, so it should not yet be used for security-critical products.

Virtual FIDO is a virtual USB device that implements the FIDO2/U2F protocol (like a YubiKey) to support 2FA and WebAuthN.

## Features

-   Support for both Windows and Linux through USB/IP (Mac support coming later)
-   Connect using both U2F and FIDO2 protocols for both normal 2FA and WebAuthN
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (example provided: terminal-based)

## How it works

Virtual FIDO creates a USB/IP server over local TCP to attach a virtual USB device. This USB device then emulates the USB/CTAP protocols to provide U2F/FIDO services to the host computer. In the demo, credentials created by the virtual device are stored in a local file, and approvals are done using the terminal.

## Demo Usage

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.

### Windows

Run `go run main.go start` to attach the USB device. Run `go run main.go --help` to see more commands, such as to list or delete credentials from the file.

### Linux

Note that this tool requires elevated permissions.

1. Run `sudo modprobe vhci-hcd` to load the necessary drivers.
2. Run `sudo go run main.go start` to start up the USB device server. Authenticate when `sudo` prompts you; this is necessary to attach the device.
