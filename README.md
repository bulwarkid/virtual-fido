# Virtual FIDO

_Note: Virtual FIDO is currently in beta, so it should not yet be used for security-critical products._

Virtual FIDO is a virtual USB device that implements the FIDO2/U2F protocol (like a YubiKey) in order to support 2FA and WebAuthN.

## Features

-   Support for both Windows and Linux through USB/IP (Mac support coming later)
-   Connect using both U2F and FIDO2 protocols for both normal 2FA and WebAuthN
-   Store credentials in an encrypted format with a passphrase
-   Store credential data anywhere (example provided: a local file)
-   Generic approval mechanism for credential creation and login (example provided: terminal based)

## How it works

Virtual FIDO creates a USB/IP server over local TCP in order to attach a virtual USB device. This USB device then emulates the USB/CTAP protocols to provide U2F/FIDO services to the host computer. In the demo, credentials created by the virtual device are stored to a local file and approvals are done using the terminal.

## Demo Usage

The demo is currently set up to run on Windows, though the demo could work on Linux by removing the call to `usbip.exe` and running the USB/IP attachment manually (see https://wiki.archlinux.org/title/USB/IP). Run `go run main.go start` to attach the USB device. Run `go run main.go --help` to see more commands, namely to list or delete credentials from the file.

Go to the [YubiKey test page](https://demo.yubico.com/webauthn-technical/registration) in order to test WebAuthN.
