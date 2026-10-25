## Transport

This package provides transport selection helpers and concrete transport
implementations for exposing a virtual FIDO authenticator as a HID device.

### Overview

- `transport.go`: transport selection and startup helpers.
- `uhid/`: Linux-only UHID implementation (pure Go, `/dev/uhid`).
- `usbipwin2/`: Windows usbip-win2 client integration (requires [driver][usbip-win2]).
- `usbip_*.go`: OS-specific usbip attach helpers for the external `usbip` binary.

### Transports

- `uhid` (Linux only): pure Go HID device via `/dev/uhid`.
- `usbip` (Linux/Windows): uses external `usbip` tooling for attachment.
- `usbip-win2` (Windows only): uses the [usbip-win2][usbip-win2] driver to attach
  a local virtual USB device via IOCTLs.

[usbip-win2]: https://github.com/vadimgrn/usbip-win2
