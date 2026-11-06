# Linux Desktop Integration & X11 Touch Hotkey Helper

This directory provides desktop-friendly utilities for running `virtual-fido` on Linux X11 desktop sessions (including lightweight window managers without GNOME/KDE polkit agents):

- **`virtual-fido-hotkey`**: Dependency-free Python 3 (`ctypes` + `libX11.so.6`) global X11 hotkey daemon for FIDO2 / WebAuthn user-presence approval:
  - **`Ctrl + CapsLock`** (automatically unlocks `CapsLock` via `XkbLockModifiers` so `CapsLock` is never left toggled on)
  - **`Ctrl + F12`** (alternative global chord)
  - **`F12`** alone while `<config-dir>/pending.prompt` exists
  - Combines passive `XGrabKey` across `LockMask` / `Mod2Mask` modifier permutations with 40 Hz `XQueryKeymap` polling so chords still work when popups or window managers hold passive grabs.
  - Emits both `<config-dir>/touch.sig` (for signal-file `uhid` builds) and non-blocking `y\n` to `<config-dir>/touch.fifo` when present (for stdin-based `cmd/demo start` builds).
- **`virtual-fido-ctl`**: `start | stop | restart | touch | status` lifecycle script storing per-user `0700` state in `${XDG_CONFIG_HOME:-~/.config}/virtual-fido/`.
- **`70-virtual-fido-uhid.rules`**: `udev` rule granting `plugdev` and active local sessions (`TAG+="uaccess"`) access to `/dev/uhid` and `/dev/hidraw*`.
- **`virtual-fido.service`**: Optional `systemd --user` service unit.

## Quick Start

1. Install the scripts onto your `PATH`:

   ```bash
   install -m 0755 contrib/linux-desktop/virtual-fido-ctl ~/.local/bin/virtual-fido-ctl
   install -m 0755 contrib/linux-desktop/virtual-fido-hotkey ~/.local/bin/virtual-fido-hotkey
   ```

2. (For `uhid` builds) Install the `udev` rule once:

   ```bash
   sudo install -m 0644 contrib/linux-desktop/70-virtual-fido-uhid.rules /etc/udev/rules.d/
   sudo modprobe uhid
   sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=misc --subsystem-match=hidraw
   ```

3. Start the daemon and X11 hotkey helper:

   ```bash
   virtual-fido-ctl start
   ```

   When a browser or SSH prompt requests WebAuthn / FIDO2 touch verification, press **`Ctrl + CapsLock`** or **`Ctrl + F12`** (or run `virtual-fido-ctl touch`).

## Running Unit Tests

```bash
python3 -m unittest contrib/linux-desktop/test_hotkey.py
```
