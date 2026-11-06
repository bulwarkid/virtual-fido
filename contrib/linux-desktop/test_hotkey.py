import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


def _load_hotkey_module():
    script_path = Path(__file__).with_name("virtual-fido-hotkey")
    loader = importlib.machinery.SourceFileLoader("virtual_fido_hotkey", str(script_path))
    spec = importlib.util.spec_from_loader("virtual_fido_hotkey", loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hotkey = _load_hotkey_module()


def _make_keymap(*pressed_keycodes: int) -> bytes:
    buf = bytearray(32)
    for kc in pressed_keycodes:
        buf[kc >> 3] |= 1 << (kc & 7)
    return bytes(buf)


class VirtualFidoHotkeyTests(unittest.TestCase):
    def test_detects_ctrl_capslock_and_marks_caps_unlock(self) -> None:
        km = _make_keymap(37, 66)
        result = hotkey.detect_hotkey_combo(
            km,
            kc_ctrl_l=37,
            kc_ctrl_r=105,
            kc_caps=66,
            kc_f12=96,
            pending_prompt=False,
        )
        self.assertEqual(result, ("Ctrl+CapsLock (keymap)", True))

    def test_detects_right_ctrl_f12_and_pending_f12(self) -> None:
        km_chord = _make_keymap(105, 96)
        self.assertEqual(
            hotkey.detect_hotkey_combo(
                km_chord,
                kc_ctrl_l=37,
                kc_ctrl_r=105,
                kc_caps=66,
                kc_f12=96,
                pending_prompt=False,
            ),
            ("Ctrl+F12 (keymap)", False),
        )

        km_f12 = _make_keymap(96)
        self.assertIsNone(
            hotkey.detect_hotkey_combo(
                km_f12,
                kc_ctrl_l=37,
                kc_ctrl_r=105,
                kc_caps=66,
                kc_f12=96,
                pending_prompt=False,
            )
        )
        self.assertEqual(
            hotkey.detect_hotkey_combo(
                km_f12,
                kc_ctrl_l=37,
                kc_ctrl_r=105,
                kc_caps=66,
                kc_f12=96,
                pending_prompt=True,
            ),
            ("F12 (pending prompt)", False),
        )

    def test_emit_touch_approval_writes_0600_signal_and_nonblocking_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sig = root / "touch.sig"
            fifo = root / "touch.fifo"
            os.mkfifo(fifo, 0o600)

            # With no reader open on the FIFO, emit_touch_approval must not block (ENXIO ignored).
            hotkey.emit_touch_approval(sig, fifo)
            self.assertEqual(sig.read_text(), "touch\n")
            self.assertEqual(sig.stat().st_mode & 0o777, 0o600)

            # With a non-blocking reader attached, emit_touch_approval delivers "y\n" to the FIFO.
            rfd = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
            try:
                hotkey.emit_touch_approval(sig, fifo)
                self.assertEqual(os.read(rfd, 16), b"y\n")
            finally:
                os.close(rfd)


if __name__ == "__main__":
    unittest.main()
