"""Regression tests for the 1.0.3 changes (one or more per fix)."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import secret_map as sm

# assembled at run time; no complete key-shaped string is stored in this file
FAKE_GITHUB = "gh" + "p_" + "Q" * 36


def korean_text(lines=40):
    """Text that is more than 80% Hangul, with a little ASCII."""
    row = "가나다라마바사아자차카타파하대한민국"
    text = "".join("%s %d\n" % (row, i % 10) for i in range(lines))
    hangul = sum(1 for c in text if "가" <= c <= "힣")
    assert hangul / len(text) >= 0.8
    return text


def rule_102(raw):
    """The 1.0.2 heuristic (zero-byte ratio only), kept here to show why it missed."""
    head = raw[:8192]
    even, odd = head[0::2].count(0), head[1::2].count(0)
    half = max(1, len(head) // 2)
    return odd > half * 0.6 and even < half * 0.05


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class Utf16(Base):
    def test_bomless_utf16_mostly_korean_file_is_scanned(self):
        text = korean_text() + "GITHUB_TOKEN=" + FAKE_GITHUB + "\n" + korean_text(10)
        for codec in ("utf-16-le", "utf-16-be"):
            (self.root / ("notes-%s.txt" % codec)).write_bytes(text.encode(codec))
        self.assertFalse(rule_102(text.encode("utf-16-le")))        # 1.0.2 called this file binary
        r = sm.scan(self.root)
        self.assertEqual(sorted(f["file"] for f in r["findings"] if f["rule"] == "github-token"),
                         ["notes-utf-16-be.txt", "notes-utf-16-le.txt"])
        self.assertEqual(r["stats"]["skipped_binary"], 0)
        self.assertEqual([f["line"] for f in r["findings"]], [41, 41])

    def test_binary_with_zero_bytes_is_still_skipped(self):
        (self.root / "blob.dat").write_bytes(bytes(range(256)) * 8 + FAKE_GITHUB.encode())
        (self.root / "ok.txt").write_text("nothing\n", encoding="utf-8")
        r = sm.scan(self.root)
        self.assertEqual((r["findings"], r["stats"]["skipped_binary"]), ([], 1))

    def test_cp949_korean_is_not_mistaken_for_utf16(self):
        self.assertIsNone(sm.sniff_utf16(korean_text().encode("cp949")))


class NoKeyShapedStrings(unittest.TestCase):
    def test_this_package_contains_no_key_shaped_string(self):
        # M36 A3: public push protection must never trip on our own files, tests included.
        r = sm.scan(HERE)
        self.assertEqual(r["findings"], [], r["findings"])
        self.assertGreaterEqual(r["stats"]["files_scanned"], 5)


class Console(Base):
    def test_cp949_and_ascii_consoles_exit_cleanly(self):
        d = self.root / "—키"
        d.mkdir()
        (d / ".env").write_text("TOKEN=" + FAKE_GITHUB + "\n", encoding="utf-8")
        for enc in ("cp949", "ascii"):
            with self.subTest(enc=enc):
                env = dict(os.environ, PYTHONIOENCODING=enc, PYTHONUTF8="0")
                p = subprocess.run([sys.executable, "-I", str(HERE / "secret_map.py"), str(self.root)],
                                   capture_output=True, env=env)
                self.assertEqual(p.returncode, 1, p.stderr)
                self.assertNotIn(b"Traceback", p.stderr)
                self.assertIn(b"github-token", p.stdout)
                self.assertNotIn(FAKE_GITHUB.encode(), p.stdout)


if __name__ == "__main__":
    unittest.main()
