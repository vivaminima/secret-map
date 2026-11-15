"""Regression tests for the 1.0.4 changes: the closing line, and --remember (off by default)."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import secret_map as sm

FOUND = "%d finding%s. Pro can save a baseline and show only the new ones next run."
NEW = "%d new since last run. Baseline diff and the HTML report are in Pro."


def fake_value(n):
    """A long random-looking value, put together at run time so that no key-shaped string is in this file."""
    return "".join(["Zx9", "Qm4", "Lp7", "Vr2", "Tk8", "Wb5", "Ny3", "%02d" % n])


def secret_line(n, name="service_token"):
    return name + ' = "' + fake_value(n) + '"\n'


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "project 프로젝트"
        self.root.mkdir()
        self.home = Path(self._tmp.name) / "memory"
        self._old = os.environ.get("SECRET_MAP_HOME")
        os.environ["SECRET_MAP_HOME"] = str(self.home)
        (self.root / "notes.txt").write_text("nothing to see\n", encoding="utf-8")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("SECRET_MAP_HOME", None)
        else:
            os.environ["SECRET_MAP_HOME"] = self._old
        self._tmp.cleanup()

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = sm.main([str(self.root)] + list(args))
        return code, out.getvalue(), err.getvalue()

    def add(self, name, *numbers):
        (self.root / name).write_text("".join(secret_line(n) for n in numbers), encoding="utf-8")

    def scanned_files(self):
        return sorted((p.relative_to(self.root).as_posix(), p.read_bytes(), p.stat().st_mtime_ns)
                      for p in self.root.rglob("*") if p.is_file())


class ClosingLine(Base):
    """Default behaviour: one line with the number of findings, and nothing is written anywhere."""

    def test_line_carries_the_real_number_and_is_the_last_line(self):
        self.add("settings.ini", 1)
        code, out, _ = self.run_main()
        self.assertEqual(code, 1)
        self.assertTrue(out.rstrip().endswith(FOUND % (1, "")), out[-200:])
        self.add("settings.ini", 1, 2)
        self.add("deploy.env", 3)
        code, out, _ = self.run_main()
        self.assertTrue(out.rstrip().endswith(FOUND % (3, "s")), out[-200:])

    def test_no_finding_no_line(self):
        code, out, err = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("Pro", out + err)
        self.assertNotIn("finding.", out)

    def test_default_run_never_says_new_and_never_writes_anything(self):
        self.add("settings.ini", 1)
        before = self.scanned_files()
        for _ in range(3):
            code, out, err = self.run_main()
            self.assertNotIn("since last run", out + err)
        self.assertFalse(self.home.exists())                                   # no memory without --remember
        self.assertEqual(before, self.scanned_files())
        self.assertEqual(sorted(p.name for p in Path(self._tmp.name).iterdir()), [self.root.name])

    def test_json_output_stays_json_and_the_line_goes_to_stderr(self):
        self.add("settings.ini", 1, 2)
        code, out, err = self.run_main("--json")
        self.assertEqual(json.loads(out)["counts"]["medium"], 2)
        self.assertEqual(err.strip(), FOUND % (2, "s"))
        code, out, err = self.run_main("--json", "--remember")
        json.loads(out)
        self.add("settings.ini", 1, 2, 3)
        code, out, err = self.run_main("--json", "--remember")
        json.loads(out)
        self.assertEqual(err.strip(), NEW % 1)

    def test_low_findings_count_too(self):
        (self.root / ".env").write_text("PORT=8080\n", encoding="utf-8")       # an environment file: low
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)                                              # below the default level
        self.assertTrue(out.rstrip().endswith(FOUND % (1, "")))


class Remember(Base):
    """--remember is opt-in: it is the only thing that makes the tool write a file."""

    def test_first_remember_run_and_unchanged_runs_show_the_findings_line(self):
        self.add("settings.ini", 1)
        for _ in range(2):
            code, out, _ = self.run_main("--remember")
            self.assertNotIn("since last run", out)
            self.assertTrue(out.rstrip().endswith(FOUND % (1, "")))

    def test_new_since_last_run_carries_the_real_number(self):
        self.add("settings.ini", 1)
        self.run_main("--remember")
        self.add("settings.ini", 1, 2)
        self.add("deploy.env", 3)
        code, out, _ = self.run_main("--remember")
        self.assertTrue(out.rstrip().endswith(NEW % 2), out[-200:])            # one new value in each file
        code, out, _ = self.run_main("--remember")
        self.assertNotIn("since last run", out)                               # nothing new the third time

    def test_fewer_findings_or_moved_lines_are_not_new(self):
        self.add("settings.ini", 1, 2)
        self.run_main("--remember")
        self.add("settings.ini", 1)
        self.assertNotIn("since last run", self.run_main("--remember")[1])
        (self.root / "settings.ini").write_text("# a comment\n\n\n" + secret_line(1), encoding="utf-8")
        self.assertNotIn("since last run", self.run_main("--remember")[1])    # same finding on another line

    def test_changed_value_in_the_same_place_is_new(self):
        self.add("settings.ini", 1)
        self.run_main("--remember")
        self.add("settings.ini", 9)
        self.assertIn(NEW % 1, self.run_main("--remember")[1])

    def test_clean_folder_then_one_finding(self):
        self.assertEqual(self.run_main("--remember")[0], 0)
        self.add("settings.ini", 1)
        self.assertIn(NEW % 1, self.run_main("--remember")[1])

    def test_a_run_without_remember_neither_reads_nor_changes_the_memory(self):
        self.add("settings.ini", 1)
        self.run_main("--remember")
        saved = next((self.home / "last-runs").glob("*.json"))
        before = (saved.read_bytes(), saved.stat().st_mtime_ns)
        self.add("settings.ini", 1, 2)
        code, out, _ = self.run_main()
        self.assertNotIn("since last run", out)
        self.assertEqual(before, (saved.read_bytes(), saved.stat().st_mtime_ns))
        self.assertIn(NEW % 1, self.run_main("--remember")[1])                # still measured against the first run

    def test_memory_lives_outside_the_scanned_folder_and_the_folder_is_never_changed(self):
        self.add("settings.ini", 1)
        before = self.scanned_files()
        self.run_main("--remember")
        self.run_main("--remember")
        self.assertEqual(before, self.scanned_files())
        self.assertEqual(len(list((self.home / "last-runs").glob("*.json"))), 1)

    def test_memory_holds_no_value_no_file_name_and_no_path(self):
        self.add("settings.ini", 1)
        self.run_main("--remember")
        blob = next((self.home / "last-runs").glob("*.json")).read_text(encoding="utf-8")
        for secret in (fake_value(1), fake_value(1)[:8], "settings.ini", "service_token", "project", str(self.root),
                       self._tmp.name):
            self.assertNotIn(secret, blob)
        data = json.loads(blob)
        self.assertEqual(sorted(data), ["ids", "tool", "version"])
        self.assertTrue(all(len(k) == 16 and isinstance(v, int) for k, v in data["ids"].items()))

    def test_two_folders_are_remembered_apart(self):
        other = Path(self._tmp.name) / "other"
        other.mkdir()
        (other / "a.ini").write_text(secret_line(5), encoding="utf-8")
        self.add("settings.ini", 1)
        self.run_main("--remember")
        out = io.StringIO()
        with redirect_stdout(out):
            sm.main([str(other), "--remember"])
        self.assertNotIn("since last run", out.getvalue())                    # first run of that folder
        self.assertEqual(len(list((self.home / "last-runs").glob("*.json"))), 2)

    def test_memory_that_cannot_be_written_or_read_never_breaks_the_scan(self):
        self.add("settings.ini", 1)
        self.home.write_text("a file where the folder should be", encoding="utf-8")
        code, out, err = self.run_main("--remember")
        self.assertEqual((code, err), (1, ""))
        self.home.unlink()
        (self.home / "last-runs").mkdir(parents=True)
        sm.state_path(self.root).write_text("{broken", encoding="utf-8")
        code, out, err = self.run_main("--remember")
        self.assertEqual(code, 1)
        self.assertNotIn("since last run", out)

    def test_ids_do_not_change_the_report(self):
        self.add("settings.ini", 1)
        plain = sm.scan(self.root)
        ids = []
        with_ids = sm.scan(self.root, ids=ids)
        self.assertEqual(plain, with_ids)
        self.assertEqual(len(ids), len(plain["findings"]))
        self.assertTrue(all(f["fingerprint"] is None for f in plain["findings"]))


class Console(Base):
    def test_cp949_and_ascii_consoles_exit_cleanly_with_either_line(self):
        self.add("설정.ini", 1)
        for enc in ("cp949", "ascii"):
            env = dict(os.environ, PYTHONIOENCODING=enc, PYTHONUTF8="0", SECRET_MAP_HOME=str(self.home / enc))
            command = [sys.executable, "-I", str(HERE / "secret_map.py"), str(self.root)]
            r = subprocess.run(command, capture_output=True, env=env)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn(b"1 finding. Pro can save a baseline", r.stdout)
            self.assertFalse((self.home / enc).exists())
            subprocess.run(command + ["--remember"], capture_output=True, env=env)
            with open(self.root / "설정.ini", "a", encoding="utf-8") as handle:
                handle.write(secret_line(2))
            r = subprocess.run(command + ["--remember"], capture_output=True, env=env)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn(b"1 new since last run.", r.stdout)
            (self.root / "설정.ini").write_text(secret_line(1), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
