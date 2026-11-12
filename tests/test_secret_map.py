import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import secret_map as sm

A = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6S7t8U9v0W1x2Y3z4"   # synthetic filler, not a real key
# Every key-shaped test value is assembled at run time from fragments, so no complete
# key-shaped string is stored in this file (public push protection never trips on it).
BEGIN = "-----" + "BEGIN "
PW = "hunter2" + "!long"

# name -> line that must be detected
TRUE_POSITIVES = {
    "openai": "OPENAI_API_KEY=sk-proj-" + A,
    "anthropic": "ANTHROPIC_API_KEY=sk-ant-api03-" + A,
    "github": "GITHUB_TOKEN=ghp_" + A[:36],
    "github_pat": "GH=github_pat_" + A + A[:20],
    "slack": "SLACK_BOT_TOKEN=" + "xo" + "xb-" + "111111111111-222222222222-" + A[:24],
    "stripe": "STRIPE_SECRET=sk_live_" + A[:24],
    "google": "GOOGLE_API_KEY=AIza" + A[:35],
    "aws_id": "AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
    "aws_secret": "AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/" + "K7MDENG/" + "bPxRfiCYzzzzzzKEY1",
    "sendgrid": "SENDGRID_KEY=SG." + A[:22] + "." + A[:43],
    "npm": "NPM_TOKEN=npm_" + A[:36],
    "db_url": "DATABASE_URL=postgres://admin:" + "SuperS3" + "cretPw" + "@db.internal:5432/app",
    "generic_prefixed": "MYAPP_CLIENT_SECRET=" + A[:32],
    "yaml": "  api_key: \"" + A[:30] + "\"",
    "json": '  "accessToken": "' + A[:30] + '",',
    "python": 'DB_PASSWORD = "' + PW + '"',
    "export": "export SERVICE_TOKEN=" + A[:28],
    "private_key": BEGIN + "OPENSSH PRIVATE KEY-----",
    "jwt": "x = " + ".".join(["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVP" + "mB92K27uhbUJU1p1r"]),
    "gcp_json_key": '"private_key": "' + BEGIN + 'PRIVATE KEY-----\\n' + "MIIEvQIBADAN" + "BgkqhkiG9w0BAQEFAASC" + '\\n",',
    "aws_doc_secret": "AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/" + "K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "code_literal": 'oauth_token="' + 'ad180jjd' + '733klru7' + '"',
    "slack_hook": "https://hooks.slack" + ".com/services/" + "T00000000/B00000000/" + A[:24],
}

FALSE_POSITIVES = [
    "OPENAI_API_KEY=",
    "OPENAI_API_KEY=your-key-here",
    "API_KEY=<paste your key>",
    "API_KEY=${API_KEY}",
    "TOKEN=xxxxxxxxxxxxxxxxxxxx",
    "PASSWORD=changeme",
    "password: null",
    "token_count = 15000",
    "max_tokens: 4096",
    "secret_name = get_secret_name()",
    "api_key = os.environ['OPENAI_API_KEY']",
    "const token = process.env.GITHUB_TOKEN;",
    "password = input('Password: ')",
    "author = somebody",
    "# set the api key before running the tests in this folder",
    "DATABASE_URL=postgres://localhost:5432/app",
    "DATABASE_URL=postgres://user:${DB_PASSWORD}" + "@db/app",
    "url = https://example.com/path?token_type=bearer",
    "tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')",
    "keyboard_shortcut = ctrl+shift+p",
    "refresh_token_key = 'refresh_token'",
    'ACCESS_TOKEN_KEY = "access_key:84"',
    'request_token_page = "+request-token"',
    ':type credential_store: `CredentialStore`',
    'AttributeOID.CHALLENGE_PASSWORD: "challengePassword",',
    '_SK_START = b"' + BEGIN + 'OPENSSH PRIVATE KEY-----"',
    'help="Specify a proxy in the form scheme://[user:passwd' + '@]proxy.server:port."',
    "'http://username:password" + "@host.com:80/path?query#fragment'",
    'token_type_hint="access_token", body=None',
]


class Detection(unittest.TestCase):
    def hits(self, line, config_like=True):
        return list(sm.scan_text(line, config_like))

    def test_true_positives(self):
        for name, line in TRUE_POSITIVES.items():
            with self.subTest(name=name):
                self.assertTrue(self.hits(line), "missed: " + name)

    def test_false_positives(self):
        for line in FALSE_POSITIVES:
            with self.subTest(line=line):
                self.assertEqual(self.hits(line), [], "false alarm: " + line)
                self.assertEqual(self.hits(line, config_like=False), [], "false alarm in code: " + line)

    def test_prefixed_env_names_are_caught(self):
        # the classic miss: a word boundary never exists between "_" and the keyword
        for name in ("OPENAI_API_KEY", "STRIPE_SECRET", "AWS_SECRET_ACCESS_KEY", "MY_APP_AUTH_TOKEN", "X.API-KEY"):
            with self.subTest(name=name):
                self.assertTrue(self.hits(name + "=q9Zx7Lm2Vb4Nc8Rt6Yp1Ws3K"))

    def test_one_finding_per_secret(self):
        self.assertEqual(len(self.hits(TRUE_POSITIVES["openai"])), 1)
        self.assertEqual(self.hits(TRUE_POSITIVES["openai"])[0]["rule"], "openai-api-key")

    def test_unquoted_expression_in_code_is_not_flagged(self):
        self.assertEqual(self.hits("api_key = settings_loader_value_9", config_like=False), [])
        self.assertTrue(self.hits("api_key = '" + "q9Zx7Lm2Vb4N" + "c8Rt6Yp1Ws3K'", config_like=False))

    def test_inline_ignore(self):
        self.assertEqual(self.hits(TRUE_POSITIVES["stripe"] + "  # secretmap:ignore"), [])

    def test_guessable_values_get_no_fingerprint_or_length(self):
        # a 12-hex-digit hash of a human-chosen password can be reversed with a word list
        for line in ('DB_PASSWORD = "' + PW + '"', "DATABASE_URL=postgres://admin:" + "SuperS3" + "cretPw" + "@db:5432/app",
                     "PASSWORD=" + "letmein" + "2024", "ADMIN_PASSWORD=" + "aaaaaaaa1111" * 2 + "aaaa"):
            with self.subTest(line=line):
                hit = self.hits(line)[0]
                self.assertIsNone(hit["fingerprint"])
                self.assertIsNone(hit["length"])

    def test_notion_tokens(self):
        self.assertEqual(self.hits("NOTION=ntn_" + A[:46])[0]["rule"], "notion-token")
        self.assertEqual(self.hits("x: secret_" + A[:43])[0]["rule"], "notion-token")

    def test_long_random_values_keep_a_fingerprint(self):
        hit = self.hits(TRUE_POSITIVES["openai"])[0]
        self.assertEqual(len(hit["fingerprint"]), 12)
        self.assertEqual(hit["fingerprint"], self.hits(TRUE_POSITIVES["openai"])[0]["fingerprint"])

    def test_private_key_marker_has_no_fingerprint(self):
        self.assertIsNone(self.hits(TRUE_POSITIVES["private_key"])[0]["fingerprint"])

    def test_example_values_are_labelled(self):
        self.assertTrue(self.hits(TRUE_POSITIVES["aws_id"])[0]["example_like"])


class Folder(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text, raw=None):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw if raw is not None else text.encode("utf-8"))
        return p

    def cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sm.main([str(self.root)] + list(args))
        return code, buf.getvalue()

    def test_value_is_never_printed(self):
        secret = "sk-proj-" + A
        self.write("app/.env", "OPENAI_API_KEY=%s\nDB_PASSWORD=%s\n" % (secret, PW))
        for args in ((), ("--json",)):
            code, out = self.cli(*args)
            self.assertEqual(code, 1)
            self.assertNotIn(secret, out)
            self.assertNotIn(A[:12], out)
            self.assertNotIn("hunter2", out)
            import hashlib
            self.assertNotIn(hashlib.sha256(PW.encode()).hexdigest()[:12], out)

    def test_clean_folder_exit_zero_and_honest_wording(self):
        self.write("main.py", "print('hello')\n")
        code, out = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("Scanned 1 files", out)
        self.assertIn("does not prove", out)

    def test_empty_folder_is_not_reported_as_clean(self):
        code, out = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("nothing was scanned", out)

    def test_missing_folder(self):
        self.assertEqual(sm.main([str(self.root / "nope")]), 2)

    def test_bom_crlf_and_latin1_files_are_scanned(self):
        line = TRUE_POSITIVES["github"]
        self.write("a.env", "", raw=b"\xef\xbb\xbf" + line.encode() + b"\r\n")
        self.write("b.txt", "", raw=b"caf\xe9\r\n" + line.encode() + b"\r\n")
        r = sm.scan(self.root)
        self.assertEqual(sorted((f["file"], f["line"]) for f in r["findings"]), [("a.env", 1), ("b.txt", 2)])

    def test_binary_large_and_vendor_are_skipped_and_counted(self):
        self.write("img.dat", "", raw=b"\x00\x01" + TRUE_POSITIVES["github"].encode())
        self.write("big.txt", TRUE_POSITIVES["github"] + "\n" + "x" * 5000)
        self.write("node_modules/pkg/.env", TRUE_POSITIVES["github"])
        self.write("ok.txt", "nothing here\n")
        r = sm.scan(self.root, max_bytes=1000)
        self.assertEqual(r["findings"], [])
        self.assertEqual((r["stats"]["files_scanned"], r["stats"]["skipped_binary"], r["stats"]["skipped_large"]), (1, 1, 1))

    def test_fingerprints_are_off_by_default_and_opt_in(self):
        self.write("a.env", TRUE_POSITIVES["openai"] + "\nDB_PASSWORD=" + PW + "\n")
        for f in sm.scan(self.root)["findings"]:
            self.assertIsNone(f["fingerprint"])
            self.assertIsNone(f["length"])
        code, out = self.cli()
        self.assertNotIn(" id ", out)
        shown = [f["fingerprint"] for f in sm.scan(self.root, show_fingerprints=True)["findings"] if f["line"]]
        self.assertEqual([bool(x) for x in shown], [True, False])     # long random: yes, password: never
        self.assertIn(" id ", self.cli("--fingerprints")[1])

    def test_utf16_files_are_scanned(self):
        # Windows PowerShell 5.1 `>` writes UTF-16 LE with a BOM
        line = TRUE_POSITIVES["github"] + "\r\n"
        self.write("ps51.env", "", raw=b"\xff\xfe" + line.encode("utf-16-le"))
        self.write("be.env", "", raw=b"\xfe\xff" + line.encode("utf-16-be"))
        self.write("nobom.env", "", raw=("# settings file\r\n" + line).encode("utf-16-le"))
        r = sm.scan(self.root)
        self.assertEqual(sorted(f["file"] for f in r["findings"] if f["rule"] == "github-token"),
                         ["be.env", "nobom.env", "ps51.env"])
        self.assertEqual(r["stats"]["skipped_binary"], 0)

    def test_token_json_and_client_secret_filenames(self):
        for name in ("token.json", "client_secret_1234-abc.apps.googleusercontent.com.json", "Client_Secret.JSON",
                     "my-service-account-prod.json", ".npmrc"):
            self.write("cfg/" + name, "{}\n")
        self.write("cfg/package.json", "{}\n")
        self.write("cfg/tokenizer.json", "{}\n")
        files = sorted(f["file"] for f in sm.scan(self.root)["findings"] if f["rule"] == "sensitive-file")
        self.assertEqual(len(files), 5)
        self.assertNotIn("cfg/package.json", files)
        self.assertNotIn("cfg/tokenizer.json", files)

    def test_ignore_file_paths_and_fingerprints(self):
        self.write("fixtures/fake.env", TRUE_POSITIVES["stripe"])
        self.write("real.env", TRUE_POSITIVES["npm"])
        fp = sm.scan(self.root, show_fingerprints=True)["findings"][-1]["fingerprint"]
        self.write(".secretmapignore", "# test data\nfixtures/\nfingerprint:%s\n" % fp)
        r = sm.scan(self.root)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["stats"]["skipped_ignored"], 1)

    def test_sensitive_filenames_are_low_and_do_not_fail_by_default(self):
        self.write(".env", "DEBUG=1\n")
        self.write(".env.example", "DEBUG=1\n")
        self.write("deploy.pem", "not a key\n")
        r = sm.scan(self.root)
        self.assertEqual(sorted(f["file"] for f in r["findings"]), [".env", "deploy.pem"])
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli("--fail-on", "low")[0], 1)

    def test_read_only_and_deterministic(self):
        self.write("a/.env", TRUE_POSITIVES["openai"])
        before = sorted(p.as_posix() for p in self.root.rglob("*"))
        self.assertEqual(sm.scan(self.root), sm.scan(self.root))
        self.assertEqual(before, sorted(p.as_posix() for p in self.root.rglob("*")))

    def test_json_shape(self):
        self.write(".env.local", TRUE_POSITIVES["db_url"])
        code, out = self.cli("--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["counts"]["high"], 1)
        self.assertNotIn("value", data["findings"][0])


if __name__ == "__main__":
    unittest.main()
