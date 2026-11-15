#!/usr/bin/env python3
"""Secret Map - offline, read-only scan for credentials left in a project folder.

Reports where a secret appears (file, line, variable name, rule). It does not print,
store or transmit the secret value itself. Standard library only. No network.

A clean result means "no known pattern matched", not "no secrets exist".
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
import unicodedata
from pathlib import Path

VERSION = "1.0.4"
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".tox", ".idea", ".next", "target", "vendor"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar",
                 ".exe", ".dll", ".so", ".dylib", ".pyc", ".class", ".jar", ".woff", ".woff2", ".ttf", ".otf",
                 ".mp3", ".mp4", ".mov", ".avi", ".bin", ".lock"}
CONFIG_SUFFIXES = {"", ".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".txt", ".sh",
                   ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".tfvars", ".envrc"}
IGNORE_FILE = ".secretmapignore"
INLINE_IGNORE = "secretmap:ignore"
LEVELS = ("low", "medium", "high")

# Provider formats: the value itself is recognisable. (rule id, severity, description, regex)
PROVIDER_RULES = [
    ("private-key-block", "high", "Private key block",
     r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?=\s*$|(?:\\r)?\\n\s*[A-Za-z0-9+/=]{16,})"),
    ("aws-access-key-id", "high", "AWS access key ID", r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ("anthropic-api-key", "high", "Anthropic API key", r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"),
    ("openai-api-key", "high", "OpenAI API key",
     r"(?<![A-Za-z0-9])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    ("github-token", "high", "GitHub token",
     r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"),
    ("gitlab-token", "high", "GitLab personal access token", r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}"),
    ("slack-token", "high", "Slack token", r"(?<![A-Za-z0-9])xox[abeoprs]-[A-Za-z0-9-]{10,}"),
    ("slack-webhook", "high", "Slack incoming webhook",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ("stripe-live-key", "high", "Stripe live key", r"(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{16,}"),
    ("stripe-webhook-secret", "high", "Stripe webhook secret", r"(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{24,}"),
    ("google-api-key", "high", "Google API key", r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    ("sendgrid-api-key", "high", "SendGrid API key", r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("npm-token", "high", "npm access token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    ("pypi-token", "high", "PyPI upload token", r"(?<![A-Za-z0-9])pypi-AgE[A-Za-z0-9_-]{40,}"),
    ("notion-token", "high", "Notion integration token",
     r"(?<![A-Za-z0-9])(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43}(?![A-Za-z0-9]))"),
    ("huggingface-token", "high", "Hugging Face token", r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}"),
    ("digitalocean-token", "high", "DigitalOcean token", r"(?<![A-Za-z0-9])do[opr]_v1_[a-f0-9]{64}"),
    ("telegram-bot-token", "high", "Telegram bot token", r"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])"),
    ("discord-webhook", "high", "Discord webhook",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
    ("jwt", "medium", "JSON Web Token",
     r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("url-with-password", "high", "Password inside a connection URL",
     r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]+:(?P<value>[^\s/@'\"]{3,})@[^\s/'\"]+"),
]
PROVIDER_RULES = [(i, s, d, re.compile(r)) for i, s, d, r in PROVIDER_RULES]

# Generic assignment: the variable NAME says it is a secret. No \b before the keyword,
# so prefixed names such as OPENAI_API_KEY or STRIPE_SECRET are matched.
KEYWORDS = (r"secret|token|passwd|password|pwd|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key|"
            r"client[_.-]?secret|auth[_.-]?key|credential|signing[_.-]?key|encryption[_.-]?key")
ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]*(?:" + KEYWORDS + r")[A-Za-z0-9_.-]*)[\"']?\s*(?::=|=>|[:=])\s*"
    r"(?:(?P<quote>[\"'`])(?P<qvalue>[^\"'`\n]{6,})(?P=quote)|(?P<value>[^\s\"'`,;#]{6,}))",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(
    r"example|sample|changeme|change[_-]me|your[_-]?|placeholder|dummy|redacted|replace|insert|todo|fixme",
    re.IGNORECASE,
)
STRUCTURAL_PLACEHOLDER_RE = re.compile(
    r"^x+$|^\*+$|^\.+$|^-+$|^0+$|xxxx|<[^>]*>|\$\{|\$\(|\{\{|%[A-Za-z_]+%|"
    r"^(?:none|null|nil|true|false|undefined|empty|password|passwd|pass|pwd|secret|token|key|user|username)\]?$",
    re.IGNORECASE,
)
VALUE_IS_LABEL_RE = re.compile(r"secret|token|passw|api[_.-]?key|access[_.-]?key|credential", re.IGNORECASE)
REFERENCE_RE = re.compile(
    r"^(?:os\.|process\.|env\.|ENV\[|getenv|System\.|config\.|settings\.|self\.|this\.|args\.|\$[A-Za-z_]|secrets\.|var\.|data\.)")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?:\(.*)?$")
SENSITIVE_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json", "service-account.json",
                   "service_account.json", "token.json", "tokens.json", "token.pickle", ".htpasswd", ".netrc",
                   ".pgpass", ".npmrc", ".pypirc")
SENSITIVE_GLOBS = ("client_secret*.json", "*-service-account*.json", "*_service_account*.json")
SENSITIVE_SUFFIXES = (".pem", ".p12", ".pfx", ".key", ".keystore", ".jks", ".ppk")
TEMPLATE_HINTS = ("example", "sample", "template", "dist", "defaults")


def entropy(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum(c / n * math.log(c / n, 2) for c in counts.values())


FINGERPRINT_MIN_LENGTH = 20
FINGERPRINT_MIN_ENTROPY = 3.5


def fingerprint(value):
    """Short one-way id so the same secret can be recognised without revealing it.

    Only long, random-looking values get one. A hash of a short or guessable value
    (a human-chosen password) could be reversed by trying a word list, so those
    get no id and no length at all.
    """
    if len(value) < FINGERPRINT_MIN_LENGTH or entropy(value) < FINGERPRINT_MIN_ENTROPY:
        return None
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def describe(value):
    """Return (fingerprint, length) - both None when the value is short or guessable."""
    value = value.strip()
    mark = fingerprint(value)
    return mark, (len(value) if mark else None)


def is_placeholder(value):
    """Placeholder words only count when the value is short or low-entropy.

    A long random string that merely contains "EXAMPLE" is still reported (and labelled).
    """
    if STRUCTURAL_PLACEHOLDER_RE.search(value):
        return True
    if PLACEHOLDER_RE.search(value):
        return len(value) < 24 or entropy(value) < 3.0
    return False


def looks_like_secret(name, value, quoted, config_like):
    """Decide whether a generic NAME=value assignment is worth reporting."""
    value = value.strip()
    if len(value) < 6 or is_placeholder(value) or REFERENCE_RE.match(value):
        return False
    if re.search(r"\s", value):
        return False                          # credentials do not contain whitespace
    if VALUE_IS_LABEL_RE.search(value) and len(value) < 24:
        return False                          # e.g. token_key = "access_token"
    if not quoted:
        if not config_like:
            return False                      # unquoted value in source code is an expression
        if IDENT_RE.match(value) and not re.search(r"\d", value):
            return False                      # points at another setting, not a literal
    if re.search(r"passw|pwd", name, re.IGNORECASE):
        return len(value) >= 6
    if len(value) < 12 or entropy(value) < 3.0:
        return False
    if quoted and not config_like:            # string literal in source code: must look random
        return bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value))
    return True


def scan_text(text, config_like=True):
    """Yield findings for one file's text. Values are never returned."""
    for number, line in enumerate(text.split("\n"), 1):
        if INLINE_IGNORE in line or len(line) > 5000:
            continue
        spans = []
        for rule, severity, description, regex in PROVIDER_RULES:
            for m in regex.finditer(line):
                value = m.groupdict().get("value") or m.group(0)
                if rule == "url-with-password" and (is_placeholder(value) or REFERENCE_RE.match(value)):
                    continue
                spans.append(m.span())
                mark, size = (None, None) if rule == "private-key-block" else describe(value)
                yield {"line": number, "rule": rule, "severity": severity, "description": description,
                       "name": None, "fingerprint": mark, "length": size,
                       "example_like": bool(re.search(r"example|sample|test|dummy|fake", value, re.IGNORECASE))}
        for m in ASSIGN_RE.finditer(line):
            quoted = m.group("qvalue") is not None
            value = m.group("qvalue") if quoted else m.group("value")
            vspan = m.span("qvalue") if quoted else m.span("value")
            if any(s[0] < vspan[1] and vspan[0] < s[1] for s in spans):
                continue                       # already reported by a provider rule
            if looks_like_secret(m.group("name"), value, quoted, config_like):
                mark, size = describe(value)
                yield {"line": number, "rule": "secret-assignment", "severity": "medium",
                       "description": "Secret-like value assigned to a secret-named variable",
                       "name": m.group("name"), "fingerprint": mark, "length": size,
                       "example_like": False}


_TEXT_WS = "\t\n\r\f\v"


def sniff_utf16(raw):
    """Return 'utf-16-le' or 'utf-16-be' when BOM-less bytes are UTF-16 text, else None.

    Counting zero bytes alone misses text that is mostly Korean (or Chinese, Japanese):
    those characters have no zero byte. So the side that holds more zero bytes only picks
    the byte order; the decision is made by decoding and checking the result - almost no
    control or unassigned characters, and at least a little plain ASCII.
    """
    if len(raw) < 2 or b"\x00" not in raw:
        return None
    sample = raw[:65536]
    if len(sample) % 2:
        sample = sample[:-1]
    even, odd = sample[0::2].count(0), sample[1::2].count(0)
    if even == odd:
        return None
    codec = "utf-16-le" if odd > even else "utf-16-be"
    text = None
    for cut in (sample, sample[:-2]):
        try:
            text = cut.decode(codec)
            break
        except UnicodeDecodeError:
            continue
    if not text:
        return None
    bad = plain = 0
    for ch in text:
        code = ord(ch)
        if code < 0x80:
            if ch in _TEXT_WS or 0x20 <= code < 0x7F:
                plain += 1
            else:
                bad += 1
        elif unicodedata.category(ch) in ("Cc", "Cn", "Co", "Cs"):
            bad += 1
    if bad > len(text) * 0.01 or plain < len(text) * 0.02:
        return None
    return codec


def decode_bytes(raw):
    """Return text, or None when the bytes are binary.

    Handles UTF-8 (with or without BOM) and UTF-16 (with a BOM, or without one) - Windows
    PowerShell 5.1 writes UTF-16 with `>`. BOM-less UTF-16 is recognised by decoding, so a
    file that is mostly Korean is caught as well (sniff_utf16).
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        text = raw[3:].decode("utf-8", "replace")
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        codec = sniff_utf16(raw)
        if codec:
            try:
                text = raw.decode(codec)
            except UnicodeDecodeError:
                return None
        elif b"\x00" in raw[:8192]:
            return None
        else:
            text = raw.decode("utf-8", "replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")

def load_ignores(root):
    patterns, prints = [], set()
    path = root / IGNORE_FILE
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines() if path.is_file() else []
    except (OSError, UnicodeDecodeError):
        lines = []
    for raw in lines:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.lower().startswith("fingerprint:"):
            prints.add(entry.split(":", 1)[1].strip().lower())
        else:
            patterns.append(entry.replace("\\", "/"))
    return patterns, prints


def path_ignored(rel, patterns):
    for pattern in patterns:
        bare = pattern.rstrip("/")
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(os.path.basename(rel), pattern):
            return True
        if rel == bare or rel.startswith(bare + "/"):
            return True
    return False


def sensitive_filename(name):
    lower = name.lower()
    if lower in SENSITIVE_NAMES or lower.endswith(SENSITIVE_SUFFIXES):
        return "Key or credential file"
    if any(fnmatch.fnmatch(lower, pattern) for pattern in SENSITIVE_GLOBS):
        return "Key or credential file"
    if lower == ".env" or (lower.startswith(".env.") and not any(h in lower for h in TEMPLATE_HINTS)):
        return "Environment file (make sure it is not committed or shipped)"
    return None


def finding_id(item):
    """An opaque id for one finding: where it is and what kind, plus - for long random values only -
    the first 6 characters of a hash of the value. Never the value, and nothing a value can be read from."""
    mark = (item.get("fingerprint") or "")[:6]
    text = "%s|%s|%s|%s" % (item["file"], item["rule"], item.get("name") or "", mark)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def scan(root, max_bytes=MAX_FILE_BYTES, show_fingerprints=False, ids=None):
    """Scan a folder. `ids`, when a list is given, is filled with one opaque id per finding (see
    finding_id) - used to tell what is new since the last run without keeping any value."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("Path is not an existing directory: %s" % root)
    patterns, prints = load_ignores(root)
    findings = []
    stats = {"files_scanned": 0, "skipped_binary": 0, "skipped_large": 0, "skipped_unreadable": 0, "skipped_ignored": 0}
    for base, dirs, names in os.walk(root, followlinks=False):
        base_path = Path(base)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (base_path / d).is_symlink())
        for name in sorted(names):
            path = base_path / name
            rel = path.relative_to(root).as_posix()
            if name == IGNORE_FILE:
                continue
            if path_ignored(rel, patterns):
                stats["skipped_ignored"] += 1
                continue
            if path.is_symlink() or not path.is_file():
                continue
            note = sensitive_filename(name)
            if note:
                findings.append({"file": rel, "line": 0, "rule": "sensitive-file", "severity": "low",
                                 "description": note, "name": None, "fingerprint": None, "length": None,
                                 "example_like": False})
                if ids is not None:
                    ids.append(finding_id(findings[-1]))
            if path.suffix.lower() in SKIP_SUFFIXES:
                stats["skipped_binary"] += 1
                continue
            try:
                if path.stat().st_size > max_bytes:
                    stats["skipped_large"] += 1
                    continue
                raw = path.read_bytes()
            except OSError:
                stats["skipped_unreadable"] += 1
                continue
            text = decode_bytes(raw)
            if text is None:
                stats["skipped_binary"] += 1
                continue
            stats["files_scanned"] += 1
            config_like = path.suffix.lower() in CONFIG_SUFFIXES or name.lower().startswith(".env")
            for item in scan_text(text, config_like):
                if item["fingerprint"] and item["fingerprint"] in prints:
                    continue
                item["file"] = rel
                if ids is not None:
                    ids.append(finding_id(item))
                if not show_fingerprints:      # ids are opt-in; ignore-file matching above still works
                    item["fingerprint"], item["length"] = None, None
                findings.append(item)
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in LEVELS}
    return {"tool": "Secret Map", "version": VERSION, "root": str(root), "stats": stats, "counts": counts,
            "rules": len(PROVIDER_RULES) + 2, "findings": findings,
            "note": "No match does not prove a folder is free of secrets."}


def render_text(report, fail_on):
    stats, counts = report["stats"], report["counts"]
    skipped = stats["skipped_binary"] + stats["skipped_large"] + stats["skipped_unreadable"] + stats["skipped_ignored"]
    lines = ["Secret Map v%s" % report["version"],
             "Scanned %d files (%d skipped: %d binary, %d too large, %d unreadable, %d ignored)"
             % (stats["files_scanned"], skipped, stats["skipped_binary"], stats["skipped_large"],
                stats["skipped_unreadable"], stats["skipped_ignored"]),
             "Findings: high %d  medium %d  low %d" % (counts["high"], counts["medium"], counts["low"]), ""]
    for f in report["findings"]:
        where = "%s:%d" % (f["file"], f["line"]) if f["line"] else f["file"]
        detail = f["description"]
        if f["name"]:
            detail += " [%s]" % f["name"]
        if f["fingerprint"]:
            detail += " (len %d, id %s)" % (f["length"], f["fingerprint"])

        if f["example_like"]:
            detail += " - looks like a documentation example"
        lines.append("%-6s %s  %s: %s" % (f["severity"].upper(), where, f["rule"], detail))
    if not report["findings"]:
        lines.append("No known secret pattern matched in %d files." % stats["files_scanned"])
    if stats["files_scanned"] == 0:
        lines.append("WARNING: nothing was scanned. Check the path.")
    lines += ["", "Values are never shown. A clean result does not prove the folder is free of secrets.",
              "Treat this report as sensitive: it tells a reader exactly where your secrets are."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- what is new since the last run

def state_dir():
    """Where the last run of each folder is remembered: SECRET_MAP_HOME, else ~/.secret-map."""
    return Path(os.environ.get("SECRET_MAP_HOME") or (Path.home() / ".secret-map"))


def state_path(root):
    name = hashlib.sha256(os.path.normcase(str(Path(root).resolve())).encode("utf-8", "replace")).hexdigest()[:16]
    return state_dir() / "last-runs" / (name + ".json")


def load_last(root):
    """The ids of the previous run of this folder as {id: count}, or None when there was none."""
    try:
        data = json.loads(state_path(root).read_text(encoding="utf-8"))
        ids = data.get("ids")
        return ids if isinstance(ids, dict) else None
    except (OSError, ValueError, AttributeError):
        return None


def save_last(root, ids):
    """Remember this run: ids and counts only - no value, no file name, no path. Best effort."""
    counts = {}
    for one in ids:
        counts[one] = counts.get(one, 0) + 1
    try:
        path = state_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".tmp")
        temp.write_text(json.dumps({"tool": "Secret Map", "version": VERSION, "ids": counts}, sort_keys=True),
                        encoding="utf-8")
        os.replace(str(temp), str(path))
        return True
    except OSError:
        return False


def count_new(ids, previous):
    """How many findings of this run were not there in the previous run."""
    left = dict(previous)
    new = 0
    for one in ids:
        if left.get(one, 0) > 0:
            left[one] -= 1
        else:
            new += 1
    return new


def closing_line(findings, new=None):
    """One closing line with the real numbers, or None when there is no finding at all.

    `new` is the number of findings that were not there on the last run - known only when the
    user asked for --remember and there was a last run."""
    if new:
        return "%d new since last run. Baseline diff and the HTML report are in Pro." % new
    if not findings:
        return None
    return "%d finding%s. Pro can save a baseline and show only the new ones next run." % (
        findings, "" if findings == 1 else "s")


def safe_stdio():
    """Never crash on a console that cannot show a character (cp949, ascii): replace it instead."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and (stream.encoding or "").lower().replace("-", "").replace("_", "") != "utf8":
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv=None):
    safe_stdio()
    parser = argparse.ArgumentParser(prog="secret_map", description="Offline, read-only scan for leaked credentials.")
    parser.add_argument("folder")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--fail-on", choices=LEVELS, default="medium",
                        help="lowest severity that makes the exit code 1 (default: medium)")
    parser.add_argument("--max-size", type=int, default=MAX_FILE_BYTES, help="skip files larger than this many bytes")
    parser.add_argument("--fingerprints", action="store_true",
                        help="show a short one-way id for long random values (off by default; see README)")
    parser.add_argument("--remember", action="store_true",
                        help="remember this run under ~/.secret-map so the next run can say what is new (see README)")
    parser.add_argument("--version", action="version", version="Secret Map " + VERSION)
    args = parser.parse_args(argv)
    ids = []
    try:
        report = scan(args.folder, args.max_size, args.fingerprints, ids=ids)
    except (OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    rendered = json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report, args.fail_on)
    try:
        print(rendered)
    except UnicodeEncodeError:
        sys.stdout.buffer.write((rendered + "\n").encode("utf-8", "replace"))
    new = None
    if args.remember and report["stats"]["files_scanned"]:   # off unless asked: by default nothing is ever written
        previous = load_last(report["root"])
        new = count_new(ids, previous) if previous is not None else None
        save_last(report["root"], ids)
    line = closing_line(len(report["findings"]), new)
    if line:                                       # after the report; on stderr with --json so the JSON stays clean
        sys.stdout.flush()
        print(("\n" if not args.json else "") + line, file=sys.stderr if args.json else sys.stdout)
    threshold = LEVELS.index(args.fail_on)
    if report["stats"]["files_scanned"] == 0:
        return 2
    return 1 if any(LEVELS.index(f["severity"]) >= threshold for f in report["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
