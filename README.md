# Secret Map

*Part of the [Vivaminima tools](https://github.com/vivaminima) for Claude Code users.*

<img src="https://raw.githubusercontent.com/vivaminima/vivaminima/main/img/run/secret-map.png" width="760" alt="secret-map: real output of the free version on a made-up sample">

**Install in Claude Code:** `/plugin install secret-map --marketplace vivaminima/vivaminima`

See where API keys and passwords are sitting in a folder. The report shows locations, not values.

## New to this? Start here

**Who it's for:** you let Claude work inside your folders, and you're not sure whether an API key or password is sitting in some file — one you might upload, share or zip up for someone. Secret Map lists *where* they are. It never prints the values.

**You don't need to know Python or the terminal.** Claude runs it for you.

1. Open the **Claude desktop app → Code tab** (Claude Code) and pick the project folder you want to check.
2. Download this repository (green **Code** button → **Download ZIP**) and unzip it anywhere.
3. Type the sentence below to Claude, with the path to the unzipped folder. Claude runs the script and explains the result in plain words.
4. If Claude says Python is missing, ask: *"Install Python 3 for me, step by step."*

> *"Run secret_map.py from the secret-map folder on this project and tell me which files hold keys or passwords, without showing the values."*

What you get back: a list like `HIGH config/.env:2 openai-api-key`. Then you decide: move it, delete it, or keep it out of what you share.

One Python file. No dependencies. Works offline. Read-only.

```
python secret_map.py path/to/project
```

Real output from a small demo folder with made-up keys (exit code 1):

```
Secret Map v1.0.3
Scanned 5 files (0 skipped: 0 binary, 0 too large, 0 unreadable, 0 ignored)
Findings: high 2  medium 2  low 2

LOW    config/.env  sensitive-file: Environment file (make sure it is not committed or shipped)
HIGH   config/.env:2  openai-api-key: OpenAI API key
MEDIUM config/.env:3  secret-assignment: Secret-like value assigned to a secret-named variable [MYAPP_CLIENT_SECRET]
HIGH   deploy.sh:2  url-with-password: Password inside a connection URL
MEDIUM src/settings.py:3  secret-assignment: Secret-like value assigned to a secret-named variable [DB_PASSWORD]
LOW    token.json  sensitive-file: Key or credential file

Values are never shown. A clean result does not prove the folder is free of secrets.
Treat this report as sensitive: it tells a reader exactly where your secrets are.
```

### Optional ids

`--fingerprints` adds a short one-way id to long, random-looking values, so you can tell that two
findings are the same key:

```
HIGH   config/.env:2  openai-api-key: OpenAI API key (len 56, id 8da0c0e99618)
```

It is off by default. An id lets anyone who already holds a candidate value confirm it, so share such a
report with care. Short or human-chosen values (ordinary passwords) never get an id or a length, because
a hash of a guessable value can be reversed with a word list.

## What it finds

- **Provider formats** (high): OpenAI, Anthropic, GitHub, GitLab, Slack tokens and webhooks, Stripe, Google,
  AWS access key IDs, SendGrid, Notion, npm, PyPI, Hugging Face, DigitalOcean, Telegram, Discord webhooks,
  private key blocks, passwords inside connection URLs. JSON Web Tokens are reported as medium.
- **Secret-named assignments** (medium): a random-looking value assigned to a name containing
  `secret`, `token`, `password`, `api_key`, `access_key`, `credential` and similar — including prefixed
  names such as `OPENAI_API_KEY`, `STRIPE_SECRET` or `MYAPP_CLIENT_SECRET`.
- **Sensitive files** (low): `.env`, `id_rsa`, `*.pem`, `*.p12`, `credentials.json`, `token.json`,
  `client_secret*.json`, `.npmrc` and similar.

It stays quiet on placeholders (`your-key-here`, `${API_KEY}`, `changeme`), on references
(`os.environ[...]`, `process.env.X`) and on ordinary code such as `max_tokens: 4096`.

## Ignoring known findings

- Add `secretmap:ignore` as a comment on the line.
- Or create `.secretmapignore` in the scanned folder (`fingerprint:` lines take an id from `--fingerprints`):

```
# test fixtures
tests/fixtures/
*.snapshot
fingerprint:50d783eecb15
```

## Options and exit codes

```
--json               machine-readable report
--fail-on LEVEL      low | medium | high   (default: medium)
--max-size BYTES     skip larger files (default 2 MiB)
--fingerprints       show one-way ids for long random values (off by default)
--remember           save this run's finding ids under ~/.secret-map, to say what is new next time
```

`0` nothing at or above the level, `1` findings, `2` bad path **or nothing was scanned**.
An empty or unreadable folder is never reported as clean.

## The closing line, and `--remember`

When a scan has findings, the report ends with one line that says how many, for example
`3 findings. Pro can save a baseline and show only the new ones next run.` With no finding, nothing is added.
With `--json` the line goes to stderr, so the JSON stays clean.

By default this tool writes nothing, anywhere. `--remember` is the one exception, and only when you ask for it:
it saves one opaque id per finding and a count - **no value, no file name, no path** - in
`~/.secret-map/last-runs/` (or under the folder named by the `SECRET_MAP_HOME` environment variable), so that
the next `--remember` run of the same folder can end with `N new since last run.` The folder you scan is only
read either way. Deleting `~/.secret-map` forgets everything.

## Limits — read this

- The report is not a secret-safe document. It lists the exact file and line of every finding.
  Do not post reports publicly.
- Files saved as UTF-16 are read, with or without a BOM. A BOM-less UTF-16 file with no ASCII at all (not one
  space, digit or line break) cannot be told apart from binary and is skipped as binary.

## Windows

Use UTF-8 mode so non-English text prints correctly in the console:

```
python -X utf8 secret_map.py path/to/project
```

## Requirements and what was tested

Python 3 standard library only - nothing to install.

- Tested: Windows 11, Python 3.10.11 (this release, 46 tests, including a cp949 console run).
- Version 1.0.2 was tested on Linux, Python 3.13; 1.0.0 was also run on Windows with Python 3.10 by an independent reviewer.
- Other versions and platforms have not been tested.

Run the tests yourself with `python -m unittest discover -s tests`.

MIT licence. See CHANGELOG.md for what changed.

## More from Vivaminima

- **Secret Map Pro ($19)**, the paid edition of this tool, one-time payment on Gumroad: https://vivastory4.gumroad.com/l/secret-map-pro

  <a href="https://vivastory4.gumroad.com/l/secret-map-pro"><img src="https://raw.githubusercontent.com/vivaminima/vivaminima/main/img/secret-map.png" width="480" alt="Secret Map Pro"></a>

- **Token Audit Kit ($19)** — see how many tokens your CLAUDE.md and its @imports cost before your first prompt, and a step-by-step guide to split it. Free script: https://github.com/vivaminima/context-file-audit · Paid kit (store): https://vivastory4.gumroad.com
- Free tools: [skill-audit-kit](https://github.com/vivaminima/skill-audit-kit) · [secret-map](https://github.com/vivaminima/secret-map) · [inbox-ledger](https://github.com/vivaminima/inbox-ledger) · [release-gate](https://github.com/vivaminima/release-gate) · [skill-install-gate](https://github.com/vivaminima/skill-install-gate) · [console-safe](https://github.com/vivaminima/console-safe) · [checklist-stop](https://github.com/vivaminima/checklist-stop) · [handoff-check](https://github.com/vivaminima/handoff-check) · [llm-budget-router-lite](https://github.com/vivaminima/llm-budget-router-lite) · [go-no-go-verdict-skill](https://github.com/vivaminima/go-no-go-verdict-skill) · [ai-company-starter-kit](https://github.com/vivaminima/ai-company-starter-kit) · [beginner-readme-section](https://github.com/vivaminima/beginner-readme-section)

Vivaminima is not affiliated with, endorsed by or sponsored by Anthropic.
