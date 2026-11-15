# Changelog

## 1.0.4
- New closing line when a scan has findings: `N findings. Pro can save a baseline and show only the new ones
  next run.` Nothing is added when there is no finding. With `--json` it goes to stderr.
- New `--remember` (off by default): saves one opaque id per finding and a count under `~/.secret-map/last-runs/`
  (or `SECRET_MAP_HOME`) - no value, no file name, no path - so the next `--remember` run of the same folder can
  end with `N new since last run.` A finding that only moved to another line is not new; a changed value is.
- Without `--remember` the tool still writes nothing at all. The scanned folder is only read either way.
- Tests: 46 (was 29).

## 1.0.3
- BOM-less UTF-16 files that are mostly Korean (or another script without zero bytes) are now scanned. 1.0.2 only
  looked at the share of zero bytes and skipped such files as binary. The byte order is now picked from the zero
  bytes and the file is accepted only if decoding gives almost no control or unassigned characters.
- Test files no longer contain any complete key-shaped string. Every fake key is assembled from fragments while the
  tests run, so public push protection does not trip. A new test scans this package with Secret Map itself and
  requires zero findings.
- Console output never crashes on a console that cannot show a character (for example cp949 or ASCII); such
  characters are replaced. Values are still never printed.
- Tests: 29 (was 24). Every fix above has its own regression test.

## 1.0.2
- UTF-16 files are now scanned (with a BOM, or without one when the byte pattern is unambiguous).
  Windows PowerShell 5.1 writes UTF-16 when output is redirected with `>`; such files were skipped as binary.
- Sensitive file names: added `token.json`, `tokens.json`, `token.pickle`, `client_secret*.json`,
  service-account JSON files, `.npmrc`, `.pypirc`.
- Fingerprint ids are off by default; `--fingerprints` turns them on. `.secretmapignore` fingerprint lines still work.
- Added Notion integration tokens (`ntn_...`, `secret_...`).
- README: sample output is real tool output; removed wording that could read as a guarantee of secrecy;
  Windows UTF-8 note; tested-versions list names only what was actually run.

## 1.0.1
- Ids and lengths are no longer produced for short or guessable values (a hash of an ordinary password
  can be reversed with a word list).

## 1.0.0
- First release.
