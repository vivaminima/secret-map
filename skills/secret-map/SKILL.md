---
name: secret-map
description: Maps where API keys, passwords and tokens sit in a project without showing their values. Use when the user asks, for example, "where are my keys", "find secrets in this project", "secret map", "키가 어디 있는지 찾아 줘".
---

# secret-map

Maps where API keys, passwords and tokens sit in a project without showing their values. A small Python tool shipped in this plugin: standard library only, nothing to install, runs locally.

## Run

Use `python` (Windows: `py -3` also works; macOS/Linux: `python3`). On Windows add `-X utf8` if the console shows broken characters.

    python "${CLAUDE_PLUGIN_ROOT}/secret_map.py" <project-folder>

Run it from the user's project folder and pass the path they mean. If no path is given, ask which folder or file to check.

## Read the result

Values are masked by design. Never print or copy a full value, even if the user asks; point to the file and line instead.

Show the tool's own output (shortened if long) and then a two- or three-line summary. Do not change the user's files unless they ask.
