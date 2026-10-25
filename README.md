# blackoct-check

Non-intrusive exposure checker for the "Black October" 2026 disclosure wave.
It sends ordinary GET requests (plus one TLS handshake per host) and **never sends exploit payloads**.

> Use only against assets you own or are authorised to test.

## Checks

| Check | What it looks for |
|-------|-------------------|
| `php` | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 (banner version compare) |
| `node` | Node.js Oct 2026 security releases (banner version) |
| `gitlab` | GitLab CVE-2026-110264 (instance detection, version via `/help` or API token) |
| `litellm` | LiteLLM proxy running the malicious 1.107.0 release |
| `emudhra` | TLS chain issued under eMudhra / emSign (8 compromised intermediates) |
| `hosting` | Hosted on Railway / Zeabur (provider-side incidents, rotate secrets) |

Provider/data breaches (California schools, Ahold Delhaize, Onamae, Railway/Zeabur internals) are not remotely detectable; only hosting fingerprints are reported.

## Files

- `blackoct_check.py` - command-line checker (Python 3.8+, standard library only)
- `blackoct_gui.py` - local web interface, bound to 127.0.0.1 with a per-run token
- `blackoct_tui.py` - full-screen terminal interface (`pip install textual`, Python 3.9+)

Keep all three files in the same folder.

## Usage

```bash
python3 blackoct_check.py --help
python3 blackoct_check.py example.com git.example.com
python3 blackoct_check.py --tui          # terminal UI
python3 blackoct_gui.py                  # opens the browser UI
```

## Install (optional TUI)

```bash
pip install -r requirements.txt
```

## License

MIT, see `LICENSE`.
