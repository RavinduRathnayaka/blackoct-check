#!/usr/bin/env python3
"""
blackoct-tui - full-screen terminal interface for blackoct_check.py

    python3 blackoct_check.py --tui                       # open the TUI
    python3 blackoct_check.py --tui example.com git.example.com
    python3 blackoct_check.py --tui -l domains.txt --run --yes
    python3 blackoct_tui.py ...                           # same thing, direct

Needs one extra package:  pip install textual   (Linux, macOS and Windows)
Keep blackoct_check.py in the same folder. Python 3.9+.

Use only against assets you own or are authorised to test.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import sys
import threading
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import blackoct_check as bc
except ImportError:  # pragma: no cover
    sys.exit("error: blackoct_check.py must be in the same folder as blackoct_tui.py")

try:
    from rich.text import Text
    from textual import work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input, Label,
                                 Markdown, ProgressBar, SelectionList, Static, TabbedContent,
                                 TabPane, TextArea)
    from textual.widgets.selection_list import Selection
except ImportError:  # pragma: no cover
    sys.exit("The TUI needs the 'textual' package.  Install it with:  pip install textual")

SEV_STYLE = {
    "CRITICAL": "bold white on red3", "HIGH": "bold red", "MEDIUM": "bold yellow",
    "LOW": "bold cyan", "INFO": "bold blue", "OK": "bold green",
}
FILTERS = [("Everything", 0), ("Info+", 1), ("Low+", 2), ("Medium+", 3), ("High+", 4), ("Critical", 5)]

CHECK_LABELS = {
    "php": "PHP2Shell      CVE-2026-109618/9",
    "node": "Node.js        Oct 2026 releases",
    "gitlab": "GitLab         CVE-2026-110264",
    "litellm": "LiteLLM        malicious 1.107.0",
    "emudhra": "eMudhra TLS    8 bad intermediates",
    "hosting": "Hosting        Railway / Zeabur",
}

USAGE_MD = """\
# Usage guide

## Quick start
1. Type or paste **targets** in the left box, one per line. Domains, host:port and URLs all work.
2. Leave the **checks** you want ticked. Move with the arrow keys, toggle with Space.
3. Tick **I am authorised**. This is required before any scan starts.
4. Press **F5** (or the Start button). Results fill the table as each target finishes.
5. Move through the table with the arrow keys. The panel underneath shows the evidence and the fix.
6. Press **F2** to save the report as JSON and CSV in the current folder.

## Keys
- **F5** or **Ctrl+R**: start a scan
- **F6**: cancel the running scan
- **F1**: switch between this guide and the results
- **F2**: export JSON and CSV
- **F3**: cycle the severity filter (Everything, Info+, Low+, Medium+, High+, Critical)
- **F4**: show or hide OK results
- **Tab / Shift+Tab**: move between form fields. **F10** or **Ctrl+Q**: quit
- Everything is also clickable with the mouse. If your terminal grabs the F-keys (some macOS setups), use Ctrl+R and the buttons.

## What each check does
- **PHP2Shell**: reads the PHP version from response headers and compares it with the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older are end of life. Banner only: hidden headers give no result, and distro backports keep the old version string.
- **Node.js**: looks for a Node version in headers and compares it with 22.23.4, 24.22.1 and 26.12.1. Node rarely exposes its version, so expect "verify on host".
- **GitLab**: detects a GitLab sign-in page and reads the version from /help, or from the API if you give a token. Fixed releases: 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10, 18.11.13. Servers patched on 12 Oct are still vulnerable.
- **LiteLLM**: looks for a public LiteLLM proxy running the compromised 1.107.0 release.
- **eMudhra TLS**: fetches the certificate chain and flags eMudhra or emSign issuers. Python 3.10 or newer returns the full chain.
- **Hosting**: fingerprints Railway and Zeabur so you know to rotate secrets held there.

Not detectable from outside: the California schools, Ahold Delhaize and Onamae incidents, and anything inside the Railway or Zeabur platforms.

## Reading severities
- **CRITICAL**: confirmed vulnerable or compromised version. Act now.
- **HIGH**: version below the fixed release, end of life, or a distrusted CA root. Patch, then confirm the real package version.
- **MEDIUM**: software present but version unreadable, or an eMudhra chain to review.
- **INFO**: version hidden, provider fingerprint, unreachable target, or a check that could not run.
- **OK**: checked, nothing found (hidden by default, F4 shows it).

Banner findings are indicators, not proof. Linux distributions backport fixes without changing the version string, so confirm on the host, for example with `apt list --installed 'php*'` or `rpm -q php`, then restart PHP workers.

## Command line
- `python3 blackoct_check.py example.com` plain CLI report
- `python3 blackoct_check.py -l domains.txt -c 20 -f json -o report.json` bulk scan to a file
- `python3 blackoct_check.py --tui -l domains.txt --run --yes` open the TUI and start immediately
- `--proxy http://127.0.0.1:8080` routes web requests through ZAP or Burp (the TLS chain check connects directly)

Exit codes for the plain CLI: 0 clean, 2 a finding at or above `--fail-on`, 1 usage error.

## Targets and troubleshooting
- Targets can be a bare name (`example.com`), `host:port`, a full URL (`http://10.0.0.5:8080`), a URL with a path prefix (`http://host/gitlab`), or IPv6 (`[::1]:8443`). Plain HTTP works.
- With no scheme it tries HTTPS then HTTP, or HTTP first on ports such as 8080. Same-host redirects are followed. A redirect to a name that does not resolve still counts as reachable.
- **Target unreachable**: the finding lists every URL tried and the error for each. Check DNS, the port, firewalls and the proxy, or give the scheme and port explicitly.
- **Version hidden**: the server strips its banner, so check the version on the host.

## Safety
The checks send ordinary GET requests and one TLS handshake per host and never send exploit payloads. Only scan systems you own or have written permission to test.
"""


def parse_targets(text: str) -> List[str]:
    seen, out = set(), []
    for t in text.replace(",", " ").split():
        if t and not t.startswith("#") and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:500]


def sev_text(sev: str) -> Text:
    return Text(f" {sev:<8} ", style=SEV_STYLE.get(sev, ""))


class BlackOctTUI(App):
    TITLE = "Black October Checker"
    SUB_TITLE = "passive exposure checks - authorised targets only"

    CSS = """
    #side { width: 48; border-right: tall $primary-background; }
    #form { height: 1fr; padding: 0 1; }
    #actions { height: auto; padding: 0 1; border-top: tall $primary-background; }
    #main { padding: 0 1; }
    .lbl { color: $text-muted; margin-top: 1; height: 1; }
    #side Input { height: 1; border: none; padding: 0 1; background: $surface-lighten-1; }
    #side Input:focus { background: $primary-darken-1; }
    #targets { height: 6; }
    #checks { height: 8; }
    #timeout, #conc { width: 1fr; }
    #nums { height: auto; }
    #buttons { height: auto; }
    #buttons Button { margin-right: 1; }
    #statusline { height: 1; }
    #summary { height: 1; margin-bottom: 1; }
    #bar { margin-bottom: 1; }
    #table { height: 1fr; min-height: 5; }
    #detailbox { height: 45%; min-height: 8; border: round $primary; padding: 0 1; margin-top: 1; }
    #help { padding: 0 1; }
    """

    BINDINGS = [
        Binding("f5", "run", "Run"),
        Binding("ctrl+r", "run", "Run", show=False, priority=True),
        Binding("f6", "cancel", "Cancel"),
        Binding("f1", "toggle_help", "Help"),
        Binding("f2", "export", "Export"),
        Binding("f3", "cycle_filter", "Filter"),
        Binding("f4", "toggle_ok", "OK on/off"),
        Binding("f10", "quit", "Quit"),
    ]

    def __init__(self, cli_args) -> None:
        super().__init__()
        self.cli = cli_args
        self.results: Dict[str, List[bc.Finding]] = {}
        self.rows: List[bc.Finding] = []
        self.order: List[str] = []
        self.total = 0
        self.done = 0
        self.running = False
        self.cancelled = False
        self.scanned = False
        self._futs: List[cf.Future] = []
        self.filter_idx = 1
        self.show_ok = False
        self.started = 0.0

    # ---- layout -------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="side"):
                with VerticalScroll(id="form"):
                    yield Label("Targets (one per line)", classes="lbl")
                    yield TextArea(id="targets", placeholder="example.com\ngit.example.com")
                    yield Label("Checks (Space toggles)", classes="lbl")
                    yield SelectionList[str](*[Selection(CHECK_LABELS[c], c, True) for c in bc.ALL_CHECKS], id="checks")
                    with Horizontal(id="nums"):
                        with Vertical():
                            yield Label("Timeout s", classes="lbl")
                            yield Input(value=str(int(self.cli.timeout)), id="timeout", type="number")
                        with Vertical():
                            yield Label("Parallel", classes="lbl")
                            yield Input(value=str(self.cli.concurrency), id="conc", type="integer")
                    yield Label("HTTP proxy (optional)", classes="lbl")
                    yield Input(value=self.cli.proxy or "", id="proxy", placeholder="http://127.0.0.1:8080")
                    yield Label("GitLab token (optional)", classes="lbl")
                    yield Input(value=self.cli.gitlab_token or "", id="gltoken", password=True,
                                placeholder="reads exact GitLab version")
                    yield Checkbox("Verify TLS certificates", self.cli.verify_tls, id="verify")
                with Vertical(id="actions"):
                    yield Checkbox("I am authorised to test these targets", bool(self.cli.yes), id="auth")
                    with Horizontal(id="buttons"):
                        yield Button("Start (F5)", id="start", variant="success")
                        yield Button("Cancel (F6)", id="cancel", variant="error", disabled=True)
            with Vertical(id="main"):
                yield Static("", id="statusline")
                yield ProgressBar(total=100, show_eta=False, id="bar")
                yield Static("", id="summary")
                with TabbedContent(initial="results-tab", id="tabs"):
                    with TabPane("Results", id="results-tab"):
                        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
                        with VerticalScroll(id="detailbox"):
                            yield Static("", id="detail")
                    with TabPane("Usage guide (F1)", id="help-tab"):
                        with VerticalScroll(id="help"):
                            yield Markdown(USAGE_MD)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_column("Severity", key="sev", width=12)
        table.add_column("Target", key="target", width=30)
        table.add_column("Check", key="check", width=9)
        table.add_column("Finding", key="title")
        try:
            pre = bc.load_targets(self.cli)
        except OSError as e:
            pre = []
            self.notify(f"Could not read target list: {e.strerror}", severity="error")
        self.query_one("#targets", TextArea).text = "\n".join(pre)
        chosen = [x.strip().lower() for x in self.cli.checks.split(",") if x.strip()]
        skip = {x.strip().lower() for x in self.cli.skip.split(",") if x.strip()}
        sl = self.query_one("#checks", SelectionList)
        for c in bc.ALL_CHECKS:
            if c in chosen and c not in skip:
                sl.select(c)
            else:
                sl.deselect(c)
        self.set_status("Ready. Add targets, tick the authorisation box, press F5.")
        self.refresh_summary()
        self.show_detail(None)
        if self.cli.run:
            if self.cli.yes and pre:
                self.call_after_refresh(self.action_run)
            else:
                self.notify("--run needs targets and --yes (authorisation).", severity="warning")

    # ---- helpers ------------------------------------------------------------
    def set_status(self, msg: str, bad: bool = False) -> None:
        self.query_one("#statusline", Static).update(Text(msg, style="bold red" if bad else ""))

    def make_args(self, checks: List[str]):
        a = bc.build_parser().parse_args(["placeholder"])
        a.checks = checks
        try:
            a.timeout = min(60.0, max(1.0, float(self.query_one("#timeout", Input).value or 8)))
        except ValueError:
            a.timeout = 8.0
        a.proxy = self.query_one("#proxy", Input).value.strip() or None
        a.gitlab_token = self.query_one("#gltoken", Input).value.strip() or None
        a.verify_tls = self.query_one("#verify", Checkbox).value
        a.header = self.cli.header or []
        return a

    def refresh_summary(self) -> None:
        cnt = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in self.rows:
            if f.severity in cnt:
                cnt[f.severity] += 1
        t = Text()
        for k, v in cnt.items():
            t.append(f" {k} {v} ", style=SEV_STYLE[k] if v else "dim")
            t.append(" ")
        name, _ = FILTERS[self.filter_idx]
        t.append(f"  filter: {name}  OK: {'shown' if self.show_ok else 'hidden'}", style="dim")
        self.query_one("#summary", Static).update(t)

    def rebuild_table(self) -> None:
        table = self.query_one("#table", DataTable)
        keep = None
        try:
            if table.row_count:
                keep = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:  # noqa: BLE001
            keep = None
        table.clear()
        floor = FILTERS[self.filter_idx][1]
        order = sorted(range(len(self.rows)), key=lambda i: -bc.SEV[self.rows[i].severity])
        for i in order:
            f = self.rows[i]
            if f.severity == "OK":
                if not self.show_ok:
                    continue
            elif bc.SEV[f.severity] < floor:
                continue
            title = f.title if len(f.title) <= 110 else f.title[:107] + "..."
            table.add_row(sev_text(f.severity), Text(f.target), Text(f.check), Text(title), key=str(i))
        if keep is not None:
            try:
                table.move_cursor(row=table.get_row_index(keep))
            except Exception:  # noqa: BLE001
                pass
        if table.row_count == 0:
            self.show_detail(None)
        self.refresh_summary()

    def show_detail(self, f: Optional[bc.Finding]) -> None:
        d = self.query_one("#detail", Static)
        if f is None:
            msg = "Select a finding to see the evidence and the fix." if self.rows or self.running else \
                  "No scan yet. Add targets on the left, tick the authorisation box, then press F5.\nPress F1 for the usage guide."
            d.update(Text(msg, style="dim"))
            return
        t = Text()
        t.append(f" {f.severity} ", style=SEV_STYLE.get(f.severity, ""))
        t.append("  " + f.title + "\n\n", style="bold")
        for label, val in (("Target", f.target), ("Check", f.check), ("Reference", f.cve),
                           ("Evidence", f.evidence), ("Confidence", f.confidence)):
            if val:
                t.append(f"{label:<11}", style="dim")
                t.append(val + "\n")
        if f.detail:
            t.append("\n" + f.detail + "\n")
        d.update(t)

    # ---- events -------------------------------------------------------------
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        try:
            self.show_detail(self.rows[int(event.row_key.value)])
        except (TypeError, ValueError, IndexError):
            self.show_detail(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self.action_run()
        elif event.button.id == "cancel":
            self.action_cancel()

    # ---- actions ------------------------------------------------------------
    def action_run(self) -> None:
        if self.running:
            return
        targets = parse_targets(self.query_one("#targets", TextArea).text)
        checks = list(self.query_one("#checks", SelectionList).selected)
        if not targets:
            self.set_status("Enter at least one target.", True)
            return
        if not checks:
            self.set_status("Select at least one check.", True)
            return
        if not self.query_one("#auth", Checkbox).value:
            self.set_status("Tick the authorisation box first.", True)
            self.query_one("#auth", Checkbox).focus()
            return
        try:
            conc = min(50, max(1, int(self.query_one("#conc", Input).value or 10)))
        except ValueError:
            conc = 10
        args = self.make_args(checks)
        self.results, self.rows, self.order = {}, [], targets
        self.total, self.done = len(targets), 0
        self.running, self.cancelled, self.scanned = True, False, True
        self.started = time.time()
        self.query_one("#bar", ProgressBar).update(total=self.total, progress=0)
        self.query_one("#start", Button).disabled = True
        self.query_one("#cancel", Button).disabled = False
        self.query_one("#tabs", TabbedContent).active = "results-tab"
        self.rebuild_table()
        self.show_detail(None)
        self.set_status(f"Scanning 0 of {self.total}...")
        self.scan_worker(targets, args, conc)

    @work(thread=True, exclusive=True)
    def scan_worker(self, targets: List[str], args, conc: int) -> None:
        with cf.ThreadPoolExecutor(max_workers=conc) as ex:
            futs = {ex.submit(bc.scan_target, t, args): t for t in targets}
            self._futs = list(futs)
            for fut in cf.as_completed(futs):
                t = futs[fut]
                try:
                    res = fut.result()
                except cf.CancelledError:
                    continue
                except Exception as e:  # noqa: BLE001
                    res = [bc.Finding(t, "scan", "INFO", f"Scan error: {e}")]
                self.call_from_thread(self.on_target_done, t, res)
        self.call_from_thread(self.on_scan_finished)

    def on_target_done(self, target: str, res: List[bc.Finding]) -> None:
        self.results[target] = res
        self.rows.extend(res)
        self.done += 1
        self.query_one("#bar", ProgressBar).update(progress=self.done)
        self.set_status(f"Scanning {self.done} of {self.total}  ({time.time() - self.started:.0f}s)")
        self.rebuild_table()

    def on_scan_finished(self) -> None:
        self.running = False
        self.query_one("#start", Button).disabled = False
        self.query_one("#cancel", Button).disabled = True
        secs = time.time() - self.started
        self.set_status(("Cancelled after " if self.cancelled else f"Finished {self.total} target(s) in ") + f"{secs:.1f}s.  F2 exports the report.")
        self.rebuild_table()
        table = self.query_one("#table", DataTable)
        if table.row_count:
            table.focus()
        else:
            self.show_detail(None)
            d = self.query_one("#detail", Static)
            d.update(Text("Nothing at this filter level. Press F3 to lower the filter or F4 to show OK results.", style="dim"))

    def action_cancel(self) -> None:
        if not self.running:
            return
        self.cancelled = True
        for f in self._futs:
            f.cancel()
        self.set_status("Cancelling, waiting for running requests to finish...")

    def action_toggle_help(self) -> None:
        # TabbedContent follows focus, so focus must move into the destination
        # tab or the old focused widget pulls the view straight back.
        tabs = self.query_one("#tabs", TabbedContent)
        if tabs.active == "help-tab":
            tabs.active = "results-tab"
            self.call_after_refresh(self.query_one("#table", DataTable).focus)
        else:
            tabs.active = "help-tab"
            self.call_after_refresh(self.query_one("#help", VerticalScroll).focus)

    def action_cycle_filter(self) -> None:
        self.filter_idx = (self.filter_idx + 1) % len(FILTERS)
        self.rebuild_table()

    def action_toggle_ok(self) -> None:
        self.show_ok = not self.show_ok
        self.rebuild_table()

    def action_export(self) -> None:
        if not self.results:
            self.notify("Nothing to export yet. Run a scan first.", severity="warning")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        ordered = {t: self.results[t] for t in self.order if t in self.results}
        try:
            with open(f"blackoct-{stamp}.json", "w", encoding="utf-8") as fh:
                fh.write(bc.render_json(ordered))
            with open(f"blackoct-{stamp}.csv", "w", encoding="utf-8", newline="") as fh:
                fh.write(bc.render_csv(ordered))
        except OSError as e:
            self.notify(f"Export failed: {e.strerror}", severity="error")
            return
        self.notify(f"Saved blackoct-{stamp}.json and .csv in the current folder.", title="Exported")


def run(args) -> int:
    app = BlackOctTUI(args)
    app.run()
    if args.fail_on != "never" and app.scanned and app.results:
        lim = bc.SEV[args.fail_on.upper()]
        if any(bc.SEV[f.severity] >= lim for fs in app.results.values() for f in fs):
            return 2
    return 0


def main(argv=None) -> int:
    args = bc.build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
