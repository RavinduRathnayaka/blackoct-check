#!/usr/bin/env python3
"""
blackoct-check - exposure checker for the "Black October" 2026 disclosure wave.

Non-intrusive, fingerprint and version based. It sends ordinary GET requests
(plus one TLS handshake per host) and NEVER sends exploit payloads.

Checks
  php      PHP2Shell, CVE-2026-109618 / CVE-2026-109619 (banner version compare)
  node     Node.js Oct 2026 security releases (banner version, mostly not exposed)
  gitlab   GitLab CVE-2026-110264 (detect instance, version via /help or API token)
  litellm  LiteLLM proxy running the malicious 1.107.0 release
  emudhra  TLS chain issued under eMudhra / emSign (8 compromised intermediates)
  hosting  Hosted on Railway / Zeabur (provider-side incidents, rotate secrets)

Not remotely detectable (provider/data breaches): California schools, Ahold
Delhaize, Onamae, Railway/Zeabur internals. Only hosting fingerprints are given.

Use only against assets you own or are authorised to test.
Python 3.8+, standard library only. The optional --tui screen needs: pip install textual
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import io
import json
import os
import re
import socket
import ssl
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

SEV = {"OK": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
ALL_CHECKS = ["php", "node", "gitlab", "litellm", "emudhra", "hosting"]

# ---- fixed-release tables (from vendor advisories, 21 Oct 2026) -------------
PHP_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}      # 8.1 and older: EOL
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}  # 20/21/23/25 EOL
GITLAB_FIXED = {(18, 11): 13, (19, 0): 10, (19, 1): 9, (19, 2): 9,
                (19, 3): 6, (19, 4): 3, (19, 5): 1}
LITELLM_BAD = "1.107.0"
LITELLM_SAFE = "1.106.2"


# ---- data types -------------------------------------------------------------
@dataclass
class Finding:
    target: str
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""
    confidence: str = "medium"
    cve: str = ""


@dataclass
class Resp:
    status: int
    headers: Dict[str, str]
    cookies: List[str]
    body: bytes
    url: str
    error: str = ""

    def h(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects automatically; Fetcher follows same-host ones itself,
    so a redirect to an unreachable name still counts as a reachable target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def tls_context(verify: bool) -> ssl.SSLContext:
    """Default context, or a lenient one (old TLS and ciphers allowed) when not verifying,
    so legacy servers can still be fingerprinted."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for step in (lambda: setattr(ctx, "minimum_version", ssl.TLSVersion.TLSv1),
                     lambda: ctx.set_ciphers("ALL:@SECLEVEL=0"),
                     lambda: setattr(ctx, "options", ctx.options | getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4))):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass
    return ctx


class Fetcher:
    def __init__(self, base: str, timeout: float, verify: bool,
                 headers: Dict[str, str], proxy: Optional[str]):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.headers = headers
        self.cache: Dict[Tuple[str, Tuple], Resp] = {}
        self.extra: List[Resp] = []  # intermediate redirect responses, kept for banner checks
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=tls_context(verify))]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)

    def _same_host(self, url: str) -> bool:
        a, b = urllib.parse.urlparse(url), urllib.parse.urlparse(self.base)
        return a.scheme in ("http", "https") and (a.hostname or "").lower() == (b.hostname or "").lower()

    def _once(self, url: str, extra: Optional[Dict[str, str]]) -> Resp:
        req = urllib.request.Request(url, headers={**self.headers, **(extra or {})})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return self._mk(r.status, r.headers, r.read(131072), r.geturl())
        except urllib.error.HTTPError as e:
            try:
                body = e.read(131072)
            except Exception:  # noqa: BLE001
                body = b""
            return self._mk(e.code, e.headers, body, url)
        except Exception as e:  # noqa: BLE001
            why = getattr(e, "reason", None) or e
            return Resp(0, {}, [], b"", url, error=f"{type(e).__name__}: {why}")

    def get(self, path: str, extra: Optional[Dict[str, str]] = None) -> Resp:
        key = (path, tuple(sorted((extra or {}).items())))
        if key in self.cache:
            return self.cache[key]
        url, resp, last_hop = self.base + path, None, None
        for _ in range(6):
            resp = self._once(url, extra)
            loc = resp.h("location")
            if resp.status and 300 <= resp.status < 400 and loc:
                nxt = urllib.parse.urljoin(url, loc)
                if nxt != url and self._same_host(nxt):
                    self.extra.append(resp)
                    last_hop, url = resp, nxt
                    continue
            break
        if resp.status == 0 and last_hop is not None:  # redirect target failed: the redirect itself answered
            resp = last_hop
            self.extra.pop()
        self.cache[key] = resp
        return resp

    @staticmethod
    def _mk(status, hdrs, body, url) -> Resp:
        d = {k.lower(): v for k, v in hdrs.items()}
        cookies = hdrs.get_all("Set-Cookie") or []
        return Resp(status, d, cookies, body, url)

    def seen(self) -> List[Resp]:
        return [r for r in list(self.cache.values()) + self.extra if r.status]


@dataclass
class Ctx:
    target: str
    host: str
    port: int
    fetcher: Optional[Fetcher]
    https: bool
    args: argparse.Namespace
    chain: List[bytes] = field(default_factory=list)


# ---- helpers ----------------------------------------------------------------
def parse_ver(s: str) -> Optional[Tuple[int, int, int]]:
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", s.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def split_target(raw: str, port_override: Optional[int]) -> Tuple[str, Optional[str], Optional[int], str]:
    """-> (host, scheme or None, port or None for the default, path prefix without trailing slash)."""
    raw = raw.strip()
    u = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
    try:
        port = u.port
    except ValueError:
        port = None
    return (u.hostname or ""), (u.scheme.lower() or None), (port_override or port), u.path.rstrip("/")


def fetch_chain(host: str, port: int, timeout: float) -> List[bytes]:
    ctx = tls_context(False)
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            leaf = ss.getpeercert(binary_form=True)
            chain: List[bytes] = []
            sslobj = getattr(ss, "_sslobj", None)
            for getter in (getattr(ss, "get_unverified_chain", None),
                           getattr(sslobj, "get_unverified_chain", None)):
                if not getter:
                    continue
                try:
                    for c in getter():
                        if isinstance(c, (bytes, bytearray)):
                            chain.append(bytes(c))
                        else:
                            chain.append(c.public_bytes(ssl._ssl.ENCODING_DER))  # type: ignore[attr-defined]
                    if chain:
                        break
                except Exception:  # noqa: BLE001
                    chain = []
            if not chain and leaf:
                chain = [leaf]
            return chain


# ---- checks -----------------------------------------------------------------
def check_php(c: Ctx) -> List[Finding]:
    t = c.target
    banners, php_hint = [], False
    for r in c.fetcher.seen():
        for hn in ("x-powered-by", "server"):
            v = r.h(hn)
            if v:
                banners.append((hn, v))
                if "php" in v.lower():
                    php_hint = True
        if any(ck.lower().startswith("phpsessid") for ck in r.cookies):
            php_hint = True
    cve = "CVE-2026-109618, CVE-2026-109619"
    for hn, v in banners:
        m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", v, re.I)
        if not m:
            continue
        maj, mino, pat = (int(x) for x in m.groups())
        full = f"{maj}.{mino}.{pat}"
        ev = f"{hn}: {v}"
        note = ("Version comes from a banner only. Distro packages backport fixes without "
                "changing the string, so confirm the package version on the host.")
        if (maj, mino) in PHP_FIXED:
            fixed = PHP_FIXED[(maj, mino)]
            if pat < fixed:
                return [Finding(t, "php", "HIGH",
                                f"PHP {full} is below fixed release {maj}.{mino}.{fixed} (PHP2Shell, unauth RCE)",
                                f"Upgrade to {maj}.{mino}.{fixed}+ and restart all workers. Interim: "
                                f"session.upload_progress.enabled=0 and block multipart/set memory_limit=-1 "
                                f"per vendor guidance. {note}", ev, "low", cve)]
            return [Finding(t, "php", "OK", f"PHP {full} banner is at or above the fixed release", "", ev, "low", cve)]
        if (maj, mino) < (8, 2):
            return [Finding(t, "php", "HIGH",
                            f"PHP {full} is end of life, no official fix for PHP2Shell",
                            f"Migrate to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later, or use vendor backports/ELS. "
                            f"Interim: session.upload_progress.enabled=0. {note}", ev, "low", cve)]
        return [Finding(t, "php", "OK", f"PHP {full} is newer than the tracked branches", "", ev, "low", cve)]
    if php_hint:
        return [Finding(t, "php", "INFO", "PHP detected but version is hidden",
                        "Cannot judge PHP2Shell exposure remotely. Check the version on the host or use an "
                        "authorised active scanner against staging.", "", "low", cve)]
    return [Finding(t, "php", "OK", "No PHP indicators in headers or cookies", "", "", "low", cve)]


def check_node(c: Ctx) -> List[Finding]:
    t = c.target
    cve = "Node.js Oct 2026 releases (e.g. CVE-2026-111497)"
    stack = None
    for r in c.fetcher.seen():
        for hn in ("x-powered-by", "server", "via"):
            v = r.h(hn)
            m = re.search(r"node(?:\.js)?/(\d+\.\d+\.\d+)", v, re.I)
            if m:
                ver = parse_ver(m.group(1))
                ev = f"{hn}: {v}"
                if ver[0] in NODE_FIXED:
                    if ver < NODE_FIXED[ver[0]]:
                        fx = ".".join(map(str, NODE_FIXED[ver[0]]))
                        return [Finding(t, "node", "HIGH", f"Node.js {m.group(1)} is below fixed release {fx}",
                                        "Upgrade to 22.23.4, 24.22.1 or 26.12.1 (or later) and rebuild images.",
                                        ev, "medium", cve)]
                    return [Finding(t, "node", "OK", f"Node.js {m.group(1)} is at or above the fixed release", "", ev, "medium", cve)]
                if ver[0] < 27:
                    return [Finding(t, "node", "HIGH", f"Node.js {m.group(1)} is end of life, no fix",
                                    "Move to 22, 24 or 26 and apply the October releases.", ev, "medium", cve)]
                return [Finding(t, "node", "OK", f"Node.js {m.group(1)} is newer than tracked lines", "", ev, "medium", cve)]
            if re.search(r"express|next\.js|node", v, re.I):
                stack = f"{hn}: {v}"
    if stack:
        return [Finding(t, "node", "INFO", "Node.js-based stack detected, runtime version not exposed",
                        "Node runtime version is not remotely detectable here. Verify with `node -v` / image tag "
                        "(need 22.23.4, 24.22.1 or 26.12.1+).", stack, "low", cve)]
    return [Finding(t, "node", "OK", "No Node.js indicators", "", "", "low", cve)]


def check_gitlab(c: Ctx) -> List[Finding]:
    t = c.target
    cve = "CVE-2026-110264"
    r = c.fetcher.get("/users/sign_in")
    blob = r.text + " ".join(r.cookies)
    if not (r.status == 200 and re.search(r"gon\.gitlab_url|gitlab-logo|<title>[^<]*GitLab|content=\"GitLab\"|_gitlab_session", blob, re.I)):
        return [Finding(t, "gitlab", "OK", "No GitLab instance detected at /users/sign_in", "", "", "medium", cve)]
    version, ev = None, ""
    tok = c.args.gitlab_token
    if tok:
        a = c.fetcher.get("/api/v4/version", {"PRIVATE-TOKEN": tok})
        try:
            version = json.loads(a.text).get("version")
            ev = f"/api/v4/version -> {version}"
        except Exception:  # noqa: BLE001
            pass
    if not version:
        h = c.fetcher.get("/help")
        m = re.search(r"GitLab (?:Community|Enterprise) Edition\s*(?:<[^>]*>\s*)*v?(\d+\.\d+\.\d+)", h.text)
        if m:
            version, ev = m.group(1), f"/help -> {m.group(1)}"
    if not version:
        return [Finding(t, "gitlab", "MEDIUM", "GitLab detected, version not exposed anonymously",
                        "CVE-2026-110264 is unauthenticated RCE (CVSS 10.0) with no workaround. Verify the version "
                        "(Admin Area or `gitlab-rake gitlab:env:info`) or rerun with --gitlab-token. Fixed: "
                        "19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10, 18.11.13. Servers patched on 12 Oct "
                        "(19.4.2/19.3.5/19.2.8) are still affected.", "", "low", cve)]
    v = parse_ver(version)
    key = (v[0], v[1])
    if key in GITLAB_FIXED:
        vuln = v[2] < GITLAB_FIXED[key]
        want = f"{key[0]}.{key[1]}.{GITLAB_FIXED[key]}"
    elif key < (18, 11):
        vuln, want = True, "18.11.13 or a newer fixed branch"
    else:
        vuln, want = False, ""
    if vuln:
        return [Finding(t, "gitlab", "CRITICAL", f"GitLab {version} is vulnerable to unauthenticated RCE",
                        f"Upgrade to {want} immediately. No workaround exists.", ev, "high", cve)]
    return [Finding(t, "gitlab", "OK", f"GitLab {version} is at or above the fixed release", "", ev, "high", cve)]


def check_litellm(c: Ctx) -> List[Finding]:
    t = c.target
    cve = "LiteLLM 1.107.0 supply chain"
    r = c.fetcher.get("/health/readiness")
    data = None
    if r.status == 200:
        try:
            data = json.loads(r.text)
        except Exception:  # noqa: BLE001
            data = None
    if isinstance(data, dict) and "litellm_version" in data:
        ver = str(data["litellm_version"])
        ev = f"/health/readiness -> litellm_version {ver}"
        if ver == LITELLM_BAD:
            return [Finding(t, "litellm", "CRITICAL", "LiteLLM proxy is running the malicious 1.107.0 release",
                            f"Treat the host as compromised: isolate, pin {LITELLM_SAFE}, rotate ALL provider keys and "
                            "stored credentials from a clean machine, look for cook.pth / sitecustomize.py and "
                            "traffic to litellm.dev.", ev, "high", cve)]
        return [Finding(t, "litellm", "INFO", f"LiteLLM proxy exposed, version {ver} (not 1.107.0)",
                        "Proxy health endpoint is public. If this deployment pulled 1.107.0 or tags latest/main-latest "
                        "on 21 Oct 11:39-14:20 UTC and was later replaced, rotate its keys anyway.", ev, "high", cve)]
    o = c.fetcher.get("/openapi.json")
    if o.status == 200 and re.search(r'"title"\s*:\s*"LiteLLM', o.text):
        return [Finding(t, "litellm", "INFO", "LiteLLM proxy detected, version not exposed",
                        "Check the version on the host (must not be 1.107.0).", "/openapi.json", "medium", cve)]
    return [Finding(t, "litellm", "OK", "No LiteLLM proxy detected", "", "", "medium", cve)]


def check_emudhra(c: Ctx) -> List[Finding]:
    t = c.target
    cve = "eMudhra intermediate CA key compromise"
    if not c.https:
        return [Finding(t, "emudhra", "INFO", "No TLS endpoint, certificate check skipped")]
    if not c.chain:
        return [Finding(t, "emudhra", "INFO", "Could not retrieve the TLS chain")]
    pat = re.compile(rb"[ -~]{0,50}(?:emudhra|emsign|EM (?:DV|OV|EV|CS) [A-Za-z ]{0,10}CA)[ -~]{0,50}", re.I)
    hits, ecc_root = [], False
    for der in c.chain:
        for m in pat.finditer(der):
            hits.append(m.group(0).decode("ascii", "replace").strip())
        if b"emSign ECC Root CA - G3" in der:
            ecc_root = True
    if not hits:
        return [Finding(t, "emudhra", "OK", "TLS chain has no eMudhra / emSign certificates", "", "", "medium", cve)]
    ev = "; ".join(sorted(set(hits)))[:300]
    if ecc_root:
        return [Finding(t, "emudhra", "HIGH", "Chain terminates at emSign ECC Root CA - G3 (distrusted)",
                        "Browsers are removing this root (Chrome rolling out to all devices by 27 Oct 2026). Reissue "
                        "the certificate from another CA.", ev, "medium", cve)]
    return [Finding(t, "emudhra", "MEDIUM", "Certificate chain issued under eMudhra / emSign",
                    "Eight eMudhra intermediates had recoverable private keys. Browsers now block them, but confirm "
                    "this leaf was not issued by one of them (EM DV/OV/EV TLS CA G3B/G3C etc.), refresh CA bundles "
                    "(certifi 2026.10.19, NSS 3.131.1, webpki-roots 1.0.10) and consider reissuing.", ev, "low", cve)]


def check_hosting(c: Ctx) -> List[Finding]:
    t, found = c.target, []
    try:
        canon, aliases, _ = socket.gethostbyname_ex(c.host)
        names = " ".join([canon] + aliases).lower()
    except Exception:  # noqa: BLE001
        names = ""
    keys, blob = "", ""
    if c.fetcher:
        for r in c.fetcher.seen():
            keys += " ".join(r.headers.keys()) + " "
            blob += " ".join(r.headers.values()).lower() + " "
    if "railway.app" in names or "x-railway" in keys or "railway-edge" in blob:
        found.append(Finding(t, "hosting", "INFO", "Appears to be hosted on Railway",
                             "Railway reported a possible exposure of customer secrets. Follow the provider advisory and "
                             "rotate API keys and environment secrets.", names.strip() or keys.strip(), "medium", "Railway incident"))
    if "zeabur" in names or "zeabur" in blob or "zeabur" in keys:
        found.append(Finding(t, "hosting", "INFO", "Appears to be hosted on Zeabur",
                             "Zeabur reported a platform breach. Follow the provider advisory and rotate secrets.",
                             names.strip() or blob.strip()[:120], "medium", "Zeabur incident"))
    return found or [Finding(t, "hosting", "OK", "No Railway / Zeabur fingerprints", "", "", "medium")]


CHECK_FUNCS = {
    "gitlab": check_gitlab, "litellm": check_litellm, "emudhra": check_emudhra,
    "hosting": check_hosting, "php": check_php, "node": check_node,
}


# ---- scanning ---------------------------------------------------------------
def scan_target(raw: str, args: argparse.Namespace) -> List[Finding]:
    host, scheme, port, path = split_target(raw, args.port)
    if not host:
        return [Finding(raw, "connect", "INFO", "Invalid target", "No host name found in this entry.")]
    hostpart = f"[{host}]" if ":" in host else host

    def netloc(sch: str) -> str:
        default = 443 if sch == "https" else 80
        return hostpart if port in (None, default) else f"{hostpart}:{port}"

    if scheme in ("http", "https"):
        cands = [scheme]
    elif scheme:
        return [Finding(raw, "connect", "INFO", "Unsupported scheme", f"Only http and https are supported, got '{scheme}'.")]
    elif port in (None, 443, 8443, 9443, 4443):
        cands = ["https", "http"]
    else:  # unknown port: plain HTTP is the common case (dev servers, 8080, 8000, 3000 ...)
        cands = ["http", "https"]
    headers = {"User-Agent": args.user_agent, "Accept": "*/*"}
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    fetcher, first, tried = None, None, []
    for sch in cands:
        base = f"{sch}://{netloc(sch)}{path}"
        f = Fetcher(base, args.timeout, args.verify_tls, headers, args.proxy)
        r = f.get("/")
        if r.status:
            fetcher, first = f, r
            break
        tried.append(f"{base} -> {r.error or 'no response'}")
    if not fetcher:
        return [Finding(raw, "connect", "INFO", "Target unreachable over HTTP(S)",
                        "Tried: " + "; ".join(tried) + ". Check DNS, the port, firewalls and any proxy. "
                        "Give the scheme and port explicitly, for example http://host:8080.")]
    final = urllib.parse.urlparse(first.url)
    https = final.scheme == "https"
    tls_host, tls_port = final.hostname or host, final.port or 443
    port = tls_port
    ctx = Ctx(raw, host, port, fetcher, https, args)
    if https and "emudhra" in args.checks:
        try:
            ctx.chain = fetch_chain(tls_host, tls_port, args.timeout)
        except Exception:  # noqa: BLE001
            ctx.chain = []
    out: List[Finding] = []
    for name in ["gitlab", "litellm", "emudhra", "hosting", "php", "node"]:
        if name in args.checks:
            try:
                out += CHECK_FUNCS[name](ctx)
            except Exception as e:  # noqa: BLE001
                out.append(Finding(raw, name, "INFO", f"Check failed: {e}"))
    return out


# ---- output -----------------------------------------------------------------
class Style:
    COL = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36",
           "INFO": "34", "OK": "32", "DIM": "2", "BOLD": "1"}

    def __init__(self, on: bool):
        self.on = on

    def __call__(self, key: str, s: str) -> str:
        return f"\033[{self.COL[key]}m{s}\033[0m" if self.on else s


def render_text(results: Dict[str, List[Finding]], args, st: Style) -> str:
    buf = io.StringIO()
    min_sev = SEV[args.min_severity.upper()]
    for target, fs in results.items():
        worst = max((SEV[f.severity] for f in fs), default=0)
        wname = next(k for k, v in SEV.items() if v == worst)
        buf.write(f"\n{st('BOLD', target)}  [{st(wname, wname)}]\n")
        for f in sorted(fs, key=lambda x: -SEV[x.severity]):
            if f.severity == "OK" and not args.verbose:
                continue
            if SEV[f.severity] < min_sev and f.severity != "OK":
                continue
            buf.write(f"  {st(f.severity, f'{f.severity:<8}')} {f.check:<8} {f.title}\n")
            if f.cve:
                buf.write(f"  {'':<8} {'':<8} {st('DIM', 'ref: ' + f.cve)}\n")
            if f.evidence:
                buf.write(f"  {'':<8} {'':<8} {st('DIM', 'evidence: ' + f.evidence)}\n")
            if f.detail:
                for line in textwrap.wrap(f.detail, 88):
                    buf.write(f"  {'':<8} {'':<8} {line}\n")
    total = {k: 0 for k in SEV}
    for fs in results.values():
        for f in fs:
            total[f.severity] += 1
    buf.write("\n" + st("BOLD", "Summary") + f": {len(results)} target(s)  ")
    buf.write("  ".join(f"{st(k, k)}={total[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) + "\n")
    buf.write(st("DIM", "Banner/version findings are indicators, not proof. Confirm on the host.") + "\n")
    return buf.getvalue()


def render_json(results: Dict[str, List[Finding]]) -> str:
    return json.dumps({"tool": "blackoct-check", "version": __version__,
                       "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "results": {t: [asdict(f) for f in fs] for t, fs in results.items()}}, indent=2)


def render_csv(results: Dict[str, List[Finding]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "check", "severity", "confidence", "title", "evidence", "cve", "detail"])
    for fs in results.values():
        for f in fs:
            w.writerow([f.target, f.check, f.severity, f.confidence, f.title, f.evidence, f.cve, f.detail])
    return buf.getvalue()


# ---- CLI --------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blackoct-check",
        description="Non-intrusive exposure checker for the Black October 2026 CVEs and incidents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              blackoct-check example.com
              blackoct-check -l domains.txt -c 20 -f json -o report.json
              blackoct-check --checks php,gitlab https://git.example.com
              blackoct-check example.com --proxy http://127.0.0.1:8080     # route via ZAP
              blackoct-check git.example.com --gitlab-token $GITLAB_TOKEN
              blackoct-check --tui                                     # full-screen terminal UI
              blackoct-check --tui -l domains.txt --run --yes          # TUI, start straight away

            exit codes: 0 clean, 2 finding at/above --fail-on, 1 usage/runtime error.
            Only scan systems you own or are authorised to test."""))
    p.add_argument("targets", nargs="*", help="domains, host:port or URLs")
    p.add_argument("-l", "--list", metavar="FILE", help="file with one target per line ('-' for stdin)")
    p.add_argument("--checks", default=",".join(ALL_CHECKS), help=f"comma list (default: all). Options: {', '.join(ALL_CHECKS)}")
    p.add_argument("--skip", default="", help="comma list of checks to skip")
    p.add_argument("-c", "--concurrency", type=int, default=10, help="parallel targets (default 10)")
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="per-request timeout seconds (default 8)")
    p.add_argument("--port", type=int, help="override port")
    p.add_argument("--proxy", help="HTTP proxy for web requests, e.g. ZAP at http://127.0.0.1:8080")
    p.add_argument("-H", "--header", action="append", help="extra request header 'Name: value' (repeatable)")
    p.add_argument("--user-agent", default=f"blackoct-check/{__version__}", help="User-Agent string")
    p.add_argument("--verify-tls", action="store_true", help="verify TLS certificates (off by default)")
    p.add_argument("--gitlab-token", default=os.environ.get("GITLAB_TOKEN"), help="GitLab token for /api/v4/version (or env GITLAB_TOKEN)")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("-o", "--output", metavar="FILE", help="write report to file")
    p.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"], help="hide findings below this level (text)")
    p.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical", "never"], help="exit 2 at/above this level (default high)")
    p.add_argument("-v", "--verbose", action="store_true", help="also show OK results")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    p.add_argument("--tui", action="store_true", help="open the full-screen terminal UI (needs: pip install textual)")
    p.add_argument("--run", action="store_true", help="with --tui: start scanning immediately (needs --yes)")
    p.add_argument("--yes", action="store_true", help="with --tui: confirm you are authorised to test the targets")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def load_targets(args) -> List[str]:
    ts = list(args.targets)
    if args.list:
        fh = sys.stdin if args.list == "-" else open(args.list, encoding="utf-8")
        with fh:
            ts += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    seen, out = set(), []
    for t in ts:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if args.tui:
        try:
            import blackoct_tui
        except SystemExit as e:  # textual missing: message is carried in the exit
            print(e.code if isinstance(e.code, str) else "error: could not start the TUI", file=sys.stderr)
            return 1
        return blackoct_tui.run(args)
    targets = load_targets(args)
    if not targets:
        p.print_usage(sys.stderr)
        print("error: no targets given", file=sys.stderr)
        return 1
    chosen = [x.strip().lower() for x in args.checks.split(",") if x.strip()]
    skip = {x.strip().lower() for x in args.skip.split(",") if x.strip()}
    bad = [x for x in chosen + list(skip) if x not in ALL_CHECKS]
    if bad:
        print(f"error: unknown check(s): {', '.join(bad)}", file=sys.stderr)
        return 1
    args.checks = [x for x in chosen if x not in skip]

    color = not args.no_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not args.output
    st = Style(color)
    results: Dict[str, List[Finding]] = {}
    done = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futs = {ex.submit(scan_target, t, args): t for t in targets}
        try:
            for fut in cf.as_completed(futs):
                t = futs[fut]
                try:
                    results[t] = fut.result()
                except Exception as e:  # noqa: BLE001
                    results[t] = [Finding(t, "scan", "INFO", f"Scan error: {e}")]
                done += 1
                if not args.quiet:
                    print(f"\r[{done}/{len(targets)}] scanned", end="", file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            for f in futs:
                f.cancel()
            return 1
    if not args.quiet:
        print(file=sys.stderr)
    ordered = {t: results[t] for t in targets if t in results}

    if args.format == "json":
        report = render_json(ordered)
    elif args.format == "csv":
        report = render_csv(ordered)
    else:
        report = render_text(ordered, args, st)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        if not args.quiet:
            print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    if args.fail_on != "never":
        lim = SEV[args.fail_on.upper()]
        if any(SEV[f.severity] >= lim for fs in ordered.values() for f in fs):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
