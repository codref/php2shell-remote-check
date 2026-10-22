#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""php2shell remote vulnerability check -- CVE-2026-109618 / CVE-2026-109619.

Black-box checker. It uses only information an unauthenticated attacker can get
from the public HTTP(S) endpoint: no shell, no local files, no credentials.

This tool **checks** for the vulnerability. It does not exploit it and never runs
a command on the target.

What the two CVEs are
---------------------
Both are "state corruption via bailout" in the PHP core (GHSA-w8hw-w9fx-j79w =
CVE-2026-109618, GHSA-6wmf-4rv5-p3rp = CVE-2026-109619). PHP handles
out-of-memory with a `longjmp` (`zend_bailout`). When that abort fires inside
engine code that is mid-operation -- in particular the `session.upload_progress`
handler, which decodes and rewrites a session during multipart parsing, before
the request's script runs -- it leaves PHP's internal state inconsistent. Request
shutdown then reads or branches on invalid data (CVE-2026-109618), and stale
worker-global state can survive into a later request (CVE-2026-109619).

Fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. End-of-life branches (8.1, 8.0,
7.x, 5.x) get no vendor fix.

What this checker does (in increasing strength / invasiveness)
--------------------------------------------------------------
1. PASSIVE   : fingerprint SAPI + PHP version from response headers.
2. PROBE     : confirm the multipart upload-progress path is reachable and is not
               blocked at the edge (WAF/proxy), using only harmless requests.
3. VERSION   : map the PHP version against the fixed releases / EOL branches.

Reaching the OOM window itself (the actual proof of exploitability) is done by
the separate, opt-in ``poc_state_corruption.py``. That script triggers the
condition and reports state corruption; it does not run commands either.

Exit codes: 0 no evidence (patched), 1 vulnerable, 2 unknown/error,
            3 edge mitigation detected (origin status unknown).

Only run this against systems you own or are explicitly authorized to test.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Knowledge (from the PHP advisories)
# ---------------------------------------------------------------------------

# First fixed (secure) release per PHP 8 branch.
FIXED_8X = {2: "8.2.35", 3: "8.3.36", 4: "8.4.27", 5: "8.5.12"}
# Branches with no official patch expected (end of life).
EOL_MINORS_8X = (0, 1)
EOL_MAJORS = (5, 6, 7)

UPLOAD_PROGRESS_NAME = "PHP_SESSION_UPLOAD_PROGRESS"
PHP_HEADER_HINTS = ("x-powered-by", "x-turbo-charged-by", "server")

CVE_618 = "CVE-2026-109618"
CVE_619 = "CVE-2026-109619"


# ---------------------------------------------------------------------------
# Minimal black-box HTTP client (stdlib only)
# ---------------------------------------------------------------------------


class HTTPError(Exception):
    pass


class HTTPResponse:
    def __init__(self, url: str, status: int, reason: str, headers: dict[str, list[str]], body: bytes):
        self.url = url
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    def header(self, name: str, default: str | None = None) -> str | None:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else default

    @property
    def status_line(self) -> str:
        return f"{self.status} {self.reason}".strip()

    def text(self) -> str:
        return self.body.decode("latin1", "replace")


def _decode_chunked(raw: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(raw)
    while i < n:
        j = raw.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(raw[i:j].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return raw
        i = j + 2
        if size == 0:
            break
        out += raw[i : i + size]
        i += size + 2
    return bytes(out)


class HTTPClient:
    def __init__(self, timeout: float = 15.0, verify: bool = True,
                 proxy: str | None = None, user_agent: str = "php2shell-check/1.0"):
        self.timeout = timeout
        self.verify = verify
        self.proxy = proxy
        self.user_agent = user_agent

    def _tls_context(self) -> ssl.SSLContext:
        return ssl.create_default_context() if self.verify else ssl._create_unverified_context()

    def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None,
                body: bytes = b"") -> HTTPResponse:
        parts = urlsplit(url)
        scheme = (parts.scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise HTTPError(f"unsupported scheme: {scheme!r}")
        host = parts.hostname
        if not host:
            raise HTTPError("missing host")
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        hdrs = {
            "Host": host if parts.port is None else f"{host}:{port}",
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        if body and "Content-Length" not in hdrs:
            hdrs["Content-Length"] = str(len(body))

        target = path
        if self.proxy:
            p = urlsplit(self.proxy)
            phost, pport = p.hostname or "127.0.0.1", p.port or 8080
            sock = socket.create_connection((phost, pport), timeout=self.timeout)
            if scheme == "https":
                sock.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").encode())
                head = self._read_head(sock)
                if not head.startswith(b"HTTP/1.") or b" 200" not in head.split(b"\r\n", 1)[0]:
                    sock.close()
                    raise HTTPError("proxy CONNECT failed")
                sock = self._tls_context().wrap_socket(sock, server_hostname=host)
            else:
                target = url
        else:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if scheme == "https":
                sock = self._tls_context().wrap_socket(sock, server_hostname=host)

        try:
            head = f"{method} {target} HTTP/1.1\r\n"
            for k, v in hdrs.items():
                head += f"{k}: {v}\r\n"
            head += "\r\n"
            sock.sendall(head.encode() + body)
            sock.settimeout(self.timeout)
            raw = self._read_all(sock)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if not raw:
            raise HTTPError("empty response")
        return self._parse(url, raw)

    def _read_head(self, sock: socket.socket) -> bytes:
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf

    def _read_all(self, sock: socket.socket) -> bytes:
        chunks = []
        while True:
            try:
                d = sock.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)

    @staticmethod
    def _parse(url: str, raw: bytes) -> HTTPResponse:
        sep = raw.find(b"\r\n\r\n")
        head_bytes, body = (raw[:sep], raw[sep + 4:]) if sep >= 0 else (raw, b"")
        lines = head_bytes.decode("latin1", "replace").split("\r\n")
        status, reason, headers = 0, "", {}
        if lines and lines[0].startswith("HTTP/"):
            bits = lines[0].split(" ", 2)
            try:
                status = int(bits[1])
            except (IndexError, ValueError):
                status = 0
            reason = bits[2] if len(bits) > 2 else ""
            for line in lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                headers.setdefault(k.strip().lower(), []).append(v.strip())
        if headers.get("transfer-encoding", [""])[0].lower() == "chunked":
            body = _decode_chunked(body)
        return HTTPResponse(url, status, reason, headers, body)


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

_PHP_VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)


def php_version_from(headers: dict[str, list[str]]) -> tuple[int, int, int] | None:
    for name in PHP_HEADER_HINTS:
        for value in headers.get(name, []):
            m = _PHP_VER_RE.search(value)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    for values in headers.values():
        for value in values:
            m = _PHP_VER_RE.search(value)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def sapi_from(headers: dict[str, list[str]]) -> str:
    powered = (headers.get("x-powered-by", [""])[0] or "").strip()
    turbo = (headers.get("x-turbo-charged-by", [""])[0] or "").strip()
    server = (headers.get("server", [""])[0] or "").strip()
    if "litespeed" in (turbo + " " + server).lower():
        return f"LiteSpeed LSAPI (lsphp) {powered}".strip()
    bits = [b for b in (server, powered, turbo) if b]
    return " | ".join(bits) if bits else "unknown"


# ---------------------------------------------------------------------------
# Version assessment
# ---------------------------------------------------------------------------


def assess_version(ver: tuple[int, int, int] | None) -> tuple[str, str]:
    """Return (status, reason). status in PATCHED/VULNERABLE/UNKNOWN."""
    if ver is None:
        return "UNKNOWN", "PHP version is not disclosed in the response headers"
    major, minor, patch = ver
    sver = f"{major}.{minor}.{patch}"
    if major in EOL_MAJORS:
        return "VULNERABLE", f"PHP {sver} is an end-of-life branch: no official php2shell fix"
    if major < 5:
        return "VULNERABLE", f"PHP {sver} (< 5.4) has no upload-progress counter but still exposes the multipart parser"
    if major == 8:
        if minor in EOL_MINORS_8X:
            return "VULNERABLE", f"PHP {sver} is end-of-life (8.0/8.1): no official php2shell fix"
        fixed = FIXED_8X.get(minor)
        if fixed is None:
            return "UNKNOWN", f"PHP {sver} is newer than the affected table; fix status unknown"
        if (major, minor, patch) >= tuple(int(x) for x in fixed.split(".")):
            return "PATCHED", f"PHP {sver} >= {fixed} (fixed release)"
        return "VULNERABLE", f"PHP {sver} < {fixed} (unpatched for {CVE_618}/{CVE_619})"
    return "UNKNOWN", f"PHP {sver}: unexpected branch"


# ---------------------------------------------------------------------------
# Reachability probe (harmless)
# ---------------------------------------------------------------------------


def _boundary() -> bytes:
    import random
    return ("----php2shell" + "".join(random.choice("0123456789abcdef") for _ in range(16))).encode()


def _part(boundary: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def probe_upload_progress(client: HTTPClient, url: str, extra_headers: dict[str, str], token: str) -> dict:
    """Harmless multipart POST carrying the upload-progress field.

    Observations:
      * edge_blocked     : multipart rejected at the edge while a urlencoded POST is not
      * session_autostart: the progress request emits a Set-Cookie the plain baseline
                           does not. Positive-only: modern PHP reuses the supplied
                           session id and does not mint one, so absence means nothing.
      * status           : application status for the multipart request
    """
    base = client.request(url, "POST",
                          headers={**extra_headers, "Content-Type": "application/x-www-form-urlencoded"},
                          body=b"php2shell_probe=1")
    bnd = _boundary()
    body = (
        _part(bnd, UPLOAD_PROGRESS_NAME, token.encode()) + b"\r\n"
        + _part(bnd, "file", b"A" * 1024, filename="probe.txt") + b"\r\n"
        + b"--" + bnd + b"--\r\n"
    )
    mp = client.request(url, "POST",
                        headers={**extra_headers, "Content-Type": f"multipart/form-data; boundary={bnd.decode()}"},
                        body=body)

    def cookies(resp: HTTPResponse) -> set[str]:
        return {c.split("=", 1)[0].strip().lower() for c in resp.headers.get("set-cookie", [])}

    blocked = {403, 406, 444, 501}
    edge_blocked = mp.status in blocked and mp.status != base.status
    base_c, mp_c = cookies(base), cookies(mp)
    session_autostart = bool(mp_c - base_c) and mp.status == base.status
    crash_like = mp.status in {500, 502, 503, 504} and base.status < 500

    return {
        "baseline_status": base.status,
        "multipart_status": mp.status,
        "edge_blocked": edge_blocked,
        "session_autostart": session_autostart,
        "new_cookies": sorted(mp_c - base_c),
        "crash_like": crash_like,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_C = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[1;33m",
      "cyan": "\033[36m", "bold": "\033[1m", "reset": "\033[0m"}


def _color(s: str, name: str, enabled: bool) -> str:
    return f"{_C[name]}{s}{_C['reset']}" if enabled else s


def verdict_line(label: str, status: str, reason: str, tty: bool) -> str:
    tag = {
        "VULNERABLE": _color("VULNERABLE", "red", tty),
        "EDGE-MITIGATED": _color("EDGE-MITIGATED", "green", tty),
        "PATCHED": _color("PATCHED", "green", tty),
        "UNKNOWN": _color("UNKNOWN", "yellow", tty),
    }.get(status, status)
    return f"  {label}: {tag}\n      -> {reason}"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Remote php2shell vulnerability check (CVE-2026-109618 / CVE-2026-109619).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  php2shell_check.py https://host/app/index.php\n"
            "  php2shell_check.py https://host/ --json\n"
            "  php2shell_check.py https://host/ --no-probe      # passive only\n"
        ),
    )
    p.add_argument("url", help="target URL (any endpoint the server executes as PHP)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--user-agent", default="php2shell-check/1.0")
    p.add_argument("--header", action="append", default=[], metavar="K:V")
    p.add_argument("--cookie", default=None)
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--proxy", default=os.environ.get("PHP2SHELL_PROXY"))
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", action="store_true", help="only the verdict lines")
    p.add_argument("--no-probe", action="store_true", help="passive fingerprint only")
    args = p.parse_args(argv)

    extra_headers: dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            print(f"bad --header (want K:V): {h}", file=sys.stderr)
            return 2
        k, v = h.split(":", 1)
        extra_headers[k.strip()] = v.strip()
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    client = HTTPClient(timeout=args.timeout, verify=not args.insecure,
                        proxy=args.proxy, user_agent=args.user_agent)

    result: dict = {
        "target": args.url, "tool": "php2shell-check", "php_version": None, "sapi": None,
        "version": {}, "probe": {}, "verdict": {},
        "cvss": {CVE_618: "9.2 Critical", CVE_619: "9.2 Critical"},
    }
    tty = sys.stdout.isatty() and not args.json

    def emit(msg: str = "") -> None:
        if not args.json and not args.quiet:
            print(msg)

    try:
        base = client.request(args.url, "GET", headers=dict(extra_headers))
    except (HTTPError, OSError, ssl.SSLError) as exc:
        print(f"error: cannot reach {args.url}: {exc}", file=sys.stderr)
        return 2

    ver = php_version_from(base.headers)
    sapi = sapi_from(base.headers)
    result["php_version"] = ".".join(map(str, ver)) if ver else None
    result["sapi"] = sapi
    result["baseline"] = {"status": base.status, "server": base.header("server"), "powered_by": base.header("x-powered-by")}

    v_status, v_reason = assess_version(ver)
    result["version"] = {"status": v_status, "reason": v_reason}

    probe: dict = {}
    if not args.no_probe:
        try:
            probe = probe_upload_progress(client, args.url, extra_headers, "php2shell-probe")
        except (HTTPError, OSError, ssl.SSLError) as exc:
            probe = {"error": str(exc)}
    result["probe"] = probe

    edge_blocked = probe.get("edge_blocked", False)
    session_autostart = probe.get("session_autostart", False)
    crash_like = probe.get("crash_like", False)

    def verdict(base_status: str) -> tuple[str, str]:
        if edge_blocked:
            return "EDGE-MITIGATED", "multipart upload-progress requests are blocked at the edge (WAF/proxy); origin is unknown"
        if base_status == "VULNERABLE":
            extra = ""
            if session_autostart:
                extra = "; upload-progress auto session-start observed"
            elif crash_like:
                extra = "; multipart caused 5xx (worker instability)"
            return "VULNERABLE", v_reason + "; multipart reaches PHP" + extra
        if base_status == "PATCHED":
            if crash_like:
                return "UNKNOWN", "version claims patched but multipart caused 5xx; verify the build"
            return "PATCHED", v_reason
        return "UNKNOWN", v_reason

    v618 = verdict(v_status)
    v619 = verdict(v_status)
    result["verdict"] = {CVE_618: {"status": v618[0], "reason": v618[1]},
                         CVE_619: {"status": v619[0], "reason": v619[1]}}

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(_color("php2shell remote check", "bold", tty))
        print(f"target  : {args.url}")
        print(f"baseline: HTTP {base.status} | server: {base.header('server') or '-'} | php: {result['php_version'] or 'not disclosed'}")
        print(f"sapi    : {sapi}")
        if probe:
            print(f"probe   : multipart HTTP {probe.get('multipart_status')} "
                  f"(edge_blocked={probe.get('edge_blocked')}, session_autostart={probe.get('session_autostart')}, "
                  f"crash_like={probe.get('crash_like')})")
        print()
        print(_color("Verdict", "bold", tty))
        print(verdict_line(CVE_618, v618[0], v618[1], tty))
        print(verdict_line(CVE_619, v619[0], v619[1], tty))
        print()
        print(_color("Note", "bold", tty) + ": version disclosure can be spoofed or hidden;")
        print("      an edge 403 is a stopgap, not a patch. Reaching the OOM window")
        print("      is verified separately by poc_state_corruption.py. Upgrade PHP.")

    statuses = {v618[0], v619[0]}
    if "VULNERABLE" in statuses:
        return 1
    if "EDGE-MITIGATED" in statuses:
        return 3
    if statuses == {"PATCHED"}:
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
