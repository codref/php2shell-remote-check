# php2shell remote check

**CVE-2026-109618 / CVE-2026-109619 — remote vulnerability check for PHP**

A small, dependency-free toolkit that tells you whether a PHP endpoint is exposed
to the *php2shell* vulnerabilities, using only what an unauthenticated attacker
can see (black-box, over HTTP/S). It **checks**; it does not exploit and never
runs a command on the target.

---

## Background

Both CVEs are *"state corruption via bailout"* in the PHP core:

- **CVE-2026-109618** — GHSA‑w8hw‑w9fx‑j79w
- **CVE-2026-109619** — GHSA‑6wmf‑4rv5‑p3rp

PHP handles out-of-memory with a `longjmp` (`zend_bailout`). When that abort
fires inside engine code that is mid-operation — in particular the
`session.upload_progress` handler, which decodes and rewrites a session during
multipart parsing, **before the request's script runs** — it leaves PHP's
internal state inconsistent. Request shutdown then reads or branches on invalid
data (CVE‑2026‑109618), and stale worker-global state can survive into a later
request (CVE‑2026‑109619).

- **Reachable pre-auth**, via a `multipart/form-data` request carrying
  `PHP_SESSION_UPLOAD_PROGRESS` (enabled by default).
- **Fixed in** PHP **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** (then restart the PHP
  workers).
- **End-of-life branches** (8.1, 8.0, 7.x, 5.x) get no vendor fix.

---

## What is in this toolkit

| File | What it does |
| :--- | :--- |
| `php2shell_check.py` | Remote, non-invasive check: SAPI/PHP fingerprint, version assessment, upload-progress reachability probe |
| `poc_state_corruption.py` | Opt-in **verification**: triggers the OOM condition and reports the observable state corruption. No command execution |
| `demo.py` | Video-friendly console demo of both steps |
| `demo/lab.sh`, `demo/lab/` | One-command Docker lab (a vulnerable and a fixed PHP node) |

There is deliberately **no exploit** here: no RCE payload, no session-file
injection, no handler-mismatch chain.

---

## Quick start (lab)

```sh
./demo/lab.sh up        # 8.4.26 vulnerable :8084, 8.4.27 fixed :8080
./demo/lab.sh run       # run the demo (detection + state-corruption check)
./demo/lab.sh down
```

Requires Docker; the containers bind to `127.0.0.1` only. This is unpatched PHP
by design — keep it on an isolated host.

---

## The checker

Non-invasive. It sends a GET, a normal POST, and one benign multipart POST
carrying the upload-progress field. It changes nothing.

```sh
python3 php2shell_check.py https://your-host/
python3 php2shell_check.py https://your-host/index.php --json
python3 php2shell_check.py https://your-host/ --no-probe     # passive only
```

Use any URL the server executes as PHP (the homepage is fine).

**How it works**

1. **Passive** — reads the SAPI/PHP version from `Server` / `X-Powered-By` /
   `X-Turbo-Charged-By`.
2. **Version map** — compares against the fixed releases and the EOL branches.
3. **Reachability probe** — a harmless multipart POST with the upload-progress
   field, checking whether the path reaches PHP or is blocked at the edge.

**Exit codes**

| Code | Meaning |
| :--- | :--- |
| `0` | No evidence — version is at/above the fixed release |
| `1` | Vulnerable (affected version and the upload-progress path is reachable) |
| `2` | Unknown (version not disclosed / could not classify) |
| `3` | Multipart is blocked at the edge (WAF/proxy); origin status unknown |

Options: `--timeout`, `--user-agent`, `--header K:V`, `--cookie`,
`--insecure`, `--proxy`, `--json`, `--quiet`, `--no-probe`.

---

## The state-corruption check

> **Warning:** this deliberately exhausts `memory_limit` and can leave workers
> stuck — a self-inflicted denial of service until PHP is restarted. Run it only
> against a system you own or are authorized to test, ideally a staging copy.

```sh
python3 poc_state_corruption.py http://your-host/index.php --check-leak --variant parts
```

It reproduces the inputs from PHP's own regression test
(`tests/basic/oom_rfc1867_upload_progress.phpt`), shaped to exhaust
`memory_limit` from **inside** the upload-progress handler, then checks the
consequence:

```
phase 1: trigger OOM in the upload-progress handler   -> clean-OOM-fatal
phase 2: reuse the SAME session id                    -> HUNG            (vulnerable)
phase 3: a fresh session id (control)                 -> clean-OOM-fatal
```

On the vulnerable build the `longjmp` bailout skips the session unlock, so the
session file is left locked and a later request with the same id blocks forever.
The fixed build releases the session and all three phases return cleanly.

It reaches the OOM window with the same inputs the advisory documents (many
parts / oversized headers / a huge `PHP_SESSION_UPLOAD_PROGRESS` value). A small
`memory_limit` (as in the lab) makes it deterministic; on default configurations
the request has to be scaled up.

Options: `--variant {parts,longparts,hugename,bigprogress}`, `--flood N`,
`--timeout`, `--check-leak`.

---

## The demo

```sh
python3 demo.py                 # against the default lab
python3 demo.py --clear --pause 1.4
python3 demo.py --skip-check    # detection only
NO_COLOR=1 python3 demo.py      # no colour
```

It shows the check on a patched host and a vulnerable host, then the
state-corruption verification. Options: `--vuln`, `--patched`, `--clear`,
`--fast`, `--pause`, `--skip-check`.

---

## Scope, honesty, and limits

- A black-box result is **evidence, not proof**. Version disclosure can be
  spoofed or hidden; an edge `403` is a stopgap (the origin may still be
  vulnerable to traffic that bypasses the edge).
- The configuration stopgap `session.upload_progress.enabled = Off` is **not**
  externally observable, so an affected version that accepts multipart is
  reported vulnerable even if that setting was applied.
- The checker reports the *version/reachability* condition; the
  `poc_state_corruption.py` step confirms the target actually reaches the OOM
  window. Neither runs code on the target.
- Zero-dependency code execution is a separate matter and is not part of this
  toolkit.

**Remediation:** update PHP to the fixed release for your branch and restart the
PHP workers. A package update that has not restarted PHP-FPM or Apache leaves
the vulnerable code resident in running workers.

---

## Legal

For authorized security testing only. Use this strictly against systems you own
or have explicit, written permission to test. Do not point it at third-party
systems.

---

## License

[MIT](LICENSE).
