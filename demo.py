#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""php2shell console demo -- detection, then deep verification. Check only.

Walks through:
  ACT 1  Vulnerability check   (php2shell_check.py against a vulnerable + a patched host)
  ACT 2  State-corruption check (poc_state_corruption.py -- no command execution)

Defaults point at a local lab:
  vulnerable (8.4.26, low memory_limit)  http://127.0.0.1:8084
  patched    (8.4.27)                     http://127.0.0.1:8080

Usage:
  python3 demo.py
  python3 demo.py --vuln http://127.0.0.1:8084 --patched http://127.0.0.1:8080 --clear
  python3 demo.py --skip-check            # detection only
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

BANNER = r"""
   ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
   ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
   ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
   ██╔═══╝ ██╔══██║██╔═══╝  ╚═══██╗╚════██║██╔══██║██╔══╝  ██║     ██║
   ██║     ██║  ██║██║     ██████╔╝███████║██║  ██║███████╗███████╗███████╗
   ╚═╝     ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"""

SHELL = r"""
       .--.
      |o_o |      CVE-2026-109618 / CVE-2026-109619
      |:_/ |      PHP session.upload_progress  ->  OOM bailout state corruption
     //   \ \      pre-auth · CVSS v4.0 9.2 Critical · check only
    (|     | )
   /'\_   _/`\
   \___)=(___/
"""


class C:
    R = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YEL = "\033[33m"
    MAG = "\033[35m"; CYAN = "\033[36m"; GRY = "\033[90m"


def _on() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def col(s: str, c: str) -> str:
    return f"{c}{s}{C.R}" if _on() else s


def width() -> int:
    return max(68, min(shutil.get_terminal_size((90, 24)).columns, 100))


def act(n: int, title: str) -> None:
    w = width()
    bar = "═" * (w - 2)
    print()
    print(col(f"╔{bar}╗", C.CYAN))
    print(col("║", C.CYAN) + col(f"  ACT {n}  —  {title}".ljust(w - 2), C.B + C.CYAN) + col("║", C.CYAN))
    print(col(f"╚{bar}╝", C.CYAN))
    print()


def labels(title: str) -> None:
    print(col(f"  {title}", C.YEL + C.B))


def framed(text: str, indent: str = "   ") -> None:
    for line in text.rstrip("\n").split("\n"):
        print(f"{indent}{col('│', C.GRY)} {line}")


def pause(args: argparse.Namespace, extra: float = 0.0) -> None:
    if not args.fast:
        time.sleep(args.pause + extra)


def reachable(url: str, timeout: float = 2.0) -> bool:
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout)
        return True
    except Exception:
        return False


def run(cmd: list[str], timeout: float = 60.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "(timed out)"
    except FileNotFoundError as exc:
        return 127, str(exc)


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell console demo (check only)")
    ap.add_argument("--vuln", default="http://127.0.0.1:8084", help="vulnerable target base URL")
    ap.add_argument("--patched", default="http://127.0.0.1:8080", help="patched target base URL")
    ap.add_argument("--clear", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--pause", type=float, default=1.1)
    ap.add_argument("--skip-check", action="store_true", help="detection only, skip the state-corruption check")
    args = ap.parse_args()

    if args.clear and _on():
        print("\033[2J\033[H", end="")

    print(col(BANNER, C.MAG + C.B))
    print(col(SHELL, C.GRY))
    print(col("  PHP2SHELL — remote check", C.B) + col("   ·   ", C.GRY) + col("detect, then verify", C.DIM))
    print(col("  " + "─" * (width() - 4), C.GRY))
    pause(args)

    checker = os.path.join(HERE, "php2shell_check.py")
    statecheck = os.path.join(HERE, "poc_state_corruption.py")

    # ================================================================ ACT I
    act(1, "VULNERABILITY CHECK")
    labels("Baseline: patched host (PHP 8.4.27 — fixed release)")
    if reachable(args.patched):
        _, out = run([sys.executable, checker, args.patched + "/index.php", "--quiet"])
        framed(out)
    else:
        framed(col(f"(unreachable: {args.patched})", C.DIM))
    pause(args)

    labels("Target: vulnerable host (PHP 8.4.26 — pre-patch)")
    if reachable(args.vuln):
        _, out = run([sys.executable, checker, args.vuln + "/index.php", "--quiet"])
        framed(out)
    else:
        framed(col(f"(unreachable: {args.vuln})", C.DIM))
    pause(args)

    # ================================================================ ACT II
    if not args.skip_check:
        act(2, "STATE-CORRUPTION CHECK  —  no command execution")
        labels(f"Trigger OOM inside the upload-progress handler: {args.vuln} (low memory_limit)")
        if reachable(args.vuln):
            _, out = run([sys.executable, statecheck, args.vuln + "/index.php", "--check-leak", "--timeout", "5"], timeout=120)
            shown = []
            for line in out.rstrip("\n").split("\n"):
                if "RESULT: vulnerable" in line or "HUNG" in line:
                    shown.append(col(line, C.RED + C.B))
                elif "RESULT:" in line:
                    shown.append(col(line, C.GREEN + C.B))
                else:
                    shown.append(line)
            framed("\n".join(shown))
        else:
            framed(col(f"(unreachable: {args.vuln})", C.DIM))
        pause(args)

    print()
    print(col("  " + "─" * (width() - 4), C.GRY))
    print(col("  detection: php2shell_check.py    verification: poc_state_corruption.py", C.DIM))
    print(col("  check only — no code is executed on the target.", C.DIM))
    print(col("  authorized testing only.", C.DIM))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
