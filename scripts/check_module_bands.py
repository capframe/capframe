#!/usr/bin/env python3
"""Check each module's version band against what the module ACTUALLY ships.

Why this exists
---------------
`capframe bind` was unreachable in production for an unknown window: the Bind
band said `>=0.7.0, <0.8.0` while capnagent shipped 0.9.0, so `resolve_compatible`
rejected a wire-compatible binary and every `capframe bind` failed. The fix
(#44) added a unit test pinning each band against the shipped version — but
that pin is a hand-maintained constant, so it only catches drift once somebody
remembers to update it. It had already gone stale again (Guard pinned 0.5.6,
actual release 0.5.7).

This resolves the shipped versions LIVE, from every channel a user can install
from, and fails if any of them falls outside the band. A module can publish a
release without touching this repo, so the check is scheduled, not push-gated.

Two channels matter because they disagree: capnagent's GitHub release is 0.9.0
while `pip install capnagent` — the command in our own install docs — yields
0.7.4. Both must sit in band or some users get a broken `capframe`.

Fails closed: a lookup that cannot be resolved is an error, not a pass.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MODULES_RS = Path(__file__).resolve().parents[1] / "crates" / "capframe-cli" / "src" / "modules.rs"

# module short name -> (github repo, pypi package or None)
SOURCES = {
    "Find": ("euanmcrosson-dotcom/mcp-recon", None),
    "Bind": ("euanmcrosson-dotcom/capnagent", "capnagent"),
    "Guard": ("euanmcrosson-dotcom/mcp-guard", "mcp-guardrails"),
}


def parse_bands(src: str) -> dict[str, str]:
    """Pull the bands out of `pub fn version_req`, the single source of truth."""
    start = src.index("pub fn version_req")
    body = src[start : src.index("\n    }", start)]
    bands = dict(re.findall(r"Module::(Find|Bind|Guard)\s*=>\s*\"([^\"]+)\"", body))
    missing = set(SOURCES) - set(bands)
    if missing:
        raise SystemExit(f"could not parse bands for {sorted(missing)} from {MODULES_RS}")
    return bands


def to_tuple(v: str) -> tuple[int, ...]:
    """`v0.9.0-rc.1` -> (0, 9, 0). Pre-release is stripped, matching
    `version_in_band` in modules.rs, which accepts an RC of an in-band release."""
    v = v.strip().lstrip("vV").split("+")[0].split("-")[0]
    return tuple(int(p) for p in v.split("."))


def in_band(band: str, version: str) -> bool:
    """Evaluate a `>=X, <Y` band. Deliberately tiny: the bands are all this
    shape, and an unparseable comparator must fail loudly rather than pass."""
    v = to_tuple(version)
    for part in band.split(","):
        part = part.strip()
        m = re.fullmatch(r"(>=|<=|<|>|=)?\s*([0-9][0-9.]*)", part)
        if not m:
            raise SystemExit(f"unparseable comparator {part!r} in band {band!r}")
        op, bound = m.group(1) or "=", to_tuple(m.group(2))
        ok = {
            ">=": v >= bound, "<=": v <= bound,
            "<": v < bound, ">": v > bound, "=": v == bound,
        }[op]
        if not ok:
            return False
    return True


def fetch(url: str, path: tuple[str, ...]) -> str:
    """`path` walks into the JSON: ("tag_name",) for GitHub,
    ("info", "version") for PyPI. A missing key raises KeyError -> fail closed."""
    req = urllib.request.Request(url, headers={"User-Agent": "capframe-band-check"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    for key in path:
        data = data[key]
    if not isinstance(data, str):
        raise KeyError(f"expected a version string at {'.'.join(path)}, got {type(data).__name__}")
    return data


def main() -> int:
    bands = parse_bands(MODULES_RS.read_text(encoding="utf-8"))
    failures, checked = [], 0

    for name, (repo, pypi) in SOURCES.items():
        band = bands[name]
        channels = [
            ("github release", f"https://api.github.com/repos/{repo}/releases/latest", ("tag_name",))
        ]
        if pypi:
            channels.append((f"pypi/{pypi}", f"https://pypi.org/pypi/{pypi}/json", ("info", "version")))

        for channel, url, path in channels:
            try:
                version = fetch(url, path)
            except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
                failures.append(f"{name} [{channel}]: could not resolve shipped version ({e})")
                continue
            checked += 1
            ok = in_band(band, version)
            print(f"  {'ok ' if ok else 'DRIFT'}  {name:<6} {channel:<22} {version:<10} band {band}")
            if not ok:
                failures.append(
                    f"{name} [{channel}] ships {version}, outside its band {band} — "
                    f"`capframe {name.lower()}` is unreachable for anyone on that channel"
                )

    if failures:
        print(f"\n{len(failures)} problem(s):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"\nall {checked} shipped versions are in band")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
