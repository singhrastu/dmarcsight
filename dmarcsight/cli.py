"""CLI.

  dmarcsight example.com
  dmarcsight example.com --json
  dmarcsight example.com --selector s1 --selector s2

Exit code: 0 clean, 1 warnings, 2 failures. Usable as a CI gate.
"""
import argparse
import json
import sys

from .audit import audit
from .dnsq import Resolver
from .report import FAIL, WARN, INFO, OK

MARK = {FAIL: "FAIL", WARN: "WARN", INFO: "info", OK: "ok  "}


def main(argv=None):
    p = argparse.ArgumentParser(prog="dmarcsight",
                                description="Audit a domain's email authentication posture.")
    p.add_argument("domain")
    p.add_argument("--selector", action="append", help="DKIM selector (repeatable)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", action="store_true", help="hide ok and info findings")
    p.add_argument("--timeout", type=float, default=5.0)
    a = p.parse_args(argv)

    rep = audit(a.domain, resolver=Resolver(timeout=a.timeout), selectors=a.selector)

    if a.json:
        print(json.dumps(rep.as_dict(), indent=2))
        return rep.exit_code()

    print(f"\n{rep.domain}\n")
    hide = {OK, INFO} if a.quiet else set()
    for f in rep.sorted():
        if f.severity in hide:
            continue
        print(f"  [{MARK[f.severity]}] {f.check:12} {f.finding}")
        if f.detail:
            print(f"                      {f.detail[:150]}")
        if f.remediation and f.severity in (FAIL, WARN):
            print(f"                      -> {f.remediation}")
    c = rep.counts()
    print(f"\n  {c[FAIL]} fail, {c[WARN]} warn, {c[INFO]} info, {c[OK]} ok\n")
    return rep.exit_code()


if __name__ == "__main__":
    sys.exit(main())
