"""Findings and severity."""
from dataclasses import dataclass, asdict, field

FAIL = "fail"      # mail is broken or trivially spoofable
WARN = "warn"      # works today, will bite you
INFO = "info"      # worth knowing
OK = "ok"

_ORDER = {FAIL: 0, WARN: 1, INFO: 2, OK: 3}


@dataclass
class Finding:
    check: str
    severity: str
    finding: str
    remediation: str = ""
    detail: str = ""

    def as_dict(self):
        return asdict(self)


@dataclass
class Report:
    domain: str
    findings: list = field(default_factory=list)

    def add(self, check, severity, finding, remediation="", detail=""):
        self.findings.append(Finding(check, severity, finding, remediation, detail))

    def sorted(self):
        return sorted(self.findings, key=lambda f: (_ORDER[f.severity], f.check))

    def counts(self):
        c = {FAIL: 0, WARN: 0, INFO: 0, OK: 0}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def exit_code(self):
        c = self.counts()
        if c[FAIL]:
            return 2
        if c[WARN]:
            return 1
        return 0

    def as_dict(self):
        return {"domain": self.domain,
                "counts": self.counts(),
                "findings": [f.as_dict() for f in self.sorted()]}
