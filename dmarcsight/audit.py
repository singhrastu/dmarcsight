"""Run every check against a domain."""
from . import checks
from .dnsq import Resolver
from .report import Report


def audit(domain, resolver=None, selectors=None, fetch=None):
    domain = domain.strip().lower().rstrip(".")
    r = resolver or Resolver()
    rep = Report(domain)
    kw = {"fetch": fetch} if fetch else {}

    checks.check_spf(domain, r, rep)
    checks.check_dkim(domain, r, rep, selectors)
    checks.check_dmarc(domain, r, rep)
    checks.check_mta_sts(domain, r, rep, **kw)
    checks.check_tls_rpt(domain, r, rep)
    checks.check_bimi(domain, r, rep, **kw)
    checks.check_mx(domain, r, rep)
    checks.check_bulk_sender_readiness(domain, rep)   # must be last
    return rep
