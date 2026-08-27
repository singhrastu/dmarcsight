"""Thin DNS wrapper.

Kept separate so tests can swap in a fixture resolver instead of hitting the
network. Everything in checks.py goes through this.
"""
import dns.resolver
import dns.exception


class Resolver:
    def __init__(self, timeout=5.0, nameservers=None):
        self._r = dns.resolver.Resolver()
        self._r.timeout = timeout
        self._r.lifetime = timeout
        if nameservers:
            self._r.nameservers = nameservers

    def txt(self, name):
        """TXT records as joined strings. DNS splits long TXT into 255-byte
        chunks and they must be concatenated before parsing - a long DKIM key
        or SPF record will look malformed otherwise."""
        try:
            answers = self._r.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        out = []
        for rdata in answers:
            out.append("".join(s.decode("utf8", "replace") for s in rdata.strings))
        return out

    def mx(self, name):
        try:
            answers = self._r.resolve(name, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        return sorted(((r.preference, str(r.exchange).rstrip(".")) for r in answers))

    def a(self, name):
        out = []
        for rr in ("A", "AAAA"):
            try:
                out += [str(r) for r in self._r.resolve(name, rr)]
            except Exception:
                pass
        return out

    def exists(self, name):
        try:
            self._r.resolve(name, "A")
            return True
        except dns.resolver.NoAnswer:
            return True   # name exists, just no A
        except Exception:
            return False


class FixtureResolver:
    """Test double. Give it dicts of name -> records."""

    def __init__(self, txt=None, mx=None, a=None):
        self._txt, self._mx, self._a = txt or {}, mx or {}, a or {}

    def txt(self, name):
        return self._txt.get(name.rstrip("."), [])

    def mx(self, name):
        return self._mx.get(name.rstrip("."), [])

    def a(self, name):
        return self._a.get(name.rstrip("."), [])

    def exists(self, name):
        n = name.rstrip(".")
        return n in self._a or n in self._txt or n in self._mx
