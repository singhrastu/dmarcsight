"""The actual checks.

Each check_* takes (domain, resolver, report) and appends findings. Nothing
raises: a check that can't resolve anything reports that as a finding rather
than blowing up the run.
"""
import re
import ssl
import urllib.request

from .report import FAIL, WARN, INFO, OK

# selectors worth probing when we have no better information. Ordered roughly by
# how often they turn up in the wild.
COMMON_SELECTORS = [
    # Microsoft, Google
    "selector1", "selector2", "google",
    # Proton and Fastmail publish fixed selectors via CNAME and are large enough
    # that omitting them means reporting "no DKIM found" for a correctly
    # configured domain, which is the worst kind of wrong answer this tool can
    # give: confident, and about the thing the user came to check.
    "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
    # ESPs
    "k1", "k2", "s1", "s2", "mandrill", "mailjet", "sendgrid", "smtpapi",
    "zoho", "everlytickey1", "pm", "mte1", "sig1", "hs1", "hs2", "ctct1",
    # generic
    "default", "mail", "dkim", "dkim1", "dkim2", "smtp", "fd", "key1", "key2",
]

# SPF mechanisms that each cost a DNS lookup. RFC 7208 caps the total at 10 and
# anything over it is a permerror, which most receivers treat as "no SPF".
LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")


def _fetch(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dmarcsight"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf8", "replace")
    except Exception as e:
        return None, str(e)


def _tags(record, sep=";"):
    """Parse DNS-style 'k=v; k=v' records."""
    out = {}
    for part in record.split(sep):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _policy_tags(body):
    """Parse an MTA-STS policy file. RFC 8461 uses 'key: value' per line, not
    the 'key=value' of the DNS records - easy to get wrong, and getting it wrong
    makes a perfectly good policy look malformed."""
    out = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.setdefault(k.strip().lower(), v.strip())
    return out


# --------------------------------------------------------------------------- SPF
def check_spf(domain, r, rep):
    records = [t for t in r.txt(domain) if t.lower().startswith("v=spf1")]

    if not records:
        rep.add("SPF", FAIL, "No SPF record",
                "Publish a v=spf1 record listing every source that sends as this domain, ending in -all.")
        return
    if len(records) > 1:
        rep.add("SPF", FAIL, f"{len(records)} SPF records published",
                "Merge into one. Multiple SPF records are a permerror and receivers will ignore SPF entirely.",
                " | ".join(records))
        return

    spf = records[0]
    rep.add("SPF", OK, "SPF record present", detail=spf)

    # all-qualifier
    m = re.search(r"([-~+?])all\b", spf)
    if not m:
        rep.add("SPF", WARN, "No 'all' mechanism",
                "Add -all (or ~all while testing). Without it the record has no default.")
    else:
        q = m.group(1)
        if q == "+":
            rep.add("SPF", FAIL, "SPF ends in +all",
                    "+all authorises the entire internet to send as you. Change to -all.")
        elif q == "?":
            rep.add("SPF", WARN, "SPF ends in ?all (neutral)",
                    "Neutral tells receivers nothing. Move to ~all then -all.")
        elif q == "~":
            rep.add("SPF", INFO, "SPF ends in ~all (softfail)",
                    "Fine while you're validating sources. Tighten to -all once you're confident.")
        else:
            rep.add("SPF", OK, "SPF ends in -all")

    # the lookup budget. This is the failure nobody sees coming: the record looks
    # fine, resolves fine, and silently permerrors once you add one more vendor.
    count = _count_lookups(domain, spf, r, set())
    if count > 10:
        rep.add("SPF", FAIL, f"SPF exceeds the 10 DNS-lookup limit (~{count})",
                "Flatten or remove includes. Over 10 lookups is a permerror and SPF stops working "
                "even though the record still resolves.")
    elif count >= 8:
        rep.add("SPF", WARN, f"SPF is near the 10-lookup limit (~{count})",
                "You have little headroom. Adding one more vendor will break SPF.")
    else:
        rep.add("SPF", OK, f"SPF uses about {count} of 10 DNS lookups")

    # A mechanism, not a substring: "include:ptr.example.com" is not ptr usage.
    uses_ptr = any((_mechanism(t) or (None,))[0] == "ptr" for t in spf.split())
    if uses_ptr:
        rep.add("SPF", WARN, "SPF uses the ptr mechanism",
                "ptr is deprecated by RFC 7208 and some receivers ignore it. Remove it.")


# RFC 7208 section 4.6.4: include, a, mx, ptr and exists each cost one DNS lookup,
# as does the redirect modifier. all, ip4, ip6 and exp cost nothing.
#
# Every mechanism may carry a qualifier (+ - ~ ?) and a and mx may carry a CIDR
# suffix (a/24, mx//64). Matching on bare "a:" and "a" misses "+a", "-a", "a/24"
# and "ptr:example.com", all of which are legal and all of which cost a lookup.
# Undercounting here means telling someone their record is safe when it permerrors.
_QUALIFIER = "+-~?"
_COSTS_A_LOOKUP = re.compile(r"^(include|a|mx|ptr|exists)(?:[:/]|$)", re.I)


def _mechanism(token):
    """(name, target) for a token, with the qualifier stripped. None if it is not
    a mechanism that costs a lookup."""
    t = token[1:] if token[:1] in _QUALIFIER else token
    low = t.lower()
    if low.startswith("redirect="):
        return "redirect", t.split("=", 1)[1].strip()
    m = _COSTS_A_LOOKUP.match(low)
    if not m:
        return None
    name = m.group(1)
    rest = t[len(name):]
    target = rest[1:].split("/")[0].strip() if rest[:1] == ":" else ""
    return name, target


def _count_lookups(domain, spf, r, path, depth=0):
    """Approximate the RFC 7208 lookup count by walking includes/redirects.

    `path` is the include chain above this record, not every target ever seen. A
    global set was wrong twice over: it made a domain that includes the same
    provider from two branches cost one lookup instead of two, which is not what
    a receiver does, and it was doing cycle detection's job badly. A cycle is a
    property of the path.
    """
    n = 0
    # RFC 7208 section 6.1: a redirect modifier is ignored when the record also
    # has an all mechanism. Counting it inflates the total and can report a
    # record that passes as one that permerrors.
    has_all = any((t[1:] if t[:1] in _QUALIFIER else t).lower() == "all"
                  for t in spf.split())
    for token in spf.split():
        mech = _mechanism(token)
        if mech is None:
            continue
        name, target = mech
        if name == "redirect" and has_all:
            continue
        n += 1
        if name not in ("include", "redirect") or not target:
            continue
        if target in path:
            continue
        # Past ten levels the record has already spent more than ten lookups, so
        # the verdict cannot change. Stop walking rather than returning a magic
        # number that the caller adds and reports as 110.
        if depth >= 10:
            continue
        sub = [x for x in r.txt(target) if x.lower().startswith("v=spf1")]
        if sub:
            n += _count_lookups(target, sub[0], r, path | {target}, depth + 1)
    return n


# --------------------------------------------------------------------------- DMARC
def check_dmarc(domain, r, rep):
    records = [t for t in r.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]

    if not records:
        rep.add("DMARC", FAIL, "No DMARC record",
                "Publish _dmarc TXT with p=none and rua= first, read the reports, then move to enforcement.")
        return
    if len(records) > 1:
        rep.add("DMARC", FAIL, f"{len(records)} DMARC records published",
                "Only one is allowed. Receivers will treat this as no DMARC.")
        return

    rec = records[0]
    t = _tags(rec)
    rep.add("DMARC", OK, "DMARC record present", detail=rec)

    p = t.get("p", "").lower()
    if p == "reject":
        rep.add("DMARC", OK, "Policy is p=reject (full enforcement)")
    elif p == "quarantine":
        rep.add("DMARC", WARN, "Policy is p=quarantine",
                "Partial protection. Spoofed mail lands in spam rather than being rejected. Move to p=reject.")
    elif p == "none":
        rep.add("DMARC", WARN, "Policy is p=none (monitoring only)",
                "p=none blocks nothing. It satisfies the bulk-sender minimum but does not stop spoofing.")
    else:
        rep.add("DMARC", FAIL, f"Invalid or missing policy tag (p={p or 'absent'})",
                "p= is required and must be none, quarantine or reject.")

    pct = t.get("pct")
    if pct and pct != "100":
        rep.add("DMARC", WARN, f"pct={pct}: policy applies to only {pct}% of mail",
                "The other portion is unprotected. Ramp pct to 100 once reports look clean.")

    if not t.get("rua"):
        rep.add("DMARC", WARN, "No rua= aggregate reporting address",
                "Without rua you are enforcing blind. Add one and read the reports.")
    else:
        rep.add("DMARC", OK, "Aggregate reporting (rua) configured", detail=t["rua"])

    sp = t.get("sp")
    if sp and sp.lower() == "none" and p in ("quarantine", "reject"):
        rep.add("DMARC", FAIL, f"Subdomains are unprotected (sp=none while p={p})",
                "Attackers will spoof a subdomain instead. Remove sp= so it inherits p, or set sp=reject.")
    elif not sp:
        rep.add("DMARC", INFO, "No sp= tag, so subdomains inherit the main policy")

    adkim, aspf = t.get("adkim", "r"), t.get("aspf", "r")
    if adkim == "r" and aspf == "r":
        rep.add("DMARC", INFO, "Relaxed alignment for both SPF and DKIM (the default)")
    if adkim == "s" or aspf == "s":
        rep.add("DMARC", INFO, f"Strict alignment in use (adkim={adkim}, aspf={aspf})",
                "Strict alignment breaks subdomain and some ESP sending. Confirm that is intended.")


# --------------------------------------------------------------------------- DKIM
def check_dkim(domain, r, rep, selectors=None):
    sels = selectors or COMMON_SELECTORS
    found = []
    for s in sels:
        for txt in r.txt(f"{s}._domainkey.{domain}"):
            if "v=dkim1" in txt.lower() or "p=" in txt:
                found.append((s, txt))
                break

    if not found:
        rep.add("DKIM", WARN, f"No DKIM key found on {len(sels)} common selectors",
                "This is inconclusive, not proof of absence - selectors are arbitrary. "
                "Pass --selector if you know yours.",
                "tried: " + ", ".join(sels[:8]) + "...")
        return

    for sel, txt in found:
        t = _tags(txt)
        key = t.get("p", "")
        if not key:
            rep.add("DKIM", FAIL, f"Selector '{sel}' has an empty p= (revoked key)",
                    "An empty p= means the key is revoked. Remove the record or publish a real key.")
            continue
        # RFC 8463 keys are Ed25519 and 32 bytes, which is 44 base64 characters.
        # Measuring one in RSA bits reports about 227 and fails a perfectly good
        # record, so read k= before judging length.
        if t.get("k", "rsa").lower() == "ed25519":
            if len("".join(key.split())) >= 40:
                rep.add("DKIM", OK, f"Selector '{sel}' publishes an Ed25519 key",
                        "", "k=ed25519")
            else:
                rep.add("DKIM", FAIL, f"Selector '{sel}' Ed25519 key looks truncated",
                        "An Ed25519 public key is 32 bytes, so 44 base64 characters. "
                        "Republish it.")
            continue
        # rough bit estimate from the base64 length
        bits = int(len(key) * 6 / 8 * 8 / 1.16)
        if bits < 1024:
            rep.add("DKIM", FAIL, f"Selector '{sel}' key looks shorter than 1024 bits",
                    "Keys under 1024 bits are rejected by several receivers. Rotate to 2048.")
        elif bits < 2000:
            rep.add("DKIM", INFO, f"Selector '{sel}' publishes roughly a 1024-bit key",
                    "Acceptable, but 2048 is the current norm.")
        else:
            rep.add("DKIM", OK, f"Selector '{sel}' publishes roughly a 2048-bit key")


# --------------------------------------------------------------------------- MTA-STS
def check_mta_sts(domain, r, rep, fetch=_fetch):
    txts = [t for t in r.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    if not txts:
        rep.add("MTA-STS", INFO, "No MTA-STS record",
                "Optional, but it prevents TLS downgrade on inbound mail. Worth publishing.")
        return

    rep.add("MTA-STS", OK, "MTA-STS DNS record present", detail=txts[0])

    status, body = fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    if status != 200:
        rep.add("MTA-STS", FAIL, "Policy file is not reachable",
                "The DNS record promises a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt. "
                "If it 404s the whole mechanism is inert.",
                f"result: {status or body}")
        return

    policy = _policy_tags(body)
    mode = policy.get("mode", "").lower()
    if mode == "enforce":
        rep.add("MTA-STS", OK, "Policy mode is enforce")
    elif mode == "testing":
        rep.add("MTA-STS", WARN, "Policy mode is testing",
                "Testing mode reports but does not enforce. Move to enforce once TLS-RPT looks clean.")
    elif mode == "none":
        rep.add("MTA-STS", WARN, "Policy mode is none (disabled)")
    else:
        rep.add("MTA-STS", FAIL, f"Policy has an invalid mode ({mode or 'absent'})")

    # the mismatch that quietly breaks inbound mail
    listed = re.findall(r"^mx:\s*(\S+)", body, re.M | re.I)
    actual = [h.lower() for _, h in r.mx(domain)]
    if listed and actual:
        unmatched = [h for h in actual
                     if not any(_mx_matches(pat.lower(), h) for pat in listed)]
        if unmatched:
            rep.add("MTA-STS", FAIL, "Live MX hosts are not covered by the policy",
                    "Under enforce, mail to an uncovered MX is refused. Add the missing hosts.",
                    "uncovered: " + ", ".join(unmatched))
        else:
            rep.add("MTA-STS", OK, f"All {len(actual)} MX hosts are covered by the policy")


def _mx_matches(pattern, host):
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return pattern == host


# --------------------------------------------------------------------------- misc
def check_tls_rpt(domain, r, rep):
    txts = [t for t in r.txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    if txts:
        rep.add("TLS-RPT", OK, "TLS-RPT configured", detail=txts[0])
    else:
        rep.add("TLS-RPT", INFO, "No TLS-RPT record",
                "Add one to get reports on TLS negotiation failures against your MX.")


def check_bimi(domain, r, rep, fetch=_fetch):
    txts = [t for t in r.txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
    if not txts:
        rep.add("BIMI", INFO, "No BIMI record",
                "BIMI needs DMARC at enforcement first. Not worth attempting before then.")
        return
    t = _tags(txts[0])
    rep.add("BIMI", OK, "BIMI record present", detail=txts[0])
    if not t.get("a"):
        rep.add("BIMI", WARN, "BIMI has no VMC (a= tag)",
                "Gmail and Apple require a Verified Mark Certificate to display the logo.")
    if t.get("l"):
        status, _ = fetch(t["l"])
        if status != 200:
            rep.add("BIMI", FAIL, "BIMI logo URL is not reachable",
                    "The SVG at l= must be publicly fetchable over HTTPS.", t["l"])


def check_mx(domain, r, rep):
    mx = r.mx(domain)
    if not mx:
        rep.add("MX", WARN, "No MX records",
                "Fine for a send-only domain, but it cannot receive replies, bounces or FBL mail.")
        return
    rep.add("MX", OK, f"{len(mx)} MX host(s)",
            detail=", ".join(f"{p} {h}" for p, h in mx))
    for _, host in mx:
        if not r.a(host):
            rep.add("MX", FAIL, f"MX host {host} does not resolve",
                    "An MX pointing at a name with no A/AAAA record silently blackholes inbound mail.")


def check_bulk_sender_readiness(domain, rep):
    """Composite verdict against the Gmail/Yahoo/Microsoft bulk sender rules.

    Derived from findings already gathered, so it must run last.
    """
    by = {}
    for f in rep.findings:
        by.setdefault(f.check, []).append(f)

    def failed(check):
        return any(f.severity == FAIL for f in by.get(check, []))

    problems = []
    if failed("SPF") or not by.get("SPF"):
        problems.append("SPF")
    if failed("DMARC") or not by.get("DMARC"):
        problems.append("DMARC")
    if any("No DMARC record" in f.finding for f in by.get("DMARC", [])):
        problems.append("DMARC (absent)")
    dkim_unverified = any("No DKIM key found" in f.finding for f in by.get("DKIM", []))

    if problems:
        rep.add("BULK-SENDER", FAIL,
                "Not meeting the Gmail/Yahoo/Microsoft bulk sender requirements",
                "Senders over 5,000 messages/day need SPF, DKIM and DMARC (p=none minimum), "
                "one-click List-Unsubscribe, and a spam complaint rate under 0.3%.",
                "gaps: " + ", ".join(problems))
    elif dkim_unverified:
        rep.add("BULK-SENDER", WARN,
                "SPF and DMARC meet the baseline, DKIM could not be verified",
                "Re-run with --selector once you know your selector. Also confirm one-click "
                "List-Unsubscribe and a complaint rate under 0.3% - neither is visible from DNS.")
    else:
        rep.add("BULK-SENDER", OK,
                "Authentication meets the bulk sender baseline",
                "Still verify one-click List-Unsubscribe and complaint rate under 0.3% - "
                "neither is visible from DNS.")
