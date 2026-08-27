import pytest

from dmarcsight import audit
from dmarcsight.dnsq import FixtureResolver
from dmarcsight.report import FAIL, WARN, INFO, OK


def sev(rep, check):
    return {f.severity for f in rep.findings if f.check == check}


def findings(rep, check):
    return [f.finding for f in rep.findings if f.check == check]


def no_fetch(url, timeout=6):
    return None, "fetch disabled in tests"


def run(txt=None, mx=None, a=None, **kw):
    return audit("example.com",
                 resolver=FixtureResolver(txt=txt or {}, mx=mx or {}, a=a or {}),
                 fetch=no_fetch, **kw)


# --- SPF -------------------------------------------------------------------
def test_missing_spf_is_a_failure():
    assert FAIL in sev(run(), "SPF")


def test_plus_all_is_a_failure():
    rep = run(txt={"example.com": ["v=spf1 +all"]})
    assert any("+all" in f for f in findings(rep, "SPF"))
    assert FAIL in sev(rep, "SPF")


def test_two_spf_records_is_a_failure():
    rep = run(txt={"example.com": ["v=spf1 -all", "v=spf1 ip4:1.2.3.4 -all"]})
    assert FAIL in sev(rep, "SPF")


def test_lookup_limit_counted_through_nested_includes():
    # 11 includes, each resolving, should trip the RFC 7208 limit
    txt = {"example.com": ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(11)) + " -all"]}
    for n in range(11):
        txt[f"i{n}.test"] = ["v=spf1 ip4:10.0.0.1 -all"]
    rep = run(txt=txt)
    assert any("10 DNS-lookup limit" in f for f in findings(rep, "SPF"))


def test_include_loop_does_not_hang():
    rep = run(txt={"example.com": ["v=spf1 include:a.test -all"],
                   "a.test": ["v=spf1 include:b.test -all"],
                   "b.test": ["v=spf1 include:a.test -all"]})
    assert findings(rep, "SPF")


# --- DMARC -----------------------------------------------------------------
def test_missing_dmarc_is_a_failure():
    assert FAIL in sev(run(), "DMARC")


def test_reject_policy_is_ok():
    rep = run(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"]})
    assert any("p=reject" in f for f in findings(rep, "DMARC"))
    assert FAIL not in sev(rep, "DMARC")


def test_sp_none_under_enforcement_is_a_failure():
    # the subdomain hole: p=reject but sp=none leaves *.example.com spoofable
    rep = run(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com"]})
    assert FAIL in sev(rep, "DMARC")
    assert any("Subdomains are unprotected" in f for f in findings(rep, "DMARC"))


def test_partial_pct_is_flagged():
    rep = run(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; pct=20; rua=mailto:r@example.com"]})
    assert any("pct=20" in f for f in findings(rep, "DMARC"))


def test_missing_rua_is_flagged():
    rep = run(txt={"_dmarc.example.com": ["v=DMARC1; p=reject"]})
    assert any("rua" in f for f in findings(rep, "DMARC"))


# --- DKIM ------------------------------------------------------------------
def test_revoked_key_is_a_failure():
    rep = run(txt={"default._domainkey.example.com": ["v=DKIM1; k=rsa; p="]},
              selectors=["default"])
    assert FAIL in sev(rep, "DKIM")


def test_dkim_absence_is_warn_not_fail():
    # selectors are arbitrary, so not finding one proves nothing
    rep = run(selectors=["default"])
    assert FAIL not in sev(rep, "DKIM")
    assert WARN in sev(rep, "DKIM")


# --- MX --------------------------------------------------------------------
def test_mx_pointing_nowhere_is_a_failure():
    rep = run(mx={"example.com": [(10, "mail.example.com")]}, a={})
    assert FAIL in sev(rep, "MX")


def test_resolvable_mx_is_ok():
    rep = run(mx={"example.com": [(10, "mail.example.com")]},
              a={"mail.example.com": ["1.2.3.4"]})
    assert FAIL not in sev(rep, "MX")


# --- composite -------------------------------------------------------------
def test_bulk_sender_fails_without_auth():
    assert FAIL in sev(run(), "BULK-SENDER")


def test_bulk_sender_passes_with_full_auth():
    rep = run(txt={
        "example.com": ["v=spf1 ip4:1.2.3.4 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
        "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + "A" * 392],
    }, selectors=["s1"])
    assert FAIL not in sev(rep, "BULK-SENDER")


def test_exit_codes():
    assert run().exit_code() == 2
    clean = run(txt={
        "example.com": ["v=spf1 ip4:1.2.3.4 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
        "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + "A" * 392],
    }, mx={"example.com": [(10, "mx.example.com")]},
       a={"mx.example.com": ["1.2.3.4"]}, selectors=["s1"])
    assert clean.exit_code() in (0, 1)


def test_mta_sts_policy_uses_colon_syntax():
    # RFC 8461 policy files are "key: value", unlike the "k=v" DNS records.
    from dmarcsight.checks import _policy_tags
    body = "version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 86400\n"
    assert _policy_tags(body)["mode"] == "enforce"
