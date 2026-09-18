# dmarcsight

**[Run it in your browser](https://rastu.tech/check/)** &mdash; no install, nothing sent
to a server. The hosted version is a JavaScript port of this package, checked against it
on every build so the two cannot report different findings.

Audits a domain's email authentication posture and tells you what is actually broken.

```
$ dmarcsight example.com

  [FAIL] SPF          SPF exceeds the 10 DNS-lookup limit (~13)
                      -> Flatten or remove includes. Over 10 lookups is a permerror and SPF
                         stops working even though the record still resolves.
  [FAIL] DMARC        Subdomains are unprotected (sp=none while p=reject)
                      -> Attackers will spoof a subdomain instead. Remove sp= so it inherits p.
  [WARN] MTA-STS      Policy mode is testing
  [ok  ] DKIM         Selector 's1' publishes roughly a 2048-bit key
```

Checks SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI and MX, then gives a composite verdict
against the Gmail/Yahoo/Microsoft bulk sender requirements.

## Install

```
pip install -e .
```

## Use

```
dmarcsight example.com
dmarcsight example.com --quiet          # only fails and warnings
dmarcsight example.com --json
dmarcsight example.com --selector s1 --selector s2
```

Exit code is `0` clean, `1` warnings, `2` failures, so it works as a CI gate:

```
dmarcsight "$DOMAIN" --quiet || exit 1
```

As a library:

```python
from dmarcsight import audit

rep = audit("example.com")
rep.exit_code()                              # 2
[f.finding for f in rep.sorted()][:3]
```

## The checks that matter

Most authentication checkers tell you whether a record exists. Existing is not the same as
working. These are the ones that bite:

**The SPF 10-lookup limit.** RFC 7208 caps `include`, `a`, `mx`, `ptr`, `exists` and
`redirect` at 10 DNS lookups combined. Go over and it is a permerror, which most receivers
treat as no SPF at all. The record still resolves and still looks correct, so nothing
appears wrong until mail starts failing. `dmarcsight` walks nested includes and counts.

**`sp=none` under enforcement.** A domain at `p=reject` with `sp=none` has left every
subdomain wide open. Attackers don't spoof `example.com`, they spoof
`billing.example.com`.

**`pct` below 100.** A policy that applies to 20% of mail protects 20% of mail. It is
frequently set during a rollout and then forgotten.

**MTA-STS MX mismatch.** If the policy file lists MX hosts that no longer match live DNS,
then under `mode: enforce` mail to the uncovered hosts is refused outright. Adding an MX
without updating the policy is how this happens.

**Empty DKIM `p=`.** A revoked key. The record exists, the selector resolves, and every
signature fails.

## Notes

DKIM absence is reported as a warning, never a failure. Selectors are arbitrary strings,
so probing 22 common ones and finding nothing proves nothing. Pass `--selector` when you
know yours.

MTA-STS policy files use `key: value` per line (RFC 8461), unlike the `k=v; k=v` of the DNS
records. Parsing them with the DNS parser makes a perfectly valid policy look malformed.
That one cost me a bug.

Key-size estimates from the base64 `p=` blob are approximate. They are good enough to tell
1024 from 2048, which is the distinction that matters.

## Planned

- DANE and TLSA
- ARC chain inspection
- An optional live SMTP probe, to confirm STARTTLS behaviour matches what the
  MTA-STS policy promises

Aggregate report parsing shipped separately, as the
[DMARC report reader](https://rastu.tech/dmarc/).

## What it will not tell you

- **That DKIM is absent.** Selectors are arbitrary strings chosen by the sender, so
  probing a list of common ones and finding nothing proves nothing. A miss is reported
  as inconclusive, never as absent, and any tool that publishes a "DKIM adoption" figure
  derived that way is guessing.
- **That a published record is correct.** DNS presence is not correctness. A record can
  resolve perfectly and still authorise the wrong sources.
- **That you are compliant.** Two of the Gmail and Yahoo bulk sender requirements,
  one-click List-Unsubscribe and a complaint rate under 0.3%, are not visible from DNS.

## Related

- [DMARC report reader](https://rastu.tech/dmarc/) &mdash; read an aggregate rua report,
  in the browser, without uploading it anywhere
- [SPF lookup counter](https://rastu.tech/spf/) &mdash; the full include tree with a
  running RFC 7208 lookup count
- [smtpsift](https://github.com/singhrastu/smtpsift) &mdash; the bounce half: classify an
  SMTP rejection into the action it needs
- [The State of Email Authentication](https://rastu.tech/research/) &mdash; this tool run
  across 100,000 domains, with the dataset published

## Author

**Rastu Singh** &mdash; Infrastructure Engineer working on email platforms, deliverability
and email security, in Tallinn, Estonia. The checks here are the ones that turned out to
matter while running production sending estates: the SPF lookup limit that breaks a record
silently, and an MTA-STS policy that 404s behind a DNS record promising it.

[rastu.tech](https://rastu.tech) &middot;
[LinkedIn](https://www.linkedin.com/in/rastu) &middot;
[ORCID 0009-0002-0526-3005](https://orcid.org/0009-0002-0526-3005)

## Licence

MIT.
