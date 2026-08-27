# dmarcsight

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

## TODO

- parse DMARC aggregate (RUA) XML reports
- DANE / TLSA
- ARC chain inspection
- optional live SMTP probe to confirm STARTTLS behaviour matches the MTA-STS policy

MIT.
