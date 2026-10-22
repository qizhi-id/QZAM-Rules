# QZAM-Rules

Separate public rule-data repository: `qizhi-id/QZAM-Rules`.
Never publish live client profiles, server settings, UUIDs, subscription URLs or SS passwords.

Once independently reviewed, store approved unsupported AutoProxy rule hashes in
`policy/approved_unsupported.json`. The first official run **deliberately fails**
with `REVIEW_REQUIRED` until a reviewer signs off on *every* unsupported rule.
New unsupported rules or new exception/deny collisions stop publication. The last
committed verified rule files remain available unchanged.

Schedule: daily at 02:27 UTC, plus manual workflow dispatch. Only changed valid
outputs are committed to `main` using the repo's scoped GitHub token.

Client URLs after the public repo has been created and first verified publication:
- `https://raw.githubusercontent.com/qizhi-id/QZAM-Rules/main/rules/gfwlist-direct.yaml`
- `https://raw.githubusercontent.com/qizhi-id/QZAM-Rules/main/rules/gfwlist-proxy.yaml`

AutoProxy includes URL/path, wildcard and regex syntax that a domain-only
Mihomo rule-provider cannot represent exactly. This build publishes an
**explicitly reviewed domain-oriented subset**, not a full semantics-preserving GFWList port. Original `||example.com` patterns without the `^` terminator are mapped to `DOMAIN-SUFFIX,example.com`; that captures intended host/subdomain routing but does not preserve every URL matcher edge case.
Rules requiring URL/path matching remain excluded until intentionally reviewed
or replaced with exact domain-equivalent handling.

Network access to `raw.githubusercontent.com` may require a working proxy;
configure Mihomo's provider fetch via `QZ-FIXED` and verify cold-start cache.
Do not treat GitHub schedules or iOS client refresh intervals as real-time guarantees.
