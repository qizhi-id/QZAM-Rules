# First publication review — 2026-10-22

## Source and scope

- Official upstream: <https://github.com/gfwlist/gfwlist>.
- Source commit: [`4238995aba9dddd7d9f3e6821cd43bad9b87523d`](https://github.com/gfwlist/gfwlist/commit/4238995aba9dddd7d9f3e6821cd43bad9b87523d).
- Source header: `Last Modified: Sat, 17 Oct 2026 14:35:56 +0000`.
- Decoded UTF-8 SHA-256: `2009e12bbf4f8a4ae67ff0438c7e00f99a6219ff19c7e3d7107a6f8da1d02362`.
- Snapshot: 4,528 total lines, 4,413 effective rules; total lines include comments/headers/blanks.
- Reviewer: Claude Code, acting on the owner's final-integration request. Every quarantined original string was displayed and read before approval hashes were recorded.
- This is a reviewed **domain-oriented subset**, not a lossless AutoProxy implementation.

## Decisions

| Output / exclusion | Count | Decision |
| --- | ---: | --- |
| DIRECT domain suffixes | 31 | Preserve upstream domain-anchored exceptions |
| Proxy domain suffixes | 4,090 | Project domain anchors to Mihomo `DOMAIN-SUFFIX` |
| URL scheme/start/path-qualified expressions | 279 | Exclude; do not replace with broader domain matches |
| Wildcard/path expressions | 7 | Exclude; do not expand or guess hostnames |
| URL regex | 1 | Exclude; domain-only routing cannot retain URL semantics |
| Single-label domain fragments | 3 | Exclude `gle`, `google`, `goog`; not complete hostnames |
| Unanchored URL substrings | 2 | Exclude; URL substring is not a domain suffix |
| Exact DIRECT/proxy collisions | 0 | No collision approvals needed |

The 292 individual decisions, original strings, SHA-256 values and rationale are in [`policy/reviews/2026-10-22.json`](../policy/reviews/2026-10-22.json). The approval file contains exactly those reviewed hashes, not a blanket syntax/category approval. Changed or additional unsupported expressions must fail the next build until separately reviewed. Stale approvals are reported.

### Excluded DIRECT exceptions

- `@@||*.tokenplus.app`: no broader root/subdomain DIRECT rule is substituted. The supported proxy list includes `tokenplus.app`; excluding the exception can therefore cause proxy routing where upstream would use DIRECT.
- `@@/^https?:\/\/(?=.*?(2x3|ni5|j5o))[a-z0-9.-]+\.xn--ngstr-lra8j\.com$`: a URL regex exception; no whole-domain DIRECT substitution. Client fallback/other rules determine routing.

The converter's coarse `WILDCARD_OR_PATH` reason includes the second regex exception because of the `*` characters. It is explicitly reviewed as an exception regex here; this label does not change the exclusion decision.

### Domain hierarchy and priority

All 31 DIRECT domains are children of a supported proxy suffix (for example `fonts.gstatic.com` / `gstatic.com`). These are intentional upstream exceptions, not exact-domain collisions. A client must evaluate the DIRECT provider before the proxy provider. Any static client rules placed before either provider still take precedence; this repository does not override client policy.

### Important coverage boundaries

The subset includes `google.com`, `github.com`, `githubusercontent.com`, `openai.com`, `chatgpt.com`, `anthropic.com`, `claude.ai` and `telegram.org`.

URL-specific rules for Mozilla add-on downloads, Skype paths, `certificate.revocationcheck.com`, and `raindrop.io` are excluded and have no equivalent domain entry in this snapshot. Their actual routing depends on the client's other rules and GEOIP/fallback. No domain-wide replacement is asserted, and no real-site success is implied by converter unit tests.

## Publication and client acceptance

- Before approvals: the official fetch returned exit 3 (`REVIEW_REQUIRED`), and no provider YAML was published.
- After approvals: offline generation from the same captured source produced 31 DIRECT + 4,090 proxy entries, with zero unreviewed exclusions/collisions.
- Local converter suite: 5/5 passing with Python 3.12 and pinned PyYAML 6.0.2.
- GitHub online publication, cold-start provider fetch and Windows/iPhone checks are separate acceptance items. Do not mark them passed solely because this review exists.

## Attribution and license

Generated rule data is derived from GFWList, licensed under GNU LGPL 2.1; upstream license text is preserved in [`COPYING.txt`](../COPYING.txt). The modification here is domain-only normalization, sorting/deduplication, reviewed exclusions and YAML provider formatting. Original source for this snapshot is available at the source commit linked above; the upstream project remains the authoritative source.
