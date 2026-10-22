#!/usr/bin/env python3
"""Conservative GFWList AutoProxy -> Mihomo classical rule-provider conversion.

Domain-anchored patterns are projected to Mihomo domain-suffix rules. AutoProxy
anchors WITHOUT a trailing ^ are not exactly equivalent to domain-suffix
matching; this is an intentional domain-level subset, NOT a lossless port.
All URL-path,
regex, wildcard and substring rules are quarantined for human review. The
unapproved quarantine must stop publication rather than silently drop rules.
This is a public-rule builder, not a client config or secret store.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import yaml

UPSTREAM_URL = 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'
MAX_SOURCE_BYTES = 1_000_000
DOMAIN = re.compile(r'^\|\|([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)\^?$')
LABEL = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def download_source() -> bytes:
    req = Request(UPSTREAM_URL, headers={'User-Agent': 'QZAM-Rules-Builder/1.1'})
    with urlopen(req, timeout=25) as response:
        if response.geturl() != UPSTREAM_URL:
            raise ValueError('upstream redirected; manual review required')
        if response.status != 200:
            raise ValueError('upstream returned unexpected status')
        data = response.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES or len(data) < 100:
        raise ValueError('unreasonable GFWList source size')
    return data


def decode_source(raw: bytes) -> str:
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError('source too large')
    try:
        compact = re.sub(rb'\s+', b'', raw)
        decoded = base64.b64decode(compact, validate=True).decode('utf-8-sig')
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError('not valid Base64 UTF-8 GFWList') from exc
    if not decoded.startswith('[AutoProxy '):
        raise ValueError('AutoProxy header absent')
    return decoded


def normalized_domain(rule: str) -> str | None:
    match = DOMAIN.fullmatch(rule)
    if not match:
        return None
    value = match.group(1).lower().rstrip('.')
    if len(value) > 253 or '.' not in value:
        return None
    if not all(LABEL.fullmatch(label) for label in value.split('.')):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        return value


def unsupported_reason(rule: str) -> str:
    expr = rule[2:] if rule.startswith('@@') else rule
    if expr.startswith('/') and expr.endswith('/'):
        return 'REGEX_URL_MATCH'
    if expr.startswith(('http://', 'https://', '|http://', '|https://')):
        return 'URL_SCHEME_OR_PATH'
    if '*' in expr:
        return 'WILDCARD_OR_PATH'
    if '/' in expr:
        return 'URL_PATH'
    if expr.startswith('||'):
        return 'NONSTANDARD_DOMAIN_ANCHOR'
    return 'SUBSTRING_OR_OTHER'


def convert(source: str) -> tuple[dict, dict, dict]:
    direct: set[str] = set()
    proxy: set[str] = set()
    unsupported: dict[str, str] = {}
    total = 0
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
        total += 1
        exception = line.startswith('@@')
        expr = line[2:] if exception else line
        domain = normalized_domain(expr)
        if domain:
            (direct if exception else proxy).add(domain)
        else:
            digest = sha256_text(line)
            unsupported[digest] = line
    both = direct & proxy
    reason_counts: dict[str, int] = {}
    for value in unsupported.values():
        reason = unsupported_reason(value)
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    # A whitelist exception is always evaluated before the blocklist provider.
    # Do not delete proxy members; track collisions in the report.
    direct_rule = {'payload': [f'DOMAIN-SUFFIX,{d}' for d in sorted(direct)]}
    proxy_rule = {'payload': [f'DOMAIN-SUFFIX,{d}' for d in sorted(proxy)]}
    report = {
        'source_kind': 'gfwlist-autoproxy-base64',
        'source_sha256_decoded': sha256_text(source),
        'effective_entries': total,
        'direct_domains': len(direct),
        'proxy_domains': len(proxy),
        'unsupported_count': len(unsupported),
        'unsupported_sha256': sorted(unsupported),
        'unsupported_for_review': [{'sha256': h, 'reason': unsupported_reason(unsupported[h]), 'original_rule': unsupported[h]} for h in sorted(unsupported)],
        'unsupported_reason_counts': dict(sorted(reason_counts.items())),
        'direct_proxy_collision_count': len(both),
        'direct_proxy_collisions': sorted(both),
        'conversion_semantics': 'domain-anchor to DOMAIN-SUFFIX projection; un-terminated ||host may differ at URL host boundary; URL/path/regex/substring excluded',
    }
    return direct_rule, proxy_rule, report


def build(source_b64: bytes, approved_hashes: set[str], *, minimum_proxy: int = 1000):
    source = decode_source(source_b64)
    direct, proxy, report = convert(source)
    unreviewed = sorted(set(report['unsupported_sha256']) - approved_hashes)
    stale = sorted(approved_hashes - set(report['unsupported_sha256']))
    report['unreviewed_sha256'] = unreviewed
    report['unreviewed_count'] = len(unreviewed)
    report['stale_approvals'] = stale
    if len(proxy['payload']) < minimum_proxy:
        raise ValueError(f'proxy rule count below reviewed safety minimum {minimum_proxy}')
    if not direct['payload']:
        raise ValueError('direct exceptions vanished')
    return direct, proxy, report


def save_yaml(path: Path, content: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = yaml.safe_dump(content, allow_unicode=True, sort_keys=False)
    source_notice = '# Derived from GFWList: https://github.com/gfwlist/gfwlist\n'
    license_notice = '# License: GNU LGPL 2.1; see COPYING.txt in this repository.\n'
    if path.is_file():
        previous = path.read_text('utf-8')
        if (previous.startswith(source_notice) and license_notice in previous
                and re.search(r'^# Modified by QZAM on \d{4}-\d{2}-\d{2}:', previous, re.M)
                and previous.endswith(payload)):
            return  # Keep the actual modification date when content is unchanged.
    modified = datetime.now(timezone.utc).date().isoformat()
    notice = (source_notice + f'# Modified by QZAM on {modified}: domain-only normalization, '
              'reviewed exclusions and YAML formatting.\n' + license_notice)
    path.write_text(notice + payload, encoding='utf-8', newline='\n')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--input', type=Path, help='Base64 GFWList source, offline')
    source.add_argument('--fetch', action='store_true', help='fetch official upstream, CI only')
    parser.add_argument('--approved-file', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--min-proxy', type=int, default=1000)
    args = parser.parse_args(argv)
    try:
        approvals = json.loads(args.approved_file.read_text('utf-8'))
        reviewed = approvals['approved_unsupported_sha256']
        if not isinstance(reviewed, list) or not all(isinstance(x, str) and re.fullmatch(r'[0-9a-f]{64}', x) for x in reviewed):
            raise ValueError('invalid approvals')
        approved = set(reviewed)
        raw = download_source() if args.fetch else args.input.read_bytes()
        direct, proxy, report = build(raw, approved, minimum_proxy=args.min_proxy)
        allowed_collisions = set(approvals.get('approved_collisions', []))
        collision_violations = sorted(set(report['direct_proxy_collisions']) - allowed_collisions)
        report['unreviewed_collisions'] = collision_violations
        out = args.output_dir
        (out / 'report').mkdir(parents=True, exist_ok=True)
        (out / 'report' / 'conversion.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', 'utf-8')
        if report['unreviewed_count'] or collision_violations:
            print(f'REVIEW_REQUIRED: {report["unreviewed_count"]} unsupported, '
                  f'{len(collision_violations)} collision approvals missing; files NOT published', file=sys.stderr)
            return 3
        save_yaml(out / 'rules' / 'gfwlist-direct.yaml', direct)
        save_yaml(out / 'rules' / 'gfwlist-proxy.yaml', proxy)
        print(f'OK: {len(direct["payload"])} direct; {len(proxy["payload"])} proxy; '
              f'{report["unsupported_count"]} reviewed exclusions')
        return 0
    except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
        print(f'BUILD_FAILED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
