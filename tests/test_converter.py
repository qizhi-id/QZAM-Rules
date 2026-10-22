import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from scripts.gfwlist_convert import build, convert, decode_source, sha256_text, main, save_yaml


class ConverterTests(unittest.TestCase):
    SOURCE = ('[AutoProxy 0.2.9]\n! sample\n||google.com^\n||github.com\n'
              '@@||apple.com^\n@@||github.com^\n|https://foo.example.com/private\n'
              '/^https?:\\/\\/.*\\.blocked/\n||cdn*.foo.com\n')

    def b64(self, text=None):
        return base64.b64encode((text or self.SOURCE).encode('utf-8'))

    def test_strict_domain_only_and_direct_override(self):
        direct, proxy, report = convert(self.SOURCE)
        self.assertEqual(proxy['payload'], ['DOMAIN-SUFFIX,github.com', 'DOMAIN-SUFFIX,google.com'])
        self.assertEqual(direct['payload'], ['DOMAIN-SUFFIX,apple.com', 'DOMAIN-SUFFIX,github.com'])
        self.assertEqual(report['unsupported_count'], 3)
        self.assertEqual(report['direct_proxy_collisions'], ['github.com'])

    def test_invalid_source_and_untrusted_syntax_not_interpreted(self):
        for raw in (b'invalid!', base64.b64encode(b'not an AutoProxy header')):
            with self.assertRaises(ValueError):
                decode_source(raw)
        direct, proxy, report = convert('[AutoProxy 0.2.9]\n@@|https://www.specific.com/private\n')
        self.assertEqual(direct['payload'], [])
        self.assertEqual(report['unsupported_count'], 1)

    def test_review_gate_and_approved_generation(self):
        direct, proxy, report = build(self.b64(), set(), minimum_proxy=2)
        self.assertEqual(report['unreviewed_count'], 3)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            file = root / 'input.txt'
            file.write_bytes(self.b64())
            approvals = root / 'approved.json'
            out = root / 'output'
            approvals.write_text(json.dumps({'approved_unsupported_sha256': [], 'approved_collisions': []}))
            status = main(['--input', str(file), '--approved-file', str(approvals),
                           '--output-dir', str(out), '--min-proxy', '2'])
            self.assertEqual(status, 3)
            self.assertFalse((out / 'rules' / 'gfwlist-proxy.yaml').exists())
            approvals.write_text(json.dumps({'approved_unsupported_sha256': report['unsupported_sha256'],
                                             'approved_collisions': ['github.com']}))
            status = main(['--input', str(file), '--approved-file', str(approvals),
                           '--output-dir', str(out), '--min-proxy', '2'])
            self.assertEqual(status, 0)
            self.assertTrue((out / 'rules' / 'gfwlist-direct.yaml').exists())
            self.assertTrue((out / 'rules' / 'gfwlist-proxy.yaml').exists())

    def test_new_unsupported_changes_must_require_new_approval(self):
        known = convert(self.SOURCE)[2]['unsupported_sha256']
        changed = self.SOURCE + '|https://brandnew.example.net/path\n'
        _, _, report = build(self.b64(changed), set(known), minimum_proxy=2)
        self.assertEqual(report['unreviewed_count'], 1)

    def test_safety_floor(self):
        with self.assertRaises(ValueError):
            build(self.b64(), set(), minimum_proxy=1000)

    def test_generated_notice_and_unchanged_modification_date(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'provider.yaml'
            content = {'payload': ['DOMAIN-SUFFIX,example.com']}
            with patch('scripts.gfwlist_convert.datetime') as clock:
                clock.now.return_value = datetime(2026, 10, 22, tzinfo=timezone.utc)
                save_yaml(path, content)
                first = path.read_text('utf-8')
                self.assertIn('# Modified by QZAM on 2026-10-22:', first)
                self.assertIn('GNU LGPL 2.1', first)
                clock.now.return_value = datetime(2026, 10, 23, tzinfo=timezone.utc)
                save_yaml(path, content)
                self.assertEqual(path.read_text('utf-8'), first)
                save_yaml(path, {'payload': ['DOMAIN-SUFFIX,changed.example.com']})
                self.assertIn('# Modified by QZAM on 2026-10-23:', path.read_text('utf-8'))


if __name__ == '__main__':
    unittest.main()
