"""Regression checks for false-green reports. No cryptographic benchmarks here."""
import os
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from check_timing import classify
from check_dependencies import check
from check_test_results import check as check_rust
from run_timing_attribution import verdict

HERE = Path(__file__).resolve().parent


def result(name, t):
    return f'bench {name} ... : n == +0.100M, max t = {t}, max tau = 0\ndudect benches complete\n'


class Timing(unittest.TestCase):
    def test_detects_signal(self):
        self.assertEqual(classify(result('bench_case', 722), ['bench_case'])['status'], 'FAIL')

    def test_control_is_inconclusive(self):
        self.assertEqual(classify(result('bench_same_key_control', 7), ['bench_same_key_control'])['status'], 'INCONCLUSIVE')

    def test_unflagged_screen(self):
        self.assertEqual(classify(result('bench_case', 2), ['bench_case'])['status'], 'PASS')

    def test_public_format_informational(self):
        self.assertEqual(classify(result('bench_info_public', 900), ['bench_info_public'])['status'], 'PASS')

    def test_missing_or_duplicate_or_nonfinite(self):
        for log in ('', result('bench_case', 0) * 2, result('bench_case', 'NaN'),
                    result('bench_case', 0).replace('complete', 'interrupted'),
                    result('bench_case', 0).replace('+0.100M', '+0.000M')):
            with self.subTest(log=log), self.assertRaises(ValueError):
                classify(log, ['bench_case'])


class Campaign(unittest.TestCase):
    def test_flagged_control_blocks_passing_screen(self):
        rows = [dict(mode='decap', vary='control', status='INCONCLUSIVE'),
                dict(mode='decap', vary='secret', status='PASS')]
        self.assertEqual(verdict(rows), {'decap': 'INCONCLUSIVE'})

    def test_screen_failure_retained(self):
        rows = [dict(mode='decap', vary='control', status='PASS'),
                dict(mode='decap', vary='secret', status='FAIL')]
        self.assertEqual(verdict(rows), {'decap': 'FAIL'})

    def test_public_only_decap_difference_is_reported_separately(self):
        rows = [dict(mode='decap', vary='control', status='PASS'),
                dict(mode='decap', vary='secret', status='PASS'),
                dict(mode='decap', vary='public', status='FAIL'),
                dict(mode='decap', vary='keys', status='FAIL')]
        self.assertEqual(verdict(rows), {'decap': 'PUBLIC-DIFFERENCE'})

    def test_unexplained_whole_key_difference_fails(self):
        rows = [dict(mode='decap', vary='control', status='PASS'),
                dict(mode='decap', vary='secret', status='PASS'),
                dict(mode='decap', vary='public', status='PASS'),
                dict(mode='decap', vary='keys', status='FAIL')]
        self.assertEqual(verdict(rows), {'decap': 'FAIL'})

    def test_public_difference_does_not_mask_secret_failure(self):
        rows = [dict(mode='decap', vary='control', status='PASS'),
                dict(mode='decap', vary='secret', status='FAIL'),
                dict(mode='decap', vary='public', status='FAIL'),
                dict(mode='decap', vary='keys', status='FAIL')]
        self.assertEqual(verdict(rows), {'decap': 'FAIL'})

    def test_missing_control_blocks_pass(self):
        self.assertEqual(verdict([dict(mode='decap', vary='secret', status='PASS')]),
                         {'decap': 'INCONCLUSIVE'})

    def test_attribution_control_classification(self):
        log = 'mode=decap vary=control generated_samples=100000\n' + result('bench_attribution', 9)
        self.assertEqual(classify(log, ['bench_attribution'])['status'], 'INCONCLUSIVE')


class RustResults(unittest.TestCase):
    def test_empty_failed_or_incomplete(self):
        for log in ('', 'test result: ok. 0 passed; 0 failed;',
                    'test result: FAILED. 1 passed; 1 failed;'):
            with self.assertRaises(ValueError):
                check_rust(log)

    def test_completed_tests(self):
        self.assertEqual(check_rust('test result: ok. 10 passed; 0 failed;'), 10)


class Dependencies(unittest.TestCase):
    def fixture(self, owner):
        names = ['aes-gcm', 'x25519-dalek', 'hkdf', 'sha2', 'aes']
        packages = [dict(id=n, name=n, version='1', source='registry') for n in [owner, *names]]
        nodes = [dict(id=n, features=['zeroize'], deps=[]) for n in [owner, *names]]
        nodes[0]['deps'] = [dict(name=n.replace('-', '_'), pkg=n) for n in names[:4]]
        nodes[1]['deps'] = [dict(name='aes', pkg='aes')]
        return dict(packages=packages, resolve=dict(nodes=nodes))

    def test_matching_graph(self):
        with contextlib.redirect_stdout(io.StringIO()):
            check(self.fixture('citadel-envelope'), self.fixture('citadel-gauntlet-tier1'))

    def test_direct_transitive_and_features_mismatch(self):
        for change in ('direct', 'transitive', 'features'):
            production = self.fixture('citadel-envelope')
            vectors = self.fixture('citadel-gauntlet-tier1')
            if change == 'features':
                vectors['resolve']['nodes'][1]['features'] = []
            else:
                vectors['packages'][1 if change == 'direct' else 5]['version'] = 'different'
            with self.subTest(change=change), self.assertRaises(ValueError):
                check(production, vectors)


class Runner(unittest.TestCase):
    def run_fake(self, tier, body):
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            cargo = temp / 'cargo'
            cargo.write_text('#!/bin/bash\n' + body)
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH'],
                       GAUNTLET_RECEIPTS=str(temp / 'receipts'))
            p = subprocess.run(['bash', str(HERE / 'run.sh'), tier], env=env,
                               text=True, capture_output=True)
            return p.returncode, p.stdout + p.stderr

    def test_deny_failure_survives_audit_success(self):
        rc, out = self.run_fake('tier2b', '[[ "$1" == deny ]] && exit 1\nexit 0\n')
        self.assertNotEqual(rc, 0)
        self.assertIn('| tier2b | FAIL |', out)

    def test_audit_failure_survives(self):
        rc, _ = self.run_fake('tier2b', '[[ "$1" == audit ]] && exit 1\nexit 0\n')
        self.assertNotEqual(rc, 0)

    def test_empty_fuzz_is_not_pass(self):
        rc, out = self.run_fake('tier3', 'exit 0\n')
        self.assertNotEqual(rc, 0)
        self.assertIn('INCONCLUSIVE', out)

    def test_fuzz_discovery_failure(self):
        rc, _ = self.run_fake('tier3', '[[ "$2" == list ]] && exit 1\nexit 0\n')
        self.assertNotEqual(rc, 0)

    def test_fuzz_crash_survives(self):
        rc, _ = self.run_fake('tier3', '[[ "$2" == list ]] && { echo target; exit 0; }\n[[ "$2" == run ]] && exit 1\nexit 0\n')
        self.assertNotEqual(rc, 0)

    def test_bench_process_failure(self):
        rc, _ = self.run_fake('tier4', 'exit 1\n')
        self.assertNotEqual(rc, 0)

    def test_bench_empty_success(self):
        rc, out = self.run_fake('tier4', 'exit 0\n')
        self.assertNotEqual(rc, 0)
        self.assertIn('INCONCLUSIVE', out)

    def test_bench_complete_flagged_output_and_required_feature(self):
        import re
        names = re.findall(r'BenchName\(\s*"([^"]+)"',
                           (HERE.parent / 'citadel-envelope/benches/timing_sidechannel.rs').read_text())
        log = ''.join(result(n, 20 if n == 'bench_wrong_aad_vs_wrong_tag_failure' else 0) for n in names)
        body = '[[ " $* " == *" --features timing-diagnostics "* ]] || exit 9\n'
        body += "cat <<'OUTPUT'\n" + log + 'OUTPUT\n'
        rc, out = self.run_fake('tier4', body)
        self.assertNotEqual(rc, 0)
        self.assertIn('TIMING: FAIL', out)

    def test_unknown_tier(self):
        rc, _ = self.run_fake('typo', 'exit 0\n')
        self.assertNotEqual(rc, 0)


if __name__ == '__main__':
    unittest.main()
