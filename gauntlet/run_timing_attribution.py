#!/usr/bin/env python3
"""Run isolated diagnostics sequentially, retain raw samples, and gate on controls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from check_timing import classify

ROOT = Path(__file__).resolve().parent.parent
CASES = {'import': ('control', 'secret', 'public'),
         'decap': ('control', 'secret', 'public', 'keys'),
         'aad': ('control', 'public'),
         'p384-parse': ('control',), 'p384-ecdh': ('control', 'secret')}


def verdict(rows):
    modes = {}
    for mode in {r['mode'] for r in rows}:
        group = [r for r in rows if r['mode'] == mode]
        controls = [r for r in group if r['vary'] == 'control']
        if not controls or any(r['status'] != 'PASS' for r in controls):
            modes[mode] = 'INCONCLUSIVE'
        elif any(r['status'] == 'INCONCLUSIVE' for r in group):
            modes[mode] = 'INCONCLUSIVE'
        elif any(r['status'] == 'FAIL' for r in group):
            modes[mode] = 'FAIL'
        else:
            modes[mode] = 'PASS'
    return modes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--seeds', type=int, nargs='+', default=[20260906, 20260907])
    p.add_argument('--modes', nargs='+', choices=CASES, default=list(CASES))
    p.add_argument('--samples', type=int, default=100_000)
    p.add_argument('--cpu', type=int, default=None)
    args = p.parse_args()
    if args.samples < 100_000:
        p.error('gated campaigns require at least 100000 generated samples per case')
    if not hasattr(os, 'sched_setaffinity'):
        p.error('this runner requires a Linux host with CPU affinity support')
    cpu = min(os.sched_getaffinity(0)) if args.cpu is None else args.cpu
    if cpu not in os.sched_getaffinity(0):
        p.error('CPU is outside the available affinity set')
    args.out.mkdir(parents=True, exist_ok=True)
    build_cmd = ['cargo', 'bench', '--locked', '-p', 'citadel-envelope', '--bench',
                 'timing_attribution', '--features', 'timing-diagnostics', '--no-run', '--message-format=json']
    build = subprocess.run(build_cmd, cwd=ROOT, text=True, capture_output=True)
    (args.out / 'build.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        print('BUILD FAILED; see build.log', file=sys.stderr)
        return 1
    executables = []
    for line in build.stdout.splitlines():
        try:
            artifact = json.loads(line)
        except ValueError:
            continue
        if artifact.get('target', {}).get('name') == 'timing_attribution' and artifact.get('executable'):
            executables.append(artifact['executable'])
    if len(executables) != 1:
        print('INCONCLUSIVE: expected one built benchmark executable', file=sys.stderr)
        return 2
    rows = []
    for mode in args.modes:
        for seed in args.seeds:
            for swap in (False, True):
                for vary in CASES[mode]:
                    label = f'{mode}-{vary}-{seed}-{int(swap)}'
                    cmd = [executables[0], '--mode', mode, '--vary', vary,
                           '--seed', str(seed), '--samples', str(args.samples),
                           '--out', str((args.out / (label + '.csv')).resolve())]
                    if swap:
                        cmd.append('--swap')
                    completed = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True,
                                               preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
                    log = completed.stdout + completed.stderr
                    (args.out / (label + '.log')).write_text(log)
                    try:
                        result = classify(log, ['bench_attribution'])
                    except ValueError as error:
                        result = dict(status='INCONCLUSIVE', error=str(error))
                    if completed.returncode:
                        result['status'] = 'INCONCLUSIVE'
                    result.update(mode=mode, vary=vary, seed=seed, swap=swap,
                                  cpu=cpu, command=cmd, exit_code=completed.returncode)
                    rows.append(result)
                    print(label, result['status'], flush=True)
                    (args.out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    summary = verdict(rows)
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0 if summary and all(v == 'PASS' for v in summary.values()) else 2 if 'INCONCLUSIVE' in summary.values() else 1


if __name__ == '__main__':
    sys.exit(main())
