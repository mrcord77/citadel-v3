#!/usr/bin/env python3
"""Interpret dudect output; a successful benchmark process is not a CT verdict."""
import argparse
import json
import math
import re
from pathlib import Path

THRESHOLD = 4.5


def classify(output, expected):
    matches = re.findall(r'bench\s+(\w+)\s+\.\.\.\s*:\s*n ==\s*(\S+)M, max t =\s*([^,]+),', output)
    rows = []
    for name, millions, statistic in matches:
        n, t = float(millions) * 1_000_000, float(statistic)
        if not math.isfinite(n) or n <= 0 or not math.isfinite(t):
            raise ValueError('non-finite statistic or empty sample set')
        kind = 'informational' if name.startswith('bench_info_') else (
            'control' if 'control' in name or 'same_key' in name or (
                name == 'bench_attribution' and re.search(r'^mode=\S+ vary=control ', output, re.M)) else 'screen')
        rows.append(dict(name=name, samples_rounded=n, max_t=t, kind=kind,
                         flagged=abs(t) >= THRESHOLD))
    names = [r['name'] for r in rows]
    if not expected or len(set(names)) != len(names) or set(names) != set(expected):
        raise ValueError(f'incomplete/duplicate/unexpected results: expected {len(expected)}, received {names}')
    if 'dudect benches complete' not in output:
        raise ValueError('missing benchmark completion marker')
    bad_control = any(r['flagged'] and r['kind'] == 'control' for r in rows)
    bad_screen = any(r['flagged'] and r['kind'] == 'screen' for r in rows)
    status = 'INCONCLUSIVE' if bad_control else 'FAIL' if bad_screen else 'PASS'
    return dict(status=status, threshold=THRESHOLD, results=rows,
                interpretation='Statistical screen only; PASS is not a constant-time proof.')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('log', type=Path)
    p.add_argument('source', type=Path)
    p.add_argument('--json', required=True, type=Path)
    args = p.parse_args()
    expected = re.findall(r'BenchName\(\s*"([^"]+)"', args.source.read_text())
    try:
        result = classify(args.log.read_text(), expected)
    except (ValueError, OSError) as error:
        result = dict(status='INCONCLUSIVE', error=str(error))
    args.json.write_text(json.dumps(result, indent=2) + '\n')
    print('TIMING:', result['status'])
    return {'PASS': 0, 'FAIL': 1, 'INCONCLUSIVE': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
