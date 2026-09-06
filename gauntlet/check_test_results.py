#!/usr/bin/env python3
"""Require completed Rust test summaries with at least one passed test."""
import re
import sys
from pathlib import Path


def check(text):
    rows = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed;', text)
    if not rows or sum(int(passed) for _, passed, _ in rows) == 0:
        raise ValueError('no completed passing tests')
    if any(state != 'ok' or int(failed) != 0 for state, _, failed in rows):
        raise ValueError('failed tests in output')
    return sum(int(passed) for _, passed, _ in rows)


if __name__ == '__main__':
    try:
        print(f'Completed passing tests: {check(Path(sys.argv[1]).read_text())}')
    except (ValueError, OSError) as error:
        print(f'INCONCLUSIVE: {error}', file=sys.stderr)
        sys.exit(2)
