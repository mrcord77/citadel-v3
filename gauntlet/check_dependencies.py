#!/usr/bin/env python3
"""Fail if primitive vector dependencies differ from the production envelope."""
import json
from pathlib import Path
import subprocess
import sys

PRIMITIVES = ('aes-gcm', 'x25519-dalek', 'hkdf', 'sha2')


def direct(metadata, package, dependency):
    packages = {p['id']: p for p in metadata['packages']}
    owner = next(p for p in packages.values() if p['name'] == package)
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    dep = next(d for d in nodes[owner['id']]['deps']
               if d['name'] == dependency.replace('-', '_'))
    resolved = packages[dep['pkg']]
    return (resolved['version'], resolved['source']), set(nodes[dep['pkg']]['features'])


def check(production, vectors):
    def graph(metadata):
        return ({p['id']: p for p in metadata['packages']},
                {n['id']: n for n in metadata['resolve']['nodes']})
    pp, pn = graph(production)
    vp, vn = graph(vectors)
    prod_owner = next(p['id'] for p in pp.values() if p['name'] == 'citadel-envelope')
    vector_owner = next(p['id'] for p in vp.values() if p['name'] == 'citadel-gauntlet-tier1')
    def edge(nodes, owner, name):
        return next(d['pkg'] for d in nodes[owner]['deps'] if d['name'] == name.replace('-', '_'))
    seen = set()
    def compare(pid, vid):
        if (pid, vid) in seen:
            return
        seen.add((pid, vid))
        expected, actual = pp[pid], vp[vid]
        required, enabled = set(pn[pid]['features']), set(vn[vid]['features'])
        if any(expected[k] != actual[k] for k in ('name', 'version', 'source')):
            raise ValueError(f"{expected['name']}: production {expected['version']} "
                             f"features={sorted(required)}; vectors {actual['version']} features={sorted(enabled)}")
        for dep in pn[pid]['deps']:
            compare(dep['pkg'], edge(vn, vid, dep['name']))
    for name in PRIMITIVES:
        pid, vid = edge(pn, prod_owner, name), edge(vn, vector_owner, name)
        if not set(pn[pid]['features']) <= set(vn[vid]['features']):
            raise ValueError(f'{name}: vector primitive lacks production-resolved features')
        compare(pid, vid)
        print(f"MATCH {name} {pp[pid]['version']} (subtree versions match; direct primitive features included)")


def main():
    root = Path(__file__).resolve().parent.parent
    def metadata(manifest):
        return json.loads(subprocess.check_output([
            'cargo', 'metadata', '--locked', '--format-version', '1',
            '--manifest-path', str(manifest)], text=True))
    try:
        check(metadata(root / 'Cargo.toml'),
              metadata(root / 'gauntlet/tier1_vectors/Cargo.toml'))
    except (ValueError, KeyError, StopIteration, subprocess.CalledProcessError) as error:
        print(f'DEPENDENCY CHECK FAILED: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
