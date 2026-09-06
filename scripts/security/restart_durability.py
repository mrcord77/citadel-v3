#!/usr/bin/env python3
"""Independent Citadel HTTP checks; only starts a local server with temporary keys.
Usage: python3 scripts/security/restart_durability.py /absolute/path/to/citadel-api
No third-party Python packages required. Expected failures remain failures.
"""
import concurrent.futures
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

OUT = Path(os.environ.get('CITADEL_VERIFICATION_DIR') or tempfile.mkdtemp(prefix='citadel-verification-')).resolve()
OUT.mkdir(parents=True, exist_ok=True)
BINARY = str(Path(sys.argv[1]).resolve())
results = []
completed = False
admin = secrets.token_hex(24)
master = secrets.token_bytes(32)
proc = None
log = None
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
base = f'http://127.0.0.1:{port}'

def check(name, condition, detail=''):
    results.append({'name': name, 'pass': bool(condition), 'detail': detail})
    print(('PASS ' if condition else 'FAIL ') + name + ' ' + str(detail), flush=True)

def req(path, data=None, key=admin, method=None):
    headers = {'Content-Type': 'application/json'}
    if key is not None:
        headers['Authorization'] = 'Bearer ' + key
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(base + path, body, headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            body = json.loads(body)
        except ValueError:
            pass
        return e.code, body

def start(env):
    global proc, log
    log = (OUT / 'live-server.log').open('ab')
    proc = subprocess.Popen([BINARY], env=env, stdout=log, stderr=log)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f'Server exited: {proc.returncode}; see live-server.log')
        try:
            status, body = req('/health', key=None)
            if status == 200:
                return body
        except OSError:
            pass
        time.sleep(.1)
    raise RuntimeError('Server health timed out')

def stop():
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if log:
        log.close()

def create(name, kind, parent=None):
    body = {'name': name, 'key_type': kind}
    if parent:
        body['parent_id'] = parent
    status, response = req('/api/keys', body)
    if status != 201 or 'key_id' not in response:
        raise RuntimeError(f'Create {kind}: {status} {response}')
    kid = response['key_id']
    status, response = req(f'/api/keys/{kid}/activate', {})
    if status != 200:
        raise RuntimeError(f'Activate {kind}: {status} {response}')
    return kid

def encrypt(kid, text='Citadel actual plaintext — André 🔐\nline two'):
    status, blob = req(f'/api/keys/{kid}/encrypt', {'plaintext': text, 'aad': 'record-71', 'context': 'verification'})
    if status != 200:
        raise RuntimeError(f'Encrypt: {status} {blob}')
    return blob, text

def decrypt(blob, key=admin, aad='record-71', context='verification'):
    return req('/api/decrypt', {'blob': blob, 'aad': aad, 'context': context}, key)

try:
    with tempfile.TemporaryDirectory(prefix='citadel-independent-') as td:
        env = {k:v for k,v in os.environ.items() if not k.startswith('CITADEL_')}
        env.update(CITADEL_MASTER_KEY=master.hex(),
                   CITADEL_API_KEY_HASH=hmac.new(master, admin.encode(), hashlib.sha256).hexdigest(),
                   CITADEL_ENV='production', CITADEL_REPLAY_STORE='file',
                   CITADEL_DATA_DIR=td, CITADEL_PORT=str(port),
                   CITADEL_RATE_LIMIT_RPS='10000', CITADEL_RATE_LIMIT_BURST='20000')
        health = start(env)
        check('production-config server starts', health.get('status') == 'ok', health)
        check('missing credentials rejected', req('/api/status', key=None)[0] == 401)
        check('wrong credentials rejected', req('/api/status', key='wrong-test-key')[0] == 401)
        root = create('root', 'Root')
        domain = create('domain-a', 'Domain', root)
        kek = create('kek-a', 'KeyEncrypting', domain)
        dek = create('dek-a', 'DataEncrypting', kek)
        check('four-level hierarchy created and activated', True)
        blob, plain = encrypt(dek)
        check('envelope contains ciphertext, not plaintext', bool(blob.get('ciphertext_hex')) and plain not in json.dumps(blob))
        code, body = decrypt(blob)
        check('exact Unicode plaintext round trip', code == 200 and body.get('plaintext') == plain, {'status': code})
        check('same-process replay rejected', decrypt(blob)[0] == 400)

        for field in ('aad', 'context'):
            fresh, plain = encrypt(dek)
            code, body = decrypt(fresh, **{field:'incorrect'})
            check('wrong ' + field + ' rejected', code == 400 and body.get('error') == 'operation failed')
            code, body = decrypt(fresh)
            check('failed ' + field + ' attempt does not poison valid ciphertext', code == 200 and body.get('plaintext') == plain)
        fresh, plain = encrypt(dek)
        altered = copy.deepcopy(fresh)
        ct = bytearray.fromhex(altered['ciphertext_hex'])
        ct[-1] ^= 1
        altered['ciphertext_hex'] = ct.hex()
        check('tampered authentication tag rejected', decrypt(altered)[0] == 400)
        code, body = decrypt(fresh)
        check('valid original survives tampered attempt', code == 200 and body.get('plaintext') == plain)
        check('malformed decrypt request rejected', req('/api/decrypt', {'blob':{}})[0] == 400)

        signing = create('signing-test', 'Signing', kek)
        payload = b'Citadel signature verification'.hex()
        code, signed = req(f'/api/keys/{signing}/sign', {'payload_hex':payload,'context':'verification'})
        check('ML-DSA signing succeeds', code == 200)
        if code == 200:
            verify_body = {'key_id':signing,'key_version':signed['key_version'],
                           'payload_hex':payload,'signature_hex':signed['signature_hex']}
            code, verified = req('/api/verify', verify_body)
            check('ML-DSA original signature verifies', code == 200 and verified.get('valid') is True)
            verify_body['payload_hex'] = b'altered payload'.hex()
            code, verified = req('/api/verify', verify_body)
            check('ML-DSA altered payload fails verification', code == 200 and verified.get('valid') is False)

        d2 = create('domain-b', 'Domain', root)
        k2 = create('kek-b', 'KeyEncrypting', d2)
        dek2 = create('dek-b', 'DataEncrypting', k2)
        code, scoped = req('/api/auth/keys', {'name':'domain-a-user','scopes':['read','encrypt'],'allowed_domains':[domain]})
        if code != 201:
            raise RuntimeError(f'Create scoped key: {code} {scoped}')
        scoped_key = scoped['api_key']
        check('scoped API key can read its own domain', req(f'/api/keys/{dek}', key=scoped_key)[0] == 200)
        check('scoped API key cannot read another domain', req(f'/api/keys/{dek2}', key=scoped_key)[0] == 403)
        cross, _ = encrypt(dek2)
        code, body = decrypt(cross, key=scoped_key)
        check('cross-domain decrypt rejected', code == 400 and body.get('error') == 'operation failed', {'status':code})
        check('encrypt-only user cannot create keys', req('/api/keys', {'name':'forbidden','key_type':'Root'}, key=scoped_key)[0] == 403)

        old, oldplain = encrypt(dek)
        old_version = old['key_version']
        check('rotation succeeds', req(f'/api/keys/{dek}/rotate', {})[0] == 200)
        newer, _ = encrypt(dek)
        check('rotation increments encryption version', newer['key_version'] > old_version)
        code, body = decrypt(old)
        check('old ciphertext decrypts after rotation', code == 200 and body.get('plaintext') == oldplain)
        victim = create('revoke-test', 'DataEncrypting', kek)
        revoked_blob, _ = encrypt(victim)
        check('revocation succeeds', req(f'/api/keys/{victim}/revoke', {'reason':'independent verification'})[0] == 200)
        check('revoked key cannot decrypt', decrypt(revoked_blob)[0] == 400)
        check('revoked key cannot encrypt', req(f'/api/keys/{victim}/encrypt', {'plaintext':'blocked','aad':'a','context':'c'})[0] == 403)
        check('destroy revoked key succeeds', req(f'/api/keys/{victim}/destroy', {})[0] == 200)
        code, body = req(f'/api/keys/{victim}')
        check('destroyed state recorded', code == 200 and body.get('state','').lower() == 'destroyed')

        fresh, _ = encrypt(dek2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            codes = list(pool.map(lambda _: decrypt(fresh)[0], range(10)))
        check('concurrent replay has exactly one success', codes.count(200) == 1 and codes.count(400) == 9, codes)
        check('API key revocation succeeds', req('/api/auth/keys/'+scoped['key_id'], key=admin, method='DELETE')[0] == 200)
        check('revoked API key rejected', req('/api/status', key=scoped_key)[0] == 401)
        pending, pendingplain = encrypt(dek2)
        stop()
        start(env)
        code, body = decrypt(pending)
        check('unread ciphertext decrypts after server restart', code == 200 and body.get('plaintext') == pendingplain)
        check('API key revocation survives restart', req('/api/status', key=scoped_key)[0] == 401)
        code, body = req(f'/api/keys/{victim}')
        check('key destruction survives restart', code == 200 and body.get('state','').lower() == 'destroyed')

        # Reset the replay-store clock by restarting, then claim immediately.
        # No other decrypts occur during the idle period; health/auth do not flush it.
        idle_blob, idleplain = encrypt(dek2)
        stop()
        start(env)
        code, body = decrypt(idle_blob)
        check('idle-replay fixture initially decrypts', code == 200 and body.get('plaintext') == idleplain)
        time.sleep(7)
        check('idle replay is still blocked before restart', decrypt(idle_blob)[0] == 400)
        stop()
        start(env)
        code, body = decrypt(idle_blob)
        check('replay claim survives SIGTERM after seven idle seconds', code == 400, {'status':code,'plaintext_returned':body.get('plaintext')==idleplain})
        # Abrupt termination immediately after the successful response must not
        # depend on a timer, destructor, or graceful shutdown handler.
        abrupt, abruptplain = encrypt(dek2)
        code, body = decrypt(abrupt)
        check('SIGKILL fixture initially decrypts', code == 200 and body.get('plaintext') == abruptplain)
        proc.kill()
        proc.wait(timeout=10)
        stop()
        start(env)
        check('acknowledged replay claim survives immediate SIGKILL', decrypt(abrupt)[0] == 400)

        # Force replay writes to fail without relying on permission bits (root-safe).
        failed_blob, _ = encrypt(dek2)
        (Path(td)/'replay.tmp').mkdir()
        code, body = decrypt(failed_blob)
        check('replay write failure withholds plaintext', code == 400 and 'plaintext' not in body)
        (Path(td)/'replay.tmp').rmdir()
        stop()
        start(env)

        # Force an audit append failure. The request must expose an actual service
        # error, never report successful decryption with an unrecorded audit event.
        audit_failure_blob, _ = encrypt(dek2)
        audit_path = Path(td)/'citadel-audit.jsonl'
        saved_audit = Path(td)/'audit-preserved.jsonl'
        audit_path.rename(saved_audit)
        audit_path.mkdir()
        code, body = decrypt(audit_failure_blob)
        check('audit write failure returns explicit 503 without plaintext', code == 503 and 'plaintext' not in body and 'audit persistence unavailable' in body.get('error',''))
        check('audit failure remains visible on health endpoint', req('/health', key=None)[0] == 503)
        stop()
        audit_path.rmdir()
        saved_audit.rename(audit_path)
        start(env)
        check('valid audit log resumes after storage repair and restart', req('/health', key=None)[0] == 200)
        stop()
        audit_lines = (Path(td)/'citadel-audit.jsonl').read_text().splitlines()
        audit = [json.loads(line) for line in audit_lines]
        resets = [i for i,event in enumerate(audit) if i > 0 and event.get('sequence') == 0]
        check('audit sequence remains continuous across restarts', not resets, {'events':len(audit),'reset_indices':resets})
        (OUT/'audit-sequences.json').write_text(json.dumps([{'sequence':e.get('sequence'),'prev_hash':e.get('prev_hash')} for e in audit], indent=2)+'\n')
        (OUT/'live-audit.jsonl').write_text('\n'.join(audit_lines)+'\n')
        prev_hash = hashlib.sha256(b'citadel-audit-genesis').hexdigest()
        broken_links = []
        for index, line in enumerate(audit_lines):
            event = json.loads(line)
            if event.get('prev_hash') != prev_hash:
                broken_links.append(index)
            prev_hash = hashlib.sha256(line.encode()).hexdigest()
        check('every persisted audit hash link verifies after restarts', not broken_links, broken_links)

        # Corrupt an earlier event and prove startup rejects it without rewriting.
        damaged = audit_path.read_text().replace('PolicyRegistered', 'PolicyRegistereX', 1)
        if damaged == audit_path.read_text():
            damaged = '{broken}\n' + damaged
        audit_path.write_text(damaged)
        rejected = subprocess.run([BINARY], env=env, capture_output=True, timeout=10)
        check('corrupted audit prevents startup', rejected.returncode == 1 and b'Audit chain recovery failed' in rejected.stderr)
        check('corrupted audit evidence is preserved unchanged', audit_path.read_text() == damaged)
        completed = True

finally:
    stop()
    summary = {'binary': BINARY, 'completed':completed, 'passed':sum(r['pass'] for r in results),
               'failed':sum(not r['pass'] for r in results), 'checks':results}
    (OUT/'live-results.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='checks'}), flush=True)

sys.exit(1 if summary['failed'] or not completed else 0)
