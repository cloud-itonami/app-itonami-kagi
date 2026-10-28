#!/usr/bin/env python3
"""Funds-role host diagnostics (JUN-501 S0-c2). The native ELF does all key
generation, signing, limit checks and journalling; Python only drives it and
verifies each signature with OpenSSL as an independent oracle. New private
fixtures are written beneath --output; never publish that directory.
"""
import argparse, base64, hashlib, json, os, platform, subprocess, tempfile
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--artifact', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
assert platform.system() == 'Linux'
out = a.output.resolve()
out.mkdir(mode=0o700, parents=True, exist_ok=False)
env = dict(os.environ, KEXE_ALLOW='7,23,35,37,38,39', KEXE_CAP_RESOURCES_35=str(out))
cases = []
RECEIVER = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT'   # RFC 8032 test key 2 (public)
OTHER = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw'      # RFC 8032 test key 1 (public)
STRANGER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'    # RFC 8032 test key 3 (public)
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def run(*args, expected=0):
    r = subprocess.run([str(a.artifact.resolve()), *map(str, args)], env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == expected, (args[0], r.returncode, r.stderr)
    assert (not r.stdout) if expected else (not r.stderr)
    return r.stdout


def passed(name):
    cases.append({'case': name, 'passed': True})


def b58(b):
    n = int.from_bytes(b, 'big'); s = ''
    while n:
        n, r = divmod(n, 58); s = B58[r] + s
    return s


def did_of(pub_hex):
    return 'did:key:z' + b58(bytes([0xED, 1]) + bytes.fromhex(pub_hex))


def tid_of(body):
    h = hashlib.sha256(body.encode()).digest()
    return 'b' + base64.b32encode(bytes([1, 0x71, 0x12, 0x20]) + h).decode().lower().rstrip('=')


def openssl_verify(pub_hex, message, sig_b64):
    d = Path(tempfile.mkdtemp(dir=out))
    spki = bytes.fromhex('302a300506032b6570032100') + bytes.fromhex(pub_hex)
    (d / 'k.pem').write_text('-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(spki).decode() + '\n-----END PUBLIC KEY-----\n')
    (d / 'm').write_bytes(message.encode())
    sig = base64.urlsafe_b64decode(sig_b64 + '=' * (-len(sig_b64) % 4))
    (d / 's').write_bytes(sig)
    r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(d / 'k.pem'), '-rawin',
                        '-in', str(d / 'm'), '-sigfile', str(d / 's')], capture_output=True)
    return r.returncode == 0


root, agent = out / 'funds', out / 'agent'
root.mkdir(mode=0o700); agent.mkdir(mode=0o700)
allow = out / 'allowlist'
allow.write_text('\n' + RECEIVER + '\n' + OTHER + '\n')
ident = json.loads(run('init-local', root, 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '10', '20', allow))
author = ident['author']
spender = did_of(author)
assert (root / 'allowlist').read_text() == allow.read_text()
passed('funds root initialises with limits and a stored allowlist pinned by the policy digest')
assert json.loads(run('status-local', root))['sequence'] == 0
run('init-local', out / 'bad1', 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '30', '20', allow, expected=2)
empty = out / 'empty'
empty.write_text('')
run('init-local', out / 'bad2', 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '10', '20', empty, expected=2)
passed('a cap above the daily cap, or an empty allowlist, is refused at init')


def request(root_, receiver, amount, nonce, prev='nil', ts='1000', expected=0):
    return run('permit-funds-local', root_, receiver, amount, prev, nonce, ts, expected=expected)


def sign(root_, line, expected=0):
    f = out / 'request'
    f.write_text(line)
    return run('sign-funds-local', root_, f, expected=expected)


def body_of(receiver, amount, prev, nonce, ts):
    return 'engi/transfer-body\nspender=%s\nreceiver=%s\namount=%s\nspender-prev=%s\nnonce=%s\nts=%s\n' % (
        spender, receiver, amount, prev, nonce, ts)


journal = lambda: (root / 'journal').read_bytes()
request(root, STRANGER, '1', 'n0', expected=2)
request(root, RECEIVER, '11', 'n0', expected=2)
request(root, RECEIVER, '0', 'n0', expected=2)
request(root, spender, '1', 'n0', expected=2)
assert json.loads(run('status-local', root))['sequence'] == 0
passed('no permit is issued for a receiver off the allowlist, an amount over the per-transaction cap, zero, or the spender itself')

line1 = request(root, RECEIVER, '7', 'n0')
before = journal()
r1 = json.loads(sign(root, line1))
assert r1['sequence'] == 1 and r1['spender'] == spender and r1['spentBefore'] == 0
body1 = body_of(RECEIVER, '7', 'nil', 'n0', '1000')
assert r1['transferId'] == tid_of(body1)
assert openssl_verify(author, r1['transferId'], r1['signature'])
assert journal() != before and journal().startswith(before)
passed('a funds transfer is signed after the durable append, and OpenSSL verifies the signature over the transfer-id')

before = journal()
sign(root, line1, expected=2)
assert journal() == before
passed('replaying the signed request is refused and leaves the journal unchanged')

tampered = line1.replace(' 7 nil n0 1000', ' 8 nil n0 1000')
assert tampered != line1
sign(root, tampered, expected=2)
assert journal() == before
passed('changing the amount after the permit was issued is refused')

status = json.loads(run('status-local', root))
assert status['sequence'] == 1
passed('a restart replays the funds journal and recovers the sequence')

line2 = request(root, OTHER, '7', 'n1', prev=r1['transferId'], ts='2000')
r2 = json.loads(sign(root, line2))
assert r2['sequence'] == 2 and r2['spentBefore'] == 7
assert openssl_verify(author, r2['transferId'], r2['signature'])
passed('spent is derived from the journal: the second transfer sees 7 already spent')

request(root, RECEIVER, '7', 'n2', prev=r2['transferId'], ts='3000', expected=2)
before = journal()
passed('a third transfer that would pass the daily cap of 20 is refused (14 + 7)')
line3 = request(root, RECEIVER, '6', 'n2', prev=r2['transferId'], ts='3000')
r3 = json.loads(sign(root, line3))
assert r3['sequence'] == 3 and r3['spentBefore'] == 14
passed('spending up to the daily cap exactly is signed (14 + 6 = 20)')
request(root, RECEIVER, '1', 'n3', prev=r3['transferId'], ts='4000', expected=2)
passed('one more unit is refused once the daily cap is reached')

# the journal is the only source of spent: editing an amount must break the proof
raw = journal().decode()
lines = raw.split('\n')
idx = next(i for i, l in enumerate(lines) if l.startswith('kagi.host.fentry.v1') and ' n0 1000' in l)
fields = lines[idx].split(' ')
assert fields[19] == '7'
fields[19] = '1'
lines[idx] = ' '.join(fields)
saved = journal()
(root / 'journal').write_text('\n'.join(lines))
run('status-local', root, expected=2)
request(root, RECEIVER, '1', 'n3', prev=r3['transferId'], ts='4000', expected=2)
(root / 'journal').write_bytes(saved)
assert json.loads(run('status-local', root))['sequence'] == 3
passed('lowering a journalled amount breaks the proof, so spent cannot be reduced by editing the journal')

# a journalled signature must verify against the rebuilt transfer-id, with every other field intact
# (the LAST entry: an earlier one would also break the next entry's prev-hash link)
lines = journal().decode().split('\n')
idx = max(i for i, l in enumerate(lines) if l.startswith('kagi.host.fentry.v1'))
fields = lines[idx].split(' ')
fields[16] = ('0' if fields[16][0] != '0' else '1') + fields[16][1:]
lines[idx] = ' '.join(fields)
(root / 'journal').write_text('\n'.join(lines))
run('status-local', root, expected=2)
(root / 'journal').write_bytes(saved)
assert json.loads(run('status-local', root))['sequence'] == 3
passed('a journalled author signature that does not verify over the transfer-id breaks the proof')

# an agent-role root has no funds path, and a funds root has no agent path
run('init-local', agent, 'agent', 'cell:agent', 'hata:local', 'cell-writes', '60000')
request(agent, RECEIVER, '1', 'n0', expected=2)
(out / 'req2').write_text(line1)
run('sign-funds-local', agent, out / 'req2', expected=2)
body = out / 'body'
body.write_text('local cell operation digest fixture\n')
run('permit-local', root, body, 'cell-action', expected=2)
passed('funds and agent roots do not cross: no funds permit or signature from an agent root, no cell-action from a funds root')

report = {'schema': 'kagi.native.funds-host.gate.v1', 'host': platform.machine(),
          'artifactSha256': hashlib.sha256(a.artifact.read_bytes()).hexdigest(),
          'passed': True, 'count': len(cases), 'cases': cases,
          'productionQualified': False, 'independentCustody': False,
          'orchestration': 'Python diagnostics + OpenSSL oracle; native ELF creates keys, checks limits, signs and commits'}
(out / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
