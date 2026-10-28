#!/usr/bin/env python3
"""Isolation diagnostics for the native funds host (JUN-501 S0-f).

Run on arm64 Linux as the host's own user, with passwordless `sudo -u nobody`
available. The private root lives on a local filesystem (not a shared mount,
whose modes do not reflect Linux ownership). Measures what the host actually
enforces: file modes, whether another OS user can read the seeds or operate the
root, whether a process without the capability grant can reach it, whether
re-initialisation overwrites anything, and whether any command prints a seed.
Never publish the fixture directory.
"""
import argparse, hashlib, json, os, platform, shutil, stat, subprocess, tempfile, time
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--artifact', required=True, type=Path)
p.add_argument('--base', required=True, type=Path, help='new directory on a local filesystem')
p.add_argument('--loosen', action='store_true', help='self-test: widen the modes after init; the gate must then FAIL')
a = p.parse_args()
assert platform.system() == 'Linux'
base = a.base.resolve()
base.mkdir(mode=0o755, parents=True, exist_ok=False)
(base / 'bin').mkdir(mode=0o755)
binary = base / 'bin' / 'kagi-host'
shutil.copyfile(a.artifact, binary)
binary.chmod(0o755)
allow = base / 'allowlist'
allow.write_text('\ndid:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT\n')
allow.chmod(0o644)
root = base / 'funds'
env = dict(os.environ, KEXE_ALLOW='7,23,35,37,38,39', KEXE_CAP_RESOURCES_35=str(base))
cases = []
outputs = []


def run(*args, expected=0, user=None, grant=None):
    e = dict(env)
    if grant is not None:
        e['KEXE_CAP_RESOURCES_35'] = grant
    cmd = [str(binary), *map(str, args)]
    if user:
        cmd = ['sudo', '-n', '-u', user, 'env'] + ['%s=%s' % kv for kv in e.items() if kv[0].startswith('KEXE_')] + cmd
    r = subprocess.run(cmd, env=None if user else e, capture_output=True, text=True, timeout=120)
    outputs.append(r.stdout + r.stderr)
    assert (r.returncode == 0) == (expected == 0), (args[0], user, r.returncode, r.stderr[:200])
    if expected not in (0, None):
        assert r.returncode != 0 and not r.stdout, (args[0], r.stdout[:100])
    return r


def as_user(user, *cmd):
    return subprocess.run(['sudo', '-n', '-u', user, *map(str, cmd)], capture_output=True, text=True)


def passed(name):
    cases.append({'case': name, 'passed': True})


loose = base / 'loose'
loose.mkdir(mode=0o755)
loose.chmod(0o755)
run('init-local', loose, 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '10', '20', allow, expected=2)
assert list(loose.iterdir()) == []
passed('a root directory that is not owner-only (0755) is refused at init and nothing is created in it')
root.mkdir(mode=0o700)
init = json.loads(run('init-local', root, 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '10', '20', allow).stdout)
if a.loosen:
    root.chmod(0o755)
    (root / 'author.seed').chmod(0o644)
files = sorted(f.name for f in root.iterdir())
seeds = ['author.seed', 'guardian.seed', 'delegate.seed']
assert all(s in files for s in seeds), files
passed('the root holds a separate author, guardian and delegate seed')

dm = stat.S_IMODE(root.stat().st_mode)
fm = {n: stat.S_IMODE((root / n).stat().st_mode) for n in files}
assert dm == 0o700, oct(dm)
assert all(fm[s] == 0o600 for s in seeds), {s: oct(fm[s]) for s in seeds}
passed('the root is created 0700 and every seed 0600 (owner only)')
others = {n: oct(m) for n, m in fm.items() if m & 0o077}
passed('every file in the root is owner-only' if not others else 'FINDING: group/other-accessible files exist: %s' % others)
cases[-1]['passed'] = not others

seed_values = [(root / s).read_text().strip() for s in seeds]
for s in seed_values:
    assert len(s) == 64

denied = [as_user('nobody', 'cat', root / s) for s in seeds] + [as_user('nobody', 'ls', root)]
assert all(r.returncode != 0 and not any(v in r.stdout for v in seed_values) for r in denied)
passed('another OS user cannot read a seed or list the root')

jhash = hashlib.sha256((root / 'journal').read_bytes()).hexdigest()
for cmd in (('status-local', root), ('export-local', root), ('audit-local', root)):
    run(*cmd, expected=2, user='nobody')
run('init-local', base / 'other', 'agent', 'cell:x', 'hata:local', 'cell-writes', '60000', expected=2, user='nobody')
assert hashlib.sha256((root / 'journal').read_bytes()).hexdigest() == jhash
passed('another OS user running the host cannot operate or create a root, and the journal is unchanged')

empty = Path(tempfile.mkdtemp(dir=base))
for cmd in (('status-local', root), ('audit-local', root), ('halt-local', root)):
    run(*cmd, expected=2, grant=str(empty))
assert not (root / 'halt').exists() and hashlib.sha256((root / 'journal').read_bytes()).hexdigest() == jhash
passed('the same OS user without the capability grant for the root cannot read, audit or halt it')

before = {s: (root / s).read_text() for s in seeds}
run('init-local', root, 'funds', 'mon:funds', 'hata:funds', 'en-transfer', '60000', '10', '20', allow, expected=2)
assert before == {s: (root / s).read_text() for s in seeds}
passed('initialising an existing root is refused and no seed changes')

for cmd in (('status-local', root), ('export-local', root), ('audit-local', root)):
    run(*cmd)
run('halt-local', root)
run('halt-local', root, expected=2)
(root / 'halt').unlink()
text = '\n'.join(outputs) + '\n' + json.dumps(init)
leaked = [s[:8] for s in seed_values if s in text]
assert not leaked, leaked
passed('no command output (init, status, export, audit, halt, refusals) contains a seed')

report = {'schema': 'kagi.native.isolation.gate.v1', 'host': platform.machine(), 'filesystem': 'local',
          'artifactSha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'passed': all(c['passed'] for c in cases), 'count': len(cases), 'cases': cases,
          'rootMode': oct(dm), 'fileModes': {n: oct(m) for n, m in fm.items()},
          'limits': 'one administrator controls every seed file; nobody is an unprivileged local user, not an independent guardian',
          'productionQualified': False, 'independentCustody': False}
(base / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
