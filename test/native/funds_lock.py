#!/usr/bin/env python3
"""Rebuild the native funds host and every gate with the pinned toolchain, then write
(or verify against) native-funds-host.lock.json. Run on arm64 Linux from the repo root:

  python3 test/native/funds_lock.py --compiler amu-root --owners DIR --build NEW_DIR \
      --measured OUT.json [--verify native-funds-host.lock.json]

The compiler and the two owner sources are checked against the pins before anything is
built. Everything here is local-software qualification on a development VM with public
test material or fresh native entropy; none of it is production or independent custody.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--compiler', required=True, type=Path)
ap.add_argument('--owners', required=True, type=Path)
ap.add_argument('--build', required=True, type=Path)
ap.add_argument('--measured', required=True, type=Path)
ap.add_argument('--verify', type=Path)
a = ap.parse_args()
R = Path.cwd()
B = a.build.resolve()
B.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, KEXE_STACK_BYTES='8388608', KEXE_SECCOMP='if-available')


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


PINS = {'compiler': 'bcebb8885966e325b93868f8b29274a961233811dc5793ce12d26a2afc4803f4',
        'sha2': '2c59ef55bc2b527c1aac723c0fee896eba75ee82fecd212a2858782beadc6888',
        'ed25519': '47c086f3d93ad4f6da047bbf3b9250f7e4fbc7539ec1a0077abb2d82ceb3dc14'}
assert sha(a.compiler) == PINS['compiler'], 'compiler is not the pinned F3'
assert sha(a.owners / 'sha2.kotoba') == PINS['sha2'] and sha(a.owners / 'ed25519.kotoba') == PINS['ed25519'], 'owner sources are not pinned'


def sh(cmd, caps=None, allow=None, ok=True):
    e = dict(env)
    if caps:
        e['KEXE_CAP_RESOURCES_35'] = caps
    if allow:
        e['KEXE_ALLOW'] = allow
    r = subprocess.run(cmd, env=e, capture_output=True, text=True, timeout=10800)
    if ok:
        assert r.returncode == 0, (cmd[:3], r.stdout[-300:], r.stderr[-300:])
    return r


def compile_(src, out, caps):
    sh([str(a.compiler), 'compile', str(src), '--target', 'aarch64-linux', '--output', str(out), '--format', 'static'], caps=caps)
    os.chmod(out, 0o755)


def count(text):
    return len(re.findall(r'^PASS', text, re.M)), len(re.findall(r'^FAIL', text, re.M))


m = {'schema': 'kagi.native-funds-host.build.v1', 'target': 'aarch64-linux-static',
     'compilerSha256': PINS['compiler'], 'ownerSha256': {'sha2': PINS['sha2'], 'ed25519': PINS['ed25519']}}
m['sourceDigests'] = {f: sha(R / f) for f in ('kotoba/kagi/agent_signer.kotoba', 'kotoba/kagi/cli.kotoba',
                                              'kotoba/kagi/host.kotoba', 'kotoba/kagi/assemble.kotoba')}
caps_rb = f'{R}:{B}'
asm = B / 'assemble'
compile_(R / 'kotoba/kagi/assemble.kotoba', asm, caps_rb)
m['nativeAssemblerSha256'] = sha(asm)
ocaps = f'{a.owners}:{R}:{B}'


def assemble(mode, root, out):
    r = sh([str(asm), mode, str(a.owners / 'sha2.kotoba'), str(a.owners / 'ed25519.kotoba'), str(root), str(out)],
           caps=f'{a.owners}:{root}:{B}', allow='3,35,37,38,39')
    return re.search(r'kagi\.native\.assembly\.v1 \w+ ([0-9a-f]{64})', r.stdout).group(1)


m['assembly'] = {}
host_src = B / 'host.kotoba'
m['assembly']['host'] = assemble('host', R, host_src)
host = B / 'kagi-host'
compile_(host_src, host, caps_rb)
m['hostArtifactSha256'] = sha(host)

gates = {}
core_src = B / 'core.kotoba'
m['assembly']['coreGate'] = assemble('gate', R, core_src)
core = B / 'core-gate'
compile_(core_src, core, caps_rb)
p, f = count(sh([str(core)], allow='37', ok=False).stdout)
gates['core'] = {'pass': p, 'fail': f, 'artifactSha256': sha(core)}
for suite in ('s0a', 's0b', 's0c'):
    d = B / f'overlay-{suite}'
    (d / 'root/test/native').mkdir(parents=True)
    shutil.copytree(R / 'kotoba', d / 'root/kotoba')
    shutil.copy(R / f'test/native/{suite}/gate.kotoba', d / 'root/test/native/agent_signer_gate.kotoba')
    shutil.copy(R / f'test/native/{suite}/vectors.kotoba', d / 'root/test/native/agent_signer_vectors.kotoba')
    sasm = d / 'assemble'
    compile_(d / 'root/kotoba/kagi/assemble.kotoba', sasm, f'{d}/root:{d}')
    r = sh([str(sasm), 'gate', str(a.owners / 'sha2.kotoba'), str(a.owners / 'ed25519.kotoba'), str(d / 'root'), str(d / 'gate.kotoba')],
           caps=f'{a.owners}:{d}/root:{d}', allow='3,35,37,38,39')
    gate = d / 'gate'
    compile_(d / 'gate.kotoba', gate, f'{d}/root:{d}')
    p, f = count(sh([str(gate)], allow='37', ok=False).stdout)
    gates[suite] = {'pass': p, 'fail': f, 'artifactSha256': sha(gate)}
m['coreGates'] = gates

hg = {}
for name, script, extra in (('hostGate', 'host_gate.py', []), ('agentHostGate', 'agent_host_gate.py', []),
                            ('fundsHostGate', 'funds_host_gate.py', [])):
    out = B / f'{name}-fixtures'
    r = sh([sys.executable, '-I', str(R / 'test/native' / script), '--artifact', str(host), '--output', str(out)], ok=True)
    rep = json.loads((out / 'receipt.json').read_text())
    hg[name] = {'passed': rep['passed'], 'count': rep['count']}
iso = Path(tempfile.mkdtemp(prefix='kagi-lock-iso-', dir='/var/tmp')) / 'run'
sh([sys.executable, '-I', str(R / 'test/native/isolation_gate.py'), '--artifact', str(host), '--base', str(iso)])
rep = json.loads((iso / 'receipt.json').read_text())
hg['isolationGate'] = {'passed': rep['passed'], 'count': rep['count']}
m['hostGates'] = hg
m.update({'localSoftwareOnly': True, 'productionQualified': False, 'independentCustody': False,
          'projectLinkQualified': False, 'cdciQualified': False})
a.measured.write_text(json.dumps(m, indent=2) + '\n')
print(json.dumps(m, indent=2))
if a.verify:
    lock = json.loads(a.verify.read_text())
    bad = [k for k in m if lock.get(k) != m[k]]
    if bad:
        print('LOCK MISMATCH:', bad, file=sys.stderr)
        sys.exit(1)
    print('LOCK VERIFIED')
