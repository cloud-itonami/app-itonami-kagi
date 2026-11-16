#!/usr/bin/env python3
"""Source-pinned Mac diagnostic; no issuance, secrets, or production host."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
READER_PIN = 'f8af2953904bd0a96e7b5c3b9e34151bcae3754e5358669adb8ac289acc0872f'
SHA2_PIN = '2c59ef55bc2b527c1aac723c0fee896eba75ee82fecd212a2858782beadc6888'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified(path, expected, signed=False):
    if path.is_symlink() or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('invalid file or SHA-256')
    path = path.resolve(strict=True)
    if not path.is_file() or sha(path) != expected:
        raise ValueError('source or tool pin mismatch')
    if signed:
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)],
                       check=True, capture_output=True, timeout=30)
    return path


def body(source):
    """Remove exactly one leading namespace form, respecting comments/strings."""
    match = re.search(r'(?m)^\(ns\s', source)
    if not match:
        raise ValueError('namespace missing')
    depth = 0
    quoted = escaped = comment = False
    for i in range(match.start(), len(source)):
        c = source[i]
        if comment:
            if c == '\n': comment = False
        elif quoted:
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == '"': quoted = False
        elif c == ';': comment = True
        elif c == '"': quoted = True
        elif c == '(': depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0: return source[i + 1:]
    raise ValueError('unterminated namespace')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('reader', 'compiler', 'packager'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--sha2', type=Path, help='also test the native source assembler against this pinned owner source')
    p.add_argument('--compiler-sha256', required=True)
    p.add_argument('--packager-sha256', required=True)
    a = p.parse_args()
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise ValueError('diagnostic requires Apple Silicon macOS')
    reader = verified(a.reader, READER_PIN)
    compiler = verified(a.compiler, a.compiler_sha256, signed=True)
    packager = verified(a.packager, a.packager_sha256, signed=True)
    paths = [reader, ROOT / 'kotoba/kagi/github_lease_policy.kotoba',
             ROOT / 'test/native/github-lease/policy_cases.kotoba',
             ROOT / 'test/native/github-lease/provider_cases.kotoba']
    raw = [path.read_bytes() for path in paths]
    source = [body(item.decode('utf-8')) for item in raw]
    main_anchor = '(defn main [] :i64'
    if source[2].count(main_anchor) != 1:
        raise ValueError('policy test entry changed')
    source[2] = source[2].replace(main_anchor, '(defn glpt-policy-main [] :i64')
    unity = ('(ns kagi-github-lease-native-test (:export [main]))\n' + '\n'.join(source) +
             '\n(defn main [] :i64 (if (and (= (glpt-policy-main) 0) (test-github-provider)) 0 1))\n')
    repo_guard, http_guard = '(not (= policy-repo repo))', '(not (= http-status 201))'
    jwt_time_guard, jwt_expiry = '(< now 61)', '(+ now 300)'
    if any(unity.count(x) != 1 for x in (repo_guard, http_guard, jwt_time_guard, jwt_expiry)):
        raise ValueError('negative-control anchor changed')
    fixtures = {'fixture': unity, 'repo-mutant': unity.replace(repo_guard, 'false'),
                'http-mutant': unity.replace(http_guard, 'false'),
                'jwt-clock-mutant': unity.replace(jwt_time_guard, 'false'),
                'jwt-expiry-mutant': unity.replace(jwt_expiry, '(+ now 301)')}
    token_paths = [ROOT / 'kotoba/kagi/github_token_response.kotoba',
                   ROOT / 'kotoba/kagi/github_token_response_test.kotoba']
    token_raw = [path.read_bytes() for path in token_paths]
    token_unity = ('(ns kagi-token-response-native-test (:export [main]))\n' + source[0] + '\n' +
                   body(token_raw[0].decode('utf-8')).replace('j/', '') + '\n' +
                   body(token_raw[1].decode('utf-8')).replace('t/', '') +
                   '\n(defn main [] :i64 (if (and (= (group-a) 255) (= (group-b) 511) (= (group-c) 7)) 0 1))\n')
    error_guard = '(< (json-member b root "error") 0)'
    if token_unity.count(error_guard) != 1:
        raise ValueError('token error guard changed')
    fixtures.update({'token-fixture': token_unity,
                     'token-error-mutant': token_unity.replace(error_guard, 'true')})
    integration_paths = [ROOT / 'kotoba/kagi/github_issuance_envelope.kotoba',
                         ROOT / 'test/native/github-lease/integration_cases.kotoba']
    integration_raw = [path.read_bytes() for path in integration_paths]
    integration_source = (body(integration_raw[0].decode('utf-8')).replace('response/', '')
                          .replace('envelope/', '').replace('policy/', ''))
    # This stubbed fixture covers the approved seal only, not Ed25519 issuance.
    if integration_source.count(';; Experimental byte-level composition') != 1:
        raise ValueError('signed issuance boundary changed')
    integration_source = integration_source.split(';; Experimental byte-level composition', 1)[0]
    integration_unity = ('(ns kagi-approved-seal-test (:export [main]))\n' + source[0] + '\n' + source[1] + '\n' +
                         body(token_raw[0].decode('utf-8')).replace('j/', '') + '\n' +
                         integration_raw[1].decode('utf-8') + '\n' + integration_source +
                         '\n(defn main [] :i64 (if (test-approved-sealing) 0 1))\n')
    admitted_guard = '(not admitted)'
    if integration_unity.count(admitted_guard) != 1:
        raise ValueError('approved seal guard changed')
    clear_call = '(gi-clear! token)'
    if integration_unity.count(clear_call) != 1:
        raise ValueError('temporary token clear anchor changed')
    fixtures.update({'integration-fixture': integration_unity,
                     'integration-policy-mutant': integration_unity.replace(admitted_guard, 'false'),
                     'integration-clear-mutant': integration_unity.replace(clear_call, 'true')})
    with tempfile.TemporaryDirectory(prefix='awai71-policy-', dir='/private/tmp') as tmp:
        root = Path(tmp)
        for name, content in fixtures.items(): (root / (name + '.kotoba')).write_text(content)
        if a.sha2:
            sha2 = verified(a.sha2, SHA2_PIN)
            assembler = ROOT / 'kotoba/kagi/github_lease_assemble.kotoba'
            native_source = ('(ns kagi-gate-assembler (:export [main]))\n' +
                             body(sha2.read_text()) + '\n' + body(assembler.read_text()))
            (root / 'assembler.kotoba').write_text(native_source)
            for i, item in enumerate(raw): (root / ('source-' + str(i))).write_bytes(item)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        saved = None
        if fd != 3:
            try: saved = os.dup(3)
            except OSError: pass
            os.dup2(fd, 3)
        try:
            def run(argv, expected=0):
                r = subprocess.run([str(x) for x in argv], cwd=root, env={'PATH': '/nonexistent'},
                                   pass_fds=(3,), capture_output=True, timeout=120)
                if r.returncode != expected or r.stderr:
                    raise RuntimeError((str(argv[0]), r.returncode, r.stderr[-300:]))
                return r.stdout
            def build(name):
                run([compiler, 'compile', name + '.kotoba', '--target', 'aarch64-macos', '--output', name + '.kseed'])
                result = run([compiler, 'extract-native', name + '.kseed', '--symbol', 'main', '--output', name + '.raw'])
                match = re.search(rb':offset (\d+), :length (\d+), :arity 0}', result)
                if not match or int(match[2]) != (root / (name + '.raw')).stat().st_size:
                    raise ValueError('native extraction mismatch')
                run([packager, name + '-unsigned.macho', name + '.raw', 'fs2-cli-stdio-general', match[1].decode()])
                image = root / (name + '.macho')
                shutil.copyfile(root / (name + '-unsigned.macho'), image)
                image.chmod(0o700)
                subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(image)], check=True, capture_output=True, timeout=30)
                subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(image)], check=True, capture_output=True, timeout=30)
                return image
            native_assembler = False
            if a.sha2:
                image = build('assembler')
                args = [image] + ['/source-' + str(i) for i in range(4)] + ['/assembled.kotoba'] + [hashlib.sha256(x).hexdigest() for x in raw[1:]]
                run(args)
                if (root / 'assembled.kotoba').read_text() != unity:
                    raise ValueError('native assembler output mismatch')
                run(args, 2)  # Existing output must not be overwritten.
                bad = args.copy(); bad[5] = '/bad.kotoba'; bad[6] = '0' * 64
                run(bad, 2)
                if (root / 'bad.kotoba').exists():
                    raise ValueError('native assembler accepted wrong source hash')
                native_assembler = True
            images = {name: build(name) for name in fixtures}
            run([images['fixture']]); run([images['repo-mutant']], 1); run([images['http-mutant']], 1)
            run([images['jwt-clock-mutant']], 1); run([images['jwt-expiry-mutant']], 1)
            run([images['token-fixture']]); run([images['token-error-mutant']], 1)
            run([images['integration-fixture']]); run([images['integration-policy-mutant']], 1); run([images['integration-clear-mutant']], 1)
            if any(path.read_bytes() != before for path, before in zip(paths, raw)):
                raise ValueError('source changed during diagnostic')
            if any(path.read_bytes() != before for path, before in zip(token_paths, token_raw)):
                raise ValueError('token source changed during diagnostic')
            if any(path.read_bytes() != before for path, before in zip(integration_paths, integration_raw)):
                raise ValueError('integration source changed during diagnostic')
            if sha(compiler) != a.compiler_sha256 or sha(packager) != a.packager_sha256:
                raise ValueError('tool changed during diagnostic')
            print(json.dumps({'readerSha256': READER_PIN, 'policySha256': hashlib.sha256(raw[1]).hexdigest(),
                              'unitySha256': hashlib.sha256(unity.encode()).hexdigest(),
                              'imageSha256': sha(images['fixture']), 'positive': True,
                              'nativeAssembler': native_assembler,
                              'repositoryMutantRefused': True, 'httpMutantRefused': True,
                              'jwtClockMutantRefused': True, 'jwtExpiryMutantRefused': True,
                              'tokenSourceSha256': hashlib.sha256(token_raw[0]).hexdigest(),
                              'tokenUnitySha256': hashlib.sha256(token_unity.encode()).hexdigest(),
                              'tokenImageSha256': sha(images['token-fixture']), 'tokenErrorMutantRefused': True,
                              'integrationSourceSha256': hashlib.sha256(integration_raw[0]).hexdigest(),
                              'integrationUnitySha256': hashlib.sha256(integration_unity.encode()).hexdigest(),
                              'integrationImageSha256': sha(images['integration-fixture']),
                              'integrationPolicyMutantRefused': True,
                              'integrationClearMutantRefused': True,
                              'scope': 'synthetic diagnostic; no production broker, network or selfhost qualification'}))
        finally:
            if fd != 3:
                if saved is None: os.close(3)
                else: os.dup2(saved, 3); os.close(saved)
            os.close(fd)


if __name__ == '__main__': main()
