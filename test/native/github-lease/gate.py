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
    if unity.count(repo_guard) != 1 or unity.count(http_guard) != 1:
        raise ValueError('negative-control anchor changed')
    fixtures = {'fixture': unity, 'repo-mutant': unity.replace(repo_guard, 'false'),
                'http-mutant': unity.replace(http_guard, 'false')}
    with tempfile.TemporaryDirectory(prefix='awai71-policy-', dir='/private/tmp') as tmp:
        root = Path(tmp)
        for name, content in fixtures.items(): (root / (name + '.kotoba')).write_text(content)
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
            images = {name: build(name) for name in fixtures}
            run([images['fixture']]); run([images['repo-mutant']], 1); run([images['http-mutant']], 1)
            if any(path.read_bytes() != before for path, before in zip(paths, raw)):
                raise ValueError('source changed during diagnostic')
            if sha(compiler) != a.compiler_sha256 or sha(packager) != a.packager_sha256:
                raise ValueError('tool changed during diagnostic')
            print(json.dumps({'readerSha256': READER_PIN, 'policySha256': hashlib.sha256(raw[1]).hexdigest(),
                              'unitySha256': hashlib.sha256(unity.encode()).hexdigest(),
                              'imageSha256': sha(images['fixture']), 'positive': True,
                              'repositoryMutantRefused': True, 'httpMutantRefused': True,
                              'scope': 'synthetic diagnostic; no production broker, network or selfhost qualification'}))
        finally:
            if fd != 3:
                if saved is None: os.close(3)
                else: os.dup2(saved, 3); os.close(saved)
            os.close(fd)


if __name__ == '__main__': main()
