import pathlib, re, sys
p=pathlib.Path('/Users/junkawasaki/github/workspaces/codex/awai71-repo-lease-policy/test/native/github-lease/gate.py')
s=p.read_text()
anchor='    with tempfile.TemporaryDirectory(prefix=\'awai71-policy-\', dir=\'/private/tmp\') as tmp:'
assert s.count(anchor)==1
s=s.replace(anchor,"    fixtures = {k: fixtures[k] for k in ('integration-fixture', 'integration-clear-mutant')}\n"+anchor)
start=s.index('            images = {name: build(name) for name in fixtures}')
end=s.index('            if any(path.read_bytes()',start)
s=s[:start]+'''            images = {name: build(name) for name in fixtures}
            run([images['integration-fixture']]); run([images['integration-clear-mutant']], 1)
'''+s[end:]
start=s.index("            print(json.dumps({'readerSha256'")
end=s.index('\n        finally:',start)
s=s[:start]+'''            print(json.dumps({'fixture': sha(images['integration-fixture']), 'clearMutantRefused': True, 'source': hashlib.sha256(integration_raw[0]).hexdigest(), 'unity': hashlib.sha256(integration_unity.encode()).hexdigest()}))'''+s[end:]
sys.argv=[str(p),'--reader','/private/tmp/awai71-hybrid-src/jcs-reader.kotoba','--compiler','/tmp/codex-amu-1762/seed/bootstrap/aarch64-macos/amu-full-root.macho','--compiler-sha256','920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6','--packager','/private/tmp/awai154-fs2-darwin-gate/candidate.macho','--packager-sha256','f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d']
exec(compile(s,str(p),'exec'),{'__file__':str(p),'__name__':'__main__'})
