import hashlib, importlib.util, os, pathlib, re, resource, shutil, subprocess, sys, tempfile
sys.dont_write_bytecode = True
repo=pathlib.Path('/Users/junkawasaki/github/workspaces/codex/awai71-repo-lease-policy')
compiler=pathlib.Path('/tmp/codex-amu-1762/seed/bootstrap/aarch64-macos/amu-full-root.macho')
pack=pathlib.Path('/private/tmp/awai154-fs2-darwin-gate/candidate.macho')
reader=pathlib.Path('/private/tmp/awai71-hybrid-src/jcs-reader.kotoba')
for p,h in [(compiler,'920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6'),(pack,'f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d'),(reader,'f8af2953904bd0a96e7b5c3b9e34151bcae3754e5358669adb8ac289acc0872f')]:
 assert hashlib.sha256(p.read_bytes()).hexdigest()==h
 if p!=reader: subprocess.run(['/usr/bin/codesign','--verify','--strict',str(p)],check=True,capture_output=True)
spec=importlib.util.spec_from_file_location('gate',repo/'test/native/github-lease/gate.py'); gate=importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
sources=[reader,repo/'kotoba/kagi/github_token_response.kotoba',repo/'kotoba/kagi/github_token_response_test.kotoba']
u='(ns kagi-token-response-native-test (:export [main]))\n'+gate.body(sources[0].read_text())+'\n'+gate.body(sources[1].read_text()).replace('j/','')+'\n'+gate.body(sources[2].read_text()).replace('t/','')+'\n(defn main [] :i64 (if (and (= (group-a) 255) (= (group-b) 511) (= (group-c) 7)) 0 1))\n'
assert u.count('(not (= c 92))') == 1
with tempfile.TemporaryDirectory(prefix='awai71-raw-token-',dir='/private/tmp') as tmp:
 root=pathlib.Path(tmp);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);saved=None
 if fd!=3:
  try: saved=os.dup(3)
  except OSError: pass
  os.dup2(fd,3)
 def lim(): resource.setrlimit(resource.RLIMIT_CPU,(3,3))
 def run(args,expected=0):
  p=subprocess.run([str(x) for x in args],cwd=root,pass_fds=(3,),env={'PATH':'/nonexistent'},capture_output=True,timeout=20,preexec_fn=lim)
  if p.returncode!=expected: raise RuntimeError((args[0],p.returncode,p.stderr[-300:]))
  return p.stdout
 try:
  for name,src,expected in [('valid',u,0),('escape-mutant',u.replace('(not (= c 92))','true'),1)]:
   (root/(name+'.kotoba')).write_text(src)
   run([compiler,'compile',name+'.kotoba','--target','aarch64-macos','--output',name+'.kseed'])
   result=run([compiler,'extract-native',name+'.kseed','--symbol','main','--output',name+'.raw']);m=re.search(rb':offset (\d+), :length (\d+), :arity 0}',result);assert m
   run([pack,name+'-unsigned.macho',name+'.raw','fs2-cli-stdio-general',m[1].decode()])
   image=root/(name+'.macho');shutil.copyfile(root/(name+'-unsigned.macho'),image);image.chmod(0o700);subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(image)],check=True,capture_output=True)
   run([image],expected);print(name,'exit',expected,'source-sha256',hashlib.sha256(src.encode()).hexdigest(),'image-sha256',hashlib.sha256(image.read_bytes()).hexdigest(),flush=True)
 finally:
  if fd!=3:
   if saved is None: os.close(3)
   else: os.dup2(saved,3);os.close(saved)
  os.close(fd)
