#!/usr/bin/env python3
"""Run actual credential formatting and in-place clearing with synthetic bytes."""
import hashlib,importlib.util,os,re,resource,shutil,subprocess,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
repo=Path('/Users/junkawasaki/github/workspaces/codex/awai71-repo-lease-policy')
spec=importlib.util.spec_from_file_location('f','/Users/junkawasaki/github/workspaces/codex/awai147-job-archive-cursor/scripts/native/check-cron-decisions.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
src=(repo/'kotoba/kagi/github_git_credential.kotoba').read_text()
def form(name):a,b=h.form(src,name);return src[a:b]
pre='(ns credential-clear-fixture (:export [main]))\n'
main=r'''(defn- equal [a :vector-i64 b :vector-i64] :bool
 (and (= (vector-count a) (vector-count b)) (loop [i 0] (if (= i (vector-count a)) true (and (= (vector-at a i) (vector-at b i)) (recur (+ i 1)))))))
(defn main [] :i64
 (let [token (vector-i64 65 66 67) alias token response (ggc-format token)
       expected (ggc-bytes "username=x-access-token\npassword=ABC\n\n")
       ok (and (equal response expected) (equal alias (vector-i64 0 0 0)))
       response-alias response cleared (github-checkpoint-clear-credential! response)
       zeros (loop [i 0] (if (= i (vector-count response-alias)) true (and (= (vector-at response-alias i) 0) (recur (+ i 1)))))
       bad (vector-i64 65 10 66) refused (ggc-format bad)]
  (if (and ok cleared zeros (equal refused (vector-i64 -1)) (equal bad (vector-i64 0 0 0))) 0 1)))'''
source=pre+'\n'.join(form(n) for n in ('ggc-token?','ggc-bytes','ggc-clear!','github-checkpoint-clear-credential!','ggc-format'))+'\n'+main
compiler=Path('/tmp/codex-amu-1762/seed/bootstrap/aarch64-macos/amu-full-root.macho');pack=Path('/private/tmp/awai154-fs2-darwin-gate/candidate.macho')
for p,pin in ((compiler,'920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6'),(pack,'f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d')):
 if hashlib.sha256(p.read_bytes()).hexdigest()!=pin:raise RuntimeError('pin')
with tempfile.TemporaryDirectory(prefix='awai71-clear-',dir='/private/tmp') as d:
 root=Path(d);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 if fd!=3:os.dup2(fd,3)
 def run(cmd,expected=0):
  r=subprocess.run([str(x) for x in cmd],cwd=root,pass_fds=(3,),env={'PATH':'/nonexistent'},capture_output=True,timeout=12,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CPU,(3,3)))
  if r.returncode!=expected or r.stderr:raise RuntimeError((cmd,r.returncode,r.stdout[-500:],r.stderr[-500:]))
  return r.stdout
 def build(name,content):
  (root/(name+'.kotoba')).write_text(content);run([compiler,'compile',name+'.kotoba','--target','aarch64-macos','--output',name+'.kseed']);out=run([compiler,'extract-native',name+'.kseed','--symbol','main','--output',name+'.raw']);m=re.search(rb':offset (\d+), :length (\d+), :arity 0}',out)
  if not m or int(m[2])!=(root/(name+'.raw')).stat().st_size:raise RuntimeError('extract')
  run([pack,name+'-unsigned.macho',name+'.raw','fs2-cli-stdio-general',m[1].decode()]);img=root/(name+'.macho');shutil.copyfile(root/(name+'-unsigned.macho'),img);img.chmod(0o700);subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(img)],check=True,capture_output=True);return img
 run([build('fixture',source)]);print('PASS formatting, alias clearing and invalid token clearing',flush=True)
 anchor='(ggc-clear! token)'
 if source.count(anchor)!=2:raise RuntimeError('clear anchor')
 run([build('mutant',source.replace(anchor,'true'))],1);print('PASS internal clear mutant detected',flush=True)
 print('SOURCE_SHA',hashlib.sha256(source.encode()).hexdigest(),flush=True)
 os.close(3)
 if fd!=3:os.close(fd)
