#!/usr/bin/env python3
"""Synthetic end-to-end Git credential protocol diagnostic; no network or real token."""
import hashlib,os,pathlib,re,resource,shutil,subprocess,tempfile
from pathlib import Path
repo=Path('/Users/junkawasaki/github/workspaces/codex/awai71-repo-lease-policy');src=Path('/private/tmp/awai71-hybrid-src')
compiler=Path('/tmp/codex-amu-1762/seed/bootstrap/aarch64-macos/amu-full-root.macho');pack=Path('/private/tmp/awai71-darwin-stdin/candidate.macho')
for p,pin in ((compiler,'920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6'),(pack,'37cc4348e95e80cc0682c8f13cfe8171f350674fff1810327d56528ae5011037')):
 if hashlib.sha256(p.read_bytes()).hexdigest()!=pin:raise RuntimeError('pin')
 subprocess.run(['/usr/bin/codesign','--verify','--strict',str(p)],check=True,capture_output=True)
with tempfile.TemporaryDirectory(prefix='awai71-git-helper-',dir='/private/tmp') as d:
 root=Path(d);tree=root/'src';tree.mkdir()
 files={str(p.relative_to(src)):p.read_bytes() for p in src.rglob('*.kotoba') if p.name not in ('native_gate.kotoba','jcs-reader.kotoba')}
 files['jcs/reader.kotoba']=(src/'jcs-reader.kotoba').read_bytes()
 for n in ('credential_envelope.kotoba','github_token_response.kotoba','github_lease_policy.kotoba','github_issuance_envelope.kotoba','github_git_credential.kotoba'):
  files['kagi/'+n]=(repo/'kotoba/kagi'/n).read_bytes()
 files['test/github_git_credential_fixture.kotoba']=(repo/'test/native/github_git_credential_fixture.kotoba').read_bytes()
 for line in (repo/'docs/evidence/awai71-github-token-validation-20261103/integrated.ksl').read_text().splitlines():
  if line.startswith('file '):
   _,pin,path=line.split(' ');name=path.removeprefix('/valid/src/')
   if name in files and not name.startswith(('kagi/','pq/')):
    if hashlib.sha256(files[name]).hexdigest()!=pin:raise RuntimeError('dependency mismatch '+name)
 for name,data in files.items():
  path=tree/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 entry='/src/test/github_git_credential_fixture.kotoba';lock=root/'source.ksl'
 lock.write_text('KSL1\nentry '+entry+'\nroot /src\n'+''.join('file '+hashlib.sha256(v).hexdigest()+' /src/'+name+'\n' for name,v in sorted(files.items())))
 lockpin=hashlib.sha256(lock.read_bytes()).hexdigest();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 if fd!=3:os.dup2(fd,3)
 def run(cmd,data=None,expected=0,env=None):
  p=subprocess.run([str(x) for x in cmd],input=data,cwd=root,pass_fds=(3,),env=env or {'PATH':'/nonexistent'},capture_output=True,timeout=12,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CPU,(3,3)))
  if p.returncode!=expected:raise RuntimeError((cmd,p.returncode,p.stderr[-300:]))
  return p
 flags=['--source-path','/src','--source-lock','source.ksl','--source-lock-sha256',lockpin]
 run([compiler,'check',entry,*flags]);run([compiler,'compile',entry,'--target','aarch64-macos','--output','helper.kseed',*flags]);out=run([compiler,'extract-native','helper.kseed','--symbol','main','--output','helper.raw']).stdout
 m=re.search(rb':offset (\d+), :length (\d+), :arity 0}',out)
 if not m or int(m[2])!=(root/'helper.raw').stat().st_size:raise RuntimeError('extract')
 run([pack,'helper-unsigned.macho','helper.raw','fs2-cli-stdio-read',m[1].decode()]);img=root/'helper.macho';shutil.copyfile(root/'helper-unsigned.macho',img);img.chmod(0o700);subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(img)],check=True,capture_output=True)
 env={'PATH':'/usr/bin:/bin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','HOME':str(root)}
 req=b'protocol=https\nhost=github.com\npath=cloud-itonami/itonami-bot-state.git\n\n'
 git=['/usr/bin/git','-c','credential.useHttpPath=true','-c','credential.helper='+str(img),'credential','fill']
 p=run(git,req,env=env)
 if b'username=x-access-token\n' not in p.stdout or b'password=synthetic-token\n' not in p.stdout or p.stderr:raise RuntimeError('valid fill')
 print('PASS actual git credential fill with native synthetic helper',flush=True)
 wrong=[b'protocol=https\nhost=other.example\npath=cloud-itonami/itonami-bot-state.git\n',b'protocol=https\nhost=github.com\npath=cloud-itonami/other.git\n',b'protocol=https\nhost=github.com\n']
 for request in wrong:
  p=run([img,'get'],request,expected=1)
  if p.stdout:raise RuntimeError('credential returned for wrong target')
 print('PASS wrong host, repository and missing path return no bytes',flush=True)
 p=run([img,'store'],req,expected=1)
 if p.stdout:raise RuntimeError('credential returned for store')
 print('PASS store operation returns no bytes',flush=True)
 print('SOURCE_LOCK_SHA',lockpin,'IMAGE_SHA',hashlib.sha256(img.read_bytes()).hexdigest(),flush=True)
 os.close(3)
 if fd!=3:os.close(fd)
