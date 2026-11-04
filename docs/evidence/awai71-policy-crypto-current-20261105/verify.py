import hashlib,os,pathlib,re,resource,shutil,subprocess,tempfile
base=pathlib.Path(tempfile.mkdtemp(prefix='awai71-current-crypto-',dir='/private/tmp'));src=pathlib.Path('/private/tmp/awai71-hybrid-src');repo=pathlib.Path('/Users/junkawasaki/github/workspaces/codex/awai71-repo-lease-policy');compiler='/tmp/codex-amu-1762/seed/bootstrap/aarch64-macos/amu-full-root.macho';pack='/private/tmp/awai154-fs2-darwin-gate/candidate.macho'
for path,pin in ((compiler,'920954769b8fdc51cf50dfcab5c44a4e56cf01f261806a153b21488ba81ac4e6'),(pack,'f726f9dd8a4f169187275797a74d55ad3c62cc5f681cd31f19e1a28d67834f8d')):
 assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==pin
 subprocess.run(['/usr/bin/codesign','--verify','--strict',path],check=True,capture_output=True)
fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY);assert fd==3
def lim():resource.setrlimit(resource.RLIMIT_CPU,(3,3))
def call(name,args):
 r=subprocess.run(args,cwd=base,pass_fds=(fd,),capture_output=True,env={'PATH':'/nonexistent'},timeout=12,preexec_fn=lim);print(name,r.returncode,r.stderr[-500:].decode(errors='replace'),flush=True);assert r.returncode==0,(name,r.stdout[-500:],r.stderr[-500:]);return r.stdout
def build(label,group,mutate):
 root=base/label/'src';root.mkdir(parents=True)
 files={str(x.relative_to(src)):x.read_bytes() for x in src.rglob('*.kotoba') if x.name!='native_gate.kotoba' and x.name!='jcs-reader.kotoba'}
 files['jcs/reader.kotoba']=(src/'jcs-reader.kotoba').read_bytes()
 for n in ('credential_envelope.kotoba','github_token_response.kotoba','github_lease_policy.kotoba','github_issuance_envelope.kotoba','github_git_credential.kotoba','github_issuance_envelope_test.kotoba'):files['kagi/'+n]=(repo/'kotoba/kagi'/n).read_bytes()
 if mutate in ('token-only','both'):
  k='kagi/github_token_response.kotoba';old=b'(= (gt-str b root "repository_selection") "selected")';assert files[k].count(old)==1;files[k]=files[k].replace(old,b'true')
 if mutate=='both':
  k='kagi/github_lease_policy.kotoba';old=b'(not (= selection "selected"))';assert files[k].count(old)==1;files[k]=files[k].replace(old,b'false')
 if mutate=='issuer-mismatch':
  k='kagi/github_issuance_envelope.kotoba';old=b'(not (gi-equal? (ed/public-from-seed issuer-seed) issuer))';assert files[k].count(old)==1;files[k]=files[k].replace(old,b'false')
 if mutate=='open-clock':
  k='kagi/credential_envelope.kotoba';old=b'x-secret kem-secret principal audience lease-id issued-ms expires-ms now-ms))))';assert files[k].count(old)==1;files[k]=files[k].replace(old,b'x-secret kem-secret principal audience lease-id issued-ms expires-ms issued-ms))))')
 if mutate=='git-target':
  k='kagi/github_git_credential.kotoba';old=br'(not (= request "protocol=https\nhost=github.com\npath=cloud-itonami/itonami-bot-state.git\n"))';assert files[k].count(old)==1;files[k]=files[k].replace(old,b'false')
 # Check every copied crypto dependency against the previously recorded lock.
 for line in (repo/'docs/evidence/awai71-github-token-validation-20261103/integrated.ksl').read_text().splitlines():
  if line.startswith('file '):
   _,pin,path=line.split(' ');name=path.removeprefix('/valid/src/')
   if name in files and not name.startswith(('kagi/','pq/')):
    assert hashlib.sha256(files[name]).hexdigest()==pin, name
 entry='git-main' if group=='git' else ('issued-main' if group=='issued' else 'main')
 files['pq/entry.kotoba']=('(ns pq.entry (:require [kagi.github-issuance-envelope-test :as g]) (:export [main]))\n(defn main [] :i64 (g/'+entry+'))\n').encode()
 for n,b in files.items():
  path=root/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
 rel='/'+label+'/src';lock=base/(label+'.ksl');lock.write_text('KSL1\nentry '+rel+'/pq/entry.kotoba\nroot '+rel+'\n'+''.join('file '+hashlib.sha256(v).hexdigest()+' '+rel+'/'+k+'\n' for k,v in sorted(files.items())))
 flags=['--source-path',rel,'--source-lock',lock.name,'--source-lock-sha256',hashlib.sha256(lock.read_bytes()).hexdigest()];entry=rel+'/pq/entry.kotoba'
 call(label+'-check',[compiler,'check',entry,*flags]);call(label+'-compile',[compiler,'compile',entry,'--target','aarch64-macos','--output',label+'.kseed',*flags]);out=call(label+'-extract',[compiler,'extract-native',label+'.kseed','--symbol','main','--output',label+'.raw']);m=re.search(rb':offset (\d+), :length (\d+), :arity 0\}',out);assert m
 call(label+'-pack',[pack,label+'-unsigned.macho',label+'.raw','fs2-cli-stdio-general',m.group(1).decode()]);binary=base/(label+'.macho');shutil.copyfile(base/(label+'-unsigned.macho'),binary);os.chmod(binary,0o700);subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(binary)],check=True,capture_output=True)
 r=subprocess.run([str(binary)],cwd=base,pass_fds=(fd,),capture_output=True,env={'PATH':'/nonexistent'},timeout=12,preexec_fn=lim);print(label+'-result',r.returncode,flush=True);expected=(113 if mutate=='git-target' else 255) if group=='git' else ((61 if mutate=='open-clock' else 63) if group=='issued' else (253 if mutate=='both' else (191 if mutate=='issuer-mismatch' else 255)));assert r.returncode==expected,(r.returncode,r.stderr)
 print(label+'-sha256',hashlib.sha256(binary.read_bytes()).hexdigest(),'lock-sha256',hashlib.sha256(lock.read_bytes()).hexdigest(),flush=True)
build('valid','a','none');build('token-guard-mutant','a','token-only');build('both-guards-mutant','a','both');build('issuer-mutant','a','issuer-mismatch');build('issued','issued','none');build('issued-clock-mutant','issued','open-clock');build('git','git','none');build('git-target-mutant','git','git-target');os.close(fd);shutil.rmtree(base)
