"""Generate ENGI transfer vectors with an independent oracle (hashlib + OpenSSL).

Seeds are the PUBLISHED RFC 8032 section 7.1 test seeds. They are public and
must never be used as operational keys. Usage: python3 -I gen_engi_transfer_vectors.py > engi_transfer_vectors.json
"""
import hashlib, base64, subprocess, sys, json, os, tempfile
B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n=int.from_bytes(b,'big'); s=''
    while n: n,r=divmod(n,58); s=B58[r]+s
    return '1'*(len(b)-len(b.lstrip(b'\0')))+s
def b32(b):
    return base64.b32encode(b).decode().lower().rstrip('=')
def sign_pub(seed_hex, msg):
    seed=bytes.fromhex(seed_hex)
    d=tempfile.mkdtemp()
    pem=os.path.join(d,'k.pem'); mf=os.path.join(d,'m')
    der=bytes.fromhex('302e020100300506032b657004220420')+seed
    open(pem,'w').write('-----BEGIN PRIVATE KEY-----\n'+base64.b64encode(der).decode()+'\n-----END PRIVATE KEY-----\n')
    open(mf,'wb').write(msg)
    sig=subprocess.check_output(['openssl','pkeyutl','-sign','-inkey',pem,'-rawin','-in',mf])
    pubder=subprocess.check_output(['openssl','pkey','-in',pem,'-pubout','-outform','DER'])
    return sig,pubder[-32:]
def body(b):
    return ("engi/transfer-body\nspender=%s\nreceiver=%s\namount=%s\nspender-prev=%s\nnonce=%s\nts=%s\n"
      %(b['spender'],b['receiver'],b['amount'],b['spender-prev'],b['nonce'],b['ts']))
def tid(text):
    return 'b'+b32(bytes([1,0x71,0x12,0x20])+hashlib.sha256(text.encode()).digest())
def did(pub): return 'did:key:z'+b58(bytes([0xed,1])+pub)
seeds={"spender":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
       "receiver":"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"}
out={}
pubs={}
for k,s in seeds.items():
    _,pubs[k]=sign_pub(s,b'x'); 
dids={k:did(p) for k,p in pubs.items()}
cases=[{"amount":1,"spender-prev":"nil","nonce":"n0","ts":1000},
       {"amount":15,"spender-prev":"bafy-prev","nonce":"n1","ts":2000}]
res=[]
for c in cases:
    b=dict(c,spender=dids['spender'],receiver=dids['receiver'])
    t=body(b); i=tid(t)
    sig,_=sign_pub(seeds['spender'],i.encode())
    res.append({"body":t,"transfer-id":i,"sig-b64url":base64.urlsafe_b64encode(sig).decode().rstrip('=')})
print(json.dumps({"purpose":"interop vectors for kagi funds-role S0 (JUN-501); public RFC 8032 seeds, never operational","signs":"Ed25519 over the UTF-8 bytes of transfer-id (engi.crypto/sign-transfer)","transfer-id":"b + base32-lower(0x01 0x71 0x12 0x20 || sha256(canonical-transfer-body))","did-key":"did:key:z + base58btc(0xed 0x01 || pub32)","seeds":seeds,"dids":dids,"cases":res,"negative":["a different amount yields a different transfer-id","a signature over one transfer-id does not verify for another","a signature does not verify under the receiver did:key"]},indent=1))
