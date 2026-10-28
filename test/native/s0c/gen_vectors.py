"""Generate the S0-c funds-role vectors with an independent oracle (hashlib + OpenSSL).

All seeds are the PUBLISHED RFC 8032 section 7.1 test seeds; never operational keys.
Usage: python3 -I gen_vectors.py > vectors.kotoba
Self-check: with the existing agent policy it reproduces the genesis signatures
already pinned in test/native/agent_signer_vectors.kotoba.
"""
import base64, hashlib, os, subprocess, tempfile

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SEED = {  # RFC 8032 7.1 tests 1..3
    0: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    1: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    2: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
}
Z64 = "0" * 64
Z128 = "0" * 128


def ed(seed_hex, msg):
    seed = bytes.fromhex(seed_hex)
    d = tempfile.mkdtemp()
    pem, mf = os.path.join(d, "k.pem"), os.path.join(d, "m")
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    open(pem, "w").write("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PRIVATE KEY-----\n")
    open(mf, "wb").write(msg)
    sig = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", pem, "-rawin", "-in", mf])
    pub = subprocess.check_output(["openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER"])[-32:]
    return sig.hex(), pub.hex()


def pub(i):
    return ed(SEED[i], b"x")[1]


def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n:
        n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def did(p):
    return "did:key:z" + b58(bytes([0xED, 1]) + bytes.fromhex(p))


def tid(body):
    h = hashlib.sha256(body.encode()).digest()
    return "b" + base64.b32encode(bytes([1, 0x71, 0x12, 0x20]) + h).decode().lower().rstrip("=")


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


GUARDS = pub(0) + pub(1) + pub(2)
AUTHOR, DELEGATE = pub(2), pub(1)


def keyset(policy):
    ev = " ".join(["kagi.keyset.event.v1", "genesis", "0", Z64, AUTHOR, sha(policy), GUARDS, "2"])
    sigs = ed(SEED[0], ("kagi.keyset.manage.v1\n" + ev).encode())[0] + ed(SEED[1], ("kagi.keyset.manage.v1\n" + ev).encode())[0] + Z128
    proof = ed(SEED[2], ("kagi.keyset.author.v1\n" + ev).encode())[0]
    pin = sha(ev)
    state = " ".join(["kagi.keyset.state.v1", pin, pin, "0", "active", AUTHOR, sha(policy), GUARDS, "2"])
    return ev, sigs, proof, pin, state


def permit(pin, purpose, scope, aud, body_digest, fence, seq, issued, expires):
    return " ".join(["kagi.agent.permit.v1", pin, pin, "0", purpose, scope, aud, body_digest, Z64, str(fence), str(seq), str(issued), str(expires)])


# self-check against the pinned agent vectors
agent_policy = "kagi.agent.policy.v1 agent mon:fixture-a hata:fixture-a " + DELEGATE + " state-commit 30000"
ev, sigs, proof, pin, state = keyset(agent_policy)
assert pin == "0406853c048913478ef946d6058a99278d42cdb6a19ad8957944edbfcfb5cdc5", pin
assert proof == "a66650488212186a4fd5abf95e7164f478aa345c811bc8615c07f1209d5b911e1fc0ed2392268b9013ab7c84c095ce2fccbb7ea835515eb61f1a8174ef12d705"

SPENDER = did(AUTHOR)
RECEIVER = did(pub(0))
FIELDS = {"amount": "7", "spender-prev": "nil", "nonce": "n0", "ts": "1000"}
body = "engi/transfer-body\nspender=%s\nreceiver=%s\namount=%s\nspender-prev=%s\nnonce=%s\nts=%s\n" % (
    SPENDER, RECEIVER, FIELDS["amount"], FIELDS["spender-prev"], FIELDS["nonce"], FIELDS["ts"])
T = tid(body)
SIG = base64.urlsafe_b64encode(bytes.fromhex(ed(SEED[2], T.encode())[0])).decode().rstrip("=")

MAXAMT, DAILY = 10, 20
OTHER = did(pub(2))
ALLOW_MAIN = "\n" + RECEIVER + "\n" + OTHER + "\n"
ALLOW_OTHER = "\n" + OTHER + "\n"
ALLOW_PREFIX = "\n" + RECEIVER + "x\n"
ALLOW_FORGED = ALLOW_MAIN + "did:key:z6MkEvilEvilEvilEvilEvilEvilEvilEvilEvilEvil\n"


def fpol(allow, role="funds", purpose="en-transfer"):
    return "kagi.agent.policy.v1 %s mon:funds hata:funds %s %s 30000 %d %d %s" % (role, DELEGATE, purpose, MAXAMT, DAILY, sha(allow))


def scenario(policy, b):
    _, _, _, pin_, state_ = keyset(policy)
    pm = permit(pin_, "en-transfer", "mon:funds", "hata:funds", sha(b), 7, 1, 1000, 30000)
    return state_, pm, ed(SEED[1], pm.encode())[0]


def make_body(amount):
    return "engi/transfer-body\nspender=%s\nreceiver=%s\namount=%s\nspender-prev=%s\nnonce=%s\nts=%s\n" % (
        SPENDER, RECEIVER, amount, FIELDS["spender-prev"], FIELDS["nonce"], FIELDS["ts"])


funds_policy = fpol(ALLOW_MAIN)
fstate, fpermit, fsig = scenario(funds_policy, body)
_, _, _, fpin, _ = keyset(funds_policy)
body_cap = make_body(MAXAMT + 1)
_, cap_permit, cap_sig = scenario(funds_policy, body_cap)
other_policy = fpol(ALLOW_OTHER)
other_state, other_permit, other_sig = scenario(other_policy, body)
prefix_policy = fpol(ALLOW_PREFIX)
prefix_state, prefix_permit, prefix_sig = scenario(prefix_policy, body)
# an agent-role keyset and permit over the same transfer body
apolicy = "kagi.agent.policy.v1 agent mon:funds hata:funds " + DELEGATE + " state-commit 30000"
_, _, _, apin, astate = keyset(apolicy)
apermit = permit(apin, "state-commit", "mon:funds", "hata:funds", sha(body), 7, 1, 1000, 30000)
asig = ed(SEED[1], apermit.encode())[0]
# a receiver that smuggles a field, with a permit whose digest commits to exactly that body:
# only the receiver screen (not the digest binding) can stop it
INJ = RECEIVER + "\namount=1"
body_inj = "engi/transfer-body\nspender=%s\nreceiver=%s\namount=%s\nspender-prev=%s\nnonce=%s\nts=%s\n" % (
    SPENDER, INJ, FIELDS["amount"], FIELDS["spender-prev"], FIELDS["nonce"], FIELDS["ts"])
ipermit = permit(fpin, "en-transfer", "mon:funds", "hata:funds", sha(body_inj), 7, 1, 1000, 30000)
isig = ed(SEED[1], ipermit.encode())[0]
# a funds permit whose delegate signed another permit text
badsig = ed(SEED[1], (fpermit + "x").encode())[0]


def esc(x):
    return x.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


V = {
    "seed": SEED[2], "author": AUTHOR, "spender": SPENDER, "receiver": RECEIVER,
    "amount": FIELDS["amount"], "spender-prev": FIELDS["spender-prev"], "nonce": FIELDS["nonce"], "ts": FIELDS["ts"],
    "body": body, "tid": T, "sig-b64": SIG,
    "funds-policy": funds_policy, "funds-state": fstate, "funds-permit": fpermit, "funds-sig": fsig,
    "allow-main": ALLOW_MAIN, "allow-other": ALLOW_OTHER, "allow-prefix": ALLOW_PREFIX, "allow-forged": ALLOW_FORGED,
    "cap-amount": str(MAXAMT + 1), "cap-permit": cap_permit, "cap-sig": cap_sig,
    "other-policy": other_policy, "other-state": other_state, "other-permit": other_permit, "other-sig": other_sig,
    "prefix-policy": prefix_policy, "prefix-state": prefix_state, "prefix-permit": prefix_permit, "prefix-sig": prefix_sig,
    "agent-policy": apolicy, "agent-state": astate, "agent-permit": apermit, "agent-sig": asig,
    "bad-sig": badsig,
    "inj-receiver": INJ, "inj-permit": ipermit, "inj-sig": isig,
    "policy-agent-role": "kagi.agent.policy.v1 agent mon:funds hata:funds " + DELEGATE + " en-transfer 30000",
    "policy-wrong-purpose": fpol(ALLOW_MAIN, purpose="cell-action"),
    "policy-old-shape": "kagi.agent.policy.v1 funds mon:funds hata:funds " + DELEGATE + " en-transfer 30000",
    "policy-cap-above-daily": "kagi.agent.policy.v1 funds mon:funds hata:funds %s en-transfer 30000 30 20 %s" % (DELEGATE, sha(ALLOW_MAIN)),
    "policy-zero-cap": "kagi.agent.policy.v1 funds mon:funds hata:funds %s en-transfer 30000 0 20 %s" % (DELEGATE, sha(ALLOW_MAIN)),
    "policy-bad-digest": "kagi.agent.policy.v1 funds mon:funds hata:funds %s en-transfer 30000 10 20 zz" % DELEGATE,
}
print(";; S0-c/S0-d funds-role vectors. Generated by gen_vectors.py with PUBLIC RFC 8032 seeds; NOT live keys.")
print("(ns kagi.agent-signer-vectors (:export [kg-v]))")
print("(defn kg-v [name :string] :string")
print("  (cond")
for k, v in V.items():
    print('    (= name "%s") "%s"' % (k, esc(v)))
print('    :else ""))')
