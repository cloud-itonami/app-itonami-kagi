#!/bin/sh
# JUN-501 S0-a native gate: the pinned native Ed25519/SHA-256 owners must
# reproduce test/native/engi_transfer_vectors.json (public key, SHA-256 of the
# canonical TransferBody, Ed25519 over the transfer-id text). Public RFC 8032
# seed only; never an operational key.
#
# Run on arm64 Linux from the repository root:
#   sh test/native/s0a_gate.sh COMPILER OWNERS_DIR NEW_BUILD_DIR [SUITE]
# SUITE is the directory under test/native holding gate.kotoba and
# vectors.kotoba: s0a (default; signature vectors) or s0b (base32, base58btc,
# base64url derivation of the transfer-id, did:key and signature text).
# COMPILER is the lock-pinned amu-root, OWNERS_DIR holds sha2.kotoba and
# ed25519.kotoba (digests in native-local-host.lock.json). NEW_BUILD_DIR must
# not exist: the gate overlays s0a/{gate,vectors}.kotoba onto a copy of the
# source tree and leaves the 32-case core gate untouched.
set -e
[ $# -ge 3 ] || { echo "usage: $0 COMPILER OWNERS_DIR NEW_BUILD_DIR [SUITE]" >&2; exit 64; }
C=$1; O=$2; B=$3; S=${4:-s0a}; R=$(pwd)
[ -f "test/native/$S/gate.kotoba" ] || { echo "unknown suite $S" >&2; exit 64; }
[ ! -e "$B" ] || { echo "refusing existing build dir $B" >&2; exit 73; }
mkdir -p "$B/root/test/native"
cp -R kotoba "$B/root/kotoba"
cp test/native/$S/gate.kotoba "$B/root/test/native/agent_signer_gate.kotoba"
cp test/native/$S/vectors.kotoba "$B/root/test/native/agent_signer_vectors.kotoba"
export KEXE_STACK_BYTES=8388608 KEXE_SECCOMP=if-available
KEXE_CAP_RESOURCES_35="$B/root:$B" "$C" compile "$B/root/kotoba/kagi/assemble.kotoba" --target aarch64-linux --output "$B/assemble" --format static
chmod 755 "$B/assemble"
KEXE_ALLOW=3,35,37,38,39 KEXE_CAP_RESOURCES_35="$O:$B/root:$B" "$B/assemble" gate "$O/sha2.kotoba" "$O/ed25519.kotoba" "$B/root" "$B/gate.kotoba"
KEXE_CAP_RESOURCES_35="$B/root:$B" "$C" compile "$B/gate.kotoba" --target aarch64-linux --output "$B/s0a-gate" --format static
chmod 755 "$B/s0a-gate"
sha256sum "$B/s0a-gate"
KEXE_ALLOW=37 "$B/s0a-gate" || true
