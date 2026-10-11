
## Offline device enrollment and recovery

The `mithril-transfer` adapter encrypts a complete trusted snapshot for a new
X25519 recipient. This classical transfer is not the existing hybrid PQC actor.
Requests expire after ten minutes. The approving device compares the complete
request fingerprint with the requesting device over a trusted channel; the new
device compares the complete transfer fingerprint with the approving device.
Both comparisons are necessary: recipient encryption alone does not authenticate
the sender. The application consumes requests once and refuses state overwrite.

Recovery uses a separate random 256-bit code and an authenticated encrypted file.
Keep the code separately from the file. Neither is uploaded by this adapter.
A backup includes the record revision floors at export time; it cannot detect
server rollback after that snapshot. Re-export after important changes. Anyone
with the code and file can recover the vault. Device removal cannot erase copies
already shared; rotate affected issuer credentials. External review remains a
production-adoption gate under SECURITY.md.
