# GitHub lease policy candidate

`github_lease_policy.kotoba` provides a pure request decision for an exact
repository and authenticated principal, fixed `checkpoint-archive` purpose,
contents read/write permission and owner-supplied maximum/requested TTL. A
separate decision rejects a returned provider expiry that is not later than the
trusted clock or exceeds the requested deadline. The owner must first verify the
policy signature; the host must authenticate the requester and supply a trusted
clock. The issuer must independently enforce repository selection and exact
GitHub permissions, verify the response, seal the secret to the requester,
journal the lease and handle revocation/unknown outcomes. None of those are
implemented or implied by a `lease/request-eligible` result.

The `contents:read` and `contents:write` labels describe only contents access;
GitHub's required metadata read access and the complete provider permission
response must be checked by the future issuer. This candidate is not wired to
CLI, host, a signer, GitHub or Itonami. No token is created or handled.
Rejecting a provider expiry beyond a requested shorter deadline is deliberate;
the broker must not assume that a locally shortened lease invalidates an
otherwise valid provider token.

On one Mac, a selected unity of the actual policy forms and native source cases
passed the previously staged Amu source check and executed with a signed
native diagnostic packager. It checked exact repository, wildcard rejection,
principal, purpose, permission, TTL and expiry boundaries; a mutant that
ignored repository mismatch failed. Fixture SHA-256:
`bf43ae0489c3fd53de11354ebf24495113878ff112421bea4a3df21113cad781`;
signed test image SHA-256:
`d957f306dd3d683250c4cc4da0d82511e12e042ffba1f8e5d34276e8464d8c99`.
The fixed diagnostic compiler required the test unity to export only `main`;
the module's independent export/import closure, selfhost build, real signed
policy, host and GitHub behavior remain unqualified.
