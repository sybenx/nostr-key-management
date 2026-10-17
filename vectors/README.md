# Test vectors

Known answers for the derivations in
[NOSTR_KEY_MANAGEMENT.md](../NOSTR_KEY_MANAGEMENT.md), archived with it.

The QR transfer vector (`qrst-sas.json`) moved to
[sybenx/qr-secret-transfer](https://github.com/sybenx/qr-secret-transfer/tree/main/vectors)
with the specification.

These are normative. Where a vector and an implementation disagree, and the
vector is confirmed to follow the specification text, the implementation is
wrong. Where a vector and the specification text disagree, the text wins and the
vector is a bug — report it in [SPEC_ISSUES.md](../SPEC_ISSUES.md).

Every key, nonce and identity in these files is a fixture chosen for the file.
None belongs to anybody, and none should ever be used for anything.

## Files

| File | Covers |
|---|---|
| `nkm-frost.json` | NKM §7.4, §7.5, §7.9, §7.18 — dealing, share verification, signing, rotation. |

## Provenance

`nkm-frost.json` was generated with `@noble/curves` 2.3.0's `schnorr_FROST` — RFC
9591 over the secp256k1 taproot ciphersuite §7.4 names, rather than a
reimplementation of it — and the §7.4 share check and §7.9 rotation algebra were
then re-derived independently from raw curve operations, so the two agree about
the arithmetic without sharing any code that performs it. The file regenerates
byte-identically: the dealer, the rotation delta and every signing nonce come
from a seeded generator. **A real dealer MUST NOT**; §7.4 forbids a derived `a_1`
because a reproducible polynomial resurrects revoked shares, and the determinism
here exists only so the file can be a fixture.

Its fixture nsec has an **odd-y** pubkey, which is the point of it. §7.4's parity
rule is the only behaviour in either document that depends on key parity, and both
`nsec` and `n - nsec` serialise to the same x-only pubkey — so an even-y fixture
passes whichever reading an implementer took, and so does §7.5's check of
`group_pub` against the user's known pubkey. Two of the values in this file are
deliberately **false** (`t3[*].nkm_degree1_form_holds`): §7.18 offers `t = 3` and
states a share check that does not hold at that threshold, and an implementation
that reproduces the `false` has read the section correctly and found it
unimplementable as written. See [SPEC_ISSUES.md](../SPEC_ISSUES.md).
