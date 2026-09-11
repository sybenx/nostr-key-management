# Nostr Key Transfer & Storage

The most notable thing here is that the secret moves over public relays. You do
not run a server, you do not register with one, and the relay cannot read what it
carries or tell who sent it. Every other way of doing this needs somebody to
operate the thing in the middle.

Two specs live in this repo.

**[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md)** is the transfer mechanism, and
it is the one to read first. One device shows a QR, the other scans it, and the
secret travels inside a [gift-wrapped](https://github.com/nostr-protocol/nips/blob/master/59.md)
message over public relays. The QR holds a throwaway public key and nothing else,
so a photograph of it is worthless. Before the secret is released, the sending
device makes you type a five digit code shown on the receiving device, which is
what stops somebody sitting in the middle. It carries nsec identities, FROST
shares, and anything else a profile defines.

**[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md)** is storage and backup. It
registers the two payload profiles the transfer spec uses: `nostr-nsec` for a
whole identity key, and `frost-share` for a single threshold share. Threshold
signing itself is not specified here — it's [FROSTR](https://github.com/FROSTR-ORG/bifrost),
adopted whole; this project's own contribution is getting a share to a new
device without a plaintext QR.

The point of all this is to be better than copy-pasting an nsec between apps, and
better than leaving one in a notes file. Storage is upgraded to whatever the
device actually supports, and nothing blocks you from logging in if your device
supports none of it. Where a sensible default can be picked for the user without
giving something up, it is picked for them.

## Why this is not NIP-46

NIP-46 is a signing protocol for a remote signer that holds the whole key and must
be reachable for every signature. FROSTR improves on that structurally: any
threshold of peers signs together, none holds a usable key alone, and a
compromised peer neither reconstructs nor forges by itself. A configuration with
a server as one peer among your own devices gets the NIP-46 shape made strictly
better — the server never holds your whole key — without this project having to
build or specify that server; a configuration with no server at all, any two of
your own devices, is the thing NIP-46 structurally cannot do regardless.

NIP-46 also does not specify a key transfer method, nor how to store a key,
whether it is backed up, or what happens when a device is lost. This project
fills those gaps — and, for FROSTR specifically, replaces its plaintext QR
handoff with one gated by a typed code and end-to-end encryption (NKM §3.3).

## What this project is not

The transfer mechanism is not new cryptography. The commit-then-reveal code
comparison is ZRTP's, by way of Matrix, and it is cited as such. What is unusual
is running it over infrastructure nobody operates for the purpose.

## Status

QR_SECRET_TRANSFER.md is version 1.5-draft: the `frost://` scheme and light
returned-secret flow (§12.3) for revocable shares, a profile-gated offline tier
(§10) — passphrase-encrypted, no relay — and a non-normative note (§16) on how
this mechanism composes with FROSTR's own echo. The event kinds are
provisional — chosen from the ephemeral range and verified non-conflicting, but
not yet reserved by a NIP — and one test vector remains incomplete: the §11.4
gift-wrap timing vector (the §6 short code and the §4/P1 payload ceiling are
both covered in [vectors/](vectors/)).

NOSTR_KEY_MANAGEMENT.md is version 10.0-draft: it stops specifying its own
threshold-signing protocol and adopts [FROSTR](https://github.com/FROSTR-ORG/bifrost)
whole. `frost-share` (§3.3) now carries a FROSTR credential pair — a
`bfshare1…` and its `bfgroup1…` — instead of a bespoke encoding, still with a
passphrase-encrypted offline container for the no-transport case. §7 keeps only
what FROSTR does not have: a rotation construction and a recovery-delay
obligation, both offered to FROSTR as proposals rather than specified for this
project's own clients.

This project benefits from devs and users pressure testing the claims of the
spec. Failure modes will be handled within reason to improve it. Structural
robustness increases the convenience and security of users as far as the spec is
widely deployed and followed, across various hardware and software conditions.
Disagreements and suspected errors belong in
[SPEC_ISSUES.md](SPEC_ISSUES.md); pull requests and issue submissions should be
used where possible.
