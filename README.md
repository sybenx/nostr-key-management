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

**[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md)** is storage, backup, and
optional FROST threshold signing. It registers the two payload profiles the
transfer spec uses: `nostr-nsec` for a whole identity key, and `frost-share` for
a single threshold share.

The point of all this is to be better than copy-pasting an nsec between apps, and
better than leaving one in a notes file. Storage is upgraded to whatever the
device actually supports, and nothing blocks you from logging in if your device
supports none of it. Where a sensible default can be picked for the user without
giving something up, it is picked for them.

## Why this is not NIP-46

NIP-46 is a signing protocol for a remote signer. A remote signer has to be
reachable for every single event signature, whereas a device that has received a
key under this spec does not *need* a second device at all. If FROST is
activated, only 2 of N devices are required, and special device authorizations in
the spec allow for fully offline signing from a single device.

NIP-46 does not specify a key transfer method, nor how to store a key, whether it
is backed up, or what happens when the machine is lost. This project is intended
to fill some or all of those gaps.

## What this project is not

The transfer mechanism is not new cryptography. The commit-then-reveal code
comparison is ZRTP's, by way of Matrix, and it is cited as such. What is unusual
is running it over infrastructure nobody operates for the purpose.

## Status

QR_SECRET_TRANSFER.md is version 1.0-draft. The event kinds are placeholders and
will change, and there are no test vectors yet.

NOSTR_KEY_MANAGEMENT.md is version 8.0-rc1. The `frost-share` profile in §3.3 is
marked do-not-implement: share issuance hands a device two partials from two
different parties, and that does not fit the transfer spec's one-sender model
yet.

This project benefits from devs and users pressure testing the claims of the
spec. Failure modes will be handled within reason to improve it. Structural
robustness increases the convenience and security of users as far as the spec is
widely deployed and followed, across various hardware and software conditions.
Disagreements and suspected errors belong in
[SPEC_ISSUES.md](SPEC_ISSUES.md); pull requests and issue submissions should be
used where possible.
