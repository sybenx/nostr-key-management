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

NIP-46 is a signing protocol for a remote signer that holds the whole key and must
be reachable for every signature. This project's threshold signing comes in two
modes that each improve on something real (NKM §7):

- **Device quorum** — a serverless 2-of-N across your own devices. Any two sign; no
  server exists; nobody in the middle sees anything. This is the thing NIP-46
  structurally cannot do, and it's the upgrade to copy-pasting your nsec between your
  devices.
- **Co-signer** — a server holds one share, your device the other. This *is* the
  NIP-46 shape, made strictly better: the server never holds your whole key, and a
  breached server can neither reconstruct alone nor forge (it can't complete a
  signature without one of your devices).

NIP-46 also does not specify a key transfer method, nor how to store a key, whether
it is backed up, or what happens when the machine is lost. This project fills those
gaps too.

## What this project is not

The transfer mechanism is not new cryptography. The commit-then-reveal code
comparison is ZRTP's, by way of Matrix, and it is cited as such. What is unusual
is running it over infrastructure nobody operates for the purpose.

## Status

QR_SECRET_TRANSFER.md is version 1.4-draft: the `frost://` scheme and light
returned-secret flow (§12.3) for revocable shares, plus a profile-gated offline
tier (§10) — passphrase-encrypted, no relay. The event kinds are placeholders and
may change, and the test vectors are incomplete: the §6 short code is covered in
[vectors/](vectors/), the payload ceiling that P1 requires is not.

NOSTR_KEY_MANAGEMENT.md is version 9.2-draft: the serverless device-quorum
threshold mode (§7.18) alongside the server co-signer, and a passphrase-encrypted
offline container for `frost-share` (§3.3), the one payload with no `ncryptsec` of
its own.

This project benefits from devs and users pressure testing the claims of the
spec. Failure modes will be handled within reason to improve it. Structural
robustness increases the convenience and security of users as far as the spec is
widely deployed and followed, across various hardware and software conditions.
Disagreements and suspected errors belong in
[SPEC_ISSUES.md](SPEC_ISSUES.md); pull requests and issue submissions should be
used where possible.
