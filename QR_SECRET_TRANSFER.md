# QR Secret Transfer — moved

The QR Secret Transfer specification (QRST) now lives at
**[sybenx/qr-secret-transfer](https://github.com/sybenx/qr-secret-transfer/blob/main/QR_SECRET_TRANSFER.md)**,
beside its reference implementation.

The two payload profiles that used to be defined in
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) §3 moved with it, and supersede
that section:

- [`nostr-nsec`](https://github.com/sybenx/qr-secret-transfer/blob/main/profiles/nostr-nsec.md), a whole Nostr key
- [`frost-share`](https://github.com/sybenx/qr-secret-transfer/blob/main/profiles/frost-share.md), one share of a FROSTR group

Its history up to version 1.6-draft is in this repository's log. Report problems
with it [there](https://github.com/sybenx/qr-secret-transfer/issues/new?template=spec-issue.yml).
