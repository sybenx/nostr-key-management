# Nostr Key Management — archived notes

**The QR transfer specification moved to
[sybenx/qr-secret-transfer](https://github.com/sybenx/qr-secret-transfer)**, beside
its reference implementation, together with the two profiles it carries for Nostr
(`nostr-nsec` and `frost-share`). That is the maintained project. Report problems
with it there.

This repository is kept as notes: design work on how a Nostr client should store a
key, back it up, and split it with threshold signing. None of it is maintained, and
none of it is needed to implement QR transfer. It is here for a possible future
FROST signer, or for anyone building client-side key storage.

## What is here

The work split three ways and was never merged back together. Each line is kept as
it was.

| Where | What it is |
|---|---|
| `main` | `NOSTR_KEY_MANAGEMENT.md` 9.2-draft: key storage and unlock (§2), backup (§4), and a threshold-signing design of its own (§7) with two modes, a server co-signer and a serverless device quorum. `OVERVIEW.md` is the readable summary, `IMPLEMENTATION.md` a build proposal. |
| branch [`archive/no-server-10.0`](https://github.com/sybenx/nostr-key-management/tree/archive/no-server-10.0) | An unpublished 10.0-draft that drops this project's own threshold signing in favour of [FROSTR](https://github.com/FROSTR-ORG/bifrost), keeps only two proposals to FROSTR (share rotation and a recovery delay, §7.9 and §7.10), and redefines `frost-share` as a FROSTR credential pair. That `frost-share` is the one that moved to qr-secret-transfer. |
| branch [`claude/tiers-normative-doc-k1oq1m`](https://github.com/sybenx/nostr-key-management/tree/claude/tiers-normative-doc-k1oq1m) | `TIERS.md`: a tiered custody design built on 9.2, in which an always-online co-signer holds one share and can refuse to sign (rate limits, blocking mass deletion), plus `tiers_check.py` and its vectors. It contradicts the 10.0 draft, which removes the co-signer. It ends with three proposals to FROSTR. |

## What may be worth keeping

- **Storage and unlock** (`NOSTR_KEY_MANAGEMENT.md` §2): a ladder from platform
  keystore to passkey-derived key to encrypted browser key, and an unlock rule that
  prompts only for actions that touch the key itself.
- **Backup** (§4): when to offer it, and a passkey-default encrypted blob store.
- **The FROSTR proposals**: rotation and a recovery delay on the 10.0 branch, and
  the three at the end of `TIERS.md`, for whatever FROSTR needs next.
- **The co-signer policy** in `TIERS.md` §6, if a FROST signer server is ever
  built: what a co-signer must see before it signs, and how it stops a stolen
  device from deleting everything.

## Open issues

Issues [#1–#10](https://github.com/sybenx/nostr-key-management/issues) are all
against §7 of `NOSTR_KEY_MANAGEMENT.md` 9.2, the threshold-signing design. They
stand as notes on that design. [SPEC_ISSUES.md](SPEC_ISSUES.md) records what was
settled before the move.

## Licence

CC0 ([LICENSE](LICENSE)).
