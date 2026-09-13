# Tiered Key Custody — Specification

Version 1.0-draft
Applies to: any client or co-signer that implements FROSTR threshold signing for a
Nostr identity

> This document sits on top of [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md)
> (NKM) and [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) (QRST), both of which are
> frozen. It references them and requires no change to their normative sections. It
> defines one thing they do not: how a single Nostr key is split across **trusted
> devices**, **co-signing servers**, and **temporary app grants** at different
> weights, in one flat FROST group.

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

**Nothing that is not the user's own hardware ever holds enough weight to sign.**
Every other rule here is a consequence of that one, or an accounting of where it is
paid for.

A key that is split three ways is not thereby safer; it is safer only if the split
is chosen so that no reachable subset of the untrusted parts reaches the threshold.
This document fixes those inequalities, states which sets of parties *can* sign
under them, and does not hide the ones that are uncomfortable.

## 1. Overview

NKM §7 gives two threshold modes: a **co-signer** mode in which every device
replicates index 2 and a server holds index 1 (§7.1–§7.17), and a **device quorum**
in which every device holds a unique index and there is no server (§7.18). Both are
`t = 2`. Neither expresses a party that is *partly* trusted — a web app that should
be able to post for a week and nothing else, or a server that should be able to
enforce policy but never to act alone.

This document defines a third arrangement over the same primitives: **one `k`-of-`N`
FROST group in which parties hold different numbers of indices**, so that the weight
a party carries states how much it is trusted. It reuses NKM's storage ladder (§2),
its `frost-share` payload profile (§3.3), its delta-polynomial reshare (§7.9), its
recovery delay (§7.10), and QRST's transfer mechanism unchanged.

It is selected in place of NKM §7.4's index scheme, not alongside it. A group
MUST NOT mix this document's weighted structure with NKM §7.4's replica scheme or
§7.18's one-index-per-device quorum; the three assign indices by incompatible rules
and a member list cannot be read under two of them at once.

Vocabulary is FROSTR's: a **group** has a group public key and a threshold; a
**share** is one secret scalar at one **index**; a **peer** is one network identity
holding one share; `bfgroup` and `bfshare` are the encodings of the public group
package and of a single secret share. This document adds one term above them, the
**party** — a person, device, or operator that holds one or more peers.

## 2. Access structure

### 2.1 One flat weighted group

The access structure is a single `k`-of-`N` FROST group over `N` indices. A party
MAY hold several indices; the number it holds is its **weight**. There is no nested
sharing, no share-of-a-share, and no second threshold layer. A signing set is
authorised if and only if the indices it brings total at least `k`.

This is not a simplification; it is the only structure the ciphersuite has.
FROSTR's group package is a flat list of members under one threshold, and every
signing session is a plain `k`-of-`N` session over member indices — there is nowhere
in the protocol to put a second level. Weighting is the standard way to get
non-uniform authority out of a flat threshold, and it costs nothing in the security
argument: RFC 9591's unforgeability result quantifies over *shares*, not over the
people holding them, so an adversary who corrupts a party of weight `w` is an
adversary holding `w` shares, and forging still requires `k`. Giving one party
several indices therefore changes who can sign without changing what is proved.
The alternative — splitting `nsec = s_A + s_B` and Shamir-sharing each part to its
own class — would express "one from A *and* one from B" directly, but it is outside
RFC 9591 and outside every FROSTR implementation, and would be a construction this
project owned rather than cited. SPEC_ISSUES.md records the same limitation where
NKM §7.4 meets it.

The consequence to state plainly: because the structure is flat, **weight is the
only instrument**. There is no rule of the form "a co-signer may never be in a
signing set without a trusted device" that the mathematics will enforce. Every such
rule in this document is enforced by the honest behaviour of policy-running
co-signers (§6), and by the inequalities of §4 which bound what dishonest parties
can reach without them.

### 2.2 Index hygiene

- Each index MUST be held by exactly one peer. Two peers MUST NOT hold the same
  index, and a party's several indices MUST be held as several peers.
- An index MUST NOT be reissued. A retired index number MUST NOT be reused in any
  later epoch of the same group, so that a member list read at any epoch names the
  same holder it always named.
- `N` MUST NOT exceed 255. FROSTR implementations carry a member index in one byte
  (`bifrost-rs`, `crates/frostr-utils/src/keyset.rs:142`, `idx = id_ser[31] as u16`),
  and index 256 would alias index 0.
- `k` MUST be at least 3. At `k = 2` no weighting is expressible: every party is
  either weight 1 and signs with any other, or weight 2 and signs alone.

### 2.3 Weights are peer multiplicity, and need no protocol change

**Determination: in both `bifrost` and `bifrost-rs`, one peer holds exactly one
share index, and a peer's network identity is derived from its share.** A party
that holds several indices therefore runs several peers. Recorded with references,
because it decides whether the tiers of §3 need a protocol change or only a client
convention:

| Implementation | Evidence | Reference |
|---|---|---|
| `bifrost` | A node is constructed from one `GroupPackage` and one `SharePackage`. | `src/class/client.ts:119`–`135` |
| `bifrost` | The node's BIP-340 identity is the pubkey of the share secret, so index and pubkey are in bijection. | `src/class/signer.ts:79` |
| `bifrost` | The dealer emits one share and one member record per index, the member's pubkey being that share's pubkey. | `src/lib/package.ts:45`–`62` |
| `bifrost` | A pubkey resolves to one index by first match. | `src/api/sign.ts:133`–`139`; `src/lib/peer.ts:9`–`12` |
| `bifrost` | Session construction asserts one index per pubkey (`indexes.length === pubkeys.length`). | `src/lib/util.ts:92`–`101` |
| `bifrost` | Peers are the group members other than self, filtered by pubkey. | `src/class/client.ts:467`–`493` |
| `bifrost-rs` | The signing device holds one `SharePackage` and a `HashMap<String, u16>` from peer pubkey to a single index. | `crates/bifrost-signer/src/lib.rs:663`–`668`, `699`–`728` |
| `bifrost-rs` | A peer pubkey resolves to the first member whose key matches, and to one index. | `crates/bifrost-signer/src/util.rs:22`–`41` |
| `bifrost-rs` | A member's pubkey is that index's FROST verifying share, `share_i·G`. | `crates/frostr-utils/src/keyset.rs:112`–`152` |

The answer is therefore **no**: a peer cannot hold more than one index in either
implementation, and the map from index to pubkey is not merely a convention but the
key schedule. Two consequences, both normative:

- **Tier weights require no protocol change.** A weight-`T` party runs `T` peers,
  each a conforming FROSTR peer with its own `bfshare` and its own pubkey. Nothing
  in `/sign/req`, `/sign/res`, the group package, or the session identifier needs a
  new field. A client MUST implement weight this way and MUST NOT extend the wire
  format to carry several indices under one peer identity.
- **Party identity is a client convention and MUST be recorded outside the group
  package.** Because no FROSTR message says that two pubkeys are one party, the
  epoch record of §5.3 MUST bind each index to its party and tier, and every
  quorum-counting rule in this document MUST be evaluated against that record and
  never against the raw member list. An implementation that counts peers instead of
  parties will count a weight-2 trusted device as two independent signers.

---
