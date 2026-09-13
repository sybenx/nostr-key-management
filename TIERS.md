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

## 3. The three tiers

Every index in the group belongs to exactly one tier, recorded per index in the
epoch record (§5.3). A party's tier is the tier of its indices; a party MUST NOT
hold indices of two tiers.

### 3.1 Trusted device — weight `T`

A native application on hardware the user owns, in the sense of NKM §7.1's
`trusted` role.

- A trusted device holds `T` indices, `T > 1`. `T` is a group-wide constant fixed
  at activation; all trusted devices have the same weight.
- **Every index a trusted device holds MUST be stored at NKM §2.1 level 3 where the
  platform offers one, and MUST NOT be stored at level 1.** The share is
  enclave-wrapped: the platform keystore holds the wrapping key, the application
  never sees it, and unwrapping is gated by the device unlock. A party whose
  platform reaches only level 1 MUST NOT be admitted as a trusted device.
- A browser origin MUST NOT hold a trusted-device index, at any storage level. NKM
  §7.1 fixes every browser-origin device as `restricted`, and NKM §2.1 records that
  a browser is never level 3 because it has no authenticator-bound decryption. A
  browser that needs to act holds a grant (§3.3).
- A trusted device MAY issue a grant (§5), MAY revoke one, and MAY initiate a
  rotation (§7). It cannot complete any of these alone; §4 and §7 say what else is
  required.
- A trusted device's `T` peers MUST be co-resident: the same application instance
  on the same device, unlocked by the same platform authentication. Splitting a
  trusted device's indices across two machines creates two parties of lower weight
  wearing one label, and every inequality in §4 is then wrong about it.

### 3.2 Co-signer — weight 1

A server running signer code: a peer that receives sign and ECDH requests, applies
the policy of §6, and returns a partial signature or refuses.

- A co-signer holds exactly one index. An operator running several co-signing
  processes for one group holds several indices and is, for every rule here, several
  co-signers only if those processes are independently administered; otherwise the
  operator MUST be counted as one party holding that combined weight.
- **A co-signer MUST enforce §6.** A peer that returns partial signatures without
  applying policy is not a co-signer under this document, whatever it is called,
  and a group whose weight budget assumes policy from it is misconfigured.
- **A co-signer MUST NOT hold a share for a party that does not hold one.** Where a
  rotation would leave the group with no trusted-device index, a co-signer MUST
  refuse to take an index in the new epoch and MUST destroy the index it holds. A
  co-signer that holds weight for a user who holds none is a custodian, and the
  entire argument of §0 assumes the user holds `T`.
- A co-signer is not a relay, and a relay is not a co-signer. §8 states the rule
  that keeps the two apart.

### 3.3 Grant — weight 1

One index held by an untrusted application or device: a web client, a third-party
signer, a device the user does not fully control.

- A grant holds exactly one index, and its weight is 1 regardless of `T`.
- **Every grant MUST carry an expiry set at issue** (§5.2). A grant without an
  expiry MUST NOT be issued and MUST NOT be admitted.
- **Every grant is dropped at the next rotation, regardless of its expiry.** A
  rotation's new member list MUST omit every grant index live in the old epoch,
  whether or not that grant's expiry has passed and whether or not the rotation was
  performed for any reason connected to it. A grant that is still wanted is
  reissued as a new index with a new expiry; it is never carried forward.
- A grant MUST be stored at the best level NKM §2.1 offers on its platform, but no
  level is required of it. The construction assumes a grant's storage may fail
  entirely; that is what its weight is for.
- A grant MUST NOT issue or revoke a grant, MUST NOT initiate a rotation, MUST NOT
  act as a QRST Sender, and MUST NOT be admitted as a voter under §7.

### 3.4 What the tiers are, in one line each

| Tier | Weight | Held by | May issue and revoke grants | May initiate rotation | Expires | Dropped at rotation |
|---|---|---|---|---|---|---|
| Trusted device | `T` | Native app on the user's own hardware, indices at NKM §2.1 level 3 or 2 | Yes | Yes | No | No |
| Co-signer | 1 | A server running signer code and enforcing §6 | No | No | No | No |
| Grant | 1 | An untrusted app or device | No | No | Yes, at a time set on issue | Yes, always |

---

## 4. Constraints

### 4.1 Variables

| Symbol | Meaning |
|---|---|
| `k` | The group threshold: the total weight a signing set must bring |
| `N` | Total live weight, the sum of all indices in the current epoch |
| `T` | The weight of a trusted device — the number of indices each one holds |
| `n_s` | The number of co-signers, each of weight 1 |
| `W_g` | The sum of the weights of all live, unexpired grants — equal to their count, grants being weight 1 |
| `s` | The **co-signer slack** for a trusted device: the number of co-signers that may be unreachable or refuse while a single trusted device can still sign |

### 4.2 The inequalities

A configuration MUST satisfy all four:

```
(1)  n_s < k                    co-signers alone never sign
(2)  W_g < k                    grants alone never sign
(3)  T + n_s − s ≥ k            one trusted device signs, losing up to s co-signers
(4)  2T ≥ k                     two trusted devices recover with no co-signers
```

(1) is what makes a co-signer a co-signer rather than a custodian, and it does
double duty: it is also what stops the co-signers from authorising a rotation among
themselves (§7). (2) bounds the live-grant budget: the client MUST refuse to issue a
grant that would bring `W_g` to `k`, and MUST count a grant as live from issue until
its expiry passes or the rotation that drops it completes, whichever is earlier.
(3) is the working path — the user posts from one device. (4) is the recovery path —
two of the user's own devices are the key, with no server reachable and no grant
outstanding.

### 4.3 What follows

**`T < k` MUST hold.** It is not one of the four, but the four are chosen on the
assumption of it and the document is incoherent without it: at `T ≥ k` a trusted
device signs alone, no co-signer is ever in the signing set, and every rule in §6 is
unenforceable because nothing routes through a party that could enforce it. With (4)
this bounds `T` narrowly: `⌈k/2⌉ ≤ T ≤ k − 1`. At `k = 3` the only value is `T = 2`.

**The slack is `s ≤ T + n_s − k`.** Rearranging (3). A configuration that wants a
trusted device to survive one co-signer being down needs `T + n_s ≥ k + 1`.

**A weight-1 grant needs every co-signer online, and no weighting removes that.**
Take a signing set containing one grant and no trusted device. Its weight is
`1 + c + g`, where `c` is the co-signers in it and `g` the weight of any other
grants. By (2), `1 + g ≤ W_g < k`, so `c ≥ 1`: grants never finish alone. Where that
grant is the only live one, `g = 0` and the set reaches `k` only if `c ≥ k − 1`; by
(1), `c ≤ n_s ≤ k − 1`. Both hold only at `c = n_s = k − 1` — the number of
co-signers is exactly `k − 1`, and **every one of them must be in the signing set**.
There is no configuration of `k`, `T`, and `n_s` in which a lone weight-1 grant can
lose a single co-signer and still sign.

The operational consequence is the one that matters, and it MUST be stated on any
screen that offers a grant: **a grant's availability is the product of every
co-signer's availability.** One co-signer down takes every grant offline until a
trusted device is present. This is a deliberate cost, not an oversight: the whole
reason a grant is weight 1 is that it is one unit short of anything, and buying it
slack means buying it authority.

**Raising a grant's weight buys slack at a price that is rarely worth paying.** A
grant of weight `w` must satisfy `n_g·w = W_g < k`, so one live grant may reach
`w = k − 1` — but `k − 1 ≥ T`, so that grant is then at least as powerful as a
trusted device while being, by definition, the tier that is not trusted, and one
compromised co-signer completes it. A client MAY offer grant weights above 1 only
where `w < T` and `n_g·w < k` both hold, MUST default to `w = 1`, and MUST NOT offer
any weight at which a single co-signer plus one grant reaches `k`.

### 4.4 Reference configuration

```
k    = 3
T    = 2          two indices per trusted device
n_s  = 2          two co-signers, one index each
W_g  ≤ 2          at most two live grants, one index each
s    = 1          a trusted device survives one co-signer being down
```

Checks: `n_s = 2 < 3` ✓ — `W_g ≤ 2 < 3` ✓ — `T + n_s − s = 2 + 2 − 1 = 3 ≥ 3` ✓ —
`2T = 4 ≥ 3` ✓ — `T = 2 < 3` ✓.

With two trusted devices and two live grants, `N = 8`:

| Index | Party | Tier |
|---|---|---|
| 1, 2 | `D1` | Trusted device |
| 3, 4 | `D2` | Trusted device |
| 5 | `C1` | Co-signer |
| 6 | `C2` | Co-signer |
| 7 | `G1` | Grant |
| 8 | `G2` | Grant |

### 4.5 Every signing set of the reference configuration

Minimal authorised sets — those of weight `≥ k` with no authorised proper subset.
There are thirteen. A set is listed once; adding any further party to a listed set
is also authorised and is not listed again.

| # | Set | Weight | What it is |
|---|---|---|---|
| 1 | `D1 + D2` | 4 | Two trusted devices. The recovery path of (4); no server, no grant. |
| 2 | `D1 + C1` | 3 | Ordinary signing from a trusted device. |
| 3 | `D1 + C2` | 3 | Ordinary signing from a trusted device, the other co-signer. |
| 4 | `D2 + C1` | 3 | Ordinary signing from the second trusted device. |
| 5 | `D2 + C2` | 3 | Ordinary signing from the second trusted device, the other co-signer. |
| 6 | `D1 + G1` | 3 | A grant finishing against a trusted device, no co-signer reachable. |
| 7 | `D1 + G2` | 3 | As 6, the other grant. |
| 8 | `D2 + G1` | 3 | As 6, the other trusted device. |
| 9 | `D2 + G2` | 3 | As 6, the other trusted device and grant. |
| 10 | `C1 + C2 + G1` | 3 | **Collusion.** One grant plus both co-signers. No trusted device. |
| 11 | `C1 + C2 + G2` | 3 | **Collusion.** As 10, the other grant. |
| 12 | `C1 + G1 + G2` | 3 | **Collusion.** Two grants plus one co-signer. No trusted device. |
| 13 | `C2 + G1 + G2` | 3 | **Collusion.** As 12, the other co-signer. |

Every set of weight 2 or less is unauthorised, including all of: a single trusted
device; both co-signers together; both grants together; one co-signer with one
grant.

**Sets 10 to 13 are real and are not prevented by the mathematics.** The access
structure is flat (§2.1), so "a trusted device must be present" is not something `k`
can say. What sets 10 to 13 cost an attacker is the honest measure of the design:

- **Sets 10 and 11 require both co-signers and one grant.** That is two
  independently administered servers, each of which must abandon §6, plus one live
  app grant. If the co-signers are one operator's two processes, §3.2 requires them
  counted as one party of weight 2, and these sets do not exist.
- **Sets 12 and 13 require one co-signer and both live grants.** This is the cheapest
  hostile set in the configuration, and it is the reason (2) exists and the reason the
  live-grant budget is a budget rather than a default. A user running one live grant
  instead of two removes sets 12 and 13 entirely.
- **Nothing in sets 10 to 13 reaches a trusted device's storage.** They reach the
  threshold, which means they can sign and can reconstruct. §6 is what stops the
  honest members of such a set from participating, §7 is what stops such a set from
  quietly reissuing a trusted share, and §11 is what bounds the damage of the case
  this document cares most about.
- **Reducing the live-grant budget to one, or running only one co-signer, removes
  every collusion set.** At `n_s = 1` and `W_g ≤ 1`, no set without a trusted device
  reaches 3. The cost is that (3) then fails at `s = 1` — a trusted device has no
  slack, and the single co-signer is a single point of unavailability. This is the
  trade the configuration makes, and a client SHOULD present it as a choice rather
  than picking silently.

---
