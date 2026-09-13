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

## 5. Grants

### 5.1 Issue

A grant is issued by a trusted device, as a reshare to the next epoch whose new
member list adds one index.

1. **Authority.** A trusted device initiates. The operation is a rotation in the
   sense of §7 and MUST satisfy §7's authority in full: the new epoch record is
   signed by the group, so a trusted device alone cannot issue a grant any more than
   it can sign alone.
2. **New polynomial.** The epoch advances by the delta-polynomial reshare of NKM
   §7.9: `f'(x) = f(x) + δ(x)` with `δ(0) = 0` and fresh randomness, every existing
   member applying its own `δ` at each index it holds. NKM §7.9 gives `δ(x) = r·x`,
   which is degree 1 because NKM fixes `t = 2`. **At `k ≥ 3` the delta MUST be
   `δ(x) = Σ_{j=1}^{k−1} r_j·x^j` with every `r_j` fresh**, and the epoch record MUST
   carry one commitment per coefficient; SPEC_ISSUES.md records the same requirement
   against NKM §7.18's `t = 3` option and proposes the same form.
3. **The grant's share is `f'(x_g)`** at a fresh index `x_g` that has never been used
   in this group (§2.2).
4. **No party may reach `k` during the issue.** The grant's share is an evaluation of
   `f'` at a new point, which requires contributions weighted by `k` indices, and
   those contributions MUST be blinded. **A party MUST NOT receive another party's
   Lagrange-weighted contribution in any form from which that party's share can be
   recovered.** A raw `λ_i(x_g)·s_i` is such a form: `λ_i(x_g)` is publicly
   computable, so the contribution *is* the share. In particular the issuing trusted
   device, which holds `T = k − 1` or more, MUST NOT act as the point where
   contributions are summed in the clear; a co-signer's contribution is exactly the
   unit it is missing. NKM §7.18's "combine them on one of the two" is sound in its
   own setting, where the two combining devices already reconstruct by assumption and
   are both the user's own hardware. It MUST NOT be carried into this document.
5. **The group MUST NOT be re-dealt from a reconstruction to add a grant.**
   Reconstructing the nsec on one device and splitting it again produces a correct
   result and is the only thing FROSTR implementations offer today, and it is
   forbidden here: NKM §7.5a reserves reconstruction to disable and Re-split, and a
   grant issue is neither. SPEC_ISSUES.md records that no FROSTR implementation
   provides a reshare primitive that satisfies 2 to 4.
6. **Delivery.** One QRST session, one payload, one Sender — the issuing trusted
   device — using the `frost-share` profile of NKM §3.3 in its unique-index form,
   with `index = x_g`. The Receiver performs the profile's P4 check against the new
   epoch's commitments, renders P5, and confirms (QRST §9.4). The SAS of QRST §6 and
   §9.2 is REQUIRED unless the pairing token reached the receiving app over a channel
   the issuing device controls, in which case the light flow of QRST §12.3 MAY be
   used; QRST §12.3 states that condition and this document does not relax it.
7. **The grant is `admitted: false` on arrival** and cannot obtain a co-signature
   until admitted from a trusted device (NKM §7.1). Admission gates signing, not
   reconstruction.

**What interception of a grant share costs.** An intercepted grant index is one unit
of weight. By (2) it cannot sign alone, and by §6 no honest co-signer will co-sign
for an unadmitted index. But neither expiry nor rotation undoes a reconstruction:
in the reference configuration an intercepted grant, the other live grant, and one
co-signer total `k` (sets 12 and 13 of §4.5). The bound on interception is therefore
the live-grant budget and the co-signers' honesty, not revocation, and a client MUST
NOT present grant delivery as recoverable if it goes wrong.

### 5.2 Expiry

- **Every grant carries an expiry, set at issue by the issuing trusted device**, as
  an absolute Unix time recorded in the epoch record and in every co-signer's grant
  record. A client MUST show the expiry on the issue screen and MUST NOT offer an
  unbounded option.
- **Expiry is enforced in two places, and only one of them is algebraic.**
  - A co-signer MUST refuse every sign and ECDH round for a grant index whose expiry
    has passed, from the moment it passes, and MUST NOT extend, renew, or round up an
    expiry on the grant's request. This is a policy refusal in the sense of NKM
    §7.9's tier 1: it is immediate, requires contacting nobody, and touches no share.
  - The next rotation MUST omit the index from the new member list, whether or not
    the expiry has passed (§3.3). This is the algebraic one: after it, the retained
    share is on a dead polynomial.
- **Between expiry and the next rotation, the expired index still holds a live
  share.** It cannot obtain a co-signature, but its weight still counts toward any
  set that reconstructs. A client MUST count an expired-but-not-yet-rotated index
  against `W_g` until the rotation that drops it completes, and SHOULD rotate on
  expiry rather than wait.
- Extending a grant is issuing a new one: a new index, a new expiry, a new §5.1
  reshare. An expiry MUST NOT be edited in place.

### 5.3 Records

**The grant record, kept by every co-signer.** A co-signer MUST hold, for each grant
index in the current epoch, exactly:

| Field | Meaning |
|---|---|
| `index` | The grant's share index `x_g` |
| `issuer` | The trusted device that issued it, by the `E.pub` of NKM §7.1 |
| `expiry` | Absolute Unix time, as set at issue |
| `policy_id` | The identifier of the policy (§6) this grant is bound to |

The record is scoped to one epoch. A co-signer MUST discard every grant record on
entering a new epoch and MUST NOT carry one forward, which is the enforcement of
§3.3's "dropped at the next rotation regardless": a co-signer that has no record for
an index has no policy for it and MUST refuse it. A co-signer MUST refuse to
co-sign for any grant index for which it holds no record, and MUST NOT accept a
grant record from the grant itself or from any party other than a trusted device
under §7's authority.

**The epoch record.** A group using this document carries, inside the epoch record
NKM §7.4 already defines, the additional fields needed to evaluate §4 and §6. NKM
§7.4 fixes the record's kind, encryption, signing and the fact that its content is a
structured object; this document adds fields to that object and changes nothing
about how it is published.

- Group-wide: `k`, `T`, `n_s`, the live-grant budget, and the commitment vector of
  §5.1 step 2.
- Per member: `party` — a stable identifier shared by every index one party holds —
  and `tier`, one of `trusted`, `cosigner`, `grant`; and for a grant, `expiry`,
  `issuer` and `policy_id`.

Every quorum rule in this document is evaluated over `party` and `tier`, never over
the raw member list (§2.3). A member list read without them counts a weight-`T`
trusted device as `T` independent signers.

---

## 6. Co-signer policy

Policy is what buys the co-signer tier its place. A co-signer's weight is 1 and can
never complete a signature alone; what it can do is refuse, and §4's inequalities are
chosen so that every set containing a grant and no trusted device must route through
every co-signer (§4.3). Policy is therefore normative here, not advisory: a
co-signer that does not enforce this section is not a co-signer under §3.2.

### 6.0 Precondition — the co-signer MUST see what it signs

**A co-signer MUST refuse any sign request that does not carry the full unsigned
event.** It serialises and hashes the event itself per NIP-01 and signs only its own
computed hash. A request carrying a bare 32-byte sighash, or any digest the
co-signer did not derive, MUST be refused for every grant index without exception,
and SHOULD be refused for every index.

This is NKM §7.6's rule and it is restated because every other rule in this section
depends on it: a kinds allowlist over a request that does not contain a kind is not
a policy, it is a comment. SPEC_ISSUES.md records that FROSTR's native signing
message carries sighashes only, and that the one HTTP surface which does accept a
full event also accepts a bare hash.

### 6.1 The five rules

Each rule below is identified by the `policy_id` recorded in the grant record
(§5.3). A co-signer MUST apply the policy the record names and MUST NOT apply a
default in its place when the named policy is unknown to it; an unknown `policy_id`
MUST be refused.

**(a) A kinds allowlist per grant.** Each grant is bound to an enumerated list of
event kinds. A co-signer MUST refuse any kind not on the allowlist of the grant
index that requested it. The list is enumerated rather than expressed as a rule,
because "does not alter the identity" is not evaluable for kinds that do not yet
exist. The allowlist is fixed at issue and MUST NOT be widened for a live grant;
widening it is issuing a new grant (§5.2). Reference allowlist: `1`, `6`, `7`, `13`,
`16` — note, repost, reaction, NIP-17 seal, generic repost. A client MAY offer `30023`
by explicit opt-in per (b). Where this document governs a group, this list replaces
NKM §7.6's reference set for grant indices; it is a subset of it.

**(b) A trusted-only list.** A co-signer MUST NOT produce a partial signature for any
kind on the trusted-only list when the requesting index is a grant, regardless of
that grant's allowlist. The list MUST contain at least:

| Kind | Why |
|---|---|
| `0` | Profile metadata. Replacing it is impersonation with the user's own key. |
| `3` | Follow list. Replacing it is a silent, total edit of who the user follows. |
| `5` | Deletion requests. See §11. |
| `10002` | Relay list. Replacing it can make the user unreachable and route their future events to relays the attacker reads. |
| Every replaceable kind (`10000`–`19999`) and every addressable kind (`30000`–`39999`) **not** on the requesting grant's allowlist | A replaceable or addressable event overwrites rather than appends: it destroys state instead of adding to it, and there is no per-event revocation for it. |

`0`, `3`, `5` and `10002` are trusted-only unconditionally and MUST NOT appear on any
grant's allowlist. Every other replaceable or addressable kind is trusted-only by
default and leaves the list only by being named on the grant's allowlist at issue.
Kind `5` requires the tag check of NKM §7.6 as well: a deletion referencing any
kind-30242 coordinate MUST be refused from every index, including a trusted one.

**(c) Rate limits per index.** Limits are counted per share index, never per party,
per IP, or per connection — a party's several indices are several peers with several
network identities (§2.3), so any counter not keyed on the index is trivially
evaded by using another one. A co-signer MUST maintain, for each index in the
current epoch, a signing-rate counter and MUST refuse rounds beyond the configured
limit. Reference limits: a grant index, 60 signatures per rolling hour and 600 per
rolling day; a trusted-device index, no ceiling but the alerting of NKM §7.13. ECDH
limits are NKM §7.13's and are not restated. Exceeding a limit MUST be reported to
every trusted device as an NKM §7.17 `ALERT`; raising a limit for a live grant MUST
require a trusted device and MUST NOT be automatic.

**(d) A freeze.** A co-signer MUST support a freeze: a state, entered on the
instruction of any trusted device, in which it refuses **all** rounds for the group —
every kind, every index, trusted indices included — until lifted. Lifting MUST
require an instruction from a trusted device and MUST NOT expire on its own, MUST NOT
be liftable by a grant or by another co-signer, and SHOULD require a different
trusted device than the one that froze. A freeze MUST take effect within one round:
a co-signer that has begun a round MUST NOT complete it after receiving a freeze.

**A freeze does not stop two trusted devices.** By (4), `2T ≥ k`, so the user's own
two devices sign with no co-signer in the set and a freeze is invisible to them.
This is correct — a freeze is a tool against a compromised grant or an unexplained
signing burst, not against the user — but a client MUST NOT describe a freeze as
stopping all signing, and the freeze indicator MUST say what it actually covers.

**(e) A delay with veto, for trusted-only kinds from a single trusted device.** Where
a trusted-only kind is requested and the signing set contains exactly one trusted
device, a co-signer MUST NOT return its partial signature immediately. It MUST:

1. hold the request for the recovery delay of NKM §7.10 (NKM §4.2's default, 24
   hours);
2. send a notice to **every other trusted device** in the current epoch, naming the
   requesting device by its label, the kind, and the time at which the request
   completes;
3. complete the round when the delay elapses, or immediately on an approval from any
   other trusted device;
4. abandon the round on a veto from any other trusted device, and refuse every
   further request for that kind from that index until a trusted device clears the
   veto.

Where there is no other trusted device in the epoch, the delay elapses on its own,
exactly as NKM §4.2 provides for a recovery with no registered device. The delay
does not apply where the signing set already contains two trusted devices: the
second device's participation is the approval, and a delay on top of it would only
make the user's own hardware slower than the attacker's path.

### 6.2 Mapping onto igloo-server's peer policies

`igloo-server`'s `docs/PEER_POLICIES.md` defines a peer policy as a directional
allow/deny pair on a peer pubkey — `allowSend`, `allowReceive`, plus a `label` and a
`note` — sourced from the `PEER_POLICIES` environment variable, a per-user database
column, and a `data/peer-policies.json` override file. `bifrost-rs` carries a richer
form, `PeerScopedPolicyProfile` (`crates/bifrost-core/src/types.rs:435`–`443`), with
`block_all` and a per-method `MethodPolicy` over `echo`, `ping`, `onboard`, `sign`
and `ecdh` (`:382`–`388`). Neither reaches event kinds, counts, or time.

| This document | Exists today | Where |
|---|---|---|
| Refuse an index absent from the epoch, unadmitted, or revoked (NKM §7.1, §7.9 tier 1) | **Exists.** A deny entry: `allowReceive: false` on that peer's pubkey. | `PEER_POLICIES.md`, "Schema (Recommended)" |
| Coarse per-operation refusal, e.g. sign but not ECDH | **Exists in `bifrost-rs` only**, as `MethodPolicy`. No equivalent in `PEER_POLICIES.md`, whose granularity is the whole peer. | `bifrost-rs` `crates/bifrost-core/src/types.rs:382` |
| **(a)** Kinds allowlist per grant | **New.** Policy has no notion of an event kind; the native sign request carries no event (§6.0). | — |
| **(b)** Trusted-only kinds list | **New.** Requires both a kind and a tier, and the wire carries neither. | — |
| **(c)** Rate limits per index | **New.** `igloo-server` rate-limits HTTP per IP and per endpoint bucket (`RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW`, `RATE_LIMIT_RECOVERY_*`, `RATE_LIMIT_WS_UPGRADE_*`), which is a different axis: it bounds a client address, not a share index, and a grant reaching the co-signer over relays is not counted by it at all. | `igloo-server` `docs/SECURITY.md`, `docs/CONFIG.md` |
| **(d)** Freeze | **Partially exists.** The effect is expressible as `allowReceive: false` on every peer entry, or `block_all` per peer in `bifrost-rs`. What is new is that it is one group-scoped act rather than `N` per-peer edits, that it is atomic, and that it is lifted by a trusted device. | `PEER_POLICIES.md`; `bifrost-rs` `PeerScopedPolicyProfile.block_all` |
| **(e)** Delay with veto | **New.** Policy is a synchronous allow/deny with no held state, no timer, and no notification path. | — |
| Per-epoch grant records discarded on rotation (§5.3) | **New, and contrary to the existing persistence model.** `PEER_POLICIES.md` persists policies across restarts through `data/peer-policies.json` and the DB column, and treats the file as a "last known overrides" layer that wins over the environment baseline. A grant record MUST NOT survive its epoch, so a co-signer implementing this document MUST key grant state on the epoch and MUST NOT let the override file resurrect it. | `PEER_POLICIES.md`, "Precedence (What Wins)" |
| Policy changed **on a trusted device's authority** | **New, and the largest gap.** Every policy mutation surface in `igloo-server` authenticates the *server operator* — a session, an API key, Basic Auth, or `ADMIN_SECRET` — not a member of the group. A freeze lifted "from a trusted device" has no representation: `/api/peers/*` has no notion of an `E.pub` signature. | `igloo-server` `docs/AUTH_MATRIX.md`, `/api/peers/*` and `/api/env*` rows |

Rules (a), (b), (c) and (e) are new in full. (d) exists as an effect and not as an
authority. The last row is the one an implementer will hit first: this document
requires policy whose *principal* is the user's trusted device, and today's
co-signer treats policy as operator configuration.

---

## 7. Rotation and revocation authority

### 7.1 The two tiers, as in NKM §7.9

NKM §7.9 separates revocation into an immediate refusal that touches no share, and a
rotation that makes a retained share useless. This document keeps that separation and
puts its new authority requirement on the second only.

**Tier 1 — refusal. One trusted device, no delay.** A trusted device MAY instruct
every co-signer to refuse all rounds for a named index from that moment, and every
co-signer MUST comply. This is NKM §7.9 tier 1 and §6.1(d)'s freeze narrowed to one
index. It requires no vote and MUST NOT be delayed: an index believed compromised has
to be cut off in seconds, and a day-long window on that is not a safeguard, it is the
attack. It does not remove the share, and a set that reaches `k` without any
co-signer is unaffected by it.

**Tier 2 — rotation.** Everything below.

### 7.2 Authority for a rotation

A rotation — a new epoch under §5.1's reshare, whether to revoke an index, to add a
trusted device, to issue a grant, or to drop expired ones — MUST satisfy all three:

1. **Initiation by a trusted device.** A co-signer MUST NOT initiate, and a grant MUST
   NOT initiate or vote (§3.3).
2. **Votes totalling `k`** against the proposed new epoch record, of which the
   initiating trusted device contributes its `T` and the remaining `k − T` MUST come
   from co-signers. Because `T < k` (§4.3), **a single trusted device cannot rotate
   alone**: it is always one or more co-signer votes short, and this is the point of
   fixing `T` below `k`.
3. **The delay of NKM §7.10**, with a notice to **every** trusted device in the current
   epoch naming the initiator, what the rotation changes, and when it completes; and a
   **veto** available to any trusted device for the whole window. An approval from a
   second trusted device completes it immediately. A veto abandons it.

The new epoch record is signed by the group with the old shares before any delta is
applied, exactly as NKM §7.9 step 1 requires, so the vote and the signature are the
same act.

### 7.3 What this means, stated plainly

**A set of parties totalling weight `k` with no trusted device in it can in principle
drive a rotation and reissue a trusted-weight share, once the delay elapses.** The
requirement in 7.2(1) that a trusted device initiate is a rule co-signers follow, not
a fact the mathematics enforces; the access structure is flat (§2.1) and a weight-`k`
set can sign any epoch record it likes. In the reference configuration such sets
exist and are enumerated as sets 10 to 13 of §4.5. Where `n_s ≥ k` the co-signers
alone would be such a set, which is the second reason constraint (1) exists.

The only thing between that set and the key is 7.2(3)'s delay and veto, and **the
veto needs a surviving trusted device to cast it.** Where every trusted device is
lost, the notices reach nobody, the window elapses on its own, and the rotation
completes — precisely as NKM §4.2 provides for a recovery with no registered `E.pub`.

**This is the accepted trade, and it is accepted against loss.** A construction in
which no set without a trusted device could ever rotate would be a construction in
which losing every trusted device loses the identity permanently, with no server-side
recovery at all — NKM §7.18's device quorum is that construction, and NKM says so:
"A quorum with no usable backup and fewer than `t` surviving devices is
unrecoverable." This document buys a recovery path and pays for it in exactly one
coin: the co-signers, colluding with enough other weight, are a path to the key after
a delay. A client MUST state this on the screen where co-signers are enrolled, in
those terms, and MUST NOT describe co-signers as unable to reach the key.

Two things narrow it, and neither closes it:

- Constraint (1) means the co-signers need help — a grant, or a trusted device — to
  reach `k`. The live-grant budget is therefore a security parameter for this
  property and not only for §4.5, and a user running no live grants removes the
  cheapest version of it.
- Co-signers that are independently administered must all defect. §3.2's rule that
  one operator's several processes count as one party is what keeps that from being a
  single decision by a single operator.

### 7.4 What a rotation does

- The new member list MUST omit every grant index live in the old epoch (§3.3), with
  no exception for unexpired ones.
- A revoked index MUST be omitted from the new member list, and its number MUST NOT be
  reused (§2.2).
- A new trusted device is admitted by the same reshare as a grant (§5.1), issued `T`
  indices rather than one, and delivered by `T` QRST sessions of the `frost-share`
  profile — one payload per index, since one payload carries one share (NKM §3.3).
- Every surviving member applies its own delta at each index it holds and verifies the
  result against the new epoch's commitments before acknowledging. A member that
  cannot verify MUST NOT discard its old-epoch share; NKM §7.4's retention rule
  applies unchanged.
- Co-signers MUST discard every grant record on entering the new epoch (§5.3).

---

## 8. Backup

### 8.1 What is backed up

A backup under this section holds **one trusted device's indices** — all `T` of them,
for one epoch. It restores a trusted device and nothing else. It does not hold the
nsec, does not hold any co-signer's share, and does not hold any grant.

The container MUST be encrypted under one of exactly two factors:

- **A passkey-PRF-derived key.** `prf = PRF(credential, SALT_B)` as NKM §4.2 defines
  it, with the wrapping key derived from `prf` by HKDF-SHA256. The credential is
  origin-bound by the platform, so no other origin can produce the value.
- **A paper secret.** A client-generated phrase of at least 96 bits of entropy,
  displayed once for the user to write down. NKM §4.2's rule applies unchanged: the
  phrase MUST be generated, MUST NOT be replaceable with free text, and the screen
  MUST say that it is the only thing protecting what it wraps.

A user-chosen password MUST NOT be offered as a factor for a share backup. NKM §4.2
permits one for the nsec blob because a server-side delay and a second factor sit
behind it; there is no server in this path and no delay to hide behind.

Where the factor is a paper secret the container is NKM §3.3's `frostshare` container
unchanged — scrypt at `log_n = 18`, XChaCha20-Poly1305, bech32 with HRP `frostshare`
— one container per index. Where the factor is a passkey PRF the same container
layout is used with the scrypt step replaced by HKDF-SHA256 over `prf`, and the
`log_n` byte set to `0x00` to mark it.

### 8.2 Where it is stored

Each container is NIP-59 gift-wrapped to a **burner** key and published to relays.

- The burner keypair MUST be derived deterministically from the backup factor, so that
  the factor alone both locates and opens the backup and there is no second secret to
  keep.
- The wrap MUST NOT carry an `expiration` tag, and the client MUST republish to at
  least three relays and MUST verify retrievability from at least two before reporting
  the backup complete.
- A relay sees an anonymous wrap addressed to a key it has never seen, carrying
  ciphertext: not the identity it belongs to, not who published it, not that it is a
  backup. This is QRST's transport property and is inherited, not re-argued.

**A backup goes stale at every rotation, including every grant issue.** A rotation
moves every member to a new polynomial (§7.4), so a container holding an old epoch's
indices restores a device whose shares no longer pair with anything. The client MUST
republish the backup for the new epoch as part of the rotation, and **a rotation MUST
NOT be finalised until the new backup has been published and verified**. A client that
cannot republish MUST show the backup as stale and MUST NOT report the group as
recoverable.

### 8.3 A stored share is not a co-signer

This is normative and is the point of the section.

- **Nothing stored on a relay ever produces a partial signature.** A backup container
  is ciphertext at rest. It does not hold a nonce pool, does not receive a
  `/sign/req`, cannot refuse one, and cannot enforce a single rule of §6.
- **A backup MUST NOT be counted in `N`, MUST NOT be counted toward `n_s`, and MUST NOT
  be given an index of its own.** It is a copy of indices that already exist and are
  already counted. A client that counts it is double-counting a trusted device and
  every inequality in §4 is then wrong.
- **A relay is a co-signer only when it runs signer code.** An operator MAY run both a
  relay and a co-signer; that operator is then one party holding one co-signer index,
  and the relay half of it holds nothing. Storing a backup on a relay operated by a
  co-signer MUST be refused by the client: that operator would hold one index and the
  ciphertext of `T` more, which is the same concentration NKM §7.12 warns of for the
  blob and share 1 on one host.
- **A backup is worth a trusted device to whoever opens it.** By §4.3, `T = k − 1` at
  the reference configuration, so the factor plus one co-signer is the key. The factor
  MUST be treated by the client as material of the same sensitivity as a trusted
  device's storage, and the screen that presents it MUST say so rather than describing
  it as "a backup".

Where an NKM §4.2 blob-store backup of the **nsec** also exists — NKM §7.5 records
that it survives activation by design — it holds the whole key and outranks every
inequality in §4. That is NKM's decision and this document does not disturb it, but a
client MUST list it on the same screen as this section's backup and MUST NOT present
the two as equivalent.

---

## 9. Attestation (OPTIONAL)

A co-signer MAY require, as part of a grant's policy (§5.3, §6.1), platform
attestation evidence that the grant index lives in an enclave-gated application
before it will co-sign for that index. This section says what such evidence does and
does not establish, because the gap between the two is where it will be misread.

### 9.1 What a co-signer MAY require

Where a policy requires attestation, the co-signer MUST refuse every round for that
grant index unless the request carries, for that round:

1. **An App Attest assertion** (iOS/macOS) over a fresh challenge the co-signer
   issued, against a key the co-signer has previously seen attested; or a **Play
   Integrity** verdict (Android) over a fresh nonce the co-signer issued, asserting at
   least device integrity and application recognition.
2. **A signature by the grant index itself over the same challenge.** Attestation
   proves something about an application instance; it does not by itself say that
   *this* instance holds *that* share. Without this binding, an attested honest app
   and an unattested hostile one holding the share are indistinguishable to the
   co-signer, and the requirement buys nothing.

A co-signer MUST NOT require attestation of a trusted-device index. A trusted device
is already bound by §3.1 to NKM §2.1's top rungs, is admitted by the user, and may run
on platforms — desktop, Linux — for which no attestation service exists; requiring it
there would exclude hardware the user owns in favour of hardware a vendor recognises.

### 9.2 What is attested

- That the application binary is the one the developer published: on iOS, an App ID
  binding team and bundle identifier; on Android, a certificate-hash match against the
  Play-distributed package.
- That the hardware and operating system are ones the platform vendor vouches for —
  genuine device, bootloader and OS in a state the vendor recognises, not rooted or
  jailbroken as far as the vendor can tell.
- That an asymmetric key exists in the device's Secure Enclave or hardware keystore and
  the attestation is signed by it.
- That this particular exchange is fresh, because the challenge came from the
  co-signer.

Combined with 9.1(2), this establishes: *a genuine build of a recognised app, on a
device the vendor considers intact, is currently in possession of this grant's share.*

### 9.3 What is not attested

- **The enclave cannot sign secp256k1, and does not hold the share.** App Attest keys
  are P-256 and sign only attestation and assertion payloads; no shipping enclave
  produces a FROST partial signature over secp256k1. **The enclave gates the unwrap.**
  It holds the key that unwraps the share; the share scalar itself is in ordinary
  application memory for the duration of every signing round. Attestation therefore
  evidences that unwrapping is gated — not that the share is confined, not that it has
  never left, and not that it is not, at this moment, also on an attacker's machine.
- **It is retrospective about nothing.** A share extracted once — by a runtime
  compromise, a debugger attached while the device still attested, a memory
  disclosure — stays extracted. Every later assertion from the honest app will pass
  and will say nothing about the copy.
- **It is a statement about a moment, not an interval.** It covers the instant the
  assertion was produced. It does not cover the interval between that instant and the
  partial signature, and there is no construction here that makes it cover it.
- **It says nothing about intent.** A genuine, correctly attested, fully intact
  application that is hostile to this user attests perfectly. §6's allowlist, §6.1's
  trusted-only list and §11 are what address that; attestation does not touch it.
- **It does not exist for web grants.** There is no browser equivalent, so a policy
  requiring attestation excludes every browser-origin grant by construction. A client
  MUST say this on the issue screen rather than letting the user discover it when the
  grant silently stops working.
- **It delegates part of the decision to a third party.** A co-signer requiring
  attestation can be denied service by Apple or Google — an outage, a revoked key, an
  app pulled from the store — and MUST fail closed when the evidence cannot be
  validated, because a requirement that lapses when a service is unreachable is
  bypassed by making it unreachable. The cost of failing closed is that the vendor
  holds a switch over the user's ability to post from that grant, and a client MUST
  state that where it offers the option.

### 9.4 What attestation MUST NOT replace

Attestation is an addition to §6, never a substitute for any part of it. A co-signer
MUST apply admission (NKM §7.1), the kinds allowlist, the trusted-only list, the
expiry and the rate limits to an attested grant exactly as to an unattested one, and
MUST NOT raise a limit, widen an allowlist, or shorten the delay of §6.1(e) on the
strength of an attestation.

---

## 10. Threat model

In the format of `bifrost/docs/SECURITY.md`: a threat per row, what happens under
each arrangement per column. **Raw nsec pasted** is a key copy-pasted into an
application. **NIP-46 to a signer app** is a remote signer holding the whole key and
granting scoped sessions. **This document** is the weighted group of §3 at the
reference configuration of §4.4. One line per cell; the sections that qualify each
line are cited beside it.

| Threat | Raw nsec pasted | NIP-46 to a signer app | This document |
|---|---|---|---|
| Malicious web app | Holds the key permanently; there is nothing to revoke and no way to learn it happened. | Cannot take the key, but signs whatever the signer's policy permits, for as long as the session stands. | Holds one weight-1 grant that reaches `k` only with every co-signer or a trusted device, signs no destructive kind (§6.1b), expires, and is dropped at the next rotation (§3.3). |
| Compromised trusted device | Is the key, totally and permanently. | Is the key if that device runs the signer; otherwise one revocable session. | Holds `T = k − 1`: one unit short, delayed and vetoable on trusted-only kinds (§6.1e), cut off immediately by §7.1 and rotated out by §7.2. |
| Compromised co-signer(s) | No such party exists. | The signer is the only party, so compromising it is compromising the key. | One index each and `n_s < k`, so they neither sign nor rotate alone — but with the live grants they reach `k` (§4.5 sets 10–13), which §7.3 states as accepted. |
| Malicious grant holder | No analogue; the application was given the key. | Its session signs whatever the signer allows, for as long as the user leaves it connected. | Weight 1, allowlisted kinds only, needs every co-signer or a trusted device, and ends at its expiry or the next rotation, whichever comes first (§5.2). |
| Grant holder colluding with co-signers | No analogue. | No analogue: one party holds everything, so there is nobody to collude with. | Reaches `k` and is therefore the key (§4.5 sets 10–13); the live-grant budget of constraint (2) is the only bound, and §7.3 refuses to hide it. |
| Malicious signer app | Has the key the moment it is pasted in. | Holds the whole key by design; its scoping is its own code and it may ignore it. | Holds at most a grant, or `T` if the user made it a trusted device; the policy that binds it runs on parties it does not control (§6). |
| Phishing of a consent screen | Yields the key; the screen is the only control and the attacker wrote it. | Yields a connection the user believes is scoped, where the scope is asserted by the page requesting it. | Yields at most one grant at its allowlist — except a fake backup-factor screen, which yields a trusted device's weight (§8.3) and is the residual. |
| Device loss | Is the key, behind whatever the device's storage offered; no revocation exists. | Is one revocable session, or the key if the lost device ran the signer. | Weight `T` at NKM §2.1 level 3, inert until a second party is taken; refusal is immediate (§7.1) and rotation removes it (§7.2). |

**The two rows that are not improvements.** "Grant holder colluding with co-signers"
has no analogue in the other two columns because they have no such parties, so the
comparison flatters nothing: this document introduces the collusion set along with the
tiers, and §4.5 and §7.3 are where it is priced. "Phishing of a consent screen" is
better here only for grants; the backup factor of §8 is a phishable secret worth a
trusted device, and NKM §7.13's argument for why a generated phrase resists phishing
is the whole of the answer.

---
