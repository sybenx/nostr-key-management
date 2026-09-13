# Tiered Key Custody — Specification

Version 1.0-draft
Applies to: any client or co-signer that implements FROSTR threshold signing for a
Nostr identity

> This document sits on top of [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md)
> (NKM) and [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) (QRST), both of which are
> frozen. It references them and requires no change to their normative sections. It
> defines one thing they do not: how a single Nostr key is split across **trusted
> devices**, **co-signing servers**, and **temporary app grants** at different
> weights, in one flat FROST group, and how an application signs through a trusted
> device without holding any of it.

Key words MUST, MUST NOT, SHOULD, MAY are normative. A section reference with no
prefix is to this document; references to the two frozen specifications are always
written `NKM §…` and `QRST §…`, because several section numbers coincide.

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
a party carries states how much it is trusted. It reuses NKM §2's storage ladder,
NKM §3.3's `frost-share` payload profile, NKM §7.9's delta-polynomial reshare, NKM
§7.10's recovery delay, and QRST's transfer mechanism unchanged.

It is selected in place of NKM §7.4's index scheme, not alongside it. A group
MUST NOT mix this document's weighted structure with NKM §7.4's replica scheme or
NKM §7.18's one-index-per-device quorum; the three assign indices by incompatible rules
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
  index, and a party's several indices MUST be held as several peers. The one exception
  is the recovery index of §8.4, which no peer holds while it is sealed.
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

An application connected by a session (§5.0) holds no index and so has no tier. It
appears nowhere in §4's accounting.

One index is not a party's: the dormant recovery share of §8.4, recorded with tier
`recovery`. It is held by nobody while sealed, weighs nothing any party can bring to a
signing set until it is unsealed, and has no authority but §7.4's L2 and L3. §3.1 to
§3.3 do not apply to it.

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
  browser that needs to act opens a session with a trusted device (§5.0), or holds a
  grant (§3.3) where it must act with no trusted device reachable.
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

### 3.5 Two profiles, and which one the user is in

Constraint (4) of §4.2 — `2T ≥ k`, two trusted devices sign with no co-signer — is a
**per-user option, on by default**. It is the difference between a key that still works
when nothing is reachable and a key every signature of which is seen by a party that
enforces §6. Both are defensible; neither is right for everyone.

| | **Profile A — recovery-first (default)** | **Profile B — policy-first** |
|---|---|---|
| Constraint (4) | On: `2T ≥ k` | Off, and inverted: `2T < k` |
| Two of the user's own devices, nothing else reachable | Sign | Cannot sign |
| Signatures no co-signer sees | Possible | None, where §4.6's condition holds |
| §11.4's two-device residual | Present | Removed |

The choice MUST be presented at activation, MUST default to A, and MUST state the
trade in the terms above rather than as a security level.

**It is fixed at activation and changed only by Re-split.** The two profiles use
different `k`, and `k` cannot be changed by a rotation: `frost-core`'s `refresh_share`
refuses a refreshing share whose `min_signers` differs from the current package
(`frost-core/src/keys/refresh.rs:151`–`153`), and `frost-core` 2.2.0 added that
validation as a **security fix**, recording that refreshing to a smaller threshold does
not lower it and can cost the participants' shares (`frost-core/CHANGELOG.md`, 2.2.0).
Moving between profiles is therefore a re-deal — NKM §7.5a's Re-split, which
reconstructs — and a client MUST present it as such rather than as a setting.

---

## 4. Constraints

### 4.1 Variables

| Symbol | Meaning |
|---|---|
| `k` | The group threshold: the total weight a signing set must bring |
| `N` | Total live weight, the sum of all indices in the current epoch |
| `T` | The weight of a trusted device — the number of indices each one holds |
| `D` | The number of trusted devices in the current epoch |
| `n_s` | The number of co-signers, each of weight 1 |
| `W_g` | The sum of the weights of all live, unexpired grants — equal to their count, grants being weight 1 |
| `W_cap` | The **grant cap**: the largest total live grant weight the co-signers will allow. Fixed at activation, recorded in the epoch record (§5.3), and enforced by every co-signer |
| `s` | The **co-signer slack** for a trusted device: the number of co-signers that may be unreachable or refuse while a single trusted device can still sign |

### 4.2 The inequalities

A configuration MUST satisfy (1), (2), (3) and (6). (4) is **OPTIONAL and on by
default**; §3.5 gives the choice and §4.6 the configuration that declines it. (5) is
Profile B's, and §4.6 states it.

```
(1)  n_s < k                    co-signers alone never sign
(2)  W_g < k                    grants alone never sign
(3)  T + n_s − s ≥ k            one trusted device signs, losing up to s co-signers
(4)  2T ≥ k                     two trusted devices recover with no co-signers   [optional]
(6)  T + W_cap < k              for every trusted device: it and every grant it
                                could issue never sign without a co-signer
```

(1) is what makes a co-signer a co-signer rather than a custodian, and it does
double duty: it is also what stops the co-signers from authorising a rotation among
themselves (§7). (2) bounds live grant weight against the threshold, and (6) bounds it
against a trusted device; the client MUST count a grant as live from issue until its
expiry passes or the rotation that drops it completes, whichever is earlier. (3) is the
working path — the user posts from one device. (4) is the recovery path — two of the
user's own devices are the key, with no server reachable and no grant outstanding.

**(6) exists because a trusted device issues grants.** §3.1 lets any trusted device
issue a grant, and §5.1's issue is authorised by that device and co-signer votes to
weight `k`. Nothing in §5.1 can tell whether the application receiving the grant is the user's
or the device's own. So a **compromised trusted device can issue grants to itself** —
one index at a time, each an ordinary, correctly authorised issue — and it then holds
`T` plus the weight of every grant it issued. If that total reaches `k`, the device and
its own grants are a signing set with **no co-signer in it**: §6 never runs, so the
allowlist, the trusted-only list, the rate limits, §6.1(e)'s hold and §6.1(d)'s freeze
all stop applying to it, and a weight-`k` set also reconstructs the nsec, which no later
rotation undoes. One compromised device would have converted itself into the key using
nothing but the operations this document grants it.

(6) closes that. A co-signer MUST refuse to vote for, or act as a helper in (§5.1 step
4), any grant issue that would bring `W_g` above `W_cap`, counting expired grants the
rotation has not yet dropped (§5.2); and MUST refuse an epoch record whose `T` and
`W_cap` break (6). The attacker then holds at most `T + W_cap < k` however many issues it
attempts, and every set it can form from its own weight is short of `k` by at least one
co-signer. Two consequences follow directly:

- **Every §5.1 helper set contains a co-signer.** The helpers must reach `k` and include
  the initiator's `T` indices; the initiator's other weight is at most `W_cap`, so by (6)
  at least one helper is a co-signer, and an honest co-signer refuses an issue past the
  cap.
- **(6) implies (2),** because `W_g ≤ W_cap < k − T < k`. (2) is kept as the statement
  of what it protects — no set of grants signs — which a reader checking a membership
  wants without first deriving it.

(6) is stated over one trusted device because it is the attack of one compromised
device. Two compromised trusted devices under Profile A already reach `k` by (4), and
§4.6 is the profile that answers that case.

**The previous reference configuration violates (6).** At `k = 3, T = 2` with a
live-grant budget of 2, `T + W_cap = 4 ≥ 3`; even a budget of 1 gives `3 ≥ 3`. A single
self-issued grant was enough: the old enumeration listed `D1 + G1` as a signing set with
no co-signer in it. At `k = 3` and `T = 2`, (6) permits no grant at all. Appendix C
keeps that configuration and its enumeration as the counterexample; §4.4 replaces it.

### 4.3 What follows

**`T < k` MUST hold.** It is not one of the inequalities, and (6) implies it, but it is
stated on its own because the document is incoherent without it: at `T ≥ k` a trusted
device signs alone, no co-signer is ever in the signing set, and every rule in §6 is
unenforceable because nothing routes through a party that could enforce it. Under
Profile A, (4) and (6) bound `T` from both sides: `⌈k/2⌉ ≤ T ≤ k − 1 − W_cap`. At `k = 3`
the only value is `T = 2` and then `W_cap = 0`; a Profile A group that wants a grant needs
`k ≥ 4`. Under Profile B the lower bound is inverted — `2 ≤ T < k/2`, the lower limit
being §3.1's `T > 1`.

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
slack means buying it authority. A session (§5.0) has no such cost, because it signs
as the trusted device.

**Raising a grant's weight buys slack at a price that is rarely worth paying.** A
grant of weight `w` counts `w` against the cap, so by (6) `w ≤ W_cap < k − T`: a grant
can never be heavier than the gap between a trusted device and the threshold, less one.
Within that, a heavier grant is still the tier that is not trusted, and it needs fewer
co-signers to finish the more it weighs. A client MAY offer grant weights above
1 only where `w < T` and `n_g·w ≤ W_cap` both hold, MUST default to `w = 1`, and MUST NOT
offer any weight at which a single co-signer plus one grant reaches `k`.

### 4.4 Reference configuration (Profile A)

```
k      = 4
T      = 2          two indices per trusted device
n_s    = 3          three co-signers, one index each
W_cap  = 1          at most one live grant, of weight 1
s      = 1          a trusted device survives one co-signer being down
```

Checks: `n_s = 3 < 4` ✓ — `W_g ≤ 1 < 4` ✓ — `T + n_s − s = 2 + 3 − 1 = 4 ≥ 4` ✓ —
`2T = 4 ≥ 4` ✓ — `T + W_cap = 2 + 1 = 3 < 4` ✓ — `T = 2 < 4` ✓.

`T = k − 2` here. Every argument in this document that needs a relation between `T` and
`k` states the one it uses; none assumes `T = k − 1`.

With two trusted devices and the one live grant, `N = 8`:

| Index | Party | Tier |
|---|---|---|
| 1, 2 | `D1` | Trusted device |
| 3, 4 | `D2` | Trusted device |
| 5 | `C1` | Co-signer |
| 6 | `C2` | Co-signer |
| 7 | `C3` | Co-signer |
| 8 | `G1` | Grant |

### 4.5 Every signing set of the reference configuration (Profile A)

Minimal authorised sets — those of weight `≥ k` with no authorised proper subset.
There are fourteen. A set is listed once; adding any further party to a listed set
is also authorised and is not listed again. The **label** is `tiers_check.py`'s,
tested in this order: **no-co-signer** (no co-signer in the set, so §6 never runs),
**collusion** (no trusted device), **mixed** (a trusted device, a co-signer and a
grant), **trusted** (trusted devices and co-signers only). The table is
`vectors/tiers-profile-a.json`.

| # | Set | Weight | Label | What it is |
|---|---|---|---|---|
| 1 | `D1 + D2` | 4 | no-co-signer | Two trusted devices. The recovery path of (4); no server, no grant, no §6. |
| 2 | `D1 + C1 + C2` | 4 | trusted | Ordinary signing from a trusted device. |
| 3 | `D1 + C1 + C3` | 4 | trusted | As 2, another pair of co-signers. |
| 4 | `D1 + C2 + C3` | 4 | trusted | As 2, the third pair — the one that signs while `C1` is down. |
| 5 | `D2 + C1 + C2` | 4 | trusted | Ordinary signing from the second trusted device. |
| 6 | `D2 + C1 + C3` | 4 | trusted | As 5, another pair of co-signers. |
| 7 | `D2 + C2 + C3` | 4 | trusted | As 5, the third pair. |
| 8 | `D1 + C1 + G1` | 4 | mixed | The grant finishing against a trusted device, one co-signer checking it. |
| 9 | `D1 + C2 + G1` | 4 | mixed | As 8, another co-signer. |
| 10 | `D1 + C3 + G1` | 4 | mixed | As 8, the third co-signer. |
| 11 | `D2 + C1 + G1` | 4 | mixed | As 8, the second trusted device. |
| 12 | `D2 + C2 + G1` | 4 | mixed | As 11, another co-signer. |
| 13 | `D2 + C3 + G1` | 4 | mixed | As 11, the third co-signer. |
| 14 | `C1 + C2 + C3 + G1` | 4 | collusion | The grant with every co-signer and no trusted device. How the grant signs phone-free under honest co-signers; **collusion** if all three abandon §6. |

Every set of weight 3 or less is unauthorised, including all of: a single trusted
device; a single trusted device with the grant — the set (6) exists to keep short; a
single trusted device with one co-signer; all three co-signers; the grant with two
co-signers.

**Set 14 is real and is not prevented by the mathematics.** The access structure is
flat (§2.1), so "a trusted device must be present" is not something `k` can say. What
set 14 costs an attacker is the honest measure of the design:

- **It requires all three co-signers and the live grant.** That is three independently
  administered servers, each of which must abandon §6, plus the one grant the cap
  allows. If two of the co-signers are one operator's processes, §3.2 counts them as
  one party of weight 2, and set 14 is then two operators' decision rather than three.
- **No set in which the grant is needed lacks a co-signer.** Sets 8 to 14 all contain
  one. This is (6): a trusted device and the grant total 3, so the grant never lets a
  device skip the co-signers, whoever issued it. The only set with no co-signer is set
  1, which needs two trusted devices; Profile B is the configuration that removes it.
- **Nothing in set 14 reaches a trusted device's storage.** It reaches the threshold,
  which means it can sign and can reconstruct. §6 is what stops the honest members of
  such a set from participating, §7 is what stops such a set from quietly reissuing a
  trusted share, and §11 is what bounds the damage of the case this document cares most
  about.
- **Running no grant, or two co-signers instead of three, removes set 14.** At
  `W_cap = 0` no set without a trusted device reaches 4, and sessions (§5.0) remain
  available to every application. At `n_s = 2` the same holds, but (3) then fails at
  `s = 1` (`2 + 2 − 1 = 3 < 4`) — a trusted device has no slack — and a lone grant
  cannot sign without a trusted device at all (`1 + 2 < 4`). This is the trade the
  configuration makes, and a client SHOULD present it as a choice rather than picking
  silently.

### 4.6 Profile B — declining constraint (4)

A user who would rather every signature be seen by a party that enforces §6 than keep a
key that works with nothing reachable declines (4). The configuration then requires
`2T < k`, and the reference is:

```
k      = 5
T      = 2          two indices per trusted device
n_s    = 4          four co-signers, one index each
W_cap  = 2          live grants total weight at most 2
s      = 1          a trusted device survives one co-signer being down
```

Checks: `n_s = 4 < 5` ✓ — `W_g ≤ 2 < 5` ✓ — `T + n_s − s = 2 + 4 − 1 = 5 ≥ 5` ✓ —
`T + W_cap = 2 + 2 = 4 < 5` ✓ — `T = 2 < 5` ✓ — `2T = 4 < 5`, so two trusted devices
alone do **not** reach `k`.

**Checked against (6).** An earlier version of this profile allowed live grants up to
weight 4, the most (2) permits. That broke (6): `T + 4 = 6 ≥ 5`, so one trusted device and
two self-issued grants reached `k` with no co-signer. `W_cap = 2` is the largest cap (6)
allows at `k = 5, T = 2`.

**The benefit, stated exactly.** What Profile B removes is the set of signatures no
co-signer sees. The full property is stronger than "(4) is off", and it has its own
condition:

```
(5)  D·T + W_g < k               every signing set contains a co-signer
```

(5) is what makes §6 unconditional: every signature, from every party, in every
combination, passes through a co-signer, so the kinds allowlist, the trusted-only list,
the rate limits, the delay with veto and the freeze apply to everything the identity
ever signs. (6) is (5) at `D = 1` and a full grant cap, so under (6) a single trusted
device never breaks (5); only a second trusted device can.

**(5) is not free at the reference numbers, and this is the part that is easy to get
wrong.** At `k = 5, T = 2, W_cap = 2`:

| Trusted devices `D` | Live grants `W_g` for (5) to hold |
|---|---|
| 1 | any the cap allows, 0 to 2 |
| 2 | 0 |
| 3 or more | (5) cannot hold |

So the reference Profile B removes "two trusted devices sign alone" at any grant
weight, but reaches the full (5) with two trusted devices only when no grant is live. To
hold (5) with two trusted devices and two live grants, `D·T + W_g = 6`, so `k ≥ 7`:
`k = 7, T = 2, n_s = 6, W_cap = 2`, which satisfies (1), (2), (3) at `s = 1`, (6), and (5)
at `D ≤ 2` with the cap full.

**A client implementing Profile B MUST re-check (5) on every rotation that adds a
trusted device or issues a grant, and MUST refuse the operation that would break it.**
(5) is a property of the current membership, not of the parameters, so a configuration
that satisfied it at activation stops satisfying it the moment a third device is
admitted.

**The costs, in order of how much they will hurt.**

1. **The offline path is gone.** Two trusted devices with nothing reachable cannot sign.
   The user's identity is unusable unless `k − T` co-signers are reachable — three of
   four at `k = 5`, five of six at `k = 7`, against two of three under Profile A. §8's
   backup restores a trusted device that still cannot sign alone, and §7.18 of NKM — the
   serverless quorum — is the opposite choice from this one. This is the whole of what
   (4) was buying.
2. **More co-signers**, since (3) needs `n_s ≥ k − T + s`: four or six against Profile
   A's three. Each is another independently administered service to find, trust and keep
   reachable, and another place an index can be stolen from.
3. **Availability gets worse, not better.** The slack `s` is still 1: a single trusted
   device tolerates exactly one co-signer outage at `k = 5` as at `k = 4`. But it now
   depends on three of four rather than two of three, so the probability that enough are
   down rises with `n_s` while the tolerance does not.
4. **Collusion does not go away, and at a full cap it costs no more co-signers.** At
   `k = 5, n_s = 4`, all four co-signers plus one grant total 5 and sign with no trusted
   device — §4.5's set 14 in a larger shape — but so do three co-signers and both grants
   where `W_g = 2`. That is three independently administered servers defecting, the same
   number set 14 needs under Profile A. With one live grant it is four. §7.3's statement
   is unchanged.
5. **The choice is not reversible in place.** §3.5: `k` differs between profiles and a
   rotation cannot change `k`, so switching is a Re-split.

**What Profile B does not change.** Constraint (3) still gives a single trusted device a
working path, §6.1(e)'s delay still fires on a trusted-only kind from a single trusted
device, and §7's rotation authority is untouched. The first bullet of §11.4's residual
survives both profiles.

---

## 5. Sessions and grants

### 5.0 Sessions

**An application does not need a share to sign.** A **session** is a connection in
which an untrusted application — a web client, a third-party app — holds no index at
all and sends each request to a trusted device, which applies its own policy and, if
the request passes, signs it with co-signers exactly as it signs for itself. **A
session is the default way to log an application in.** A grant (§5.1) is the optional
mode for an application that must sign while no trusted device is reachable.

- **Shape.** NIP-46's. The application holds a client keypair of its own; `sign_event`,
  `nip44_encrypt`, `nip44_decrypt` and the other NIP-46 methods travel to the trusted
  device over relays, encrypted between that client key and a signer key the trusted
  device generates for sessions. The signer key MUST NOT be a share key: a share's
  pubkey is its peer identity (§2.3) and changes at every rotation, which would end
  every session each time a grant is issued.
- **Pairing.** The trusted device MUST learn the application's client pubkey from the
  application itself — a `nostrconnect://` QR it scans, or a token pasted from the
  application's screen — and never from a relay-delivered message alone. It MUST show
  the application's name, the kinds the session may sign, and whether it may decrypt,
  and MUST obtain the user's confirmation on the device.
- **Policy is the trusted device's, and it MUST apply at least this much.** A kinds
  allowlist per session, with the same default as §6.1(a). Every kind on §6.1(b)'s
  trusted-only list refused unless the user approves that individual request on the
  trusted device. Decryption refused unless the session was granted it at pairing, with
  §6.0.4's three values and the same warning for `all`. Per-session rate limits no
  looser than §6.1(c)'s grant limits. A session MAY carry an expiry and MUST end when the
  user ends it, when its trusted device is revoked or removed, or at that expiry.
- **What the co-signers see is the trusted device.** A session's signing set is the
  trusted device and co-signers, and the requesting index is the trusted device's. Every
  co-signer applies trusted-tier policy to it: §6.0's event visibility, §6.1(c)'s
  counters for a trusted index, §6.1(d)'s freeze, and §6.1(e)'s hold on a trusted-only
  kind requested with one trusted device in the set. A deletion approved on the device
  for a session is held and vetoable exactly as one the device originated. A co-signer
  cannot tell a session's request from the device's own and MUST NOT be asked to treat
  it differently. §6.1(e)'s hold is a hold on a *signature*, attached to the kind; it is
  not the rotation delay of §7.2, which never applies to a session.
- **A session issues nothing and triggers no rotation.** Opening, using or ending one
  adds no index, changes no member list, advances no epoch, counts toward neither `N`
  nor `W_g`, and does not stale a backup. §5.1 to §5.3, §7.2's authority and delay, and
  §8.2's republication do not apply to it. Ending a session is immediate and local: the
  trusted device forgets the client key. A session survives rotations, because its
  signer key is not a share key.

**Why a session is the default.** It puts no share on a platform the user does not
control, so interception of its pairing costs nothing that a rotation cannot fix —
there is nothing to reconstruct from. It uses none of the grant budget, adds no signing
set to §4.5, needs no co-signer to be reachable beyond the ones the trusted device
already signs with, and is opened and ended without a reshare.

**What it costs is the trusted device.** Every request needs a trusted device online,
reachable over relays, and unlocked to NKM §2.2's policy. An application that must post
while the user's phone is off or out of reach cannot be served by a session. That is
what a grant is for, and it is paid for in a share on an untrusted platform, a unit of
live grant weight, a signing set without a trusted device (§4.5), and every co-signer's
availability (§4.3). A client MUST offer a session first and MUST present a grant as
the phone-free alternative, with those costs, rather than as an equivalent choice.

**Against NIP-46 to a signer app.** A session is NIP-46 to a signer that is a trusted
device. The difference is in what that signer holds: `T < k` rather than the whole key,
so the session's requests reach a signature only through co-signers the application
and the signer device do not control, and a compromised trusted device is bounded by §6
and §7 rather than being the key.

### 5.1 Issue

A grant is issued by a trusted device, as a reshare to the next epoch whose new
member list adds one index. A grant is optional: a client MUST NOT issue one where a
session (§5.0) was asked for, and **nothing in this section applies to a session**,
which holds no share and is not a rotation.

1. **Authority.** A trusted device initiates. The operation is a grant rotation under
   §7.2 and MUST satisfy its authority: the new epoch record is signed by the group, so
   a trusted device alone cannot issue a grant any more than it can sign alone, and
   every voting co-signer refuses an issue past the grant cap of (6). It is immediate;
   §7.2's delay is for trusted-set rotations only.
2. **New polynomial.** The epoch advances by the delta-polynomial reshare of NKM
   §7.9: `f'(x) = f(x) + δ(x)` with `δ(0) = 0` and fresh randomness, every existing
   member applying its own `δ` at each index it holds. NKM §7.9 gives `δ(x) = r·x`,
   which is degree 1 because NKM fixes `t = 2`. **At `k ≥ 3` the delta MUST be
   `δ(x) = Σ_{j=1}^{k−1} r_j·x^j` with every `r_j` fresh**, and the epoch record MUST
   carry one commitment per coefficient; SPEC_ISSUES.md records the same requirement
   against NKM §7.18's `t = 3` option and proposes the same form. This is
   `frost-core`'s `keys::refresh`: `compute_refreshing_shares` builds a sharing of
   **zero** with `min_signers − 1` fresh coefficients — `δ(0) = 0` by construction —
   and `refresh_share` adds each member's `δ(i)` to its existing share
   (`frost-core/src/keys/refresh.rs:58` and `:131`, crate 3.0.0). The function that
   computes the deltas takes only the **public** key package, so the party that draws
   `δ` learns nothing about any share; it MUST nonetheless be a trusted device, because
   whoever knows `δ` can carry a revoked member's old share onto the new polynomial
   (NKM §7.9's "a surviving device can hand `r` to a revoked one"). Passing a subset of
   the identifiers is how a member is dropped, which is how §7.5's rotation removes
   grants. `refresh` cannot change `k` and cannot add an identifier — that is step 4.
3. **The grant's share is `f'(x_g)`** at a fresh index `x_g` that has never been used
   in this group (§2.2).
4. **The new index is issued by the repairable threshold scheme, and no party reaches
   `k` while it runs.** `f'(x_g)` is `Σ_i ζ_i(x_g)·s_i` over a set of `k` indices, and a
   raw `ζ_i(x_g)·s_i` **is** `s_i`, because `ζ_i(x_g)` is publicly computable. The
   contributions MUST therefore be blinded, and the construction that blinds them is
   the **repairable threshold scheme (RTS)** of *A Survey and Refinement of Repairable
   Threshold Schemes* (Laing and Stinson, IACR ePrint 2017/1155), implemented as
   `frost-core`'s `keys::repairable` and re-exported by `frost-secp256k1-tr` — the
   ciphersuite crate NKM §7.4 already names. The issue MUST follow it:

   - **Helpers: any set of indices of total weight `k`.** `repair_share_part1`
     rejects a helper set smaller than the group's threshold
     (`frost-core/src/keys/repairable.rs:111`–`119`). The set MUST include the
     initiating trusted device's `T` indices, so by `T < k` (§4.3) it always contains
     at least one co-signer. **`x_g` MUST NOT be a helper**: `ζ_i` is taken over the
     helper set evaluated at `x_g`, and an `x_g` inside the set drives it to zero.
     §2.2's never-reuse rule already guarantees this.
   - **Part 1 — pairwise deltas summing to zero.** Each helper index `i` splits
     `ζ_i(x_g)·s_i` into `k` additive parts `δ_{i→j}`, one for every helper `j`
     including itself: `k − 1` drawn uniformly at random and the last set so that
     `Σ_j δ_{i→j} = ζ_i(x_g)·s_i` (`compute_last_random_value`, `:135`–`165`). It sends
     `δ_{i→j}` to helper `j` and keeps `δ_{i→i}`. These travel helper-to-helper over
     the members' existing peer channel and never enter the QRST session.
   - **Part 2 — one masked sum per helper.** Helper `j` computes `σ_j = Σ_i δ_{i→j}`
     (`repair_share_part2`, `:170`–`178`) and sends it to the new device. A party
     holding several helper indices MUST send the sum of its own `σ_j` values as one
     value, so that the number of masked sums the new device receives is the number of
     helper **parties**, not of helper indices.
   - **Part 3 — the new device sums.** `Σ_j σ_j = Σ_i ζ_i(x_g)·s_i = f'(x_g)`
     (`repair_share_part3`, `:184`–`212`). It verifies the result against the new
     epoch's commitments before storing (NKM §3.3's P4 check, generalised per step 2).
   - **Nobody learns anyone else's share.** Helper `i`'s contribution is blinded by
     `δ_{i→i}`, which `i` never sends, so no coalition of the remaining helpers can
     recover `ζ_i(x_g)·s_i`. This is exactly the case §4.3 makes dangerous: the issuing
     trusted device holds `T` of the `k` helper indices — `k − 2` of them at the
     reference configuration of §4.4, and never fewer than `W_cap + 1` short of `k` by
     (6) — receives only the co-signers' random `δ` values,
     never receives any `δ_{i→i}`, and never receives another party's `σ`. It ends the
     issue holding weight `T`, exactly as it began.
   - **The new device learns only its own share.** Each `σ_j` it receives is masked by
     every other helper's randomness, so the sum is `f'(x_g)` and the parts say
     nothing about any `s_i`. A coalition of the new device and `k − 1` helpers can
     solve for the remaining share — but that coalition already holds `k` indices and
     is the key by §2.1, so nothing is lost to it that it did not have.

   NKM §7.18's "combine them on one of the two" is the **unblinded** version of part 2
   and part 3 collapsed onto a contributor. It is sound only in its own setting, where
   the two combining devices already reconstruct by assumption and are both the user's
   own hardware. It MUST NOT be used here.
5. **The group MUST NOT be re-dealt from a reconstruction to add a grant.**
   Reconstructing the nsec on one device and splitting it again produces a correct
   result, and it is what the only FROSTR-level operation on offer does
   (`bifrost-rs`'s `rotate_keyset_dealer`). It is forbidden here: NKM §7.5a reserves
   reconstruction to disable and Re-split, and a grant issue is neither. The
   ciphersuite needs no reconstruction for any of steps 2 to 4 — `keys::refresh` and
   `keys::repairable` are both non-reconstructing — so what is missing is a FROSTR
   layer that exposes them, not a primitive. SPEC_ISSUES.md and the Status section
   record which layer is missing what.
6. **Delivery.** One QRST session, one payload, one Sender — the issuing trusted
   device — using the `frost-share` profile of NKM §3.3 in its unique-index form,
   with `index = x_g`. The Receiver performs the profile's P4 check against the new
   epoch's commitments, renders P5, and confirms (QRST §9.4). The SAS of QRST §6 and
   §9.2 is REQUIRED unless the pairing token reached the receiving app over a channel
   the issuing device controls, in which case the light flow of QRST §12.3 MAY be
   used; QRST §12.3 states that condition and this document does not relax it. Step 4
   produces one masked sum per helper party and the QRST session has one Sender;
   **Appendix B** describes how the two are reconciled and is non-normative.
7. **The grant is `admitted: false` on arrival** and cannot obtain a co-signature
   until admitted from a trusted device (NKM §7.1). Admission gates signing, not
   reconstruction.

**What interception of a grant share costs.** An intercepted grant index is one unit
of weight. By (2) it cannot sign alone, and by §6 no honest co-signer will co-sign
for an unadmitted index. But neither expiry nor rotation undoes a reconstruction:
in the reference configuration an intercepted grant and every co-signer total `k`
(set 14 of §4.5), as do an intercepted grant, a trusted device and one co-signer (sets 8
to 13). The bound on interception is therefore the grant cap and the co-signers'
honesty, not revocation, and a client MUST
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

- Group-wide: `k`, `T`, `n_s`, the grant cap `W_cap` (§4.2), the commitment vector of
  §5.1 step 2, and `recovery_pub` where a recovery share exists (§8.4).
- Per member: `party` — a stable identifier shared by every index one party holds —
  and `tier`, one of `trusted`, `cosigner`, `grant`, `recovery`; and for a grant,
  `expiry`, `issuer` and `policy_id`.

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
event, from every index without exception.** It serialises and hashes the event
itself per NIP-01 and signs only its own computed hash. A bare 32-byte sighash, or
any digest the co-signer did not derive, is refused.

The rule covers trusted indices as well as grants, and this is not caution. §6.1(e)'s
delay and veto fire on the **kind** of a trusted-only event requested with a single
trusted device in the signing set, so a co-signer that will sign a bare hash for a
trusted index has no delay path at all — the compromised-device case of §11.4 stops
being a delayed attack and becomes an immediate one. The allowlist needs the kind; so
does the delay.

This is NKM §7.6's rule. SPEC_ISSUES.md records that FROSTR's native signing message
carries sighashes only, and that the one HTTP surface which does accept a full event
also accepts a bare hash. What follows is the wire this document needs instead.

#### 6.0.1 The `/event` tag

One additional message tag in bifrost's existing envelope:

```
/event/req   requester → co-signer   { events: [ <unsigned event>, … ] }
/event/res   co-signer → requester   { results: [ { id, accepted, reason? }, … ] }
```

- An unsigned event is NIP-01's `{pubkey, kind, created_at, tags, content}`. **The
  co-signer computes `id` itself** and MUST NOT accept an `id` the requester supplies;
  the whole point is that the digest is derived from what was inspected.
- The co-signer applies §6.1 to each event against the **requesting index** and answers
  with the verdict. Refusing here rather than at `/sign/req` gives the requester a
  reason it can put in front of a user, which bifrost's rejection path — a silent
  timeout, chosen so that refusal reasons do not leak (`docs/PROTOCOL.md`, "Error
  Handling") — does not.
- On `accepted`, the co-signer caches the event (§6.0.2). On refusal it caches nothing.

**This is additive.** The envelope `{tag, data, env}` is unchanged, no existing schema
changes, and `bifrost`'s dispatch is a `switch` on `msg.method` with **no `default`
arm** (`src/class/client.ts:174`–`205`), so a peer that has not implemented `/event`
ignores the message and the requester sees the ordinary timeout. The existing peer
authorisation filter (`_filter`, `:213`) applies to it unchanged, so an unknown or
`recv`-denied peer cannot populate a cache.

#### 6.0.2 The cache

- **Keyed by `(id, requesting index)`.** An entry MUST NOT be usable by any index other
  than the one that submitted it. Keyed by `id` alone, one grant rides another's
  accepted event and the per-index allowlist and rate limits mean nothing.
- **Short TTL.** Reference 120 seconds; a co-signer MUST NOT use more than 600 seconds,
  QRST's own session lifetime. The window exists to cover one relay round trip and a
  signing round, not to hold work.
- **Bounded.** A co-signer MUST bound entries per index and evict oldest-first;
  reference 32. An unbounded cache is a memory denial of service that costs a grant one
  message per entry.
- **Epoch-scoped.** Entries are discarded on entering a new epoch, with the grant
  records of §5.3.
- **A held round pins its event.** Where §6.1(e) holds a request for the delay, the
  co-signer MUST retain that event for the whole window independently of the TTL, and
  MUST name its kind and `id` in the notice it sends. A delay that expires against an
  evicted entry fails open.
- `created_at` is the requester's and MUST NOT be altered; an event submitted now and
  signed at the end of a delay window carries its compose-time timestamp, which is
  NKM §7.6's rule for an unsigned rumor held offline.

#### 6.0.3 What `/sign/req` must then satisfy

A co-signer MUST refuse the **whole session**, not the individual sighash, unless all
of these hold:

1. **No tweaks.** Every entry of `hashes` is a vector of exactly one element. bifrost's
   `sighash_vec` is `[hex32].rest(hex32)` (`src/schema/sign.ts`), so a vector may carry
   trailing tweaks; a tweak alters what is signed, is not expressible in a Nostr event,
   and is therefore a bypass of everything `/event` validated. Refused from every index.
2. **Every sighash matches a live cache entry** whose requesting index is the index
   that sent this `/sign/req`, whose verdict was `accepted`, and whose TTL has not
   lapsed.
3. **Batches are checked element-wise.** `hashes` may carry many vectors, and §6.1(c)
   counts each sighash rather than each session. One unmatched sighash refuses the
   session.
4. **`content` is not policy.** The session's `content` field is unvalidated free text
   folded into the session id (`src/lib/session.ts:131`–`135`). A co-signer MUST NOT
   read any permission from it.

Refusing the session rather than the offending element is deliberate: a partial refusal
would tell a requester which members of a batch passed, and bifrost has no channel to
say so anyway.

#### 6.0.4 ECDH carries no event, so it is gated by tier

`/ecdh/req` carries `{gid, members, ecdh_pks}` (`docs/PROTOCOL.md`) and nothing a kind
can be read from. There is no allowlist to apply, so the gate is the tier:

- **A trusted index: allowed.** Subject to NKM §7.13's alerting and to §6.1(c)'s
  per-index counters. A trusted device decrypts the user's own correspondence and there
  is no narrower rule that would mean anything.
- **A grant index: refused by default, and allowlisted per grant.** The policy named by
  the grant's `policy_id` (§5.3) carries an `ecdh` field with exactly three values:

  | Value | Effect |
  |---|---|
  | `none` | The default. Every `/ecdh/req` from that index MUST be refused. |
  | `listed` | An enumerated set of peer public keys fixed at issue. Any `ecdh_pks` entry not on the list refuses the **whole** request; the co-signer MUST NOT answer the subset. |
  | `all` | Any peer key, subject to NKM §7.13's restricted-origin ceilings, counted per index per §6.1(c). |

  Widening is issuing a new grant (§5.2), never an edit.
- **`listed` cannot receive gift wraps.** NKM §7.13 records that every incoming NIP-59
  wrap uses a fresh random ephemeral key, so the `P` values a recipient derives against
  are one-shot and unknowable at issue. `listed` covers NIP-04/44 conversations with
  named peers and nothing else; a grant that must read NIP-17 DMs needs `all`.
- **`all` is the user's whole DM history, not their new messages.** A grant at `all` can
  derive a conversation key for every peer the user has ever corresponded with, past
  messages included, bounded only by §6.1(c) and NKM §7.13's cumulative cap. A client
  MUST present it in those terms.
- A grant whose kinds allowlist carries `13` but whose `ecdh` is `none` can send DMs and
  never read the replies. A client MUST warn at issue where the two are set
  inconsistently.

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
rolling day; a trusted-device index, no ceiling but the alerting of NKM §7.13. Each
sighash in a batch session counts once (§6.0.3). ECDH ceilings are NKM §7.13's, counted
per index, and gated per tier by §6.0.4. Exceeding a limit MUST be reported to
every trusted device as an NKM §7.17 `ALERT`; raising a limit for a live grant MUST
require a trusted device and MUST NOT be automatic.

**(d) A freeze.** A co-signer MUST support a freeze: a state, entered on the
instruction of any trusted device, in which it refuses **all** rounds for the group —
every kind, every index, trusted indices included — until lifted. Lifting MUST
require an instruction from a trusted device and MUST NOT expire on its own, MUST NOT
be liftable by a grant or by another co-signer, and SHOULD require a different
trusted device than the one that froze. A freeze MUST take effect within one round:
a co-signer that has begun a round MUST NOT complete it after receiving a freeze.
A freeze is an L1 act (§7.4): it does not bind a rotation at L2 or L3, and it is not
§7.4's conflict freeze, which lifts only on withdrawal.

**Under Profile A, a freeze does not stop two trusted devices.** By (4), `2T ≥ k`, so
the user's own two devices sign with no co-signer in the set and a freeze is invisible
to them. This is defensible — a freeze is a tool against a compromised grant or an
unexplained signing burst, not against the user — but a client MUST NOT describe a
freeze as stopping all signing, and the freeze indicator MUST say what it actually
covers. **Under Profile B (§4.6) a freeze stops everything**, because no signing set
exists without a co-signer in it; the indicator MUST say that instead, and MUST NOT use
the same wording for both profiles.

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
exactly as NKM §4.2 provides for a recovery with no registered device — unless one is
restored from backup inside the window, which §7.6 makes a full trusted device for this
purpose. The delay
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

A refusal is an act at level L1 of §7.4, and it is bounded like one. It MUST NOT name
the recovery index (§8.4), it does not bind a rotation at L2 or L3, and it does not void
the refused index's veto, approval or withdrawal under §7.4, none of which is a signing
round (§7.6). Otherwise one trusted device could silence another's veto by refusing it
first.

**Tier 2 — rotation.** Everything below.

### 7.2 Authority for a rotation

A rotation is a new epoch under §5.1's reshare. It is one of two kinds, and they carry
different authority. A session (§5.0) is neither: opening, using and ending one is not a
rotation, and nothing in this section, delay included, applies to it.

**Grant rotations are immediate.** Issuing a grant, revoking one, dropping expired
ones, and a refresh that changes no trusted-device index and no recovery index MUST
satisfy these three, and need no other authority:

1. **Initiation by a trusted device.** A co-signer MUST NOT initiate, and a grant MUST
   NOT initiate or vote (§3.3, §7.4's L0).
2. **Votes totalling `k`** against the proposed new epoch record, of which the
   initiating trusted device contributes its `T` and the remaining `k − T` MUST come
   from co-signers. Because `T < k` (§4.3), **a single trusted device cannot rotate
   alone**: it is always one or more co-signer votes short, and this is the point of
   fixing `T` below `k`.
3. **Constraint (6), checked by every voting co-signer** against the proposed record:
   live grant weight after the rotation within `W_cap`, and `T + W_cap < k`.

There is no delay and no veto. The rotation completes when the votes are in, and every
co-signer MUST then send a notice to every trusted device naming the initiator and what
changed; nothing waits on it.

**Why no delay is safe here: (6).** A grant rotation adds at most `W_cap` of untrusted
weight, and `T + W_cap < k`, so however many a compromised trusted device performs, no
set it can form without a co-signer reaches `k`, and §6 runs on everything its grants
sign. The delay used to be the only thing standing between such a device and a
self-issued key; (6) is a structural bound in its place, and SPEC_ISSUES.md records
the change.

**Trusted-set rotations are delayed, with veto.** Any rotation that changes the set of
trusted-device indices — admitting a trusted device, reissuing trusted weight to a
device, removing a trusted device — or that creates, reissues under a new factor, or
removes the recovery share (§8.4) MUST satisfy all three:

1. **Authority at a level of §7.4.** At L1: initiation by a trusted device and votes
   totalling `k`, its `T` and `k − T` from co-signers, exactly as for a grant rotation.
2. **The delay of NKM §7.10**, with a notice to **every** trusted device in the current
   epoch — the target of a removal included — naming the initiator, the level, what the
   rotation changes, and when it completes.
3. **Veto as §7.4 allows it.** At L1, any other trusted device, **including the device
   a rotation would remove**, may veto for the whole window. A veto does not quietly
   abandon the rotation; it puts the two in conflict under §7.4.

An approval from **every** other trusted device in the current epoch, the target of a
removal included, completes a trusted-set rotation immediately. A rotation that is both
— a grant issued in the same epoch change that admits a device — is a trusted-set
rotation.

The new epoch record is signed by the group with the old shares before any delta is
applied, exactly as NKM §7.9 step 1 requires, so the vote and the signature are the
same act.

### 7.3 What this means, stated plainly

**A set of parties totalling weight `k` can sign any epoch record it likes; only policy
makes that a rotation.** §7.2's requirements and §7.4's levels are rules co-signers
follow, not facts the mathematics enforces; the access structure is flat (§2.1). In the
reference configuration the only set without a trusted device is set 14 of §4.5, and it
contains every co-signer, so the rules fail only if all of them defect. Where `n_s ≥ k`
the co-signers alone would be such a set, which is the second reason constraint (1)
exists.

**Losing every trusted device is recoverable through the recovery share, and only
through it or a §8.1 backup.** A grant has no rotation authority (§7.4's L0), so the
co-signers and a grant cannot legitimately reissue trusted weight. What can is the
recovery share at L2: its holder and every co-signer, after the delay, with a notice to
any trusted device that survives — which cannot veto it, and can only override it at L3
by also holding the recovery phrase. A trusted device restored from §8.1 inside the
window is a trusted device for this purpose (§7.6).

**This is the accepted trade, and it is accepted against loss.** A construction in
which nothing without a trusted device could ever rotate would be a construction in
which losing every trusted device loses the identity permanently — NKM §7.18's device
quorum is that construction, and NKM says so: "A quorum with no usable backup and fewer
than `t` surviving devices is unrecoverable." This document buys a recovery path and
pays for it in exactly one coin: **whoever holds the recovery phrase, with every
co-signer's cooperation, rotates after a delay that a trusted device can override but
not veto.** §7.4 gives the whole case table. A client MUST state this on the screen
where the recovery share is created and where co-signers are enrolled, in those terms,
and MUST NOT describe co-signers as unable to reach the key.

Two things narrow it, and neither closes it:

- Constraint (1) means the co-signers need help — the recovery share, a grant, or a
  trusted device — to reach `k`. Policy refuses them the grant; the mathematics does
  not, which is set 14.
- Co-signers that are independently administered must all defect. §3.2's rule that
  one operator's several processes count as one party is what keeps that from being a
  single decision by a single operator.

### 7.4 Rotation authority levels

Every trusted-set rotation carries a **level**, fixed by what signs for it. Co-signers
hold the state of every pending trusted-set rotation — its level, the proposed epoch
record, the indices that authorised it, when its delay ends, and every veto, approval,
withdrawal and cancellation received — and enforce this section as policy. A co-signer
MUST NOT vote for, apply a delta toward, or acknowledge an epoch record that has not
completed under it, and MUST forward every proposal, veto, approval and withdrawal it
receives to every other co-signer, so that no two hold different state for long.

| Level | Authority | Votes to `k` | Delay | Vetoable by | On proposal, cancels |
|---|---|---|---|---|---|
| L0 | A grant | None: no authority | — | — | — |
| L1 | A trusted device | `T`, and `k − T` co-signers | NKM §7.10 | Any other trusted device, the target of a removal included | Nothing |
| L2 | The unsealed recovery share (§8.4) | `1`, and every co-signer | NKM §7.10 | Nothing at L1 | Every pending L1 rotation |
| L3 | The recovery share and a trusted device | `1 + T`, and `k − T − 1` co-signers | NKM §7.10 | Nothing at L1 or L2 | Every pending L1 and L2 rotation |

- **L0: a grant has no rotation authority, including as part of a weight-`k` set.** A
  co-signer MUST NOT count a grant index toward any rotation and MUST refuse to vote in
  a rotation session whose members include one.
- **L2 needs every co-signer.** The recovery share weighs 1 and (1) allows at most
  `k − 1` co-signers, so it reaches `k` only where `n_s = k − 1`, with all of them. Both
  reference profiles have `n_s = k − 1`. A group with fewer co-signers has no L2, and its
  recovery share is usable only at L3.
- **Precedence.** A proposal at a higher level cancels every pending lower-level one
  the moment co-signers accept it, and they MUST notify each cancelled initiator. While
  an L2 or L3 rotation is pending, co-signers MUST refuse every new rotation at a lower
  level, grant rotations included. §6.1(d)'s freeze and §7.1's refusal are L1 acts and
  bind nothing at L2 or L3.
- **One pending trusted-set rotation per level.** A second, different proposal at the
  same level from a different authority is a conflict, as a veto is. An authority that
  revises its own proposal withdraws the first.

**Conflict at an equal level freezes the group.** A conflict is an L1 veto, or two
different pending proposals at the same level. On conflict every co-signer MUST refuse
all co-signing for the group — every kind, every index, grant rotations and L1
rotations included — until one side withdraws:

- **At L1**, the vetoing device withdraws its veto and the rotation resumes its window,
  or the initiator withdraws the rotation and it is abandoned.
- **At L3**, each side is identified by the trusted device in its authority, and
  withdraws its own proposal by that device's signature.
- **At L2**, the two sides hold the same credential and cannot be told apart, so a
  withdrawal signed by the recovery share withdraws every pending L2 proposal at once.

If neither side withdraws, the freeze does not lift on its own, no trusted device can
lift it (§6.1(d)'s lift does not apply), and **the key stays frozen**. A rotation at a
higher level is not blocked by a conflict freeze below it, and ends that freeze when it
completes; nothing is above L3.

**What each side can do.** "Holds the phrase" means can produce the recovery factor; a
phrase the attacker copied is still held by the user. A device restored from §8.1 is a
held trusted device (§7.6).

| Attacker holds | User holds a trusted device | User holds the phrase only | User holds a device and the phrase |
|---|---|---|---|
| **A trusted device** | **Freeze.** Either side's L1 proposal meets the other's veto, and neither signs through a co-signer until one withdraws. The user's way out is the phrase. | **User wins.** An L2 rotation removes the attacker's device and admits the user's; the device cannot veto it, and its own pending L1 is cancelled. | **User wins** at L2, or L3. The attacker has nothing above L1. |
| **The phrase** | **Attacker wins.** Its L2 rotation cannot be vetoed by the user's device and cancels any pending L1, including a reissue of the recovery share under a new phrase that had not yet completed. | **Freeze.** Two L2 proposals under one credential; a withdrawal by either withdraws both. | **User wins.** An L3 rotation cancels the attacker's L2. |
| **A trusted device and the phrase** | **Attacker wins,** at L2 or L3. | **Attacker wins.** Its L3 cancels the user's L2. | **Freeze.** Two L3 proposals, each withdrawable only by its own device. |

**The last cell is the intended outcome.** An attacker holding a trusted device and the
recovery phrase holds everything the user holds; nothing the co-signers can observe
tells the two apart, and the protocol refuses to pick. A frozen key is the result,
stated to the user in those terms. It is the outcome for everything that routes through a
co-signer, and not a bound on the key: that attacker can also issue itself grants and
reach `k` with its device and the recovery share alone (§8.4).

Two consequences a client MUST state where the recovery share is created. **The phrase
outranks every device**: against a user who can no longer produce it, whoever can wins.
And **reissuing the recovery share under a new phrase is a trusted-set rotation**,
delayed like any other, so a phrase known to be exposed is safe only once that rotation
completes.

**The table is policy.** The collusion sets of §4.5 can bypass it cryptographically:
set 14 can sign any epoch record without a trusted device, and set 1 under Profile A is
two trusted devices that already reach `k`. Neither adds anything to the residual. Set
14 is every co-signer abandoning §6, which §7.3 already prices, and an attacker holding
both devices of set 1 is outside the table because it holds the key. The recovery share's
own sets do add one, and §8.4 states it.

### 7.5 What a rotation does

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

### 7.6 A restored trusted device is a trusted device

A device that restores a trusted share from the backup of §8 holds the same `T`
indices at the same epoch as the device it restores. **For every rule in this document
it is that trusted device.** It MAY cast a veto under §6.1(e) and §7.4, MAY approve,
MAY freeze and lift a freeze under §6.1(d), MAY issue a tier-1 refusal under §7.1, and
MAY initiate a rotation under §7.2. Nothing in this document distinguishes a restored
holder of an index from the original holder, because the index is what the rules are
written over.

**So recovery-from-backup and the delay path compose.** A trusted-set rotation's
window (§7.2) is not only a notice period; it is long enough to be a *recovery* period.
A user with no trusted device reachable when an L1 rotation starts can restore one from
§8.1 inside the window and veto it. A restored device cannot veto an L2 rotation; a user
who also holds the recovery phrase overrides one at L3 (§7.4).

For this to hold, three things are required of co-signers, and each of them is a way
an implementation could break it by accident:

- A co-signer MUST address §6.1(e), §7.2 and §7.4 notices to the **trusted-device indices
  of the current epoch**, not to the devices that were recently online.
- A co-signer MUST accept a veto, an approval or a withdrawal on the strength of a
  signature by a trusted-device index of the current epoch alone. It MUST NOT require prior liveness,
  session state, a registration step, or any "known device" marker that a device
  restored ten minutes ago cannot present.
- A co-signer MUST NOT let §6.1(c)'s rate limits refuse a veto. Vetoes and freezes are
  not signing rounds and are not counted against a signing budget.

Three limits, stated because the composition is easy to overstate:

- **It needs a current backup.** §8.2 requires republication as part of every rotation
  and forbids finalising one until the new backup is verified, which is exactly what
  makes a restore land on the current epoch. A stale backup restores indices on a dead
  polynomial and can veto nothing.
- **It needs the factor to be reachable independently of whatever went wrong.** Where
  the factor is a passkey PRF held on the compromised device itself, restoring gives an
  attacker a second copy and the user nothing. The paper secret of §8.1 is the form that
  survives losing the device, and a client SHOULD say which of the two the user has.
- **Whoever can restore can veto, including an attacker.** §8.3 puts the factor at the
  sensitivity of a trusted device; this section is one more reason why. A phished factor
  buys a veto and a freeze as well as a share.

**A restored device is not a second party.** Until the next rotation it holds the same
indices as the device it restored, which §2.2 forbids two peers from doing. Until that
rotation the original and the restoration are **one party** for every quorum rule: a
co-signer MUST NOT count an approval from an index and a veto from the same index as
two parties, and MUST NOT treat `D1`-restored plus `D1`-original as satisfying
§6.1(e)'s "two trusted devices in the signing set". Where the two disagree — a proposal
and a veto signed by the same index — co-signers MUST treat it as a §7.4 conflict that a
withdrawal by that index resolves in full, as at L2, because the two cannot be told
apart. A restore SHOULD be followed promptly by a rotation that reissues the restored
device its own indices.

---

## 8. Backup

### 8.1 What is backed up

A backup under §8.1 to §8.3 holds **one trusted device's indices** — all `T` of them,
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
moves every member to a new polynomial (§7.5), so a container holding an old epoch's
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
- **A backup is worth a trusted device to whoever opens it.** The factor plus `k − T`
  co-signers is the key — two at §4.4's reference configuration, where `T = k − 2`, and
  three under §4.6's Profile B — and the factor plus grants its holder issues itself
  still needs at least one, by (6). Under Profile A the factor plus any *other* trusted
  device is also the key, by (4); plus the device it was taken from it is nothing more,
  because the two hold the same indices (§7.6). The factor
  MUST be treated by the client as material of the same sensitivity as a trusted
  device's storage, and the screen that presents it MUST say so rather than describing
  it as "a backup". §7.6 adds the other half: whoever restores from it can veto, approve
  and freeze, so the factor carries a trusted device's *authority* as well as its
  weight.

Where an NKM §4.2 blob-store backup of the **nsec** also exists — NKM §7.5 records
that it survives activation by design — it holds the whole key and outranks every
inequality in §4. That is NKM's decision and this document does not disturb it, but a
client MUST list it on the same screen as this section's backup and MUST NOT present
the two as equivalent.

### 8.4 The dormant recovery share

**One index of the group is held by nobody.** The recovery share `R` is a share at an
index of its own, recorded in the epoch record with tier `recovery`, sealed under a
recovery factor, and stored only as ciphertext. **It weighs 1, and only while unsealed.**
Sealed, it is weight that no party can bring to a signing set.

- **Factor.** Exactly §8.1's two: a passkey-PRF-derived key, or a generated paper phrase
  of at least 96 bits; never a chosen password. From the factor the client derives a
  **recovery keypair** by §8.2's burner derivation under its own label, and records its
  public key `recovery_pub` in the epoch record. The factor MUST NOT be the factor of a
  §8.1 backup: one secret that opens both is a trusted device and the recovery share
  together, which is L3 authority (§7.4).
- **Issue, without anyone holding it.** `R` is issued by §5.1 step 4's repairable
  threshold scheme with the recovery keypair as target: every helper party gift-wraps its
  `σ` to `recovery_pub`, as Appendix B.1 carries `σ` to a new device, and the initiating
  trusted device adds one wrap carrying the epoch's group package and commitments. Only
  the factor's holder can sum them. At activation, the dealer of NKM §7.5 MAY instead
  seal `R` directly, because it holds the nsec at that moment anyway.
- **Storage, on relays or on a co-signer.** On relays, the wraps are published and
  verified exactly as §8.2 requires of a backup. On a co-signer, the co-signer holds them
  and releases them only against a signature by the recovery keypair. §8.3 forbids a
  trusted-share backup on a co-signer's relay; `R` is permitted there because the
  concentration is bounded: that co-signer holds its own index and the ciphertext of one
  more, and even unsealed the two weigh 2, short of `k ≥ 3`. A co-signer storing `R` MUST
  NOT receive the factor or anything derived from it except `recovery_pub`.
- **It goes stale at every rotation and is repaired at every rotation.** A delta moves
  every index, and nobody can apply one to a sealed share. Every rotation MUST discard
  `δ(R)` and re-issue `R` at the new epoch, by the same scheme, to the same
  `recovery_pub`. That repair is not a change to the recovery share under §7.2 and adds no
  delay, but a rotation MUST NOT be finalised until the new wraps are published and
  verified. Only the latest epoch's wraps are ever needed.
- **Its only use is rotation authority.** A co-signer MUST refuse every sign and ECDH
  round from the recovery index except votes, approvals and withdrawals in an L2 or L3
  rotation under §7.4. An unsealed `R` signs no event, decrypts nothing and issues no
  grant, and what it does authorise completes only after NKM §7.10's delay, with notice to
  every trusted device. The delay applies whichever factor unsealed it — unlike NKM §4.2,
  a passkey does not skip it — because what it gates is authority over the trusted set,
  and the window is what lets a user who holds a device and the phrase answer an L2 with
  an L3.
- **Recovery.** On a new device — a native app; a browser MUST NOT offer it, as NKM
  §7.10 — the user presents the factor; the client derives the recovery keypair, fetches
  the latest wraps, sums them into `R`, checks it against the commitments (NKM §3.3's P4
  check), and proposes a rotation that admits itself as a trusted device (§7.5), removes
  the trusted devices the user names, and reissues `R`, under a new factor where the old
  one may be exposed. With no trusted device available that rotation is L2 and needs
  every co-signer; with a surviving trusted device it is L3 and needs `k − T − 1`.

**The recovery sets.** At §4.4's reference configuration, with `R` unsealed, the
minimal signing sets containing it — labelled as §4.5 labels them, `R` counted as a
grant — are:

| Sets | Count | Label | What they are |
|---|---|---|---|
| `R + C1 + C2 + C3` | 1 | collusion | **L2.** Recovery with no trusted device; every co-signer must take part. |
| `R +` a trusted device `+` a co-signer | 6 | mixed | **L3.** Recovery share and a surviving device. |
| `R + G1 +` two co-signers | 3 | collusion | Weight `k` with no rotation authority: the grant is L0, and co-signers refuse the recovery index everything else. |
| `R +` a trusted device `+ G1` | 2 | no-co-signer | Weight `k` with no co-signer. See below. |

Under Profile B (`k = 5, W_cap = 2`) the shapes are the same — `R` with all four
co-signers is L2, `R` with a device and two co-signers is L3 — and two more sets have no
co-signer: `R` with a device and both grants, and **`R` with both trusted devices and no
grant at all**, which breaks the property (5) exists to give while `R` is unsealed.

**Sealed, `R` changes nothing in §4.** It contributes no weight any party can bring, so
(1), (2), (3) and (6) hold exactly as they did: at the reference configuration
`n_s = 3 < 4`, including for the co-signer that stores `R`, whose usable weight stays
1; under Profile B `4 < 5`. `R` counts in `N` for §2.2, as an index number that is never
reused, and nowhere else. Unsealed, `R` and every co-signer reach `k` by design: that is
L2, and it exists only where `n_s = k − 1`.

**What unsealing adds to the residual.** A trusted device, `R` and grants issued to the
cap weigh `T + 1 + W_cap`, which is `k` at both reference profiles (`2 + 1 + 1 = 4`,
`2 + 1 + 2 = 5`). Grant issue is immediate (§7.2), so **an attacker holding a trusted
device and the phrase can issue itself grants and then sign or reconstruct with no
co-signer**, past §6 and past §7.4's freeze. This is no more than §8.1's factor already
gives: a device and a trusted-share backup are `2T`, which is `k` under Profile A, and
`2T` plus one self-issued grant is `k` under Profile B. The recovery factor MUST therefore
be presented as authority over the whole identity, not as "a backup", and a client MUST
say that the phrase together with any one trusted device is the key. SPEC_ISSUES.md files
the constraint that would close it.

### 8.5 A recovery artifact is required at setup

**A client MUST NOT complete activation of a group under this document until at least
one recovery artifact exists and has been verified:** the dormant recovery share of §8.4,
or a trusted-share backup of §8.1 and §8.2 for the activating device. After activation, a
client MUST NOT let a rotation leave the group with neither, and §8.2 and §8.4 keep
whichever exists current.

**The reason: without one, a single-device user has no recovery, which is worse than a
raw nsec.** A raw nsec is one secret its holder can copy at any moment — written down,
exported as `ncryptsec` — and any copy recovers it. A key under this document cannot be
copied from anywhere. The trusted device holds `T < k` and exports nothing that signs;
the co-signers hold `n_s < k`, and §3.2 forbids them from holding weight for a user who
holds none; grants have no rotation authority (§7.4's L0). So a user with one trusted
device and no artifact who loses that device loses the identity permanently, and nobody —
not the user, not the co-signers, not their operators — can bring it back.

This does not contradict NKM §4.1, whose backup offer stays skippable, or NKM §7.5 step 1,
which records a decline: those govern the nsec. This section governs whether a group may
activate. A user who declines every artifact keeps the nsec in base mode. An NKM §4.2
blob of the nsec, where one exists, also recovers the identity but does not satisfy this
section: it holds the whole key outside every rule here (§8.3), and a client MUST NOT
steer a user toward it as the way to meet this requirement.

The two artifacts recover differently, and a client SHOULD say how. A §8.1 backup restores
one trusted device's weight with no vote and no delay, and is L1 authority once restored.
The recovery share restores nothing by itself; it carries L2 authority over the trusted
set, after the delay and with every co-signer, and outranks every device (§7.4).

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
| Malicious web app | Holds the key permanently; there is nothing to revoke and no way to learn it happened. | Cannot take the key, but signs whatever the signer's policy permits, for as long as the session stands. | By default holds no share: a session (§5.0) signs only what the trusted device approves, through co-signers, and ends the moment the user ends it. Where given a grant instead, holds one weight-1 grant that reaches `k` only with a trusted device and a co-signer (§4.5 sets 8–13) or with every co-signer (set 14), signs no destructive kind (§6.1(b)), expires, and is dropped at the next rotation (§3.3). |
| Compromised trusted device | Is the key, totally and permanently. | Is the key if that device runs the signer; otherwise one revocable session. | Holds `T`, short of `k` by §4.3, so it needs co-signers it does not control (§4.5 sets 2–13); by (6) no grant it issues itself replaces them; delayed and vetoable on trusted-only kinds where a co-signer is in the set (§6.1(e)), cut off immediately by §7.1. It changes the trusted set only at L1 (§7.4): delayed, vetoable by any other trusted device, and cancelled outright by the recovery share at L2. Where it and another trusted device disagree, co-signing freezes and the recovery phrase decides. |
| Compromised co-signer(s) | No such party exists. | The signer is the only party, so compromising it is compromising the key. | One index each and `n_s < k`, so they neither sign nor rotate alone — but all of them with the live grant reach `k` (§4.5 set 14), which §7.3 states as accepted. |
| Malicious grant holder | No analogue; the application was given the key. | Its session signs whatever the signer allows, for as long as the user leaves it connected. | Weight 1, allowlisted kinds only, needs a trusted device and a co-signer, or every co-signer (§4.5 sets 8–14), and ends at its expiry or the next rotation, whichever comes first (§5.2). |
| Grant holder colluding with co-signers | No analogue. | No analogue: one party holds everything, so there is nobody to collude with. | With every co-signer, reaches `k` and is therefore the key (§4.5 set 14); the grant cap of constraints (2) and (6) is the only bound, and §7.3 refuses to hide it. |
| Malicious signer app | Has the key the moment it is pasted in. | Holds the whole key by design; its scoping is its own code and it may ignore it. | Holds at most a grant, or `T` if the user made it a trusted device; the policy that binds it runs on parties it does not control (§6). |
| Phishing of a consent screen | Yields the key; the screen is the only control and the attacker wrote it. | Yields a connection the user believes is scoped, where the scope is asserted by the page requesting it. | Yields at most a session or one grant at its allowlist — except a fake backup-factor screen, which yields a trusted device's weight (§8.3) and is the residual. |
| Device loss | Is the key to whoever gets past the device's storage, and nothing can revoke it; recovery exists only if the user made a copy. | Is one revocable session, or the key if the lost device ran the signer; recovery is that signer's own backup, if it has one. | Weight `T` at NKM §2.1 level 3, `k − T` short of `k`, so a finder who unlocks it still needs co-signers applying §6 (§4.3); another trusted device refuses it immediately (§7.1). Recovery always exists, because §8.5 requires an artifact at setup: restore the device from §8.1 and rotate it out at L1, or with the recovery phrase and every co-signer at L2, which a finder holding the device cannot veto (§7.4). |

**The two rows that are not improvements.** "Grant holder colluding with co-signers"
has no analogue in the other two columns because they have no such parties, so the
comparison flatters nothing: this document introduces the collusion set along with the
tiers, and §4.5 and §7.3 are where it is priced. "Phishing of a consent screen" is
better here only for grants; the backup factor of §8 is a phishable secret worth a
trusted device, and NKM §7.13's argument for why a generated phrase resists phishing
is the whole of the answer.

---

## 11. Mass deletion

This section exists because mass deletion is the attack this document is shaped
around, and because the arrangement it replaces cannot stop it.

### 11.1 The attack

An application with signing access publishes kind-5 deletion requests naming every
event the identity has ever published — by `e` tag for regular events, by `a`
coordinate for addressable ones — and replaces the identity's kind-0, kind-3 and
kind-10002 events with empty ones. The signatures are valid, so no relay and no
reader can distinguish any of it from the user acting. Relays that honour deletions
drop the events, and there is no undo: a deletion is a request relays act on, not a
transaction to roll back.

Three properties make it worse than it first reads. It is **cheap** — one signing
session carries many sighashes, so thousands of deletions are a handful of rounds,
not thousands. It is **fast**, and finishes well inside the time a person takes to
notice anything. And it is **quiet**: the user's own clients render the result as the
user having deleted their history.

### 11.2 Why per-app signer policy alone cannot stop it

- **The policy and the key are held by the same party.** A remote signer's per-app
  scoping is local configuration in the process that holds the whole nsec. Compromise
  that process and the scoping goes with it. A control administered by the party it
  constrains is a preference.
- **Allowing kind 5 at all allows all of it.** "Delete my own last post" and "delete
  my entire history" are the same kind with different tags. A per-kind allowlist
  cannot separate them, and a per-event confirmation means approving thousands of
  prompts — which is not a control either, because the way through it is volume.
- **Reputation is the wrong instrument.** An application can behave correctly for
  everyone who reviews it and act only against one chosen person, so no amount of
  scrutiny of the app population protects a particular user. OVERVIEW.md states this
  and it is the reason the answer has to be structural.
- **Prompt fatigue is an attack parameter, not a user failing.** An attacker chooses
  when to issue the burst, and a dialog that appears a thousand times is approved.
- **The scope is asserted by the party being scoped.** In a remote-signer connection
  the app tells the signer what it wants and the signer tells the user; nothing
  outside that pair checks either claim.

### 11.3 How §6 stops it

- **Kind 5 is on the trusted-only list unconditionally (§6.1(b)).** A grant index cannot
  obtain a partial signature for a deletion — not a thousand, not one — and this is a
  refusal rather than a limit. It is enforced by the co-signers, which the app does not
  control and cannot compromise by compromising itself, and by §4.3 a grant needs
  *every* one of them.
- **Kinds 0, 3 and 10002 are trusted-only unconditionally (§6.1(b))**, so the
  wipe-by-replacement variant — empty profile, empty follow list, relay list pointing
  nowhere — is closed on the same grounds.
- **Every replaceable and addressable kind not on the grant's allowlist is
  trusted-only (§6.1(b))**, so overwriting long-form posts and lists is closed too. This
  is the clause that covers the kinds nobody has thought of yet, which a per-kind
  denylist cannot.
- **A session gets no destructive kind without the user approving that request on the
  trusted device (§5.0)**, and an approved one is then held by §6.1(e) like any other
  trusted-only kind from a single trusted device.
- **The reference allowlist is append-only (§6.1(a)).** Kinds `1`, `6`, `7`, `13`, `16`
  add events; none destroys one. A grant at the reference policy has no destructive
  operation available to it at all.
- **Rate limits per index (§6.1(c))** bound whatever a widened allowlist lets through and
  raise an `ALERT` to every trusted device on the way.
- **The delay with veto (§6.1(e))** covers the case the allowlist cannot: a deletion
  requested from a *trusted* index with only one trusted device in the signing set is
  held, every other trusted device is notified, and any may veto. No partial signature
  exists during the window, so a veto means **no deletion happened**, not that one was
  reversed.
- **The freeze (§6.1(d))** lets any trusted device stop every co-signing round for the
  group in one act, once anything looks wrong.
- All of it rests on **§6.0**: a co-signer that is handed a bare sighash sees no kind
  and enforces nothing. The kind-5 tag check of NKM §7.6 applies at every index,
  trusted ones included.

A co-signer holding many delayed requests for one index SHOULD coalesce its notices,
and MUST NOT let their volume suppress the notice — a flood of ten thousand held
deletions must still reach the other trusted devices as something a person reads.

### 11.4 Residual

**A compromised trusted device inside the delay window.** This is the residual and it
is not small.

- An attacker holding one trusted device avoids the second device's approval by
  signing with co-signers instead (`D1` and `k − T` of them — `D1 + C1 + C2` at the
  reference configuration), which puts the request into
  §6.1(e)'s window rather than stopping it. **If no other trusted device reads the
  notice before the delay elapses, the deletion completes.** Where the user has no
  second trusted device, the window elapses on its own by construction, exactly as NKM
  §4.2 provides for a recovery with no registered device — the notice has nobody to
  reach, unless the user restores one inside the window (§7.6). **This bullet survives
  both profiles**; Profile B does not touch it, because a single trusted device plus
  co-signers is the working path under either.
- **Under Profile A**, an attacker holding **two** trusted devices is outside this
  section entirely. `2T ≥ k` by constraint (4), so it signs with no co-signer in the
  set, and no policy in §6 runs — the allowlist, the trusted-only list, the rate limits,
  the delay and the freeze are all enforced by co-signers that are not being asked. This
  is the price of (4), which is on by default so that two of the user's own devices can
  recover with nothing reachable. **Profile B (§4.6) removes this bullet**, at the cost
  of the offline path: where `D·T + W_g < k` holds, no signing set exists without a
  co-signer, so §6 runs on every signature a compromised pair of trusted devices could
  ever produce. Within Profile A the bullet cannot be removed, only narrowed — a user
  with a single trusted device has no two-device set for an attacker to take.
- A compromised trusted device can also **veto and freeze**, so the same compromise
  that cannot quietly delete can loudly deny service until it is revoked under §7.1.
- **Relay behaviour is not a control.** Some relays ignore kind 5, and copies on relays
  that never received the deletion survive, so a real mass deletion is usually partial.
  That is luck, not a property of this document, and MUST NOT be described to a user as
  protection.

What the residual reduces to: **the window, the number of trusted devices, and the
profile.** A user with two trusted devices, both read by a person, has a mass deletion
held for a day and cancellable in one tap. A user with one has a mass deletion delayed
by a day and then completed — unless they restore a second trusted device from the §8
backup inside the window, which §7.6 makes a full veto, and which works only where the
backup factor is reachable independently of the compromised device. Under Profile A a
user whose two trusted devices are both taken has no delay at all; under Profile B that
case does not exist. A client SHOULD say which of these the user is in, on the same
screen as the lock indicator of NKM §7.16.

## Appendix A — References

[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) — storage ladder (§2), the
`frost-share` profile (NKM §3.3), blob-store backup (NKM §4.2), threshold signing,
the delta-polynomial reshare (NKM §7.9) and the recovery delay (NKM §7.10).
[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) — payload requirements (§4), profiles
(§5), consent (§9), the `frost://` light flow (§12.3).
[SPEC_ISSUES.md](SPEC_ISSUES.md) — the interpretations and gaps this document relies
on.

RFC 9591 (FROST). BIP-340. NIP-01, NIP-09, NIP-17, NIP-40, NIP-44, NIP-46, NIP-49, NIP-59.
WebAuthn Level 3 (PRF extension). Apple App Attest. Google Play Integrity.

Thalia M. Laing and Douglas R. Stinson, *A Survey and Refinement of Repairable
Threshold Schemes*, IACR ePrint [2017/1155](https://eprint.iacr.org/2017/1155) — the
repairable threshold scheme of §5.1 step 4. The scheme is often named for Stinson and
Wei, whose *Combinatorial Repairability for Threshold Schemes* (ePrint 2016/855) gives
the family its name; the construction implemented here is the enrollment-protocol
variant that the survey above presents, and it is the paper the implementation cites.

[ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) 3.0.0 —
`frost-core/src/keys/refresh.rs` (the §5.1 step 2 delta) and
`frost-core/src/keys/repairable.rs` (the §5.1 step 4 repair), re-exported by
`frost-secp256k1-tr`, the ciphersuite crate NKM §7.4 names.

FROSTR: [bifrost](https://github.com/FROSTR-ORG/bifrost) — `docs/PROTOCOL.md`,
`docs/CRYPTOGRAPHY.md`, `docs/SECURITY.md`, `docs/GLOSSARY.md`;
[igloo-core](https://github.com/FROSTR-ORG/igloo-core);
[igloo-server](https://github.com/FROSTR-ORG/igloo-server) — `docs/PEER_POLICIES.md`,
`docs/AUTH_MATRIX.md`, `docs/SECURITY.md`;
[bifrost-rs](https://github.com/FROSTR-ORG/bifrost-rs).

## Appendix B — Delivering a repaired share under QRST (non-normative)

Nothing in this appendix is normative. §5.1 fixes what must be true; this records
how it is reconciled with QRST's one-Sender, one-payload session, and what that
reconciliation assumes.

**The problem.** §5.1 step 4 produces one masked sum `σ` per helper **party**. The
helper set must reach weight `k` and must include the initiating trusted device's `T`
indices, and `T < k`, so there are always at least two helper parties: one trusted
device and at least one co-signer. QRST runs one session with one Sender and one
PAYLOAD (QRST §4 P2, §11.4: "One session carries one PAYLOAD; there is no
side-channel for additional profile messages"). Two or more parties must get material
to the new device through a mechanism that carries one payload from one party.

The initiating trusted device MUST NOT be the party that assembles them. It holds
`T` indices and the helper set reaches `k`; a `σ` it can read, summed with the others,
is `f'(x_g)`, the new index's share, in the hands of a party that already holds `T`. Where
`T = k − 1`, as in Appendix C's configuration, `T` indices plus that share reconstruct,
and the initiator can also subtract its own contribution to recover the lone other
helper's share. Where `T` is smaller, as at §4.4's reference configuration, a grant's
share does not reconstruct — `T + 1 ≤ T + W_cap < k` by (6) — but a new trusted device's
`T` indices do under Profile A, by (4), and in every case the initiator would end holding
a copy of a share issued to someone else, which §5.1 step 4 forbids. Whatever the delivery does, the initiator
carries the other helpers' contributions without being able to open them.

### B.1 Out-of-band σ, the general form

1. The initiating trusted device is the **QRST Sender** and runs the session exactly
   as §5.1 step 6 describes: the QR or `frost://` token, the SAS of QRST §6 and §9.2
   (or the §12.3 light flow where its channel condition holds), the release consent of
   QRST §9.1, and one PAYLOAD carrying the `frost-share` fields and its own `σ`.
2. **The SAS ceremony authenticates the burner once.** What a person compares is that
   this Sender is talking to the device in front of them; the artefact it pins is the
   Receiver's burner public key.
3. Every other helper party gift-wraps its `σ` to **that same burner**, sealed and
   signed with its peer key as recorded in the current epoch record. These wraps are
   not QRST messages: they carry none of QRST §11.4's kinds, so a conforming QRST
   implementation does not read them and QRST §13 does not count their senders as
   responders.
4. The new device holds the `σ` wraps as unvalidated candidates until the PAYLOAD
   arrives with the member list, then discards every wrap whose seal signer is not a
   helper named there, sums what remains with the Sender's own `σ`, and runs the P4
   check. A missing or forged `σ` fails that check; the session is abandoned and
   everything held is discarded (QRST §4 P6). The check cannot say *which* `σ` was
   wrong, so the failure is reported as the session failing, not as a named party
   misbehaving.
5. A co-signer's release of its `σ` is authorised by the §7.2 rotation it already
   voted for, not by a QRST §9.1 consent prompt. A co-signer has no user to prompt,
   and the vote is the consent.

**Where this is stronger than the SAS, and where it is weaker.** The other helpers'
contributions are authenticated cryptographically, against peer keys in a signed epoch
record — a stronger check than a five-digit code. What the SAS does and this does not
is prove a *person* was present for those contributions; only the Sender's leg has a
human in it. Since the co-signers' legs are machine-to-machine by construction, that
is the right split, but it should not be described as "the SAS covers the transfer".

**What this assumes about QRST, and why it may need a change.** It reads QRST §11.4's
"there is no side-channel for additional profile messages (P2)" as governing QRST's
own message set — the seven kinds of §11.4 within one session — rather than everything
the Receiver's burner hears from anyone. Under the other reading, `σ` wraps addressed
to the burner and carrying profile material **are** the side-channel that sentence
forbids, and B.1 needs a normative QRST change. SPEC_ISSUES.md files this for the next
QRST version with the text it would need. B.2 needs no such reading.

### B.2 σ carried inside the single PAYLOAD, where it fits

A variant that stays inside one payload under either reading of P2, at the cost of a
size ceiling.

Each other helper party NIP-44-encrypts its `σ` to the burner public key, signs the
ciphertext with its epoch-record peer key, and hands both to the initiator. The
initiator includes them as opaque entries in the one QRST PAYLOAD. It is a courier of
blobs it cannot open: it never learns any other `σ`, so it never reaches `k`. QRST §4
P3 already requires the mechanism not to parse the payload, so a payload with several
sealed entries is one payload. The new device decrypts each entry, checks each
signature against the member list in the same payload, sums, and runs the P4 check.

It is bounded by QRST §4 P1's 2048-byte default, which NKM §3.3 adopts for
`frost-share`. Measured against this repository's `payload_ceiling.py` sizing, with a
`σ` entry of 358 bytes (signer pubkey, a NIP-44 v2 ciphertext of a 32-byte scalar,
and a signature) and `k − 1` commitments:

| Configuration | Helper parties | Payload | Against the 2048 B default |
|---|---|---|---|
| `k = 3`, `T = 2`, one co-signer helping | 2 | 834 B | Fits |
| `k = 4`, `T = 2`, two co-signers helping | 3 | 1262 B | Fits |
| `k = 5`, `T = 2`, three co-signers helping | 4 | 1690 B | Fits |
| `k = 7`, `T = 2`, five co-signers helping | 6 | 2546 B | **Over** |

The `k = 4` row is not separately measured: the other three grow by exactly 358 B per
helper party and 70 B per commitment, and it is that arithmetic. The `k = 3` row is
Appendix C's configuration and is kept for comparison. So B.2 is available to the
default configuration of §4.4 and to the `k = 5` profile of §4.6, and stops being available around six helper parties — where the profile would
have to declare a larger maximum under QRST §4 P1 and clients would then have to skip
relays that cannot carry it (QRST §11.6). B.1 has no such ceiling, because each `σ` is
its own wrap.

**Which to prefer.** B.2 where it fits, because it needs no reading of P2 to be
defended and no burner lifetime beyond the session's own. B.1 above that, accepting
the QRST question filed in SPEC_ISSUES.md.


## Appendix C — The `k = 3` configuration (counterexample to (6), non-normative)

This was the reference configuration of §4.4 before constraint (6). It satisfies (1),
(2), (3) and (4), and it is kept because it shows exactly what (6) forbids. **It MUST NOT
be used.**

```
k    = 3
T    = 2          two indices per trusted device
n_s  = 2          two co-signers, one index each
W_g  ≤ 2          at most two live grants, one index each
s    = 1          a trusted device survives one co-signer being down
```

Checks: `n_s = 2 < 3` ✓ — `W_g ≤ 2 < 3` ✓ — `T + n_s − s = 2 + 2 − 1 = 3 ≥ 3` ✓ —
`2T = 4 ≥ 3` ✓ — `T + W_cap = 2 + 2 = 4 < 3` ✗. With a budget of one grant it is still
`2 + 1 = 3 < 3` ✗; at `k = 3, T = 2`, (6) holds only with no grant at all.

With two trusted devices `D1`, `D2`, co-signers `C1`, `C2` and grants `G1`, `G2`, its
thirteen minimal signing sets, labelled as in §4.5:

| # | Set | Weight | Label |
|---|---|---|---|
| 1 | `D1 + D2` | 4 | no-co-signer |
| 2 | `D1 + C1` | 3 | trusted |
| 3 | `D1 + C2` | 3 | trusted |
| 4 | `D2 + C1` | 3 | trusted |
| 5 | `D2 + C2` | 3 | trusted |
| 6 | `D1 + G1` | 3 | no-co-signer |
| 7 | `D1 + G2` | 3 | no-co-signer |
| 8 | `D2 + G1` | 3 | no-co-signer |
| 9 | `D2 + G2` | 3 | no-co-signer |
| 10 | `C1 + C2 + G1` | 3 | collusion |
| 11 | `C1 + C2 + G2` | 3 | collusion |
| 12 | `C1 + G1 + G2` | 3 | collusion |
| 13 | `C2 + G1 + G2` | 3 | collusion |

**Sets 6 to 9 are the failure.** Each is one trusted device and one grant, with no
co-signer. Written as "a grant finishing against a trusted device", they look like
availability. Read from the other side they are the §4.2 attack at its cheapest: a
compromised `D1` issues one grant to an application it controls, which §5.1 authorises
because `D1` is a trusted device, and `D1 + G_self` is then weight `k` with no co-signer —
signing anything, past every rule of §6, and reconstructing the nsec. No second grant
and no collusion are needed. Constraint (2) did not catch it, because it bounds grants
against the threshold and not against the device that issues them.

Sets 12 and 13 are a second, smaller cost of the same budget: one co-signer and two
grants reach `k`, so an intercepted grant needed only the other grant and one server.
§4.4's replacement removes both at once: `W_cap = 1` leaves no two-grant set, and `k = 4`
puts every trusted-device-and-grant set one co-signer short.

`vectors/tiers-rejected.json` carries this configuration as the case for (6).

## Status

Version 1.0-draft. Normative. It adds to
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) and
[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) and changes neither; where it
disagrees with either on a matter those documents decide, they win. Implementation
guidance belongs in [IMPLEMENTATION.md](IMPLEMENTATION.md) and is deliberately absent
here.

Three things this document needs are not available at the FROSTR layer today. **Two of
the three already exist in the ciphersuite NKM §7.4 names** — `frost-core` ships both,
and `bifrost-rs` already depends on the crate that carries them — so what is missing is
a peer operation that exposes them, not a primitive. Each is stated below as a proposal
ready to paste upstream, with the paragraph in normative language and a verdict on
whether it is additive to bifrost's envelope. All three are filed in
[SPEC_ISSUES.md](SPEC_ISSUES.md).

**What "additive to bifrost's envelope" means here.** A bifrost message is
`{tag, data, env}`, encrypted and wrapped in a Nostr event (`docs/PROTOCOL.md`). The
handler dispatches on `msg.method` through a `switch` with **no `default` arm**
(`src/class/client.ts:174`–`205`), so an unrecognised tag is ignored rather than
erroring, and the requester sees the timeout bifrost already uses for every rejection.
A proposal is additive if it introduces tags and changes no existing schema and no
envelope field, and therefore degrades on an un-upgraded peer to "does not answer".

### Proposal 1 — expose the delta-polynomial reshare

> Bifrost SHOULD expose share refreshing as a peer operation. A refresh moves a group
> to a new polynomial without reconstructing the group secret:
> `frost_core::keys::refresh::compute_refreshing_shares` builds a Shamir sharing of
> **zero** with `threshold − 1` fresh coefficients, and `refresh_share` adds each
> member's evaluation of it to that member's existing share. Two tags carry it:
> `/refresh/req`, from the initiating peer to each member, carrying that member's
> refreshing share and the refreshed group package; and `/refresh/res`, the member's
> acknowledgement, sent only after it has verified its refreshed share against the
> refreshed verifying shares. A member MUST retain its previous-epoch share until it has
> verified the new one. Passing a subset of the current identifiers removes the omitted
> members, which is how a peer is revoked without re-dealing. The threshold MUST NOT
> change and a member MUST NOT be added by a refresh — those are Proposal 2 and a
> re-deal respectively. `rotate_keyset_dealer` MUST NOT be used for this: it calls
> `recover_key` and re-splits, assembling the group secret on one machine.
>
> **Three consequences follow from bifrost's own key schedule and SHOULD be handled by
> the same operation.** A member's transport identity is the public key of its share
> secret (`src/class/signer.ts:79`), so a refresh **changes every peer's pubkey**;
> relay subscriptions and peer lists MUST be rebuilt from the refreshed group package.
> The group id is `SHA256(group_pk || threshold || sorted member pubkeys)`
> (`src/lib/group.ts`), so the `gid` changes with it and in-flight sessions MUST be
> abandoned rather than carried across. And secret nonces are derived as
> `HMAC-SHA256(share_secret, code || domain)` (`docs/PROTOCOL.md`), so **every
> outstanding nonce in every pool, incoming and outgoing, is invalidated**; pools MUST
> be cleared on both sides and replenished by the ordinary ping path before signing
> resumes.

**Additive?** Yes. Two new tags, no change to any existing schema or to the envelope.
The group package's contents are replaced rather than extended. An un-upgraded peer
ignores `/refresh/req` and does not acknowledge, which the initiator reads as a member
that cannot be refreshed — the correct outcome, since that member would otherwise be
left on a dead polynomial.

### Proposal 2 — expose the repairable threshold scheme

> Bifrost SHOULD expose the repairable threshold scheme of
> `frost_core::keys::repairable` as a peer operation, for both of its uses: restoring a
> member's lost share, and **issuing a share at an identifier the group does not yet
> hold**, which is the same computation at a different evaluation point. Three tags
> carry it: `/repair/req`, from the initiator to each helper, naming the target
> identifier and the helper set; `/repair/delta`, helper to helper, carrying the `Delta`
> values of part 1; and `/repair/sigma`, helper to target, carrying the `Sigma` of part
> 2. The helper set MUST contain at least `threshold` identifiers and **MUST NOT contain
> the target identifier** — the Lagrange coefficients are taken over the helper set
> evaluated at the target, and a target inside the set drives one of them to zero. The
> API does not check this. No helper learns another helper's share, because each helper
> retains one additive part of its own contribution; the target learns only its own
> share. **Implementations MUST NOT sum the contributions on a helper**:
> `repair_share_part3` runs on the target, and a helper that receives the other `Sigma`
> values holds `threshold` shares' worth of material and is the group secret.
>
> One structural note. When the target is an existing member repairing a lost share,
> `/repair/sigma` routes natively. When the target is **new**, it is not yet in the
> group package, so it is not in any helper's peer list (`init_peer_data`,
> `src/class/client.ts:467`) and cannot send or receive under the authorisation filter
> (`_filter`, `:213`). Either the peer model needs a provisional-peer state for a target
> mid-repair, or `/repair/sigma` needs an out-of-band carrier for that case. This
> document uses the second: the `Sigma` values reach a new index over QRST and gift
> wraps (TIERS.md Appendix B).

**Additive?** Yes for the envelope — three new tags, no existing schema changed. Not
additive for the peer model in the new-target case, which is the note above and the
reason the out-of-band carrier exists.

### Proposal 3 — an event-carrying sign request

> Bifrost SHOULD define an `/event` tag carrying the full unsigned Nostr event that a
> subsequent `/sign/req` will reference. `/event/req` carries one or more unsigned
> events `{pubkey, kind, created_at, tags, content}`. The receiving peer **computes each
> event id itself** by NIP-01 serialisation and MUST NOT accept a requester-supplied id;
> it applies whatever policy it is configured with and answers `/event/res` with a
> per-event verdict and, on refusal, a reason. A peer that accepts an event caches it
> keyed by **(event id, requesting member index)** for a short, bounded, evictable TTL;
> keyed by id alone, one member rides another member's accepted event. A peer
> configured to require events MUST refuse a `/sign/req` any of whose sighashes does not
> match a live accepted entry **for the index that sent that request**, and MUST refuse
> any sighash vector carrying tweaks, since a tweak alters what is signed and was not
> what the policy inspected.
>
> The reason this is needed rather than convenient: `/sign/req` carries `hashes` and
> `nonces` and no event (`docs/PROTOCOL.md`; `src/schema/sign.ts`), and the signing
> handler looks up its nonce, re-derives the secret and signs the hash it was given
> (`src/api/sign.ts:87`–`109`). A deployment that believes it filters by event kind is
> filtering nothing. The `content` field of a session is unvalidated free text folded
> into the session id (`src/lib/session.ts:131`–`135`) and MUST NOT be used to carry
> the event, because nothing checks it.

**Additive?** Yes, entirely. Two new tags; `/sign/req`'s schema is unchanged and the
requirement is a handler precondition on the peer that chooses to enforce it. The
existing peer policy type gains one optional field. An un-upgraded requester that never
sends `/event/req` simply cannot obtain a signature from a peer that requires it, which
is the intended failure.
