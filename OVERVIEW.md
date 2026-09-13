# Overview

The technical summary. [TIERS.md](TIERS.md),
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) (NKM) and
[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) (QRST) are the normative
documents and govern wherever this disagrees with them.
[README.md](README.md) explains the same design with no background assumed.

This document names the reference configuration and the policy rules, because
they are the design. It does not copy anything else: code lengths, rate limits,
cache lifetimes, sizes and event kinds other than the ones the rules are about
live in the specs, and an overview that copies them goes stale the first time
one changes.

---

## The one idea

Your key lives on your devices. To put it, or a share of it, on another one, you
show a code on the first, read it with the second, and type a short number back.
Everything else stacks on top of that and can never take it away. If a device
can't do one of those things, it falls back to the layer below. Nothing stops you
logging in.

On top of that base, TIERS.md splits one Nostr key into a single FROSTR group in
which parties carry different weights. Its design principle is one sentence:
**nothing that is not the user's own hardware ever holds enough weight to sign.**

## The access structure

One flat `k`-of-`N` FROST group (TIERS §2). A party that holds several indices
has that many votes; the count is its **weight**. A signing set is authorised if
and only if its indices total at least `k`. There is no nested sharing and no
second threshold, because FROSTR's group package has nowhere to put one.

Weight is peer multiplicity. In both `bifrost` and `bifrost-rs` one peer holds
exactly one index and its network identity is derived from that share, so a
weight-`T` party runs `T` ordinary FROSTR peers. No wire format changes. What
FROSTR cannot say is that two pubkeys are one party, so party and tier are recorded
per index in the epoch record, and every quorum rule counts parties from that
record, never peers from the raw member list.

Because the structure is flat, **weight is the only instrument**. "A trusted
device must be in the signing set" is not something `k` can express. Rules of that
shape are enforced by honest co-signers and bounded by the inequalities below.

Index hygiene: `k ≥ 3` (at `k = 2` no weighting is expressible), `N ≤ 255`
(FROSTR carries an index in one byte), one peer per index, and an index number is
never reused in a later epoch.

```
  one group, threshold k = 3

  D1: [1][2]   D2: [3][4]   C1: [5]  C2: [6]
  trusted      trusted      co-      co-
  device       device       signer   signer

  G1: [7]   G2: [8]
  grant     grant
  expires   expires
```

## The three tiers

| Tier | Weight | Held by | Issue/revoke grants | Initiate rotation | Expires | Dropped at rotation |
|---|---|---|---|---|---|---|
| Trusted device | `T` | A native app on the user's own hardware | Yes | Yes | No | No |
| Co-signer | 1 | A server running signer code and enforcing policy | No | No | No | No |
| Grant | 1 | An untrusted app or device, including any browser | No | No | Yes, set at issue | Yes, always |

**Trusted device** (TIERS §3.1). `T > 1`, the same for every trusted device. Its
indices are stored at NKM §2.1 level 3 where the platform offers it and never at
level 1. A browser origin never holds a trusted index at any level. Its `T` peers
are co-resident in one application instance; splitting them across machines makes
two lighter parties wearing one label.

**Co-signer** (TIERS §3.2). One index. A peer that returns partial signatures
without applying policy is not a co-signer under TIERS.md, whatever it is called.
Several processes run by one operator count as one party of their combined weight
unless independently administered. A co-signer refuses to hold weight for a user
who holds none: where a rotation would leave no trusted index, it destroys its own.

**Grant** (TIERS §3.3). One index, weight 1 regardless of `T`. Every grant carries
an expiry, and every grant is dropped at the next rotation whether or not it has
expired. Storage is best effort; the weight assumes it may fail. A grant cannot
issue or revoke grants, initiate or vote on a rotation, or act as a QRST Sender.

## Constraints

```
(1)  n_s < k         co-signers alone never sign
(2)  W_g < k         live grants alone never sign
(3)  T + n_s - s >= k
                     one trusted device signs,
                     losing up to s co-signers
(4)  2T >= k         two trusted devices sign with
                     no co-signer            [optional]
```

`n_s` is the number of co-signers, `W_g` the total weight of live grants, and `s`
the co-signer slack. `T < k` always holds: at `T ≥ k` a trusted device signs alone
and no policy is ever consulted. (1) is also what stops co-signers rotating among
themselves. (2) makes the grant budget a hard limit: a client refuses to issue a
grant that would bring `W_g` to `k`, and counts an expired grant as live until the
rotation that drops it.

**A lone weight-1 grant needs every co-signer** (TIERS §4.3). No choice of `k`,
`T` and `n_s` lets it lose one and still sign. A grant's availability is the
product of every co-signer's availability, and the screen that offers a grant says
so. Raising a grant's weight buys slack by buying authority, so clients default to
1 and never offer a weight at which one co-signer plus one grant reaches `k`.

## Reference configuration (Profile A)

```
k = 3    T = 2    n_s = 2    W_g <= 2    s = 1
```

With two trusted devices and two grants, `N = 8`, laid out as in the drawing
above. TIERS §4.5 lists the thirteen minimal signing sets:

| Sets | Members | Weight | What it is |
|---|---|---|---|
| 1 | `D1 + D2` | 4 | Two trusted devices, no server. The recovery path of (4). |
| 2–5 | a trusted device + a co-signer | 3 | Ordinary signing. |
| 6–9 | a trusted device + a grant | 3 | A grant finishing with a trusted device, no co-signer reachable. |
| 10–11 | `C1 + C2 +` a grant | 3 | **Collusion** if the co-signers abandon policy. With honest co-signers it is also how a single grant signs without a trusted device, and every request is checked. |
| 12–13 | a co-signer + `G1 + G2` | 3 | **Collusion.** The cheapest hostile set. |

Nothing of weight 2 signs: not one trusted device, not both co-signers, not both
grants, not a co-signer with a grant.

Sets 10 to 13 are real. They reach `k`, so they can sign anything and reconstruct.
Sets 10 and 11 need two independently administered co-signers both abandoning
policy, plus a live grant. Sets 12 and 13 need one co-signer and both live grants.
A one-grant budget removes 12 and 13. Running one co-signer with one grant removes
all four, at the cost of any slack for the trusted device; a client presents that
as a choice.

[`tiers_check.py`](tiers_check.py) enumerates minimal sets for any membership and
is tested against the hand-built vectors in [vectors/](vectors/).

## Profile B

Constraint (4) is a per-user option, on by default, chosen at activation and
presented as a trade rather than a security level (TIERS §3.5). Profile B declines
it:

```
k = 5    T = 2    n_s = 4    W_g <= 4    s = 1
2T = 4 < k
```

Its full benefit needs its own condition:

```
(5)  D*T + W_g < k   every signing set contains
                     a co-signer
```

where `D` is the number of trusted devices. Where (5) holds, every rule below
applies to every signature the identity ever makes. At `k = 5` it holds with one
trusted device and up to two grants, or two trusted devices and no grants. Two
trusted devices with two grants need `k = 7, T = 2, n_s = 6, W_g ≤ 2`. (5) is a
property of the current membership, so a client re-checks it at every rotation
that adds a trusted device or issues a grant, and refuses the operation that breaks
it.

The costs: the offline path is gone; two to three times the co-signers; worse
availability, since one trusted device still tolerates one co-signer outage but
now depends on more of them; collusion more expensive rather than removed; and no
switching in place. `k` cannot change by refresh (`frost-core` refuses it as a
security fix), so moving between profiles is NKM §7.5a's Re-split.

## Grants

**Issue** (TIERS §5.1) is a rotation and carries rotation's full authority,
including its delay (below). The epoch advances by a delta reshare with `k − 1`
fresh coefficients, which is `frost-core`'s `keys::refresh`. The new index is
issued by the repairable threshold scheme of Laing and Stinson, `frost-core`'s
`keys::repairable`: a helper set of weight `k` that includes the initiator's `T`
indices, and so at least one co-signer, sends blinded contributions that only the
new device can sum. No party reaches `k` while it runs, and the initiator ends
holding exactly `T`. Re-dealing from a reconstructed key is forbidden.

**Delivery** is one QRST session with the `frost-share` profile. The typed code is
required unless the pairing token reached the app over a channel the issuing device
controls, which is QRST §12.3's light-flow condition. TIERS Appendix B
(non-normative) reconciles several helpers' masked sums with QRST's one Sender and
one payload. The grant arrives unadmitted and cannot obtain a co-signature until a
trusted device admits it.

**Interception is not recoverable.** Neither expiry nor rotation undoes a
reconstruction: an intercepted grant, the other live grant and one co-signer total
`k`. The bound is the grant budget and the co-signers' honesty, and a client does
not present grant delivery as recoverable.

**Expiry** is enforced twice. Every co-signer refuses the index from the moment it
passes, and never extends it. The next rotation drops the index algebraically.
Extending a grant is issuing a new one.

**Records.** Every co-signer keeps, per grant index and per epoch, exactly
`index`, `issuer`, `expiry` and `policy_id`, accepts them only from a trusted
device under rotation authority, and discards them all on entering a new epoch. An
index with no record is refused.

## Co-signer policy

Policy is what a co-signer is for (TIERS §6). Its weight never completes a
signature; what it can do is refuse.

**Precondition: the co-signer sees what it signs.** Every sign request, from every
index including trusted ones, is preceded by the full unsigned event. The
co-signer computes the event id itself and signs only that. A bare hash is
refused. FROSTR's `/sign/req` carries hashes only, so TIERS §6.0 adds an `/event`
tag: accepted events are cached per `(id, requesting index)` for a short, bounded,
epoch-scoped window, and a `/sign/req` is refused whole unless every hash matches a
live entry for that index and carries no tweaks.

**The five rules** (TIERS §6.1):

- **(a) Kinds allowlist, per grant.** Enumerated and fixed at issue. Reference:
  `1`, `6`, `7`, `13`, `16` — note, repost, reaction, NIP-17 seal, generic repost.
  All append; none destroys. Widening is issuing a new grant.
- **(b) Trusted-only kinds.** Never co-signed for a grant. Unconditionally: `0`
  (profile; replacing it is impersonation with the user's own key), `3` (follow
  list; a silent, total edit), `5` (deletion; see mass deletion below) and `10002`
  (relay list; can make the user unreachable and route future events to relays an
  attacker reads). By default also every replaceable and addressable kind not on
  that grant's allowlist, because those overwrite rather than add. A deletion
  targeting a kind-30242 device list is refused from every index.
- **(c) Rate limits per index.** Never per party, IP or connection, since a
  party's indices are separate peers. Exceeding one alerts every trusted device;
  raising one needs a trusted device.
- **(d) Freeze.** Any trusted device can make every co-signer refuse all rounds,
  trusted indices included, until a trusted device lifts it. It never expires on
  its own. Under Profile A it does not stop two trusted devices, which sign with no
  co-signer, and the indicator says so. Under Profile B it stops everything, and
  the indicator says that instead.
- **(e) Delay with veto.** A trusted-only kind requested with exactly one trusted
  device in the signing set is held for NKM §7.10's recovery delay, and every other
  trusted device is notified. Any can approve early or veto. With no other trusted
  device the delay elapses on its own. Two trusted devices in the set are the
  approval, and nothing is held.

**Decryption carries no event,** so it is gated by tier (TIERS §6.0.4). A trusted
index is allowed. A grant is refused by default; its policy may list named peers,
which cannot cover gift wraps, or allow all, which is the user's whole DM history
and is presented in those terms.

**Against today's co-signer.** `igloo-server`'s peer policies express per-peer
allow and deny, and `bifrost-rs` adds per-method policy. Rules (a), (b), (c) and
(e) are new. (d) exists as an effect but not as an authority. The largest gap is
the principal: TIERS.md needs policy changed on a trusted device's signature, and
`igloo-server` treats policy as operator configuration (TIERS §6.2).

## Rotation and revocation

**Refusal** (TIERS §7.1). One trusted device instructs every co-signer to refuse a
named index, immediately and with no vote. It removes no share, and does not touch
a set that signs without a co-signer.

**Rotation** (TIERS §7.2), to revoke, add a trusted device, issue a grant or drop
expired ones, needs all three:

1. initiation by a trusted device;
2. votes totalling `k` on the new epoch record, `T` from the initiator and the
   rest from co-signers, so one trusted device never rotates alone;
3. NKM §7.10's delay, with notice to every trusted device and a veto for any of
   them. A second trusted device's approval completes it at once.

A rotation drops every grant, omits revoked indices, delivers `T` indices to a new
trusted device over `T` QRST sessions, and has every member verify its new share
before discarding its old one.

**What this means** (TIERS §7.3). Rule 1 is something co-signers follow, not
something the maths enforces. A weight-`k` set with no trusted device, such as
sets 10 to 13, can drive a rotation and reissue a trusted share once the delay
elapses. Only a veto stops it, and a veto needs a trusted device that is reachable
or restorable. This is accepted, and accepted against loss: a design where nothing
without a trusted device could ever rotate is one where losing every trusted
device loses the identity. The screen that enrols co-signers says so and never
describes them as unable to reach the key.

**A restored trusted device is that trusted device** (TIERS §7.5). It can veto,
approve, freeze and rotate, and co-signers accept it on its signature alone, with
no liveness or registration check. So a rotation's window is also a recovery
window: restore from backup inside it and veto. Until the next rotation, the
original and the restoration count as one party.

## Backup

**Share backup** (TIERS §8). One trusted device's `T` indices for one epoch,
encrypted under a passkey PRF or a generated paper secret of at least 96 bits,
never a chosen password. Each container is gift-wrapped to a burner key derived
from the factor, published to at least three relays, and verified from at least
two. It goes stale at every rotation, including every grant issue, and no rotation
finalises until the new backup is published and verified.

**A stored share is not a co-signer.** It is never counted in `N` or `n_s` and
never gets an index. A client refuses to store it on a relay run by a co-signer.
Whoever opens it holds a trusted device's weight and authority: at the reference
configuration, the factor plus one co-signer is the key.

**Whole-key backup** (NKM §4.2). A blob store holds the nsec, sealed. A passkey
factor releases it immediately. A passphrase factor waits a configurable delay,
default a day, while every registered device is told a recovery started and can
approve or cancel; with no device registered the delay elapses on its own. Where
this backup exists it holds the whole key and outranks every inequality above, so a
client lists it beside the share backup and never presents the two as equivalent.

## Attestation (optional)

A co-signer may require App Attest or Play Integrity evidence for a **grant**,
bound by the grant index's own signature over the same challenge (TIERS §9). It
evidences that unwrapping the share is gated by the platform. It does not show the
share is confined, never copied, or used with good intent. It does not exist for
browsers, it fails closed, and it hands the platform vendor a switch over the grant.
It is never required of a trusted device, and never replaces any part of policy.

## What's underneath

**Adding a device.** One device shows a QR. The other reads it, by camera or by
pasting the link. The device that *has* the secret asks you to type a short number
displayed on the device receiving it, and says plainly that you are handing over
your identity, or a share of it, not signing in. The receiving device shows you
whose account it is about to hold, and you confirm.

The number matters more than it looks. Comparing two screens is something people
skip; typing a number is something you cannot do without having read the other
screen.

**Transfer** (QRST). Both devices make throwaway keypairs used for one pairing and
then destroyed. The QR carries a public key and some relay addresses, never the
secret, so photographing it gets you nothing. The two devices exchange a commitment
and two random numbers, which stops an attacker in the middle from working out a
matching code. The secret then travels gift-wrapped, so relays see an anonymous
blob addressed to a throwaway key: not the contents, not who sent it, not that the
two parties are related. Any relay can be swapped for another mid-transfer. The one
exception is QRST §10's offline tier, where a profile that defines its own
passphrase encryption carries the payload in the QR itself; `frost-share` does,
`nostr-nsec` does not.

**Storage** (NKM §2). A ladder, probed silently, strongest rung that works:
platform keystore, then OS credential store or an encrypted browser key, then plain
app storage. It upgrades in place. Logging into the device is the unlock; rare,
consequential actions always ask, and that permission lasts for one transfer.

**Backup offer** (NKM §4.1). Offered once at the end of setup and again at
activation. Skippable, and if you skip it the app never nags.

**Other arrangements.** NKM §7 defines two threshold arrangements at `t = 2`: a
server co-signer (§7.1–§7.17) and a serverless device quorum (§7.18). A group uses
TIERS.md's weighted structure instead of either, never alongside them, because the
three assign indices by incompatible rules (TIERS §1).

## What this protects against, and what it doesn't

At the reference configuration (TIERS §10):

- **A malicious web app** holds one weight-1 grant. It signs no destructive kind,
  expires, and is dropped at the next rotation.
- **A compromised trusted device** holds `T < k`, so it needs a co-signer or a
  grant it does not control. It is delayed and vetoable on trusted-only kinds when
  a co-signer is in the set, refused immediately by another trusted device, and
  rotated out.
- **Compromised co-signers** neither sign nor rotate alone.
- **A lost device** is weight `T` behind level-3 storage, inert until a second
  party is taken.
- **A relay or anyone watching one,** and **a photographed or swapped QR,** learn
  nothing (QRST).

It does not protect against these, and the specs say so rather than implying
otherwise:

- **Co-signers colluding with grants.** Sets 10 to 13 reach `k` and are the key.
  The other arrangements have no such parties, so this is introduced by the tiers,
  and the grant budget is the only bound.
- **A compromised trusted device inside the delay window** (TIERS §11.4). If no
  other trusted device reads the notice in time, the held mass deletion completes.
  With one trusted device it completes by construction, unless one is restored
  from backup inside the window. This survives both profiles.
- **Two compromised trusted devices, under Profile A.** They sign with no
  co-signer, so no rule runs. Profile B removes this case.
- **A phished backup factor.** A fake backup screen yields a trusted device's
  weight and authority. A generated phrase that is never typed anywhere else is the
  whole defence.
- **A website you hand your whole key to.** The code comparison proves you're
  talking to the device you think you are; it cannot tell you that device is
  honest. A site can behave correctly for everyone who reviews it and act only
  against one chosen person, so reputation is the wrong instrument. The only
  structural answer is not giving a website a usable key, which is what a grant is.
- **A compromised device you're already using.** Same as any wallet.
- **Relay behaviour.** Some relays ignore deletions, so a real mass deletion is
  often partial. That is luck, not protection.
- **Being wrong about the mathematics.** Every other failure has a fallback. This
  one doesn't, and because a Nostr key *is* the identity, there's no rotation in
  protocol to recover with. There is a social one — announce a new key from the
  old one while you still control it — but you lose your followers, your history's
  attribution and everyone who misses the announcement. Expensive rather than
  impossible, and it is what people actually do.

**Ordering matters more than any of the above.** Splitting a key doesn't change
it. If something already got a whole copy of your key, splitting it afterwards
does nothing: they keep a working copy permanently. It reduces the attack surface
going forward; it repairs nothing backwards. Protection has to be in place before
the first time you hand anything over.

## Mass deletion

The attack TIERS.md is shaped around (TIERS §11). An app with signing access
publishes deletions for every event the identity ever made and empties its
profile, follow list and relay list. The signatures are valid, it takes a handful of
signing rounds, it finishes before anyone notices, and the user's own clients show
it as the user's doing.

Per-app scoping in a remote signer cannot stop it: the scope and the whole key sit
in one process, allowing kind 5 at all allows all of it, and a thousand prompts get
approved. Here, kinds `0`, `3`, `5` and `10002` are trusted-only unconditionally,
enforced by co-signers the app does not control, every one of which a lone grant
needs. A deletion requested from a trusted device, with only one trusted device in
the signing set, is held and vetoable. No partial signature exists during the
hold, so a veto means no deletion happened.

## FROSTR, and what it does not yet expose

Vocabulary is FROSTR's: group, share, index, peer, `bfgroup`, `bfshare`. TIERS.md
adds the party. Three things it needs are not available at the FROSTR layer today,
each written as an upstream proposal in TIERS.md's Status section and filed in
[SPEC_ISSUES.md](SPEC_ISSUES.md):

1. **Expose the delta-polynomial reshare** (`/refresh`). The primitive is in
   `frost-core`; the one FROSTR operation on offer, `rotate_keyset_dealer`,
   reconstructs the key and is forbidden here.
2. **Expose the repairable threshold scheme** (`/repair`). Also in `frost-core`.
   Additive to the envelope; not additive to the peer model when the target index
   is new.
3. **An event-carrying sign request** (`/event`). Entirely additive.

All three add tags without changing an existing schema, so an un-upgraded peer
simply does not answer.

## Implementation

[IMPLEMENTATION.md](IMPLEMENTATION.md) proposes how NKM and QRST become a library
and in what order. It is a proposal, not agreed, and it does not yet cover
TIERS.md.

## Where to read what

- [README.md](README.md) — the design, with no background assumed.
- [TIERS.md](TIERS.md) — who gets votes: trusted devices, co-signers and grants
  as one weighted FROSTR group, with the policy co-signers enforce.
- [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) — the transfer mechanism.
  Self-contained.
- [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) — storage, backup, the
  `nostr-nsec` and `frost-share` payload profiles, and NKM's own threshold modes.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — the library proposal.
- [SPEC_ISSUES.md](SPEC_ISSUES.md) — disagreements and suspected errors.
- [vectors/](vectors/) — known answers for all three specs.
