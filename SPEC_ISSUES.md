# Specification Issues

This file is the place to record disagreements with either
[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) or
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md). It exists because the
alternative is worse: an implementer who finds a passage ambiguous, or believes
a requirement is wrong, will otherwise resolve it privately and ship a client
that differs from every other client in a way nobody can see. A deviation
written down here is reviewable; a deviation made in silence is only
discoverable when two implementations fail to interoperate in the field.

Two kinds of entry belong here.

An **ambiguity** is a passage that admits more than one reading, where both
readings produce working code but the two do not interoperate, or where the
specification simply does not say what to do in a case that will occur. Say
which readings you found and which one you took.

A **suspected error** is a requirement you believe is wrong: a construction
that does not achieve what the surrounding text claims for it, a parameter that
does not match its stated cost, an invariant that some other section breaks, or
a flow that cannot be completed as written. Say what breaks and under what
conditions.

Design disagreements — cases where the specification is clear and internally
consistent and you would have chosen differently — are welcome too, but say so
explicitly, because several of the defaults that look weak were chosen
deliberately after review and are argued for in the document itself. An entry
that engages with the stated argument is useful; one that does not will
probably be answered by a pointer back to it.

## Format

Add each entry under its own heading, newest at the bottom, using this shape:

```
### <short title>

**Document:** QR_SECRET_TRANSFER.md | NOSTR_KEY_MANAGEMENT.md | TIERS.md
**Section:** §<number> (and any others it touches)
**Kind:** ambiguity | suspected error | design disagreement

<What the specification says, quoted or cited closely enough that a reader can
find it without searching.>

<What is wrong or unclear about it, and the concrete circumstances under which
it matters.>

**Proposed fix:** <the change you would make, in the specification's own
normative language where you can manage it. "This should be clarified" is not a
proposed fix; "§4 step 13 should say the Joiner discards wraps whose seal
signer is not among the burners it issued a nonce to" is.>
```

Every entry needs a section number and a proposed fix. Both are what make an
entry actionable rather than a note that something felt off.

Issues concerning the two gaps already named in [README.md](README.md) — the
placeholder event kinds and the incomplete test vectors — do not need to be
filed here. They are known and tracked.

---

## Open

### `t = 3` is offered by §7.18 and the epoch record cannot express it

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.18 (and §7.4, §7.9)
**Kind:** suspected error

§7.18 says "`t = 2` by default. A user with three or more independent trusted
devices MAY choose `t = 3`", and gives the share check as
"`share_i·G == group_pub + commitment·i` (§7.4's check generalised from the
co-signer's fixed `·2`)". The generalisation is over the *index* only. Everything
else in §7.4 is degree-1 and stays degree-1:

- The epoch record's content is `{epoch, t, group_pub, commitment: a_1·G, ...}` —
  one commitment. A `t = 3` polynomial is `f(x) = a_0 + a_1·x + a_2·x²` and its
  verifiable sharing needs `a_1·G` **and** `a_2·G`. There is no field for the
  second, so a `t = 3` member has nothing to verify its share against.
- The check itself is wrong at `t = 3`. It should be
  `share_i·G == group_pub + commitment_1·i + commitment_2·i²`. As written a member
  at `t = 3` either rejects a correct share or, if it skips the check, accepts a
  malformed one — and §7.5 makes that check the only thing standing between a
  mis-dealt share and a wiped nsec.
- §7.9's rotation delta is `δ(x) = r·x`, which re-randomises `a_1` and leaves
  `a_2` untouched for the lifetime of the key. At `t = 3` a rotation therefore
  rotates one of the two secret coefficients, and `commitment' = commitment + r·G`
  updates the one commitment the record has room for.
- §7.18's "Adding a device" has "two existing admitted devices each compute their
  Lagrange-weighted contribution to `f(k)`". At `t = 3` two contributions do not
  determine `f(k)`; three are needed.

The mode that `t = 3` exists for — "surviving any two devices being compromised" —
is the one where these matter most, and a client that implements §7.18 literally
ships a `t = 3` option that does not work.

Measured, against `@noble/curves` 2.3.0's `schnorr_FROST` and recorded in
`vectors/nkm-frost.json`: a `min: 3` trusted dealing emits **three** commitments,
and §7.18's share check is false at every index of that key set while the general
form holds and the library's own RFC 9591 `vss_verify` accepts. The library models
commitments as an array for exactly this reason, which is also the proposed fix
below.

**Proposed fix:** §7.4's epoch record should carry `commitments: [a_1·G, …,
a_{t−1}·G]` in place of the scalar `commitment`, and state the check as
`share_i·G == group_pub + Σ_{j=1}^{t−1} commitments[j]·i^j`, noting that at `t = 2`
this is the existing single-term form. §7.9 should give the delta as
`δ(x) = Σ_{j=1}^{t−1} r_j·x^j` with every `r_j` fresh and `δ(0) = 0`, and
`commitments'[j] = commitments[j] + r_j·G`. §7.18's "Adding a device" step 1 should
read "any `t` existing admitted devices". Alternatively, if `t = 3` is not intended
to be supported in this draft, §7.18 should say `t = 2` is fixed and give the
`t > 2` generalisation as future work.

### §5's "one lost device alone is inert" holds only after revocation

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §5 (device quorum), §7.18, §7.13
**Kind:** suspected error

§5 states for device quorum: "One lost device alone is inert — no honest device
will co-sign with a revoked `E` — until a second is taken." The clause after the
dash is the condition, and it is doing all the work: the device is inert once
**revoked**. Before revocation — which is to say for the whole period between a
compromise and the user noticing one — an unrevoked hostile device is the opposite
of inert. Every honest peer will complete a signing round for it, and §7.18 makes
ECDH "the same one round between two devices", so it will also complete decryption
rounds.

In co-signer mode this case is bounded, and §7.13 says exactly why the bounds are
real: the kind allowlist, the rate alerts, the 200-recurring-peer cap and the
500/hour ceiling "are enforceable rather than advisory because no device can answer
a round for another (§7.6)". §7.18 inverts that premise — every device answers
rounds for every other — and carries no replacement. It has no allowlist (there
are no `restricted` members, so the allowlist has no one to apply to), no rate
cap, no audit digest, and no requirement that the co-signing device show its user
anything or ask.

So the immediate exposure from one compromised device in a quorum is not the one
§5 and §7.18 name. Both name reconstruction ("a second compromised or colluding
device is the key"). The exposure that arrives first, needs no second device, and
is subject to no ceiling is posting as the user and reading every DM the user has
ever received — the same worst case §7.13 assigns to a hostile *restricted* origin
under a co-signer, minus every control that section relies on.

**Proposed fix:** §5's device-quorum list should replace the "inert" bullet with:
"**One compromised device signs and decrypts without limit until it is revoked.**
Honest peers answer its rounds; there is no server to refuse them, no allowlist, no
rate ceiling and no audit. A second compromised device additionally yields the key.
Revocation is the only control and it is forward-only, so the mode's safety depends
on the user noticing." §7.18's Signing paragraph should add: "A co-signing device
MUST apply §7.13's cumulative and hard ECDH ceilings to each peer `E.pub` it
answers for, MUST keep the same per-peer log, and MUST send the daily
`AUDIT_DIGEST` (kind 24317) to the other members. Because a device is not
continuously reachable these are per-peer-pair rather than global, and the section
should say so: they bound one hostile pairing, not the aggregate."

### §7.4's parity rule is redundant with its own ciphersuite, and its re-negation corrupts the exported nsec

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.4 (and §7.5, §7.15)
**Kind:** suspected error

§7.4 names the ciphersuite as "FROST per RFC 9591 with the secp256k1 Taproot
variant" and, in the same list item, specifies parity handling of its own: "If
`pubkey(nsec)` has odd y, the dealer uses `a_0 = n − nsec` so the group key is
even-y. On reconstruction the result is `n − nsec` for an odd-y key; the client
MUST re-negate before storing or exporting."

The taproot variant handles BIP-340 parity itself — that is what the variant is
for. Measured against `@noble/curves` 2.3.0's `schnorr_FROST` with an odd-y
fixture nsec (`vectors/nkm-frost.json`):

- Dealing from the **raw** nsec produces a group commitment whose x-only
  serialisation is the npub, and an aggregated signature that verifies under that
  npub as a plain BIP-340 signature. The dealer-side negation is not needed.
- Dealing from §7.4's **negated** `a_0` also works, and verifies under the same
  npub. The negation is redundant rather than harmful.
- `combineSecret` over the raw-dealt shares returns **the nsec itself**, not
  `n − nsec`.

So the first sentence is unnecessary and the second is wrong. A client that deals
per the ciphersuite — which is what an implementer reaching for the named crate
will do — and then obeys "the client MUST re-negate before storing or exporting"
stores `n − nsec` as the user's key.

Nothing in the specification detects this. `n − nsec` has the same x-only pubkey,
signs identically under BIP-340, and derives the same NIP-44 conversation keys
(§7.4 is right that ECDH is unaffected, because `(n − nsec)·P` is the negation of
`nsec·P` and shares its x-coordinate). §7.5's guard cannot see it either: it
verifies `group_pub` against "the user's known x-only pubkey", and **both parities
serialise to the same x-only value**, so the check passes whichever the dealer
chose. The share check beside it is internally consistent with whatever `a_0` was
dealt and passes too.

What breaks is the nsec as a **string**. §7.15 disable is the operation that
reconstructs and stores, so a user who turns threshold signing off gets a key that
works everywhere and matches nothing: a different `ncryptsec`, a different `nsec1…`
from the one they wrote down at §4 backup, and a different value from the one any
other client holding the same identity will show them. In a key-management
specification that is the wrong thing to be silently inconsistent about.

**Proposed fix:** §7.4's ciphersuite item should read: "Scheme: FROST per RFC 9591
with the secp256k1 Taproot variant as implemented by `frost-secp256k1-tr` or
`@noble/curves`' `schnorr_FROST`. The dealer sets `a_0 = nsec` unmodified. BIP-340
parity is the ciphersuite's responsibility — it negates the group element and
signers' contributions as required — and the group key is used **untweaked**: no
BIP-341 tweak is applied. Reconstruction (§7.15) therefore yields `nsec` directly
and the client MUST NOT re-negate it. Note that `nsec` and `n − nsec` serialise to
the same x-only pubkey, so neither §7.5's group-key check nor the share check can
detect a client that gets this wrong; `vectors/nkm-frost.json` is the test that
can." The existing sentence about ECDH being unaffected is correct and should stay,
with its reason given: the two candidate secrets produce shared points that differ
only in the sign of y, and NIP-04/44 use the x-coordinate.

*Not a defect, but worth a sentence in §7.4 so a reviewer does not have to
re-derive it:* the untweaked group key is documented as susceptible to a rogue-tweak
attack at DKG time. §7.5 is a trusted dealer holding the whole nsec and runs no DKG,
so the caveat does not apply, and the dealer model is what makes untweaked use safe
here.

### §7.9 step 4 is written for one server and the model has many

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.9 step 4 (and §7.4, §7.8, §7.2)
**Kind:** suspected error

§7.4 establishes that "every enrolled server holds a replica of share 1" and that
any number of servers is one share. §7.9 step 4 then says "**The server MUST
destroy the old-epoch share 1** — overwrite and verify, with no retained version
history, snapshot, backup or log line", and gives the reason: "A revoked device's
retained share 2 plus a surviving old share 1 is the key."

Singular. With `k` enrolled servers there are `k` copies of the old share 1, and
the property rotation exists to provide holds only if **every one** of them is
destroyed. The section provides no mechanism for that:

- Rotation's acknowledgement is `SHARE_ACK` (kind 24306) from *devices* applying
  their delta (step 3). No server acknowledges anything, so nothing distinguishes
  a rotation where every replica destroyed its old share from one where a replica
  was unreachable.
- Nothing says what an unreachable replica does when it returns. It holds a share 1
  on a dead polynomial and has missed `r`. If it later receives `r` and applies it
  it will be correct — and will have held the old share throughout the window that
  matters. If it is instead re-issued the current share 1 under §7.8, the section
  does not say the old one must be destroyed first.
- Nothing bounds `k`, and §7.2's advice against a second server from one operator
  is about *independence*, not about copies.

The compounding case is the ordinary one rather than an exotic one: a user revokes
a device *because* something went wrong, rotation reports success, and one replica
that happened to be down retains a share 1 that pairs with the retained share 2 for
as long as it stays down.

**Proposed fix:** §7.9 should add a server-side acknowledgement and gate completion
on it: "Every enrolled server MUST reply `SHARE_ACK {epoch}` after applying the
delta and destroying and verifying the overwrite of its old-epoch share 1. **A
rotation MUST NOT be reported complete until every enrolled server has acked.** A
server that has not acked within 24 hours is marked `stale` in the epoch record, is
refused as a co-signer by clients from that moment, and the lock (§7.16) shows
amber naming it. Re-admitting a stale replica is §7.8 issuance of the *current*
share 1 conditioned on the replica destroying and verifying the overwrite of every
prior share it holds — never a delta, which would leave the old share in place."
§7.2 should add that each additional server is an additional copy of share 1 and
therefore an additional place it can be stolen from, at an unchanged `t`.

### §7.8 releases share 1 on one device's authority; §7.14 releases the same share on two

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.8 (and §7.14, §7.1, §7.13)
**Kind:** suspected error

§7.14 Offline mode issues a device "a replica of **share 1**", and gates it
carefully: an `OFFLINE_REQUEST` to every other trusted device, an explicit tap on
one of them, a named prompt ("*Laptop* wants to hold your full key offline"), an
entry in the epoch record, and — where two-device approval is on — an `APPROVAL`.
The care is warranted: a holder of share 1 and share 2 is the key.

§7.8 issues the identical payload to a new *server*: "An existing server, on a
gift-wrapped instruction from a trusted device, wraps share 1 directly to the new
server's `S.pub`." One instruction, one device, no second approval, no prior epoch
record entry, no `APPROVAL` even where two-device approval is on, and no ceiling
on how many times it may happen.

The issuing server cannot supply the missing check itself, because `S.pub` and
`E.pub` are both secp256k1 public keys and the instruction is what asserts which
one this is. A hostile trusted device generates a fresh keypair, calls it a server,
and receives share 1 — at which point it holds both indices and is the key. §7.11
treats a lost trusted device as a Re-split case, which is right, but Re-split is
what the user does *after* noticing, and this path leaves nothing to notice with:
§7.13's audit log is a record of "signing and ECDH rounds", so an issuance appears
in it not at all.

The asymmetry is the finding. The same act — putting a replica of share 1 into a
new pair of hands — is two-device-gated and logged when the recipient is called a
device, and ungated and unlogged when the recipient is called a server.

**Proposed fix:** §7.8 should read: "Replica issuance requires an `APPROVAL` (kind
24311) from a second trusted device naming the target `S.pub`, on the same terms as
§7.14, and is available only where two or more trusted devices exist. The new
`S.pub` MUST appear in the current epoch's member list before any share is wrapped
to it, so the issuance is visible to every member and to the user's devices screen.
A co-signer MUST record every replica issuance in its §7.13 log and MUST include
issuances in the daily `AUDIT_DIGEST`. Clients SHOULD cap enrolled servers and MUST
show the count on the devices screen." §7.13's list of what a hostile *restricted*
device cannot do already excludes issuance; the section should add that a hostile
*trusted* device can, and that this is what the second approval is for.

### §7.15 disable and §7.14 Offline mode have no device-quorum meaning

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.18 (and §7.15, §7.14, §7.16, §7.5a)
**Kind:** suspected error

§7.18 says the device-quorum mode "shares §7.1 enrollment, §7.4's ciphersuite and
epoch records, and §4 backup, and differs as below", and the differences it lists
are parameters, activation, signing, adding a device, revocation, recovery and
security. §7.15 is not among them, so it applies as written — and as written it
cannot be performed:

> the device collects share 1 from a server (with an `APPROVAL` where two-device
> approval is on)

There is no server; §7.18 says so ("No index is reserved for a server; there is
none"). Step 1 has the same problem: "**Servers MUST delete share 1** and every
device MUST delete its share". A client implementing §7.18 has no defined way to
turn threshold signing off, which is the operation a user reaches for when the mode
is not working out — and §7.11 Re-split is defined as "§7.15 disable plus §7.5
re-activation", so device removal in the lost case inherits the gap.

§7.14 Offline mode has the mirror problem. Its mechanism is issuing the requester a
replica of share 1. In a quorum every index is unique, so the equivalent — handing
a second device's share to the requester — breaks the uniqueness invariant §7.18
states, and would leave two devices holding one index with no record of it. §7.16
accordingly lists an "Offline mode" lock state that is unreachable in this mode,
and §7.5a's keep-key option has the same difficulty.

**Proposed fix:** §7.18 should add to its list of differences: "**Disabling
(§7.15).** A trusted device collects `t − 1` other members' shares, reconstructs,
and stores the nsec per §2.1 before anything else; step 0's pre-rotation runs
jointly among the members that will remain. `DISABLE` (kind 24314) goes to every
member and every member deletes its share, `CK` and the group secret; no server
step applies. **Offline mode (§7.14) and keep-key (§7.5a) do not apply.** A device
that must sign with nothing else reachable cannot be served by this mode; that is
what §7.3 option B is for, and the §7.16 lock never shows the Offline state here."

### Rotation is automatic after revocation but not after enrollment, where the exposure is larger

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.9 (and §7.7, §7.18 "Adding a device")
**Kind:** design disagreement

§7.7 is candid that admission does not close the enrollment channel: "That
admission gates *signing*, not *reconstruction*: an intercepted share plus one
other share (share 1, §7.12) is the key, and revocation does not undo a
reconstruction. So the enrollment channel is load-bearing." §7.18 inherits this and
makes it worse — an intercepted unique share needs one more share of any index, and
the mode's own security note says a second device is the key.

§7.9 then lists when rotation happens by itself: "Automatic rotation runs on device
revocation, Offline-mode exit and after §7.10 recovery." Enrollment is not on the
list, although it is the moment at which a share crosses a channel the relay,
the server and the specification all agree is the weakest link in the design.

A rotation immediately after enrollment closes it almost entirely. The share is
issued on the current polynomial, the transfer completes, and the members —
including the new one, which is now an enrolled member reachable over an
authenticated `E.pub` — apply a delta. An intercepted copy of the transferred share
is dead from that point, so the enrollment channel is load-bearing for the duration
of one rotation rather than for the life of the key. The cost is one rotation per
device added, which is the same operation the same list already performs on every
device *removed*, and the surviving members are online in the enrollment case by
construction.

This is a design disagreement rather than an error: §7.7's statement is accurate
and the residual is disclosed. But the fix is one line in a list that already
exists, and it converts a permanent exposure into a bounded one.

**Proposed fix:** §7.9's last line should read "Automatic rotation runs on device
revocation, **device addition (§7.7, §7.18)**, Offline-mode exit and after §7.10
recovery." §7.7's paragraph should then end: "The enrollment channel is
load-bearing until the follow-on rotation completes, after which an intercepted
copy of the transferred share is on a dead polynomial. A client MUST NOT report
enrollment complete, and the lock (§7.16) MUST remain amber, until it has." §7.18's
"Adding a device" step 2 should carry the same sentence.

### The signing round structure is unspecified in §7.6 and two rounds in §7.18

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.6 (and §7.6a, §7.18 Signing)
**Kind:** ambiguity

§7.6 says the requester "sends the **full unsigned event**, not a digest; the
co-signer serialises and hashes it itself", that "requests carry the requester's
`E.pub` signature", and that they travel "gift-wrapped between `E.pub` and `S.pub`
over relays or `<url>/v1/sign` over HTTPS". It does not say how many messages a
signature takes. §7.18 does, and says the other thing: "Any two admitted,
unrevoked devices run **the two-round FROST signing of RFC 9591** with each other
directly."

FROST per RFC 9591 is a two-round protocol, and §7.6 admits two readings that do
not interoperate. In the first the device is the Coordinator: it asks the
co-signer for a round-one commitment, computes the binding factor, the group
commitment and the challenge, and asks again for the co-signer's signature share —
two round trips, and the co-signer must persist a nonce between them. In the
second the co-signer is the Coordinator: the device sends its own commitment with
the event and the co-signer returns its commitment and its share together — one
round trip, and no server-side nonce state.

The choice is not cosmetic. The two-round form requires the co-signer to store a
signing nonce and to guarantee it is used at most once, because a FROST nonce
reused across two distinct messages discloses the signer's share; the one-round
form has no such state and no such hazard. A specification that leaves the round
structure to the implementer has left that hazard to the implementer too, without
naming it.

§7.18 resolves it in the direction that carries the hazard, and in the mode where
the hazard is worse. The retained nonce sits on a phone rather than on a server —
likelier to be restored from a backup, which is precisely how a nonce gets used
twice — and the share it would disclose is a unique point rather than a replica
every other device already holds. The one-round form is available between two
devices for the same reason it is available against a server: the initiator knows
the message, so it can send `(event, D_i, E_i)` and the responder can compute the
binding factors, the group commitment and the challenge and return
`(D_j, E_j, z_j)` in one reply.

**Proposed fix:** §7.6 should specify the one-round form as normative — "A signing
request carries the full unsigned event and the requester's round-one commitment
pair `(D_2, E_2)`. The co-signer generates its own nonces, computes the binding
factors, the group commitment and the challenge per RFC 9591, and responds with
its commitment pair `(D_1, E_1)` and its signature share `z_1`. The requester
computes its own share and aggregates. A co-signer MUST NOT retain a signing nonce
between requests, and MUST generate fresh nonces for every request." §7.18's
Signing paragraph should read "run the one-round exchange of §7.6 with each other
directly, the initiator as Coordinator, combining with Lagrange coefficients over
their two indices," and inherit that nonce rule verbatim. §7.6a should state the
same for `/v1/ecdh`, which is already one round. Where a two-round form is retained
for either mode, that section MUST add: "A co-signer that implements a two-round
form MUST persist each issued nonce, MUST refuse a second use of one, and MUST
discard it after a bounded lifetime; nonce reuse across two distinct messages
discloses the signer's share."

### §7.18 does not forbid reusing a removed device's index

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.18 (Parameters, Adding a device)
**Kind:** ambiguity

"Each device holds a **unique** index `i ≥ 1`, never a replica … Indices are
assigned by the activating device and recorded per member in the epoch record."
Nothing says an index retired by a removal may not be assigned again, and the
obvious implementation — smallest free index — reuses it immediately.

Uniqueness is stated as a property of the current member set, and that is the
property signing needs. But a share is a `(index, scalar)` pair that outlives the
membership, and a removed device keeps its copy. Reuse means two holders of one
index across two polynomials, which is not directly exploitable while §7.18's rule
that revocation is always rotation is honoured, but which makes every reasoning
step about "the device at index 3" ambiguous — including the epoch record's own
history, an audit digest naming an index, and any recovery or forensic question
asked after the fact.

**Proposed fix:** §7.18's Parameters should add: "Indices are assigned
monotonically and are never reused. An index retired by a removal is retired
permanently; the epoch record retains retired indices so that a share presented at
one can be recognised as stale rather than as a member's."

### The replica scheme is the only flat-FROST way to say "a server and a device", and that is not stated

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.4 (and §7.2, §7.12)
**Kind:** design disagreement

§7.4 asserts the replica architecture — server at index 1, every device at index 2,
"replicas share an index and never combine", "the only valid signing pair is server
+ device" — and §7.2 argues its consequence socially: "Two servers from one
operator are one server … a second Cloudflare deployment adds availability and no
independence." Both are correct. Neither says *why* the scheme has to look like
this, and the reason is worth a paragraph because it also bounds what a reader may
reasonably ask for next.

FROST's access structure is a flat threshold: any `t` of `n` shares reconstruct,
and the scheme cannot express "at least one from set A **and** at least one from
set B", which is what "a server and a device" is. Replication is the encoding that
makes a flat threshold behave like that conjunction — collapse each class to one
share and set `t = 2` — and with the named ciphersuite it is the only one. The
alternative that would give genuine multi-server independence is a nested sharing:
split `nsec = s_A + s_B` additively, Shamir `s_A` among servers at `t_A` and `s_B`
among devices at `t_B`, so that `t_A` servers and `t_B` devices are jointly
required. That is not RFC 9591, is not in `frost-secp256k1-tr`, and would be a
construction this project would own rather than cite.

Two things follow that the document currently leaves the reader to work out. Adding
servers cannot raise the threshold — `t` is fixed at 2 by the conjunction — so each
additional server is an additional copy of share 1 at unchanged difficulty, which
means the probability that share 1 is stolen grows with the number of servers while
the protection it buys does not. And a user asking the natural question — "can I
require two of my three servers?" — is asking for something the ciphersuite cannot
do, which is a better answer than the one §7.2's independence argument implies,
which sounds like a matter of operator diversity.

**Proposed fix:** §7.4 should preface the index list with: "FROST's access
structure is a flat threshold, so 'a server **and** a device' cannot be expressed
as `t`-of-`n` directly. Replication is the encoding: each class collapses to one
share, `t = 2`, and the conjunction falls out. A structure requiring `t_A` of the
servers and `t_B` of the devices would need a nested sharing outside RFC 9591 and
is not offered." §7.2's "two servers from one operator are one server" paragraph
should add: "Independence is not the only cost. Because all servers replicate share
1, each additional server is an additional place share 1 can be stolen from while
`t` stays at 2. Servers buy availability and are paid for in exposure; enroll the
fewest that meet your availability need."

### A multi-index party has no representation in bifrost's message format

**Document:** TIERS.md
**Section:** §2.3 (and NOSTR_KEY_MANAGEMENT.md §7.4)
**Kind:** ambiguity

TIERS.md §2 gives a party weight by giving it several indices. Neither FROSTR
implementation can express that as one peer. In `bifrost`, a node is built from
exactly one `SharePackage` (`src/class/client.ts:119`–`135`) and its BIP-340
identity is the pubkey of that share's secret (`src/class/signer.ts:79`); the
dealer emits one member record per index with the same derivation
(`src/lib/package.ts:45`–`62`). Index and pubkey are therefore in bijection, and
`get_member_indexes` asserts it — `indexes.length === pubkeys.length`
(`src/lib/util.ts:92`–`101`). `bifrost-rs` is the same by construction: the signing
device holds one share and a `HashMap<String, u16>` from peer pubkey to a single
index (`crates/bifrost-signer/src/lib.rs:663`–`668`), resolved by first match
(`crates/bifrost-signer/src/util.rs:22`–`41`), and a member's pubkey *is* that
index's verifying share (`crates/frostr-utils/src/keyset.rs:112`–`152`).

Two readings were available. Either weights need a protocol change — a peer
identity decoupled from the share, carrying a set of indices — or a weight-`T`
party runs `T` conforming peers and "party" lives only in the client's own records.
**The second reading was taken**, because the first would change the key schedule:
the share secret is the transport secret, so a peer identity that is not a share
pubkey cannot be routed, and `/sign/req`'s `nonces` array is keyed by `idx` with one
nonce pool per peer index, so a multi-index peer would need per-index pools behind
one identity anyway. Nothing is gained and the wire format changes.

What the second reading costs, and what TIERS.md §2.3 therefore requires: **no
FROSTR message says that two pubkeys are one party.** `/sign/req` carries
`members: number[]` and `/sign/res` carries a single `idx`, so a coordinator sees a
weight-2 trusted device as two independent signers and a `gid` computed over sorted
member pubkeys cannot distinguish "four parties of weight 1" from "two parties of
weight 2". Every quorum rule that speaks of parties or tiers — TIERS.md §4's
inequalities, §6's per-tier policy, §7's rotation authority — is unenforceable from
the group package alone and must be evaluated against the epoch record, which is
this project's structure and not FROSTR's.

**Proposed fix:** none against `bifrost`; the awkwardness is inherent and the
convention works. TIERS.md §2.3 states the determination and its two normative
consequences (weights are peer multiplicity; party identity lives in the epoch
record and quorum rules are evaluated against it, never against the raw member
list). An implementer who counts peers rather than parties will miscount every rule
in §4 and §6, so the rule is stated where it can be tested rather than left to
inference.

### The reshare primitives exist in the ciphersuite; no FROSTR layer exposes them, and the one operation on offer reconstructs

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.9 (and §7.5a, §7.18, TIERS.md §5.1)
**Kind:** suspected error

NKM §7.9 specifies rotation as a delta-polynomial reshare — `δ(x) = r·x`, `δ(0) = 0`,
each member adding its own delta — and §7.5a states flatly that "rotation, share
issuance, share-1 replication, changing a backup factor and server enrollment never"
reconstruct. TIERS.md §5.1 builds grant issue on the same primitive, extended to
evaluate the new polynomial at a new index. **No FROSTR layer exposes either
operation, and the one thing on offer does what §7.5a forbids** — although, as below,
the ciphersuite NKM §7.4 names has shipped both for several releases.

- `bifrost` has a trusted dealer (`src/lib/package.ts`, `generate_dealer_package` →
  `create_dealer_set`) and full reconstruction (`src/lib/util.ts:104`, via
  `recover_secret_key`). There is no delta, no resharing, and no way to add an index
  to a live group. `/onboard/req` and `/onboard/res` are not it: the response carries
  the existing `GroupPackage` and a nonce package (`src/api/onboard.ts`,
  `build_onboard_response`), so onboarding serves a node that already holds a share
  from an earlier dealing.
- `igloo-core` exposes exactly the same two operations and nothing between them:
  `generateKeysetWithSecret` and `recoverSecretKeyFromCredentials`
  (`src/keyset.ts:50`, `:158`, `:188`).
- `bifrost-rs` does have an operation called rotation, and it reconstructs.
  `rotate_keyset_dealer` (`crates/frostr-utils/src/keyset.rs:48`–`95`) calls
  `recover_key`, deserializes the recovered signing key, and calls
  `frost::keys::split` again. It preserves the group public key and can change
  threshold and count — so it *can* add an index — but it assembles the nsec on one
  machine to do it. Its own test asserts only that the group pubkey survives
  (`:215`–`230`).

So a client implementing NKM §7.9 or TIERS.md §5.1 against today's libraries has two
choices, and both contradict something: call `rotate_keyset_dealer` and reconstruct,
against §7.5a; or write the delta reshare itself, against the project's own
preference for citing rather than owning constructions. The second is the intended
one and NKM should say so rather than leaving the reader to discover that the
obvious library call is the forbidden operation.

**Both primitives exist in the ciphersuite NKM §7.4 already names, and this entry was
filed before that was checked.** `frost-core` 3.0.0 ships:

- `keys::refresh` (`frost-core/src/keys/refresh.rs`) — exactly NKM §7.9's delta.
  `compute_refreshing_shares` (`:58`) builds a Shamir sharing of **zero** with
  `min_signers − 1` fresh coefficients, so `δ(0) = 0` by construction and the degree is
  `k − 1` rather than 1; `refresh_share` (`:131`) adds each member's `δ(i)` to its
  share. It takes only the *public* key package, so the party drawing `δ` learns
  nothing. Passing a subset of identifiers drops the omitted members. Present since
  `frost-core` 2.0.0 (trusted-dealer form) and 2.1.0 (DKG form), so it is in the
  `frost-secp256k1-tr-unofficial` 2.2.0 that `bifrost-rs` already depends on
  (`bifrost-rs/Cargo.toml:49`). It cannot change `min_signers` and cannot add an
  identifier.
- `keys::repairable` (`frost-core/src/keys/repairable.rs`) — the Repairable Threshold
  Scheme of *A Survey and Refinement of Repairable Threshold Schemes* (Laing and
  Stinson, IACR ePrint 2017/1155), which is what adds an index. Helpers split
  `ζ_i(x)·s_i` into additive parts summing to it (`:135`), exchange them, sum into one
  `σ` each (`:170`), and the recovering participant sums the `σ` values (`:184`).
  Named `repair_share_step_1/2/3` in 2.x and `repair_share_part1/2/3` since 3.0.0
  (`frost-core/CHANGELOG.md`, 3.0.0-rc.0 breaking changes).

So the second gap this entry described — "there is no obvious blinded construction" —
is wrong, and TIERS.md §5.1 step 4 now specifies RTS rather than only forbidding the
unblinded form. Two things about RTS are worth recording because they are not in its
own documentation. It is documented as repairing a **lost** share at an identifier
already in the group, but `repair_share_part1` computes
`compute_lagrange_coefficient(helpers, Some(participant), i)` and
`repair_share_part3` never looks the participant up in the public key package
(`frost-core/src/lib.rs:295`–`331`; `repairable.rs:184`–`212`), so it evaluates `f` at
**any** point and adding a new index is the same call. And the participant MUST NOT be
one of the helpers, or `ζ` is zero for that term — a condition the API does not check
and TIERS.md §5.1 step 4 states as a MUST.

What remains true is the first gap: NKM §7.18's "combine them on one of the two" is
the unblinded version, sound at `t = 2` among the user's own hardware and wrong the
moment the contributors are not equally trusted, since in a weighted group a trusted
device holds `T = k − 1` and a co-signer's contribution is the missing unit.

**Proposed fix:** NKM §7.9 should add, after step 4: "The delta of this section is
`frost-core`'s `keys::refresh`; a client SHOULD use it rather than reimplement the
delta. No FROSTR layer exposes it: `bifrost` and `igloo-core` offer trusted dealing
and reconstruction only, and `bifrost-rs`'s `rotate_keyset_dealer` reconstructs the
nsec before re-splitting, so it MUST NOT be used to perform a §7.9 rotation, which
§7.5a declares non-reconstructing." NKM §7.18's "Adding a device" should add:
"Combining the two contributions on one device is permissible here only because both
are the user's own trusted hardware and any two of them already reconstruct. Where
members are not equally trusted, a raw Lagrange-weighted contribution reveals the
contributor's share, and the combination MUST instead use the repairable threshold
scheme of `frost-core`'s `keys::repairable`, in which each helper's contribution is
split into additive parts and only the joining device sees their sum." TIERS.md §5.1
step 4 carries that construction in full; the gap that remains is at the FROSTR layer,
and the Status section of TIERS.md states it as three upstream proposals.

### §7.6 requires the co-signer to see the event; FROSTR's signing message carries only hashes

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.6 (and §7.13, TIERS.md §6.0)
**Kind:** suspected error

NKM §7.6 states it twice and builds on it: "A FROST co-signer must see what it
signs. **Every event a device signs is visible in plaintext to the co-signer**", and
"the requester sends the **full unsigned event**, not a digest; the co-signer
serialises and hashes it itself (NIP-01)." The kinds allowlist of §7.6, the kind-5
tag check, and every per-kind rule in TIERS.md §6 rest on it.

**FROSTR's signing message has no field for the event.** `/sign/req` carries
`hashes: string[][]` — sighash vectors — with `gid`, `sid`, `members`, `nonces`,
`type` and `stamp` (`bifrost/docs/PROTOCOL.md`, "Sign Request"; schema at
`bifrost/src/schema/sign.ts`, `template`/`session`). The only free field is
`content: string | null`, documented as "Optional metadata", unvalidated, and folded
into the session-id preimage (`bifrost/src/lib/session.ts:131`–`135`). The signer
handler never sees an event: it looks up its own nonce by index, re-derives the
secret, and signs the hash it was given (`bifrost/src/api/sign.ts:87`–`109`). The
required validations in `PROTOCOL.md` cover `gid`, `sid`, member indices, threshold
and nonce presence — nothing about what is being signed. A conforming FROSTR peer
therefore **cannot** implement §7.6's allowlist, and a deployment that believes it
has one has a policy that never runs.

The HTTP surface is better and still unsound by default. `igloo-server`'s
`/api/sign` accepts either a full `event`, which it hashes itself exactly as §7.6
requires, **or** a `message` field holding a bare 32-byte event id, which it signs
without seeing anything (`igloo-server/src/routes/sign.ts:22`–`27` and `:29`–`75`).
Both forms are equally available to any authenticated caller, so an app that wants
to evade a kinds allowlist sends the hash form.

This is not a defect in `bifrost` — a threshold signer that signs hashes is the
normal design — but it makes §7.6's central claim false as written against the
protocol NKM's co-signer mode is built on, and it silently disables the mechanism
NKM §7.13 relies on for its audit surface.

**Proposed fix:** NKM §7.6 should replace "Requests are gift-wrapped between `E.pub`
and `S.pub` over relays or `<url>/v1/sign` over HTTPS; both MUST be supported, HTTPS
tried first" with a statement of what the relay form must carry: "The request MUST
carry the full unsigned event. FROSTR's `/sign/req` has no field for it; a co-signer
MUST NOT sign a bare sighash, so a client using the relay transport MUST convey the
event in a field the co-signer validates, and a co-signer that receives a request
with no event MUST refuse the round rather than sign the hash." §7.6 should further
require: "Where an HTTP signing endpoint accepts both a full event and a precomputed
event id, the co-signer MUST refuse the precomputed form for any requester subject
to a kinds allowlist." TIERS.md §6.0 states the second requirement for grant indices
already; the first belongs in NKM, because NKM's co-signer mode has the same hole.

### "k co-signer votes" is unsatisfiable by co-signers, and the delay would break tier-1 revocation

**Document:** TIERS.md
**Section:** §7.2, §7.1 (and NOSTR_KEY_MANAGEMENT.md §7.9)
**Kind:** ambiguity

The decision this document was written from gives the rotation and revocation
authority as "a trusted device plus `k` co-signer votes plus the §7.10 delay, with
notice to all trusted devices and a veto during the window." Read literally against
§4.2's constraint (1), `n_s < k`, that is unsatisfiable: there are never `k`
co-signers to vote, so no rotation could ever complete and the grant issue of §5.1,
which is a rotation, could never run either. Two readings resolve it.

**Reading A, taken.** The votes are counted in *weight*, not in co-signers: a
rotation needs votes totalling `k`, the initiating trusted device contributes its `T`,
and the remaining `k − T` come from co-signers. This is satisfiable at every
configuration §4.2 permits, and it reduces to exactly NKM §7.9 step 1 — "signed by the
group key with **old** shares … so it requires server and one device — neither can
rotate alone" — which is the same rule at `T = 1`, `k = 2`. It also preserves the
sentence the decision pairs it with, that a single trusted device cannot rotate
alone, since `T < k` (§4.3). §7.2 is written this way.

**Reading B, rejected.** Every co-signer must vote, unanimously. This is satisfiable,
but it makes any one co-signer's unavailability block every rotation — including the
rotation that revokes a compromised index — which inverts the availability argument of
§4.3 and gives a single unreachable server a veto over incident response.

A second ambiguity sits beside it. The decision names "rotation **and revocation**"
together and attaches the delay to both. Applied literally, cutting off a compromised
grant would take 24 hours. NKM §7.9 already splits this — tier 1 revokes `E`
immediately, "without touching any share and without contacting the revoked device",
and tier 2 rotates — so **the reading taken attaches the three-part authority and the
delay to tier 2 only**, and leaves tier 1 as one trusted device acting immediately, as
NKM has it. TIERS.md §7.1 says so and gives the reason: a delay on refusal is not a
safeguard, it is the window the attacker wants.

**Proposed fix:** TIERS.md §7.1 and §7.2 state both readings as taken. If the intent
was Reading B, §7.2(2) should read "votes from every co-signer" and §4.3's slack
argument needs restating, because a configuration with `s = 1` would then tolerate a
co-signer outage for signing but not for rotation, which is worth saying out loud
either way. If the delay was intended to cover tier-1 refusal as well, §7.1 should be
deleted and NKM §7.9's two-tier structure declared inapplicable here — but then
nothing in this document can cut off a compromised grant faster than a day, and
§6.1(d)'s freeze becomes the only incident-response tool, which it was not designed
to be.

### §11.4's "no side-channel for additional profile messages" and multi-party share issue

**Document:** QR_SECRET_TRANSFER.md
**Section:** §11.4 (and §4 P2, §13; TIERS.md §5.1 step 6, Appendix B)
**Kind:** ambiguity

QRST §4 P2 says "One payload, one session … a session carries exactly one message
with meaning to the profile", and §11.4 restates it in the imperative: "One session
carries one PAYLOAD; there is no side-channel for additional profile messages (P2)."

Both were written when a profile's payload came from one holder. TIERS.md §5.1 issues
a share by the repairable threshold scheme, in which the joining device must receive
one masked sum from each helper **party** — always at least two, one trusted device and
one co-signer, because the helper set must reach weight `k` and a trusted device holds
`T < k`. The initiating trusted device cannot collect them first: a masked sum it can
read, added to the others, is the new share, and `T + 1 = k` is the key. So the
material has to reach the joining device from more than one party, and the sentence
above admits two readings.

**Reading A, taken in TIERS.md Appendix B.1.** The sentence governs QRST's own message
set — the seven kinds of §11.4, inside one session. Other protocols may address the
same burner; their wraps carry none of those kinds, so a conforming QRST
implementation does not read them, and §13 does not count their senders as responders
because it counts HELLO and REQUEST specifically. Under this reading TIERS.md needs no
QRST change: the QRST session still carries exactly one PAYLOAD from exactly one
Sender, and NKM §3.3's "One Sender, either shard type" note still holds.

**Reading B.** The sentence governs everything profile-relevant that reaches the
Receiver, because §4 P4, P5 and §9.4 are all defined over "what was received" and
assume the profile check can be run against the payload. Under this reading, `σ` wraps
addressed to the burner **are** the forbidden side-channel, and Appendix B.1 is
non-conforming.

The practical difference is real but narrow: TIERS.md Appendix B.2 gives a variant in
which every other helper's `σ` is sealed to the burner and carried as opaque entries
*inside* the one PAYLOAD, which conforms under either reading. It is bounded by P1's
2048-byte default — measured at 834 B for `k = 3`, 1690 B for `k = 5`, and 2546 B for
`k = 7`, so it stops fitting around six helper parties — above which only Reading A
works without the profile declaring a larger maximum.

**Proposed fix, for the next QRST version:** §11.4's sentence should read "One session
carries one PAYLOAD; there is no side-channel for additional *QRST* messages (P2). A
profile whose payload is assembled from several holders MAY have those holders deliver
their contributions to the Receiver's burner outside the session, provided the
contributions carry none of this section's kinds, the Receiver validates each against
material delivered in the PAYLOAD, and the profile's P4 check is run over the assembled
result." §4 P2 should add: "A profile MAY define contributions that reach the Receiver
outside the session; P2 constrains the session's own messages, and the profile's P4
check MUST cover whatever the contributions assemble into." Without one of these, a
profile needing more than one contributor has to fit every contribution inside the
payload and inherits P1's ceiling as a cap on its threshold.

### A trusted device and the recovery phrase reach `k` without a co-signer

**Document:** TIERS.md
**Section:** §8.4 (and §4.2, §7.2, §7.4)
**Kind:** suspected error

§7.4 makes a conflict between two equal-level authorities freeze all co-signing, and
states the last cell of its case table — an attacker holding a trusted device and the
recovery phrase, against a user holding the same — as the intended outcome: a frozen
key. That outcome holds for everything that routes through a co-signer. It does not
bound the key.

Constraint (6) bounds what a trusted device reaches with grants: `T + W_cap < k`. It does
not count the recovery share, which weighs 1 once unsealed. A device, `R` and grants to
the cap weigh `T + 1 + W_cap`, and at both reference profiles that is exactly `k`:
`2 + 1 + 1 = 4` under Profile A, `2 + 1 + 2 = 5` under Profile B. Grant issue is immediate
(§7.2), so the attacker issues itself grants before revealing anything, and the set
`D + R + G` then signs and reconstructs with no co-signer in it (`tiers_check.py`, with `R`
modelled as a weight-1 grant, lists `D1 + G1 + R` and `D2 + G1 + R` as no-co-signer sets at
the reference configuration). Under Profile B, `D1 + D2 + R` does the same with no grant.

TIERS.md §8.4 states this and argues it is no worse than §8.1's trusted-share factor, which
with a device is `2T` — the key under Profile A, and the key with one self-issued grant
under Profile B. That comparison is correct. It means the phrase is key-equivalent in the
hands of anyone who also holds a device, and §7.4's freeze is weaker protection than the
case table alone suggests.

**Proposed fix:** add to §4.2, as a requirement wherever a recovery share exists: "(7)
`T + 1 + W_cap < k` — a trusted device, the unsealed recovery share and every grant it
could issue never sign without a co-signer." It costs one unit of grant cap: Profile A
would need `W_cap = 0` at `k = 4`, or `k = 5, T = 2, n_s = 4, W_cap = 1`; Profile B would
need `W_cap = 1` at `k = 5`. With (7) holding, §7.4's last cell becomes a real bound, and
§8.4's residual paragraph reduces to the §8.1 comparison. If the cap is judged worth more
than that, §7.4 should instead say in the table itself that its device-and-phrase row is
a policy outcome only.

## Resolved

### A failed probe can leave a browser Holder with no transport at all

Resolved in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) §11.3, which makes the
probe advisory rather than selective for a client with only one transport
available in its current role. The section it was filed against
(`NOSTR_KEY_MANAGEMENT.md` §3.1) no longer exists.

### §5 did not state that at t = 2 any two shareholders are the key

Resolved, then superseded. In the 8.0 model `NOSTR_KEY_MANAGEMENT.md` §5 was
updated to state that any two shareholders reconstruct. The 9.0 "replicas by index"
rework then reversed that model entirely — under it two devices hold the *same*
share and cannot reconstruct — so the property this entry tracked no longer holds;
see the two entries below.

### Threshold mode without a server is unreachable — resolved in 9.1

Filed against the 8.0 model. The 9.0 "replicas by index" rework made the server a
mandatory co-signer, which removed the serverless configuration entirely rather than
making it reachable — and, as later review found, reduced threshold signing to a
better bunker that forgoes FROST's actual value. **9.1 answers the entry directly by
building the missing mode:** §7.18 defines the serverless device quorum (2-of-N
across the user's own devices, unique shares, no server in the signing path),
selectable at §7.3, which is now triggered by threshold enablement rather than only
by server enrollment. The mode this entry asked for exists and is reachable.

### `t` is a constant, not a parameter — resolved in 9.1

The entry wanted `t` to be a parameter so that surviving two colluding shareholders
was possible. In the co-signer mode `t = 2` remains intrinsic (server class + device
class). In the new device-quorum mode (§7.18) `t` is a parameter: `2` by default,
and `3` where the user has three or more independent trusted devices, trading "any
two present" for "surviving any two compromised." The choice is surfaced only where
the device list can satisfy it, exactly as the entry proposed.

### TIERS.md §10's threat table understated which sets reach `k` — resolved

**Document:** TIERS.md
**Section:** §10 (against §4.4, §4.5)
**Kind:** suspected error

§10 evaluates "this document" at §4.4's reference configuration, two live grants
included. Three of its cells did not match that configuration's minimal signing sets
as `tiers_check.py` enumerates them (`vectors/tiers-profile-a.json`), which are the
thirteen of §4.5:

- *Malicious web app* said the grant "reaches `k` only with every co-signer or a
  trusted device", and *Malicious grant holder* said it "needs every co-signer or a
  trusted device". §4.5 sets 12 and 13 (`C1 + G1 + G2`, `C2 + G1 + G2`) reach `k` with
  one co-signer and the other live grant. §4.3's "every one of them must be in the
  signing set" is scoped to a grant that is the only live one; the table dropped the
  scope.
- *Compromised trusted device* said it "needs co-signers it cannot control" and is
  "delayed and vetoable on trusted-only kinds (§6.1(e))". §4.5 sets 6 to 9 (`D + G`)
  reach `k` with a grant and no co-signer, and §6.1(e) is enforced by a co-signer, so
  the delay covers only the sets that contain one.

**Fix applied:** the two grant cells now read "a trusted device, every co-signer, or a
co-signer and another live grant (§4.5 sets 6–13)"; the trusted-device cell reads "a
co-signer or a live grant it does not control (§4.5 sets 2–9); delayed and vetoable on
trusted-only kinds where a co-signer is in the set (§6.1(e))". No other table in §3.5,
§4.4, §4.5 or §4.6 disagrees with the script.

### TIERS.md §7.2 delayed every rotation, which was a UX bug and an accidental safeguard — resolved

**Document:** TIERS.md
**Section:** §7.2 (and §5.1 step 1, §4.2, §7.4; README.md §3)
**Kind:** suspected error

§7.2 required every rotation — "whether to revoke an index, to add a trusted device, to
issue a grant, or to drop expired ones" — to wait out NKM §7.10's delay, with a veto for
any trusted device, and §5.1 step 1 made grant issue a rotation "in the sense of §7" with
that authority "in full". The earlier entry *"k co-signer votes" is unsatisfiable by
co-signers* already took the delay off tier-1 refusal; it stayed on everything else.

**As a UX bug.** Logging an application in with a grant waited a day for any user
without a second trusted device to approve it — the README's rewrite had to tell users
so — and so did revoking a grant by rotation and dropping expired ones. Nothing the delay
protected against at those operations was the user's to fear from their own device, and
the cost landed on the single-device user, who is the common case.

**As an accidental safeguard.** At the then-reference `k = 3, T = 2`, a trusted device
and one grant reached `k` with no co-signer (the old §4.5 sets 6 to 9, now Appendix C). A
compromised device could issue itself a grant and hold the key. The only thing in the
document between that device and the key was this delay: a second trusted device read
the notice and vetoed. Nothing stated that the delay was doing this, no inequality in §4
backed it, and for a user with one trusted device it did nothing, because the window
elapsed on its own. Removing the delay as a UX fix without replacing it would have turned
a slow, vetoable attack into an immediate one.

**Fix applied.** Constraint (6), `T + W_cap < k` (§4.2), replaces the accidental
safeguard with a structural one: no set a trusted device can form with grants reaches
`k`, however many it issues. With (6) holding, §7.2 now makes grant issue, grant
revocation, dropping expired grants and a refresh that changes no trusted or recovery
index **immediate**, needing only a trusted device and co-signer votes to weight `k`, with
every co-signer checking the grant cap. The delay applies only to trusted-set rotations —
admitting, reissuing or removing trusted weight, and creating, re-keying or removing the
recovery share — at the authority levels of the new §7.4. Removal is included because an
immediate removal lets one compromised device evict the user's other device and then add
its own with nobody left to veto; the target of a removal may veto it, and the stalemate
that leaves is resolved by §7.4's levels rather than by first mover.
