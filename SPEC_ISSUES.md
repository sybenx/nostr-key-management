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

**Document:** QR_SECRET_TRANSFER.md | NOSTR_KEY_MANAGEMENT.md
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

### §7.4's parity handling and the named ciphersuite's parity handling are two answers to one question

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.4 (and §7.5, §7.15)
**Kind:** ambiguity

§7.4 names the ciphersuite as "FROST per RFC 9591 with the secp256k1 Taproot
variant as implemented by `frost-secp256k1-tr`" and, in the same list item,
specifies parity handling of its own: "If `pubkey(nsec)` has odd y, the dealer uses
`a_0 = n − nsec` so the group key is even-y. On reconstruction the result is
`n − nsec` for an odd-y key; the client MUST re-negate before storing or
exporting."

`frost-secp256k1-tr` handles BIP-340's x-only negation itself — that is what the
`-tr` variant is for; it conditionally negates the group element and signers'
contributions at signing time so that signatures verify under an even-y x-only
group key. The specification therefore names two independent solutions to the same
problem and does not say which one is authoritative. An implementer who applies
both deals shares from a pre-negated `a_0` and then hands them to a library that
negates again. The result is a group key that is not the user's npub.

The failure mode is the reason this is worth fixing rather than leaving to
judgement. It is silent, it affects only odd-y keys so it passes roughly half of
casual testing, and it is discovered *after* §7.5 step 5 has wiped the local nsec
and every synced copy. Recovery is the §4.2 backup, if one was taken.

The choice also has a visible consequence: dealing from the raw `nsec` and letting
the ciphersuite own parity makes reconstruction yield `nsec` directly, at which
point §7.4's re-negation MUST and its restatement in §7.15 are wrong rather than
merely redundant.

**Proposed fix:** §7.4 should state one and delete the other. The narrower change
is to keep the dealer's negation and require the ciphersuite be driven with its own
parity handling in the configuration where the group key is used untweaked and
unmodified — which is also worth stating explicitly, since the crate's default is
to sign against the untweaked group key and NKM wants no BIP-341 tweak. The
cleaner change is: "The dealer sets `a_0 = nsec` unmodified. BIP-340 parity is the
ciphersuite's responsibility: `frost-secp256k1-tr` negates the group element and
signers' contributions as required, and the group key is used untweaked (no
BIP-341 tweak is applied). Reconstruction (§7.15) yields `nsec` directly and no
re-negation is performed." Either way §6 should gain a vector generated from an
**odd-y** nsec — group key, both shares, the epoch record and one verifying
signature — because that vector is the only thing that catches the wrong choice
before deployment.

*Note in passing, not a defect:* the untweaked group key is documented as
susceptible to a rogue-tweak attack at DKG time. NKM never runs a DKG — §7.5 is a
trusted dealer holding the whole nsec — so the caveat does not apply here, and the
dealer model is what makes untweaked use safe. Worth a sentence in §7.4 so a
reviewer who finds the caveat does not have to re-derive that.

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
