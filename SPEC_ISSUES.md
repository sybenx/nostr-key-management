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

### QRST §12.1 cites NKM §7.7, which NKM 10.0 deletes

**Document:** QR_SECRET_TRANSFER.md
**Section:** §12.1
**Kind:** suspected error

§12.1 says: "Copy-paste pairing earns its place for a profile whose payload has
no such standalone encrypted form — a threshold share (NKM §7.7) — where the
SAS ceremony is the delivery." NKM §7.7 ("Adding a device after activation")
named `frost-share` as that profile before NKM 10.0 adopted FROSTR and deleted
§7.7 along with the rest of the co-signer design; `frost-share` is now defined
at NKM §3.3, which still has no standalone encrypted export and so the
sentence's substance is untouched — only the citation is stale.

This document's own constraints on this revision forbid editing QRST's
normative sections, so the fix is recorded here rather than applied. §12.1's
other two citations of this kind (`NKM §7.1`, `NKM §7.9` in §12.3) still
resolve correctly, since NKM 10.0 kept both those section numbers.

**Proposed fix:** In §12.1, change "a threshold share (NKM §7.7)" to "a
threshold share (NKM §3.3)".

### Platform-sync quarantine has no protocol signal that a FROSTR group exists

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §2.4 (and §7)
**Kind:** design disagreement

§2.4 says a device restoring a synced full-nsec backup MUST quarantine it "if
the client's own local history shows it previously wiped this identity's nsec
to activate FROSTR" — a client-local check, by the section's own admission,
because FROSTR publishes no discoverable marker that an npub's signing
authority has been split. Prior to 10.0 this was a protocol check: the
restoring device fetched the epoch record this document itself published and
self-enrolled only after establishing its absence. 10.0 has no epoch record to
fetch, because FROSTR's group state is not published anywhere this document
can query.

The residual is real: a fresh install with no local history of a prior
activation — a reinstall after data loss, a second install predating the
activation, a device recovering via §7.10 — restores a full-key backup
straight into ordinary use beside a live FROSTR group it knows nothing about,
silently defeating the split. This is a consequence of adopting a threshold
protocol that was not designed to be introspected this way, not an oversight
in the drafting of §2.4.

**Proposed fix:** Either FROSTR gains a discoverable, unauthenticated way to
ask "does a group exist for this pubkey" (which this document cannot specify,
since it does not own that protocol), or this document keeps a minimal marker
of its own — a single self-signed, unencrypted event naming only "this
identity's signing authority is split; ask elsewhere for details," published
once at whatever moment a client hands the nsec to FROSTR's dealer and never
updated again, cheap enough that it does not reintroduce the bookkeeping 10.0
removed. Until one of these exists, §2.4 should say plainly that the
quarantine is best-effort and a fresh install cannot benefit from it.

### §4.2's recovery notice lost its device registry along with §7.1

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §4.2 (and §7.1)
**Kind:** design disagreement

Prior to 10.0, §4.2's password-branch recovery delay notified "every
registered device" by `RECOVERY_NOTICE`, where "registered" meant an `E.pub`
on the device list §7.1 defined and every device kept current. 10.0 deletes
that device list as part of adopting FROSTR (§7.1 is now a migration note, not
a mechanism), and §4.2 now says the notice reaches "every address the client
has for the user's other devices" and that a client "MUST track enough of one
— even informally — to make this notice reach somewhere." That is a
requirement with no defined mechanism behind it: the concrete registry the
delay's guarantee depended on is gone, and nothing replaces it.

**Proposed fix:** Either restore a minimal, purpose-built device-address list
scoped to backup notification alone — deliberately smaller than the deleted
§7.1 apparatus, since it needs to carry an address and nothing else (no role,
no admission, no epoch) — or state explicitly in §4.2 that the recovery
delay's notice is best-effort in 10.0, rather than phrasing it as a MUST with
an undefined audience.

### Interpretation notes on the FROSTR rewrite (not spec defects)

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §3.1, §7.10
**Kind:** ambiguity

Two decisions made while adopting FROSTR (10.0) that a future editor should
know were judgment calls rather than requirements stated explicitly in the
brief that produced this revision:

- **§3.1's `enroll` tag was removed, not just re-pointed.** It existed only to
  populate the device list §7.1 used to define, which 10.0 deletes. Nothing
  that named the two sections above mentioned §3.1, but leaving the tag in
  place would have left it enrolling into a mechanism that no longer exists.
  If a future revision restores a protocol-level device registry (see the
  entry above), §3.1 is the place to re-add it.
- **§7.10's scope was interpreted as new content under a carried-forward
  number, not the old section's subject restated.** The pre-10.0 §7.10
  ("Recovery, all devices lost") was entirely about this document's own
  reconstruct-and-reactivate flow under its own threshold design. 10.0 keeps
  the number but gives it a different subject: what a live FROSTR group is
  owed when §4.2's unrelated, always-present recovery mechanism reconstructs
  the nsec elsewhere. The alternative reading — restating the old
  all-devices-lost flow in FROSTR vocabulary — was rejected because that flow
  is entirely §4.2's already and has nothing FROSTR-specific to add; the
  recovery-delay obligation toward FROSTR peers is the part with no home
  elsewhere.

**Proposed fix:** None required; recorded so a reviewer comparing 9.2 to 10.0
section by section does not read §7.10's changed subject as a mistake.

---

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

### `t = 3` is offered by §7.18 and the epoch record cannot express it

Superseded. NKM 10.0 deletes §7.18 (and the rest of §7's bespoke threshold
design) and adopts FROSTR, whose dealer supports arbitrary `(t, n)` without
this document specifying a polynomial commitment scheme at all. The rotation
construction proposed in the rewritten §7.9 applies the fix this entry asked
for — commitments as an array, fresh randomness per coefficient — from the
start, generalised to any `t`.

### §5's "one lost device alone is inert" holds only after revocation

Superseded. The co-signer and device-quorum property lists in §5 that this
entry was filed against are gone; NKM 10.0 defers threshold security
properties to FROSTR's own security model
([bifrost/docs/SECURITY.md](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/SECURITY.md))
and states only what this document still owns (§3.3, §7.9, §7.10).

### §7.4's parity rule is redundant with its own ciphersuite, and its re-negation corrupts the exported nsec

Superseded. §7.4, the ciphersuite and parity-handling section this entry was
filed against, no longer exists: NKM 10.0 does not specify a ciphersuite at
all, since FROSTR's dealer (bifrost, via `@noble/curves`) handles BIP-340
parity internally and this document never sees the raw polynomial.
`vectors/nkm-frost.json` remains as the historical record of the finding.

### §7.9 step 4 is written for one server and the model has many

Superseded. The replica-by-index architecture (one server index, any number
of server replicas) this entry critiques is gone. The rewritten §7.9 rotation
is peer-based, not server/replica-based, and has no equivalent "destroy the
old share" step assigned to a distinguished server class — every member
destroys its own old share on adopting the delta.

### §7.8 releases share 1 on one device's authority; §7.14 releases the same share on two

Superseded. §7.8 (adding a server replica) and §7.14 (Offline mode) are both
deleted; NKM 10.0 has no server-replica or full-key-on-one-device concept of
its own. Analogous questions about issuing a peer's credentials belong to
FROSTR's own onboarding and peer-policy design, not this document.

### §7.15 disable and §7.14 Offline mode have no device-quorum meaning

Superseded. §7.14, §7.15, and the device-quorum/co-signer distinction this
entry depends on are all deleted; NKM 10.0 has neither an Offline mode nor a
disable operation of its own. Reconstructing under FROSTR is FROSTR's own
dealer tooling (see the rewritten §7.9's note on reconstruct-and-redeal).

### Rotation is automatic after revocation but not after enrollment, where the exposure is larger

Superseded. The rewritten §7.9 does not enumerate automatic rotation triggers
at all — that is left to the client, or to FROSTR, which has no rotation
primitive yet (§7.9's own opening paragraph). The underlying point — rotate
soon after a share transfer, not only after a loss — is still good advice and
worth carrying into whatever eventually adopts §7.9's proposal.

### The signing round structure is unspecified in §7.6 and two rounds in §7.18

Superseded. §7.6, §7.6a and §7.18, which this entry was filed against, are
deleted; signing and ECDH round structure are FROSTR's
([bifrost's `/sign` and `/ecdh` tags](https://github.com/FROSTR-ORG/bifrost/blob/main/docs/PROTOCOL.md))
and are not restated or resolved here.

### §7.18 does not forbid reusing a removed device's index

Superseded. §7.18 (device quorum) is deleted. Index assignment and reuse are
FROSTR's own concern (bifrost's `GroupPackage` member list); this document no
longer allocates indices.

### The replica scheme is the only flat-FROST way to say "a server and a device", and that is not stated

Superseded. §7.4, §7.2 and §7.12, which this entry discusses, are deleted
along with the replica-by-index architecture itself. A "server and a device"
pairing is now just a small FROSTR group like any other; the flat-threshold
limitation this entry explains is still true of FROST generally and is
documented, if at all, by FROSTR rather than by this document.
