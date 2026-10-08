# Specification Issues

**To report something, [open an issue](https://github.com/sybenx/nostr-key-management/issues/new?template=spec-issue.yml).** The form asks for the same
fields as the format below. This file is the permanent record: entries filed here
before issues were used, and every settled issue, with how it was resolved.

This file records disagreements with
[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md),
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) and [TIERS.md](TIERS.md). It
exists because the
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

The issue form asks for these fields. When an issue is settled, it is recorded
here under its own heading, newest at the bottom, in this shape, with a link to
the issue:

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

Open reports are [GitHub issues](https://github.com/sybenx/nostr-key-management/issues?q=is%3Aissue+is%3Aopen+label%3Aspec). The ten entries that were open here on 7 October 2026 were checked against the current text, found to stand (some in part, with corrections noted on the issue), and moved:

- [#1](https://github.com/sybenx/nostr-key-management/issues/1) `t = 3` is offered by §7.18 and the epoch record cannot express it
- [#2](https://github.com/sybenx/nostr-key-management/issues/2) §5's "one lost device alone is inert" holds only after revocation
- [#3](https://github.com/sybenx/nostr-key-management/issues/3) §7.4's re-negation rule cannot be applied at reconstruction, so an odd-y key can be exported wrong
- [#4](https://github.com/sybenx/nostr-key-management/issues/4) §7.9 step 4 is written for one server and the model has many
- [#5](https://github.com/sybenx/nostr-key-management/issues/5) §7.8 releases share 1 on one device's authority; §7.14 releases the same share on two
- [#6](https://github.com/sybenx/nostr-key-management/issues/6) §7.15 disable and §7.14 Offline mode have no device-quorum meaning
- [#7](https://github.com/sybenx/nostr-key-management/issues/7) Rotation is automatic after revocation but not after enrollment, where the exposure is larger
- [#8](https://github.com/sybenx/nostr-key-management/issues/8) The signing round structure is unspecified in §7.6 and two rounds in §7.18
- [#9](https://github.com/sybenx/nostr-key-management/issues/9) §7.18 does not forbid reusing a removed device's index
- [#10](https://github.com/sybenx/nostr-key-management/issues/10) §7.4 does not say why share 1 is replicated, or that each extra server is another copy of it

## Resolved

The entries from here to the next horizontal rule were found while building the
reference implementation of QRST
([sybenx/qr-secret-transfer](https://github.com/sybenx/qr-secret-transfer)), and
are resolved in QR_SECRET_TRANSFER.md 1.5-draft.

### The contacting party gets more than one code per session

**Document:** QR_SECRET_TRANSFER.md · **Section:** §6, §13 · **Kind:** suspected error

1.4 §6 said a party in the middle "gets one attempt per session". The contacting
party learns the other's nonce before revealing its own, so it knows the code
first, and can walk away and contact again from a fresh burner. With §13's caps it
got three or five codes per session; with a cap counted on candidates *currently
held*, unlimited. The implementation's first version did exactly that, and review
demonstrated a hundred codes from one burner in one session.

Resolved in §6 and §13: one nonce exchange per burner, ever; caps count every
contact over the session; §6 states the bound as the cap over 100 000. Lowering the
caps, or having the showing party commit first, is left open in Status.

### The burner key is not secret, so anyone reading a relay can respond

**Document:** QR_SECRET_TRANSFER.md · **Section:** §11.2, §11.3a, §13 · **Kind:** suspected error

The showing party publishes and subscribes with its burner key on the relays its
QR names, so a reader of those relays can contact the session without seeing the
QR. At `type` that only uses up §13's cap; at a level with no code it would win the
payload.

Resolved in §11.2 and §11.4: every QR carries a one-time `token`, echoed inside the
first sealed message; a contact without it is not a responder.

### One check level for every payload

**Document:** QR_SECRET_TRANSFER.md · **Section:** §9.2, §12.3 · **Kind:** design disagreement

1.4 allowed only a typed or captured code, plus the light flow for one profile.
How much checking a transfer deserves depends on what is moving.

Resolved in §9.2: `none`, `compare` and `type`, agreed per pairing as the stricter
of the two parties' settings, with a profile minimum (§5). The light flow is now
the `none` level.

### What ends a session when a candidate sends ABORT

**Document:** QR_SECRET_TRANSFER.md · **Section:** §13 · **Kind:** suspected error

§13 forbade a *later* responder from aborting the session, for fear of denial by
one forged message. The same holds for the first: a stranger who answers first and
then sends ABORT denied the session just as well.

The same held for a Receiver that showed the QR and declined a payload: §7 step 17
said "discard all, abort", so a stranger who answered first and sent something
ended the session by being declined.

Resolved in §7 and §13: at `compare` and `type` no responder ends the session for
the device that showed the QR, by ABORT or by a declined payload; the Receiver
drops that candidate and moves on.

### Flow B: what a typed code is compared against, and what declining does

**Document:** QR_SECRET_TRANSFER.md · **Section:** §8, §9.2 · **Kind:** ambiguity

"Works one candidate at a time" and "a value matching none of its held candidates
advances" admitted comparing with the active candidate only, or with all of them.

Resolved in §8 and §9.2: at `type`, compare with every ready candidate; exactly one
match releases, more than one is a miss. Declining ends the session.

### Flow A: who advances the Receiver's display, and which payload it may keep

**Document:** QR_SECRET_TRANSFER.md · **Section:** §7 steps 12 and 16, §9.4, §13 · **Kind:** ambiguity

The miss happens on the Sender, which transmits neither the code nor the result, so
the Receiver cannot know to advance or which candidate "the Sender confirmed".

Resolved in §9.4 and §13: the user tells the Receiver to show the next code; the
Receiver keeps only a payload from the candidate whose code is on screen, and drops
one from a candidate whose code was never shown.

### Smaller readings

**Document:** QR_SECRET_TRANSFER.md · **Section:** various · **Kind:** ambiguity

Resolved in 1.5: §9.2 against §14 on storing the code (completed transfers only);
§9.3's failed session and failed burner; §11.4's timestamps (all three true) and
window start (each party's own); §11.2's relay encoding and count; §11.6 (only the
showing party reads NIP-11); §11.5's dedupe (after signature verification) and
relay text (untrusted, bounded); §11.2a framing; §11.4's clock warning (only where
a client can tell).

---


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
