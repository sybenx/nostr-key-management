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

Issues concerning the three gaps already named in [README.md](README.md) — the
placeholder event kinds, the absence of test vectors, and the missing
`EMOJI_TABLE` in Appendix A — do not need to be filed here. They are known and
tracked.

---

## Open

### Threshold mode without a server is specified but unreachable

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.3 (touches §5, §7.4, §7.6)
**Kind:** suspected error

§5 now states that at `t = 2` any two shareholders reconstruct the key, and names
enrolling no server as the only configuration in the design where there is no
second party to collude with. §7.6 supports that: "With **zero servers enrolled**
the condition is vacuously satisfied by design: trusted devices are then the
normal co-signers for everyone."

There is no way to get there. §7.3 is the only screen that enables threshold
signing — "the client MUST NOT enable threshold signing by any path other than
the user selecting A on this screen or in settings" — and it is titled *shown
once per server enrollment*. Its option A reads "Your server sees what your other
devices post," which describes a configuration the user choosing serverless
threshold mode does not have.

So the one configuration that answers the collusion property in §5 is described
in §7.6, permitted by §7.4's index scheme, and reachable through no flow the
specification writes. A user with two native apps and no server cannot select it,
and an implementer following §7.3 literally will not build it.

**Proposed fix:** §7.3 should be triggered by threshold enablement rather than by
server enrollment, and should offer a third option, or a variant of A, whose copy
covers the serverless case: the key is split across your own devices, they
co-sign for each other, nothing is reachable when they are not, and no third
party holds a share. §5's claim that this is the only in-design answer to
collusion should link to it once it exists.

### `t` is a constant, not a parameter

**Document:** NOSTR_KEY_MANAGEMENT.md
**Section:** §7.4 (touches §5)
**Kind:** design disagreement

§7.4 states `t = 2` flatly. Combined with §5, this means the specification offers
no configuration in which two colluding shareholders is survivable — the only
mitigation available is reducing the *number* of shareholders, not raising the
threshold.

For a user who believes they may be targeted individually, `t = 3` across three
independent holders is the trade they would want: every signature needs three
parties online, in exchange for surviving any two of them agreeing.

**Proposed fix:** §7.4 should define `t` as a parameter with `2` as the default
and `3` specified for deployments with three or more independent shareholders,
and §7.3's mode screen should surface the choice only where the device list can
satisfy it. The index scheme in §7.4 already accommodates this; what is missing
is the parameter and the copy.

## Resolved

### A failed probe can leave a browser Holder with no transport at all

Resolved in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) §11.3, which makes the
probe advisory rather than selective for a client with only one transport
available in its current role. The section it was filed against
(`NOSTR_KEY_MANAGEMENT.md` §3.1) no longer exists.

### §5 did not state that at t = 2 any two shareholders are the key

Resolved. `NOSTR_KEY_MANAGEMENT.md` §5 now states the collusion property as the
first bullet of the threshold section: any two shareholders reconstruct, collusion
is not a protocol event, and no audit or approval in §7 constrains it.

The two other fixes proposed in the original entry were **not** made and are
filed separately under Open — threshold mode without a server is unreachable, and
`t` is still a constant.
