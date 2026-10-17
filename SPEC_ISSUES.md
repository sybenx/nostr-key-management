# Specification Issues

**To report something, [open an issue](https://github.com/sybenx/nostr-key-management/issues/new?template=spec-issue.yml).** The form asks for the same
fields as the format below. This file is the permanent record: entries filed here
before issues were used, and every settled issue, with how it was resolved.

> **Archived.** QR transfer (QRST) moved to
> [sybenx/qr-secret-transfer](https://github.com/sybenx/qr-secret-transfer), and its entries moved to that
> repository's [SPEC_ISSUES.md](https://github.com/sybenx/qr-secret-transfer/blob/main/SPEC_ISSUES.md). What remains
> here concerns the archived storage and threshold-signing documents.

This file records disagreements with
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) and `TIERS.md` (on the
`claude/tiers-normative-doc-k1oq1m` branch). It
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

**Document:** NOSTR_KEY_MANAGEMENT.md | TIERS.md
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

The entries found while building the QRST reference implementation, and the one
resolved in QRST §11.3, moved to
[sybenx/qr-secret-transfer's SPEC_ISSUES.md](https://github.com/sybenx/qr-secret-transfer/blob/main/SPEC_ISSUES.md) with
the specification.

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
