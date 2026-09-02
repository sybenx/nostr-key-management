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

None currently open.

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

### Threshold mode without a server is unreachable — obsoleted by 9.0

Filed against the 8.0 model, in which any two shareholders reconstruct and a
serverless configuration was named as the only one with no second party to collude
with. The 9.0 "replicas by index" rework removed that configuration. Under §7.4
every device holds a replica of index 2, replicas of one index never combine, and
§7.6 states plainly that only a server co-signs — "there is no device-to-device
fallback." There is therefore no serverless-threshold mode to make reachable, and
no two-shareholders-reconstruct property to answer: any number of devices is one
share and yields nothing alone. Availability with nothing reachable is met by a
self-hosted server (§7.2) or Offline mode (§7.14), and §7.3 being triggered by
server enrollment is now correct, since threshold signing requires a co-signer. The
§5 and §7.6 text this entry quoted no longer exists.

### `t` is a constant, not a parameter — obsoleted by 9.0

The entry wanted `t = 3` so that two colluding shareholders would be survivable.
The 9.0 "replicas by index" rework makes that survivability structural rather than a
function of the threshold. The only two share-classes are the server (index 1) and
the devices (index 2); any number of devices is one share, and two devices cannot
combine (§5, §7.6). Colluding devices therefore yield nothing, and the single
meaningful signing pair is server + device. `t = 2` is intrinsic to the two-index
design; a third independent index would be a different architecture, not a parameter
of this one. The concern the entry raised is answered by the redesign, not by
raising `t`.
