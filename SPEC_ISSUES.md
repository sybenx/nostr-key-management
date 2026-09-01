# Specification Issues

This file is the place to record disagreements with
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

### A failed probe can leave a browser Holder with no transport at all

**Section:** §3.1 (touches §0, §6, §8)
**Kind:** suspected error

§3.1 probes relay and local-network reachability in parallel with a 3-second
timeout and then selects from the result: "The transfer uses relays if
reachable, else local network, else §6." Two of those three are closed to a
browser. §3.1 itself states that browsers cannot use the local path in either
role, and §6 states that browsers cannot act as Holder there. §8 nevertheless
says that any device holding the nsec MAY act as Holder, at any storage level,
which includes a browser.

A browser Holder whose relay probe times out therefore has no transport at all:
the local path is excluded by §3.1, off-grid is excluded by §6, and the probe
has already decided. A session the specification allots ten minutes (§3,
*Session*) is closed out in three. A browser *Joiner* is not affected — §6
remains open to it — so the loss falls entirely on the Holder side.

The probe failure is not hypothetical, and reachability at t=0 is a poor
predictor of reachability a few seconds later: Safari on macOS failed the probe
on a first attempt against public relays and succeeded immediately on a retry,
with the connections warm.

This conflicts with §0: "Nothing in this spec may prevent a user from logging
in, transferring, or using their key on a device that lacks a feature." The
browser lacks mDNS and a screenshot-block flag; §3.1 converts that into a
transfer that cannot be attempted at all.

**Proposed fix:** In §3.1, replace "The transfer uses relays if reachable, else
local network, else §6." with: "The transfer uses relays if reachable, else
local network, else §6. For a client with only one transport available to it in
its current role, the probe is advisory rather than selective: the client MUST
show transfer UI, MUST re-attempt the unreachable transport for the remaining
lifetime of the session (§3), MUST proceed as soon as a transport becomes
available, and MUST report failure only once the session has expired."

### At t = 2 any two shareholders are the key, and §9 does not say so

**Section:** §9 (touches §11.4, §11.6, §11.12, §11.13)
**Kind:** suspected error

§9 states, of threshold mode: "Once every device has ACKed, no device, site, or
server holds a usable key: each holds one share." That is true and it is the
sentence a reader will carry away. The property it does not state is that **any
two shareholders, colluding, hold the key** — because `t = 2`.

The document establishes this in pieces and never in general. §11.12 says a
hostile restricted origin that obtains a server dump "can then reconstruct
silently," but files it under server *compromise*. §9 states the trusted-device
case — "A compromised trusted device plus a reachable server is the key" — but
not the restricted-site case, which is the more likely pairing in practice.

The general form is stronger than either: server + site, server + trusted device,
and trusted device + site all reconstruct. And reconstruction by collusion is not
a protocol event. Two shareholders exchange share values out of band and
interpolate; there is no signing request, no round, no `AUDIT_DIGEST` entry, no
rate to exceed, and no approval to withhold. Every detection and containment
mechanism in §11.13 assumes a party is *using* the protocol. Two-device approval
(§11.1) does not apply either, since after reconstruction the colluders need
nothing from the protocol at all.

This matters most for the pairing the design otherwise treats as routine: a user
who enrols one server and logs into one website has, at that moment, two
shareholders whose collusion is total, silent and permanent. §11.13's audit
surface is written entirely against a hostile site facing an *honest* server, and
is silent about a dishonest one.

**Proposed fix:** three changes.

1. §9, threshold section, add as the first bullet: "**At `t = 2`, any two
   shareholders reconstruct the key.** Server and site, server and trusted
   device, or trusted device and site each suffice. Collusion is not a protocol
   event — shareholders may exchange share values directly — so no audit,
   rate-limit, allowlist, or approval in §11 constrains it. The guarantee of this
   mode is that no *single* party holds a usable key; it is not a guarantee
   against two parties agreeing."

2. §11.3's mode screen, which currently frames the choice as offline posting
   versus revocability, should state the collusion boundary in the same plain
   language it uses for the rest, and should present **enrolling no server** as a
   supported configuration rather than a degenerate one. §11.6 already makes
   trusted devices the normal co-signers when no server is enrolled; a user with
   two native apps can therefore run threshold mode with no server to collude
   with, which is the only in-design answer to this entry. That configuration is
   currently discoverable only by inference from §11.6's fallback clause.

3. §11.4 should define `t` as a parameter with `t = 2` as the default rather than
   a constant, and specify `t = 3` for users who hold three or more independent
   shareholders and prefer availability loss to collusion exposure. Without this,
   the specification offers no configuration in which any two parties colluding
   is survivable.

## Resolved

*None yet.*
