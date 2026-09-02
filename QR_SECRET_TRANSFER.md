# QR Secret Transfer — Specification

Version 1.0-draft
Applies to: any two devices moving a secret between them under user supervision

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

A secret moves between two devices over infrastructure that neither device
operates, registers with, or trusts. One device shows a QR code, a person
compares a short code on two screens, and the secret travels encrypted over
public infrastructure that learns nothing — not the secret, not who sent it,
not that the two parties are related.

Everything else is an addition on top of that, and an addition MUST degrade to
it. Nothing in this specification may prevent a transfer that the user has
authorised and that both devices are capable of performing.

## 1. Overview

**The QR is a mailbox address, plus which postal system to use.** The mailbox is
created for this one exchange and destroyed when it ends. The post office cannot
read the mail, cannot tell who sent it, and did not ask anyone to register.

What makes this a *transfer* rather than any other QR code is precisely that the
code carries an address at which the showing device can be reached — never the
secret itself. A QR containing the secret is a different and weaker thing; it
appears here only as the offline fallback of §10, and only with its own
encryption.

The exchange is:

1. One device generates a throwaway keypair and shows its public half as a QR.
2. The other scans it and generates its own throwaway keypair.
3. The two exchange a commitment and two random numbers, from which both derive
   the same five-digit code.
4. A person compares that code on both screens. This is what defeats an attacker
   in the middle.
5. Only after the person confirms does the secret travel, encrypted end to end.
6. Both throwaway keypairs are destroyed.

This document specifies the mechanism. §§3–10 state what it needs without
assuming how it is provided; §11 is the Nostr binding, and is the only binding
defined here.

## 2. Definitions

- **Sender** (`SND`) — the party that holds the secret and releases it.
- **Receiver** (`RCV`) — the party that obtains it.
- **Burner** — an ephemeral keypair created for one session and destroyed after.
  `SND.pub` and `RCV.pub` are the burner public keys.
- **Session** — one transfer attempt. Lifetime 10 minutes. Burners MUST NOT be
  reused across sessions.
- **Contacting party** — whichever party scans the QR and speaks first. This is
  the Sender in Flow A (§7) and the Receiver in Flow B (§8).
- **Profile** — the definition of one kind of payload (§5).
- **Payload** — the secret being moved, as bytes, opaque to this specification.

Roles are named by what a party does with the secret, never by which party
shows the QR — the device showing it differs between Flow A and Flow B, so any
naming keyed to the QR would denote opposite parties in adjacent sections.

## 3. Transport contract

**Nostr is the only binding this document defines, and no other is anticipated.**
The requirements below are written out anyway, because a specification that names
what it needs from its transport can be checked against it, and one that simply
assumes a transport cannot.

Two things follow from having them written down. §11.1 maps each requirement to
the NIP-59 machinery that satisfies it, which makes "is Nostr sufficient?" a
question with an answer. And it makes the harder question askable too: any
requirement of gift wrap that maps to nothing below is inherited rather than
load-bearing, and either a simpler construction exists or the cost is being paid
for nothing.

A conforming transport MUST provide:

- **T1 — Ephemeral addressing.** A party can be addressed at a freshly generated
  public key, with no prior registration of that key and no relationship between
  the key and any long-lived identity.
- **T2 — No account.** Neither party holds an identity, credential, or
  relationship with the transport operator. Nothing is provisioned to begin a
  session.
- **T3 — Confidentiality.** Message contents are unreadable by the operator and
  by third parties.
- **T4 — Unlinkability.** The operator cannot link a session to either party's
  long-lived identity, and an observer cannot link the two parties of a session
  to each other.
- **T5 — Sender attribution.** Each delivered message carries a verifiable
  indication of which burner sent it, and that indication cannot be forged by
  the operator or by a third party. Every step of §§6–8 that says "verify
  attribution" depends on this; without it the short authentication string binds
  to nothing.
- **T6 — Capacity.** A single message carries at least the maximum payload
  declared by the profile in use (§4, P1).
- **T7 — Untrusted operator.** The operator may drop, delay, and observe
  messages. It MUST NOT be able to forge or substitute them undetectably.
  Substitution by an active attacker is handled by the SAS (§6); the transport
  is not required to be honest for confidentiality to hold.
- **T8 — Expiry.** A message can be given a bounded lifetime after which the
  transport ceases to carry it.
- **T9 — Liveness within the session.** Best-effort delivery inside the
  ten-minute session window. No ordering guarantee is required beyond what the
  flows themselves enforce.

**Not a requirement, but the reason this is practical.** A transport satisfying
T1–T9 through a *single* operator would technically conform, but the approach is
only interesting where many interchangeable operators exist and none of them is
yours. That is an availability and censorship property, not a correctness one,
and it belongs to §15 rather than to this contract.

## 4. Payload requirements

The payload is opaque to the mechanism. These are the constraints it must
satisfy for the mechanism to work; everything else about it is the profile's
business.

### P1 — Bounded size

One payload, one message. The payload is nested and re-encrypted by the
transport, which expands it — under the binding of §11, **×3.4 for binary
payloads and ×4.7 for hex-encoded ones**, so that a 32-byte secret occupies
about 1.9 KB on the wire.

Transport limits, not encryption limits, set the ceiling, and real transports
impose several of them at different granularities. A profile MUST therefore
declare which tier it requires:

| Tier | Max payload (binary) | Reach |
|---|---|---|
| **1 — RECOMMENDED** | **2048 B** | operators at every limit observed |
| 2 | 21 KiB | operators at the common default |
| 3 | 30 KiB | a minority of operators |

Tier 1 is the default and SHOULD be preferred. Tiers 2 and 3 are specified so
that an implementer can make the tradeoff deliberately; this document does not
make it for them. §11.6 derives these figures for the Nostr binding; another
binding replaces them.

Payloads SHOULD be binary encoded as base64 rather than hex, which costs roughly
40% of the budget for no benefit. Profiles carrying tens of bytes MAY use hex,
where framing dominates regardless.

A conformance test vector MUST exist at exactly the declared maximum. The
transport's padding is discrete, so an off-by-one-chunk error is invisible for
every payload except those near a boundary — precisely where nobody tests.

### P2 — Single-shot

**One payload, one session.** Chunking, fragmentation and resumption MUST NOT be
attempted over public infrastructure. Three reasons:

*Operational.* Relay operators are not obliged to carry anyone's traffic. A
client pushing bursts of large messages will be rate-limited and then blocked,
and such blocks land on the message type generally — which is to say on other
people's private messages, not only on the offender's transfers. The mechanism
does not get to externalise its costs onto infrastructure nobody is paying for.

*Anonymity set.* A single small wrapped message is indistinguishable from
ordinary encrypted traffic, which is why T4 holds in practice — the transfer
hides in the crowd. Twenty sequenced messages between two keys that have never
spoken before do not look like ordinary traffic, and an observer who can pick
the transfer out has recovered exactly what the wrapping was chosen to deny.

*Definitional.* T2 and P1 are one constraint seen from two sides. The mechanism
may use infrastructure it does not own, pay for, or register with precisely
because it asks almost nothing of it. Asking more forfeits the property.

**If you need to move large data this way, operate the infrastructure
yourself.** That is a
legitimate deployment and nothing here forbids it — but it is a different
proposition, not a scaling tier of this one. The moment capacity requires
infrastructure you operate, the claim collapses back to ordinary client and
server, which is the thing this mechanism exists to avoid.

Were multi-message transfer ever specified for such a deployment, it would
require at minimum: chunk ordering, a completeness check, integrity over the
reassembled whole so that dropping one chunk is detectable, and a session
lifetime beyond ten minutes. It is recorded here so that the gap is not filled
incompatibly by implementers who assume it was an oversight.

**Companion messages are a separate question, and are permitted.** P2 forbids
splitting *one* payload across messages. It does not forbid a profile defining an
additional, semantically distinct message in the same session — a new device
often needs something alongside the secret to be useful at all, a relay list
being the obvious case. A profile MAY define such messages, subject to all of:

- At most **three** per session, each individually within P1. This is a budget,
  not a licence: every extra message widens the traffic pattern P2's second
  argument is about, and a profile wanting more is describing a sync protocol
  rather than a transfer.
- **Sent alongside the payload, not after it.** The Sender emits them in the same
  session without waiting for anything; the Receiver holds them under P6 exactly
  as it holds the payload, keyed by the sending burner, and commits them only
  together with the payload they arrived beside. Companions from a burner whose
  payload is never committed are discarded with it.

  They cannot be sent after acceptance: the Receiver zeroizes its burner at the
  moment it commits and ACKs (§7 step 17, §8 step 17), and the ACK is how the
  Sender would learn acceptance had happened — so a rule to send afterwards
  addresses a channel that no longer exists. Holding-then-committing-together
  delivers the property that rule was reaching for (nothing accepted without a
  payload) without needing that window, and has the further merit that the
  release consent of §9 authorises the payload and its companions in one act
  rather than authorising something that happens later.
- **Covered by the same release consent.** §9's prompt names what will be sent,
  and that naming MUST include the companions. A user who approved sending a key
  must not discover afterwards that a relay list or a device label went with it.
- Not required for completion: a Receiver that never gets them MUST still hold a
  usable payload, since delivery is best-effort (T9). A Receiver MUST NOT make
  the user's ability to confirm contingent on companions having arrived, and MUST
  commit the payload whether or not any did.

  It MAY wait a bounded interval *after* confirmation for companions still in
  flight, provided the bound is short and expiry commits the payload regardless.
  This is worth permitting: a device that arrives holding a key but no relay list
  is functionally broken even though the transfer succeeded, and a second or two
  after the user has already decided costs nothing they will notice.

*Common misreading:* the ceiling is a property of the transport, not of the QR,
and exchanging addresses does not lift it. The QR only ever carried a public
key.

### P3 — Opaque to the carrier

The mechanism MUST NOT parse, validate, or depend on the structure of the
payload. A carrier that inspects payloads acquires a compatibility relationship
with every present and future profile.

### P4 — Identifiable against the declared profile

The Receiver MUST be able to determine that what it received belongs to the
profile declared in the QR (§11.2, `p=`), and MUST abort if it does not. The
check is defined by the profile; the requirement to have one is defined here.

Without this, an implementation supporting more than one profile can be induced
to accept a payload of a kind the user did not intend, and the consent prompt of
§9 cannot truthfully name what is being sent.

### P5 — Renderable to a person

A profile MUST define a human-meaningful rendering of the received payload,
shown for confirmation before the payload is committed to storage (§9).

This is load-bearing, not cosmetic: it is the defence against an attacker who
photographed the QR racing the real Sender to plant a payload of their own. A
payload that cannot be meaningfully summarised to its recipient MUST NOT use
this mechanism.

### P6 — Safe to hold and discard

A Receiver may hold several candidate payloads simultaneously (§13) and commits
at most one. A payload MUST tolerate being received, held, and wiped without
side effects. Implementations MUST bound the number held; see the pending cap in
§8.

### P7 — Confidentiality from the transport, except offline

A payload need not encrypt itself; T3 covers it. The exception is the offline
fallback (§10), which has no transport at all. A profile that permits offline
transfer MUST define its own passphrase-based encryption for that case.

## 5. Profiles

A profile defines one kind of payload. It is identified by a string matching
`[a-z0-9-]{1,24}`, carried in the QR, and MUST specify:

1. The payload encoding and its meaning.
2. The tier of P1 it requires.
3. The check satisfying P4.
4. The rendering satisfying P5.
5. Its confirmation copy for §9 — what the Sender's prompt says is being sent.
6. Whether the offline fallback (§10) is permitted, and if so the encryption
   satisfying P7.
7. Any additional message tags, which MUST NOT collide with the reserved names
   in §11.4.
8. Any companion messages (P2): what each carries, the value of its `companion`
   tag (§11.4), and the wording by which §9's release prompt names them.

A profile MAY restrict which parties are permitted to act as Sender, and MAY
disallow the offline fallback entirely. Implementations MUST ignore tags they do
not recognise.

Profiles are defined outside this document. `nostr-nsec` and `frost-share` are
defined in the Nostr key storage specification.

**Why the payload is parameterised at all.** Not in anticipation of users outside
this ecosystem — the transport is Nostr relays, so anyone able to adopt this has
already adopted Nostr. It is parameterised because *this* ecosystem has more than
one secret worth moving between devices, and does today: a whole identity key and
a threshold share are different sizes, need different acceptance checks, and must
be described to the user in different words. A specification handling only the
first would have to special-case the second within a year of being written.

### 5.1 Non-normative example

To show the extension point is sufficient, not to define anything:

> **Profile `example-token`.** Payload: a bearer token, UTF-8, base64. Tier 1.
> P4 check: decodes as valid base64 and parses as a JWT with a recognised
> issuer. P5 rendering: "a token for *example.com*, issued 14 March, expiring 21
> March." Sender prompt: "Send your example.com token to …". Offline fallback:
> not permitted.

## 6. Session and short authentication string

A short authentication string is only safe if neither party can choose its
inputs after seeing the other's. The contacting party therefore commits to a
nonce before the other reveals its own, and the code derives from both burners
and both nonces.

```
contacting party:  nonce_C ← random 32 B
                   commit  = SHA-256("qrst-commit-v1" || C.pub || nonce_C)
                   sends { C.pub, commit }
other party:       nonce_O ← random 32 B;  sends { nonce_O }
contacting party:  sends { nonce_C }
both:              verify SHA-256("qrst-commit-v1" || C.pub || nonce_C) == commit
                   code    = SHA-256("qrst-sas-v1" || len(p) || p
                                     || SND.pub || RCV.pub || nonce_S || nonce_R)
                   digits  = (code[0..5] as u40 BE) mod 100_000, zero-padded to 5
```

`SND.pub` and `RCV.pub` are the 32-byte burner public keys in role order,
regardless of flow. In Flow A the contacting party `C` is the Sender, so
`nonce_C = nonce_S`; in Flow B it is the Receiver. `p` is the profile identifier
from the QR (§11.2) as ASCII, preceded by its length as a single byte. Five
bytes are drawn so that the modulo bias is negligible.

Neither party transmits the code. Each derives it from values it already holds,
and it reaches the other device through a person reading a screen (§9).

### Why five digits

**Chiefly for what the length tells the user.** No secret anyone holds is five
digits long: bank and device PINs are four or six, one-time codes are six.
People carry strong templates for those shapes — a four-position field reads as
*PIN*, a six-position field reads as *the code from my messages* — and five
matches neither. The mismatch registers the way a phone number with the wrong
number of digits looks wrong before anyone has counted it.

That works in the honest case, on every ordinary pairing, rather than only during
an attack. Each legitimate transfer teaches the correct model: *this is not a
secret I already know; it is a number that appears on my other screen.* A user
who has internalised that is the user who hesitates when some unrelated page asks
for four digits or six. It reinforces the naming rules of §9, and unlike a
warning it costs no attention.

**The arithmetic is secondary and points the same way.** Because the code is
carried between devices rather than confirmed (§9), length is not doing the work
length usually does — a code that must be transported cannot be passed by someone
who never read the other screen, at any length. What it must survive is one
online attempt by an attacker whose value was fixed before the honest randomness
was revealed. Five digits make that one in a hundred thousand: a tenfold
improvement over four for one keystroke.

### What the transcript binds, and what it deliberately does not

The code commits to the protocol version (via the domain separator), the profile,
both burners, the role each burner holds, and both nonces. Binding the profile
means the two parties agree on *what kind of secret is moving* as part of what is
verified, rather than leaving P4 to a check the Receiver performs alone after the
fact.

It does **not** bind the relay set or the chosen transport, and that is a decision
rather than an omission. §11.3 permits the relay and local paths to be raced,
permits falling back between them mid-session, and permits trying the next relay
when one rejects a publish. A transcript committing to the transport would turn
every one of those recoveries into a mismatch — an availability feature becoming
a security failure the user cannot distinguish from an attack. It would also buy
nothing: the transport is untrusted by construction (T7), so an attacker who
controls the path still cannot produce a matching code.

### Why the commit

Without it, an attacker in the middle — showing the Sender a QR for a burner they
control while talking to the real Receiver as another — learns the Sender's
burner from the first message, fixes the Sender's code, and grinds their own
values offline until the Receiver's code matches. Five digits is 2^16.6: seconds
of work on ordinary hardware, finished while the user is still looking at the
second screen.

Widening the code does not fix this. Any string short enough for a person to
carry between two devices is short enough to grind offline. **Without the commit
the code is worthless at every length**, which is why the commit rather than the
length is the load-bearing part of this section.

With the commit, each attacker-chosen value is fixed before the honest randomness
it must match is revealed. The attacker gets one attempt per session — one in a
hundred thousand — and every failure is a mismatch on a screen a person is
already looking at. This is the ZRTP construction, also used by Matrix.

### The retry loop is the dominant term

A rejected code reads as a mistype, so the user restarts the pairing, and each
restart is a fresh session and a fresh attempt:

| Sessions | Cumulative risk |
|---|---|
| 1 | 1 in 100 000 |
| 10 | 1 in 10 000 |
| 100 | 1 in 1 000 |

This, not the code length, is where an attacker accumulates chances. An
implementation that lets a user restart indefinitely without comment gives back
more than any plausible number of extra digits would buy.

§9 therefore throttles it: a failed session cannot be resumed, the Sender refuses
to re-pair with a burner it has already failed against, and repeated failures
within an hour are surfaced to the user as possible interference rather than as
isolated glitches. It is the control in this specification that carries the most
weight.

**Cost.** One extra message on the contacting side. Both flows are four messages
before the payload moves.

## 7. Flow A — Receiver shows the QR

Used when the Receiver cannot scan (desktop, browser), or whenever the Sender is
a phone.

```
Receiver                                    Sender
--------                                    ------
1. gen burner RCV
2. begin listening at RCV.pub
3. show QR: mode=offer, p=<profile>
                                            4. scan QR; verify it implements p,
                                               else abort before generating
                                               anything
                                            5. gen burner SND, nonce_S
                                            6. send HELLO(SND.pub, commit)
                                               → RCV.pub
7. receive HELLO; verify attribution (T5);
   gen nonce_R for this SND
   (a HELLO from a second distinct burner
    → §13; keep each with its own nonce_R)
8. send NONCE(nonce_R) → SND.pub
                                            9. receive NONCE
                                           10. send REVEAL(nonce_S) → RCV.pub
                                           11. derive SAS; show the consent
                                               prompt of §9
12. receive REVEAL; verify commit; derive
    SAS for this SND; DISPLAY the code
    (all candidates, at most 3, newest
    first): "Type this on your other
    device"
                                           13. user types a code from the
                                               Receiver's screen (§9); match → 14
                                               declines or 5 failures → abort,
                                               zeroize SND
                                           14. send PAYLOAD → RCV.pub
15. receive payload and any companions;
    verify attribution; hold keyed by
    sending burner. MUST NOT commit
16. if more than one payload is held, user
    selects by code; applies the P4 check;
    renders per P5 ("Log in as @name?");
    asks to confirm
17. confirmed → commit payload and the
    companions held beside it; send ACK
    → SND.pub; zeroize RCV and every other
    held payload
    declined → discard all, abort
                                           18. zeroize SND on ACK or after 60 s
```

Step 13 authorises *release* on the device that holds the secret, and it is the
step that cannot be completed without having read the other screen — the code is
typed, not confirmed (§9). Steps 16–17 authorise *acceptance* on the device that
receives it. Both are required. Without the second, anyone who photographed the
QR could race the real Sender and plant their own payload on the Receiver; the
Receiver therefore never commits without the user seeing, in the P5 rendering,
whose identity is about to be adopted.

A substituted QR, with or without a grinding attacker in the middle, produces a
SAS the real Receiver's screen does not show (§6). A hostile party that *is* the
Receiver produces a matching SAS; what stands against that is the prompt at step
11, which is why §9 requires it to name what the Receiver claims to be.

## 8. Flow B — Sender shows the QR

Used when the Sender cannot scan (camera-less desktop, browser).

```
Sender                                      Receiver
------                                      --------
1. gen burner SND
2. begin listening at SND.pub
3. show QR: mode=request, p=<profile>
                                            4. scan QR; verify it implements p,
                                               else abort
                                            5. gen burner RCV, nonce_R
                                            6. send REQUEST(RCV.pub, commit)
                                               → SND.pub
7. receive REQUEST; verify attribution;
   gen nonce_S for this RCV
8. send NONCE(nonce_S) → RCV.pub
                                            9. receive NONCE
                                           10. send REVEAL(nonce_R) → SND.pub
                                           11. derive SAS; DISPLAY own code —
                                               "Type this on your other device:
                                                [digits]"
12. receive REVEAL; verify commit; derive
    SAS; show the consent prompt of §9
13. user types the code shown on the
    Receiver's screen (§9); match → 14
    (declines → discard this RCV; show the
     next pending request, if any, or keep
     waiting; abort only at 10 min)
14. send PAYLOAD → RCV.pub
                                           15. receive payload and any companions;
                                               verify attribution and that the
                                               sending burner is the SND.pub from
                                               the QR, else discard
                                           16. apply P4 check; render per P5;
                                               ask to confirm
                                           17. confirmed → commit; send ACK
                                               → SND.pub; zeroize RCV
18. zeroize SND on ACK or after 60 s
```

Requests are queued by distinct Receiver burner in arrival order, capped at
**five pending per session**; further distinct requests are dropped with the
§13 notice. Each queued request runs its own nonce exchange, and only one is
shown for approval at a time. Declining advances to the next or returns to
waiting; the session ends on approval or at the ten-minute limit. Under the cap,
a flooder costs the user at most a handful of declines.

Note that in Flow B the Receiver has no independent screen to compare against
before it sends its request — the SAS is shown to it at step 11 and to the
Sender at step 12, and the Sender is the party that acts on the comparison. The
Receiver's acceptance confirmation at step 16 remains required.

## 9. Consent and confirmation

Two distinct user actions, on two devices, guarding two different things. Both
are mandatory and neither may be defaulted, remembered, or suppressed.

**Release consent, on the Sender.** Before any payload is sent, the Sender MUST
present a prompt that:

1. Names what is being sent, in the profile's words (§5, item 5), and states
   that it is the secret itself that will leave this device — not a session, not
   a permission that can later be withdrawn. Where the profile's secret cannot
   be revoked once released, the prompt MUST say so.
2. Names what the other party claims to be — its self-declared platform and, for
   a browser, its origin. These are unverified claims. They exist so that a
   dishonest party must lie in a way the user can read. Origins containing
   non-ASCII MUST be shown as punycode, so homoglyph domains read as what they
   are.
3. Presents the means of obtaining the Receiver's code — the entry field or the
   capture control described below. The Sender MUST NOT display the code it
   derived itself. A prompt that shows the expected value beside the field for
   it reduces entry to copying from one screen, which is precisely the failure
   the requirement below exists to remove.
4. Requires a deliberate action. The Sender MUST NOT release before it.

**The Sender MUST obtain the Receiver's code from the Receiver's display and
verify it locally.** Confirming that two screens match is not enforceable: where
only one candidate is offered, a person moving quickly taps the only thing on
screen and the comparison never happens. Requiring the code to be *carried* from
one device to the other converts that from a diligence the design hopes for into
a step that cannot be completed without having read the other device. This is
the distinction Bluetooth draws between numeric comparison and passkey entry,
and it is why the latter is the stronger mode.

**Two conforming methods**, and an implementation MAY offer either or both:

- **Entry.** The user reads the digits and types them.
- **Capture.** The user points this device's camera at the Receiver's display and
  the code is read optically. A Receiver SHOULD therefore render its code in a
  machine-readable form alongside the human-readable one.

They are equivalent, because the property being enforced is not typing but that
the code crossed a channel the user had to physically aim. Capture exists so that
this specification does not require a keypad: a signer with a camera and two
buttons is a legitimate and desirable implementation, and mandating entry would
exclude it for no security gain.

Neither method defends against a user who aims at the wrong screen — reading a
code off an attacker's display and typing it in matches just as capturing it
would. What both defend against is not looking at all, which is the failure that
actually occurs.

**Confirmation alone does not conform.** A control that merely asks whether the
codes match — a tap, a button press, a biometric prompt — MUST NOT be used in
place of entry or capture. A biometric or platform credential proves *who is
present*; it carries no information about whether that person compared anything.
Where a profile requires such a check as well (§5), it is complementary to this
step and never a substitute for it.

- The Receiver displays the five digits of §6. The Sender presents an entry
  field and compares what is typed against the value it computed itself. A
  mismatch aborts.
- **Where entry is used, the field MUST make its length visible** — five discrete
  character positions, not a bare text input. The length is what tells the user
  this is not a credential they already hold (§6), and a field that does not show
  its length cannot say so. For the same reason the field MUST accept exactly
  five digits and MUST NOT silently accept more.
- Where capture is used, the same attempt budget and failure handling apply: a
  captured code that does not match counts as an attempt.
- At most **five** attempts per session; on the fifth failure the Sender abandons
  the session and zeroizes its burner. Five rather than three because of the
  multiple-responder case below. Five attempts against five digits is a
  5-in-100 000 exposure to someone typing at random — but typing at random cannot
  succeed at anything except skipping a check the user had no reason to skip, so
  the relevant bound remains the single fixed attempt of §6.
- **Where the Receiver holds more than one candidate** — someone else scanned the
  code (§13) — it displays each candidate's digits, at most three. The Sender's
  user does not need to know which is which: they type codes from that screen
  until one is accepted or the attempt budget is spent. Only the code computed
  with the party the Sender is actually talking to will match, so an attacker
  among the responders is rejected without the user having to identify it. This
  is why the budget exceeds the number of candidates shown.
- The field MUST NOT be pre-filled, and MUST NOT be auto-completed from the
  clipboard. Where both parties run on one machine they may share a clipboard,
  and an autofill would restore exactly the failure this requirement removes.

**A failed session is dead, and restarting means scanning again.** Attempts
within one session give an attacker nothing: their value was fixed when the
nonces were revealed, so retyping can only fail against the same code. Those
attempts exist for a user who mistyped, or who is working through several codes
in the multiple-responder case. Every chance an attacker gets comes from a *new*
session, so that is what must be made expensive.

- On exhausting its attempts the Sender zeroizes its burner and ends the session.
  The client MUST return the user to the scan step. It MUST NOT offer to re-enter
  a code, reopen the entry field, or resume the session in any way.
- **The Sender MUST NOT begin a new session with a peer burner it has already
  failed a code entry against**, and MUST remember those burners for at least one
  hour. Without this the rule is bypassed trivially: the Receiver is still
  displaying the same QR — it has no way to know the Sender failed — so a user
  who rescans that screen reuses the same burner and the attacker's position
  survives the restart. Refusing on the Sender's side forces a genuinely fresh
  code to be generated.
- The Sender SHOULD send `ABORT` (§11.4) to the peer burner before zeroizing, so
  the Receiver can discard that candidate and present a fresh code immediately
  rather than leaving the user waiting out a ten-minute timeout. Its absence
  means nothing and MUST NOT be relied on; a Receiver that never receives one
  simply times out as usual.
- After **three** failed sessions within one hour, the client MUST tell the user
  that repeated failures can indicate interference rather than mistyping, and
  SHOULD require an explicit acknowledgement before another attempt. This is the
  only place where an attacker accumulates chances, and it is where the user
  should be told so.

The friction is the point, and it is deliberately imposed on both parties. An
attacker who wants another attempt must get a fresh code in front of the user
again; a user who is merely being persistent is asked, by the third failure, to
consider why.

**The code is never transmitted, and the comparison is never delegated.** Both
parties derive it independently from the handshake (§6); it appears on one
screen, passes through a person, and is entered on the other. That human step is
the whole mechanism — it is the one channel an attacker in the middle does not
sit on.

- The typed value MUST NOT be sent to the peer, in any form, encrypted or not.
- The Sender MUST compare it against the value it computed itself. A comparison
  result asserted by the peer MUST NOT be accepted under any circumstances. An
  implementation that sends the code across and asks the other side "did that
  match?" has handed the decision to the party it is trying to authenticate,
  who will answer yes.
- The typed value MUST NOT be written to logs, analytics, crash reports, or any
  storage that outlives the session.

**It is not a PIN, and MUST NOT be called one.** A short numeric entry field at a
security-critical moment is exactly the shape of the prompts people are phished
with, and a protocol that trains the reflex has built something an attacker can
borrow. The five-digit length of §6 helps — it matches no credential a user
holds — but users do not count digits, so the naming does the real work. Two
requirements follow:

- Interfaces MUST NOT label it "PIN", "passcode", or anything the user might
  possess independently. It is a *pairing code*, and it belongs to this session
  only.
- The prompt MUST state where the code comes from — "the code shown on your other
  device" — rather than asking for "your code". Sourcing it externally is what
  keeps a user from reaching for a secret they already know when some other
  screen asks the same way.

Implementations MUST NOT request this code anywhere outside an in-progress
transfer.

The burden sits on the Sender because the Sender is the party who loses
something. The Receiver is not asked to type anything: it already holds a
stronger control in the P5 rendering, which names *whose identity is about to be
adopted*. Spotting a name that is not yours requires reading one word rather
than comparing eight characters, so it survives inattention better than any code
would.

**The prompt MUST contradict the expected mental model, in the heading.** A
person who has just scanned a QR believes they are signing in, because that is
what scanning a QR means nearly everywhere else. The heading's job is to break
that assumption before the buttons are read — *"This is not a login. You are
about to give this device your key."* Naming the mismatch is what converts a
reflex into a decision.

**Declining MUST be the prominent control.** The affirmative control MUST NOT be
the visually dominant one, MUST NOT be the focused or default control, and MUST
NOT be activated by a default keyboard action. Someone moving quickly, on
autopilot, must land on *not sending*. Where the two controls carry text, the
affirmative one MUST describe the transfer rather than express agreement:
"Send my key to that device" rather than "OK" or "Continue" — a person can tap
"OK" without having formed a belief about what they are approving; they cannot
tap "Send my key to that device" the same way.

**Friction MUST be graduated by what the other party claims to be.** Uniform
alarm is self-defeating: adding a second device is an ordinary act, and a
warning shown identically every time is one users learn to dismiss without
reading. Two tiers:

- **A web origin.** Maximum friction. This is the case §15 names as the
  principal residual risk, and it is the case that is almost always an attack:
  a legitimate transfer to a website is possible but rare, while a hostile page
  requesting a key is the expected shape of the attack. The prompt SHOULD
  require an additional deliberate act beyond a single tap, and MUST name the
  origin in the affirmative control itself.
- **A native application.** Standard friction. Deliberate and unambiguous, but
  not alarming. This is the ordinary case and treating it as an emergency
  spends the user's attention where it is not needed, which is what leaves none
  for the case above.

**Authorisation is scoped to one session and MUST NOT outlive it.** Consent, and
any platform credential or biometric check a profile requires alongside it (§5),
authorise exactly one transfer session. They MUST NOT be remembered, defaulted,
cached, or carried into a subsequent session, and MUST NOT open a period during
which further transfers proceed unchallenged.

Binding this to the session rather than to a clock is deliberate: a timed window
is something an attack can ride, and it asks the user to reason about a duration
they were never shown. One unlock, one transfer, and the authorisation dies with
the session it was given for — which the ten-minute lifetime already bounds.

This does not defend against a user who is deceived *during* the session; they
will unlock willingly, and the release prompt above is what stands there. What it
removes is the class of attack that exploits residual state — a window left open
by a legitimate transfer an hour earlier, or a compromised client waiting for an
unlocked moment.

**Acceptance confirmation, on the Receiver.** Before a payload is committed, the
Receiver MUST require the user to select the SAS matching the Sender's screen
from the candidates it holds, and MUST then show the P5 rendering and require
confirmation.

This side is **not** alarming, and MUST NOT be presented as though it were. The
user is gaining something rather than giving something away, and the asymmetry
in tone is deliberate: it is what keeps the Sender's warning meaningful. But it
is not risk-free either, which is why the confirmation is still mandatory — the
attack it prevents is someone planting *their* secret on this device so that the
user unknowingly operates as them (§7). The P5 rendering exists so the user can
see whose identity they are about to adopt.

**What the SAS does and does not do.** It proves that the Sender and the party
that showed the QR share an untampered channel, defeating a substituted QR and
an attacker in the middle. It does **not** defeat a hostile party that genuinely
*is* the Receiver: such a party holds a real burner, receives the real messages,
and displays a matching code. Against that, the only defence is a user reading
the release prompt and declining. This is a residual risk of the mechanism and
implementations MUST NOT describe the SAS as protecting against it.

## 10. Offline fallback

Available only when no transport is reachable and the user confirms they are
offline, and only where the profile permits it (§5). The payload here travels
inside the QR itself, so every property of §3 is forfeited and the payload's own
encryption is all that remains (P7).

1. The Sender prompts for a passphrase, with the line **"Anyone who photographs
   this code can try passwords against it forever; this passphrase is the only
   protection."**
2. The Sender displays the profile's passphrase-encrypted encoding of the
   payload as a QR. The screen sets the platform screenshot-block flag and
   auto-dismisses after 60 seconds. Where no reliable flag exists — X11 has
   none, Wayland is compositor-dependent — the Sender proceeds with an explicit
   warning that screenshots cannot be blocked.
3. The Receiver scans, prompts for the same passphrase, decrypts, applies the P4
   check, renders per P5, and asks to confirm before committing.
4. The Sender records a transfer event with the offline flag set (§14).

A party without a reliable screenshot-block flag MUST NOT act as Sender here.
There is no SAS in this flow; the passphrase and the physical proximity of the
two screens are the whole of the authentication.

## 11. Transport binding: Nostr

**This is the only Nostr-dependent section.** Everything above is written
against §3 and holds for any conforming transport. A different binding replaces
this section and nothing else.

### 11.1 How the contract is satisfied

| Requirement | Provided by |
|---|---|
| T1 ephemeral addressing | secp256k1 burner keypairs; wraps addressed by `p` tag |
| T2 no account | relays accept unauthenticated publishes; burners are unregistered |
| T3 confidentiality | NIP-44 v2, twice — rumor to seal, seal to wrap |
| T4 unlinkability | NIP-59 gift wrap: random one-time signing key, randomised `created_at` |
| T5 sender attribution | the seal (kind 13) is signed by the sending burner |
| T6 capacity | §11.6 |
| T7 untrusted operator | relays cannot forge a seal signature |
| T8 expiry | NIP-40 `expiration` tag |
| T9 liveness | relay subscription for the session's duration |

This table is the argument that Nostr is a sufficient substrate. It is also the
place to check whether it is a *minimal* one: any requirement of NIP-59 that
traces to no row here is inherited rather than load-bearing, and a simpler
construction — or a cheaper substrate — may exist.

### 11.2 QR URI

```
qrst://<npub>?v=1&mode=<offer|request>&p=<profile-id>[&relay=<wss url>]*[&local=<ws url>][&plat=<platform>][&origin=<host>]
```

- `npub` — bech32 burner public key of the device showing the QR.
- `mode=offer` — the showing device is the Receiver (Flow A).
- `mode=request` — the showing device is the Sender (Flow B).
- `p` — profile identifier (§5). REQUIRED.
- `relay` — 1–4 relay URLs the showing device is subscribed to.
- `local` — optional LAN endpoint, e.g. `ws://192.168.1.23:53317`.
- `plat` — self-attested platform: `ios|android|macos|windows|linux|web`. For
  `web`, `origin=<host>` is REQUIRED.

`plat` and `origin` are unverified claims, used only to populate the release
prompt of §9. A client MUST reject URIs with unknown `v`, missing `mode`, or
missing `p`, and MUST abort before generating a burner if it does not implement
the declared profile.

**Role collision.** A client that has already committed to a role — the user
chose to send, or to receive — MUST reject a URI whose `mode` implies that same
role, and MUST say so rather than failing later. Two Senders or two Receivers
cannot complete a session, and the failure is otherwise discovered several steps
in. A client that has not yet committed adopts the complementary role from the
`mode` it scanned, and has nothing to refuse.

**Why `p` is required rather than optional.** It is hashed into the SAS (§6), and
anything feeding that derivation must be unambiguously present: an optional field
needs a canonical encoding for its absence, two implementations will choose
differently, and the result is two devices computing different codes from
identical sessions. That failure is silent and indistinguishable from an attack —
matching inputs, mismatched screens, an abort nobody can diagnose. Requiring the
field removes the whole class for a few characters of QR.

It is also what lets the scanning party tell the truth. §9 and §11.2b require the
prompt to name what will move, and the scanner knows only what the URI says; an
absent profile forces an implementation to write "a secret" where it should
write "your key". And it moves a profile mismatch to scan time, before any burner
exists, rather than to the end of a ceremony the user has already completed —
failing late at a security prompt teaches people that failures there are noise.

With a single profile defined this is redundant today. It is required from the
outset because a field that becomes mandatory later is a breaking change, and
because a document built around an open extension point should not defer the one
field that identifies the extension in use.

Profiles MAY register additional `mode` values.

### 11.2a Carrying the URI in an `https` link

A QR SHOULD encode the URI as an `https` link with the complete `qrst://` URI in
the **fragment**:

```
https://<origin>/<path>#qrst://<npub>?v=1&mode=…&p=…
```

**Why not the scheme alone.** A page cannot register a URI scheme, and a phone's
stock camera or a third-party scanner app hands an unknown scheme to a web search
rather than to an application. Android App Links and iOS Universal Links route a
verified `https` URL to an installed app and fall back to the browser; a custom
scheme gets a disambiguation dialog at best. A QR carrying only `qrst://` is
therefore unusable by web clients and by the generic scanners many people scan
with, which is most of the ways this code will actually be read.

**Why the fragment.** Fragments are not sent in HTTP requests. The burner key and
relay list therefore never reach the origin's server, its logs, or any
intermediary — the link is addressed to a host that never learns what it carries.

**Requirements.**

- A client whose own camera reads the code MUST extract the URI from the fragment
  and MUST NOT make the request. The page load is the fallback for scanners that
  do not understand this protocol, never the normal path.
- The `origin` SHOULD be the one already serving the client that drew the code.
  No party is introduced that the user was not already trusting with the transfer.
- The landing page SHOULD be a **bounce page**: it reads its own fragment, offers
  the `qrst://` deep link for anyone holding a native client, offers the URI as
  copyable text for any other client, and acts as a party itself only if the
  visitor chooses that origin's own client. Because the fragment never reaches the
  server, such a page can be entirely static — this path introduces no operator,
  and §3's claim survives it.
- `qrst://` remains valid and is the RECOMMENDED form for deep links and for
  copied text (§12.1).

**Consequence for consent.** A scanned `https` code opens a page, so a hostile
code can deliver a hostile page which is then the Receiver. The extra friction
§12.1 requires for a pasted URI that makes the local device the Sender applies
identically to a scanned `https` code that was not read by the client's own
camera.

There is one compensation: landing on the origin puts it in the browser's address
bar, which is the only place in this protocol where the origin a party claims in
§9 is corroborated rather than self-declared.

### 11.2b Presenting the code

**A QR MUST NOT be displayed bare.** It is accompanied by a line, in the user's
language, stating the direction and what will move: "Scanning this sends your key
to this device", "Scanning this sends one share of your key", "This device is
receiving a key". The profile supplies the wording (§5, item 5).

This sentence is what makes the method obvious, and it is the only thing that
does. A code shown inside an application, on a screen the user deliberately
opened, is already unambiguous as to *kind*; what it is not automatically
unambiguous about is *direction*, which is the thing that decides whether the
user is about to gain something or give something away.

**Release and receipt MUST look different.** A `mode=offer` code, which makes
whoever scans it the Sender, is presented with visibly greater weight than a
`mode=request` code. The person who needs the warning is the one holding the
camera, and the rendered code is all they see before scanning.

**Overlays.** Implementations MAY place a logo or wordmark at the centre of the
code — this is conventional and the centre is the only available area, since the
three outer corners hold the finder patterns a scanner uses to locate and orient
the code. An implementation that overlays anything MUST raise error correction to
level **H** and keep the overlay under 25% of the code's area, and SHOULD verify
its codes still scan at the smallest screen size it supports; level H roughly
halves capacity for a given code size, so a URI of a couple of hundred characters
produces a visibly finer grid.

**No overlay may imply assurance.** Whatever sits in that space MUST NOT be a
badge, seal, shield, tick, padlock or ribbon, and MUST NOT be rendered in
whatever colour the implementation uses elsewhere for success, verified or
trusted states. Anyone can reproduce any mark on a hostile code, so a mark that
reads as safety is worse than no mark: the browser padlock meant only that a
connection was encrypted, users read it as "this site is trustworthy," and Chrome
removed it in version 117 rather than keep explaining the difference.

This specification defines no mark of its own. Identifying the code is the job of
the URI, read from the fragment by a client that implements this protocol
(§11.2a); telling the user what is about to happen is the job of the sentence
above, which a person reads. Neither job needs a logo.

Note that a generic scanner reads an `https` link and learns nothing
protocol-specific from it, because the scheme sits inside the fragment where the
origin never sees it. That is deliberate, and it is why the accompanying sentence
carries the whole burden of telling a person what they are looking at.

Implementations MUST NOT relax any consent step of §9 on the basis of anything
rendered on or beside the code.

### 11.3 Transport selection

Before showing transfer UI, the client probes in parallel, timeout 3 s:

1. Relay reachability — WebSocket open and `REQ` accepted on at least one
   configured relay.
2. Local network reachability — mDNS browse for `_qrst._tcp`, or a `local=`
   endpoint from a scanned QR.

The transfer uses relays if reachable, else the local network, else §10. Both
paths MAY be attempted concurrently; the first payload successfully received
completes the session and the other is cancelled.

**For a client with only one transport available to it in its current role, the
probe is advisory rather than selective:** the client MUST show transfer UI,
MUST re-attempt the unreachable transport for the remaining lifetime of the
session, MUST proceed as soon as a transport becomes available, and MUST report
failure only once the session has expired. Browsers have no mDNS and cannot open
`ws://` to private addresses from `https://`, so a browser has relays or §10 and
nothing else; reachability at t=0 is a poor predictor of reachability seconds
later, and a three-second probe MUST NOT close out a ten-minute session.

### 11.4 Messages

```jsonc
// HELLO — Sender → Receiver (Flow A): the Sender's commit
{ "kind": 24401, "content": "", "tags": [["burner","<SND.pub hex>"],["commit","<hex>"],["v","1"]] }

// REQUEST — Receiver → Sender (Flow B): the Receiver's commit
{ "kind": 24402, "content": "", "tags": [["burner","<RCV.pub hex>"],["commit","<hex>"],["v","1"]] }

// NONCE — non-contacting party → contacting party
{ "kind": 24403, "content": "", "tags": [["burner","<own burner hex>"],["nonce","<hex>"],["v","1"]] }

// REVEAL — contacting party opens its commit
{ "kind": 24404, "content": "", "tags": [["burner","<own burner hex>"],["nonce","<hex>"],["v","1"]] }

// PAYLOAD — Sender → Receiver
{ "kind": 24405, "content": "<profile-defined>", "tags": [["burner","<SND.pub hex>"],["v","1"]] }

// ACK — Receiver → Sender, after the payload is committed
{ "kind": 24406, "content": "", "tags": [["burner","<RCV.pub hex>"],["v","1"]] }

// ABORT — either party → peer, this session is over (§9)
{ "kind": 24407, "content": "", "tags": [["burner","<own burner hex>"],["v","1"]] }

// COMPANION — Sender → Receiver, emitted alongside the payload (§4)
{ "kind": 24408, "content": "<profile-defined>", "tags": [["burner","<SND.pub hex>"],["companion","<profile-defined name>"],["v","1"]] }
```

All kinds are unregistered placeholders and will change; they should be
reserved in the kind registry before implementations ship.

**These kinds never reach a relay.** Rumors are unsigned and are never
published — only the kind-1059 wrap is. Choosing an ephemeral range
(20000–29999) for the inner kinds therefore has no effect on relay retention,
and any reasoning about retention must be done about kind 1059, which is a
regular event. What bounds retention is the expiration tag below, together with
the receiver-side enforcement in §13.

Reserved tag names: `burner`, `commit`, `nonce`, `companion`, `v`. Profiles MAY
add tags to any message; implementations MUST ignore tags they do not recognise.

**Companions share one kind.** Every companion message a profile defines (§4)
uses kind 24408 and is distinguished by its `companion` tag, whose values the
profile assigns (§5, item 8). The kind is fixed rather than allocated per
profile because the session's profile is already fixed by the QR (§11.2), so the
tag is unambiguous in the only scope where it is ever read, and profiles defined
outside this document need no kind registry to avoid colliding with each other.
A Receiver MUST ignore a companion whose name it does not recognise and MUST NOT
treat it as an error. The three-per-session cap of §4 counts every kind-24408
rumor in the session, recognised or not.

These are unsigned rumors. **Every one of them** is sealed — kind 13, signed by
the sender's burner, NIP-44 to the recipient burner — and gift-wrapped — kind
1059, random one-time key, `p` tag set to the recipient burner — exactly per
NIP-59. There are no exceptions: every message in this protocol is addressed to a
burner and wrapped, which is what makes the attribution check below apply
uniformly.

The wrap MUST carry `["expiration","<real wall-clock now + 600>"]` per NIP-40,
computed from the true current time and **not** from the wrap's
NIP-59-randomised `created_at`, which may be up to two days in the past.

**Clock slack.** Session-window tests (§13) compare a rumor's own timestamp
against the session's ten-minute lifetime with a tolerance of
**`SLACK = 120` seconds** at each end. Two honest devices routinely disagree by
tens of seconds, and without tolerance those sessions fail for no reason. The
tolerance costs nothing: a rumor two minutes outside the window still falls
inside the session and still counts toward the multiple-responder test of §13,
so backdating within `SLACK` buys an attacker nothing.

`SLACK` is normative rather than an implementation choice. If one client accepts
what another rejects, honest pairings fail between them, and that failure is
indistinguishable from interference.

**NIP-40 is advisory and MUST NOT be relied on for enforcement.** A relay may
honour it, ignore it, or serve the event long after it has lapsed, and a hostile
relay certainly will. Expiry is enforced by the receiver: a rumor whose own
un-randomised timestamp falls outside the ten-minute session window MUST be
discarded from the session entirely (§13), whatever the wrap claims and whatever
the relay served. The `expiration` tag is a courtesy that lets well-behaved
relays drop dead traffic; it is not a security control.

**Attribution check (T5).** A sender's burner identity appears in three places,
and all three MUST agree or the rumor is discarded:

1. the rumor's own `pubkey` field, which MUST be set to the sending burner;
2. the `burner` tag;
3. the key that signed the seal.

The redundancy is deliberate but it is redundancy, and a specification that
constrains only some of the three invites implementations to disagree about the
rest. The rumor's `pubkey` is included because NIP-59 rumors carry one whether or
not this document uses it, and an unspecified field is one an implementation may
populate — and another may read.

### 11.5 Relay subscription

The receiving side subscribes:

```
{"kinds":[1059], "#p":["<own burner hex>"], "since": now - 172800}
```

Dedupe by event id. The `since` window is required because NIP-59 randomises
`created_at` up to two days back.

**Publishing is parallel, not serial.** A client publishes each message to every
relay from the QR that it has an open socket to, rather than trying them in turn.
There is no security reason to prefer serial delivery — each relay sees the same
unlinkable wrap — and racing them removes a latency cost from a session with a
ten-minute budget. If every relay rejects a publish (allowlist, paid, unknown
key), the client falls back to the local path.

**Clients MUST keep a session outbox.** Every message published during a session
is retained until the session ends, and republished to each relay (a) when a
socket to it opens, and (b) after a NIP-42 authentication with it succeeds. The
motivating case is otherwise silent in this specification: a relay may accept a
socket, receive a publish, and only then demand `AUTH`, leaving the event
discarded on a relay the peer is subscribed to. Without replay the session
stalls until timeout while both parties appear reachable. Recipients dedupe by
event id, so replay is free.

If a relay returns `auth-required`, the client authenticates with its **burner**
under NIP-42. The wrap is addressed to that burner, which is exactly what
auth-gated relays check, and it reveals nothing. Neither side ever uses a
long-lived identity for relay authentication during a transfer.

### 11.6 Size

The nested construction expands the payload substantially: rumor, then seal,
then wrap, each with base64 expansion and NIP-44's power-of-two padding.
Measured expansion from raw payload to published event is **×3.4 for base64
payloads and ×4.7 for hex**.

Two relay limits apply, and the second binds far harder than implementers
expect:

| Limit | Where | Max payload (base64) |
|---|---|---|
| `max_content_length` = 8196 | NIP-11's example value | 2 082 B |
| `maxEventSize` = 65536 | strfry's default | 21 282 B |
| `maxWebsocketPayloadSize` = 131072 | strfry's default | 30 498 B |

`max_content_length` caps the `content` field alone, which is where the entire
nested ciphertext sits. A 4 KiB payload needs 13 744 content characters and
fails outright against it. This is the origin of the tier table in P1.

Note that 8196 is the *example* value printed in NIP-11 rather than a measured
default — strfry's stock configuration sets no content cap. How many deployed
relays advertise and enforce one is unmeasured, which is the argument for tiers
rather than a single number.

**Clients SHOULD read `max_message_length` and `max_content_length` from NIP-11
during the §11.3 probe and skip relays that cannot carry the declared profile's
tier.** Otherwise the client discovers the limit from a rejected publish, inside
a three-second transport selection.

### 11.7 Local network path

- The listening party opens a WebSocket on a random port ≥ 49152 and advertises
  `_qrst._tcp` with TXT `npub=<burner npub>`.
- The other party connects and sends the wrap as a single text frame containing
  the kind 1059 event JSON.
- Same messages, seal, wrap, SAS, and cleanup as the relay path. The LAN is
  untrusted; the wrap already assumes that.

Browsers cannot use this path in either role.

## 12. Pairing without a camera

Wherever a flow says "scan the QR", the scanning party MAY instead obtain the
same URI by one of the substitutions below. Each replaces only the pairing step:
burners, SAS, messages, consent and cleanup are unchanged, and the security
argument is unaffected because the URI is not secret (§15) — it carries a burner
public key and transport hints, and an attacker holding it still cannot produce
a matching SAS.

A client MAY implement either substitution or both.

### 12.1 Copying the URI

The showing party offers its URI as selectable text; the other party pastes it.
This works wherever text can travel between the two devices at all — a shared
clipboard on one machine or across an ecosystem, but equally a message or email
the user sends to themselves. That last case is what makes paste the channel of
last resort rather than a convenience: two camera-less machines with no shared
clipboard still have a way through, provided a person can move a line of text.

**Clients MUST accept either form.** A paste field takes a bare `qrst://` URI or
an `https` link per §11.2a, from which the URI is read out of the fragment.
Parsing either is trivial and requiring one would strand users of the other.

**Clients SHOULD offer `qrst://` for copying.** It is shorter, and it does not
present as something to tap. An `https` link sent in a message looks like an
ordinary link and invites a reflex; a `qrst://` string looks like configuration
and invites reading. Given that a URI is remotely deliverable in a way a QR is
not, the less tappable form is the safer thing to put behind a copy button.

The URI MUST be validated before use: the bech32 checksum on the burner key
catches transcription errors in the part most likely to carry them.

**Sending it through a third party is permitted and costs nothing structural.**
The URI is not secret (§15) — it is a public key and some transport hints — so a
messaging provider that sees it learns nothing that helps it. It does learn
*metadata*: that a pairing happened at that moment, and which relays are involved.
That is a real if minor leak, and it is a further reason the URI must never be
permitted to carry payload material.

**Additional friction for URIs that make the local device the Sender.** A QR read
by the client's own camera implies physical proximity: someone placed it in front
of the user. A pasted URI does not — it can be sent in a message, which is the
delivery channel every credential-theft campaign already uses. Where a URI would
make the local device the Sender (`mode=offer`) and did not come from the
device's own camera, the client MUST present the release consent of §9 with an
explicit statement that the request did not originate from a scan, and MUST NOT
allow that consent to be remembered or defaulted. Per §11.2a this applies equally
to an `https` code opened from an external scanner. It does not remove the
residual risk of §9; it declines to widen it silently.

### 12.2 Channels this specification does not define

A typed code cannot carry a public key. A burner key is 32 bytes, and no
compression puts that into something a person will type, so a code-based pairing
cannot *convey* a key the way a QR does — it must **bootstrap** one, using a
low-entropy shared secret to establish a high-entropy channel. That requires a
password-authenticated key exchange, which is a cryptographic primitive nothing
else in this specification uses.

Such a channel is legitimate and an implementation MAY build one. It is not
specified here because it is a different protocol that hands off to this one
rather than a variation of it, and because two properties of it cannot be settled
within this document:

- **It needs a rendezvous nobody conveys.** The QR carries relay hints, so the
  two parties agree on where to meet because one of them said so. A typed code
  has no room for a URL, and a device being provisioned has no relay list of its
  own, so both sides must independently arrive at the same rendezvous. That means
  a designated transport relay — named infrastructure, which §3 exists to avoid,
  and which in practice limits such a channel to clients that already share a
  configuration.
- **It runs before this protocol's addressing exists.** Every message defined in
  §11.4 is sealed and wrapped to a recipient burner. A bootstrapping exchange has
  no recipient key yet, so it must be addressed to something anyone holding the
  code can compute — a public rendezvous identifier — which is a different shape
  with its own denial-of-service surface.

An implementation that builds one hands off at a defined point: once both parties
hold the other's burner public key and the parameters of §11.2, Flow A or Flow B
proceeds unchanged from immediately after the scan, and every requirement of §6
and §9 applies as written.

Interoperability is the trade. QR and paste interoperate across clients because
this document specifies them; a bootstrapped channel is a per-client feature, and
two clients implementing different ones will not pair.

## 13. Multiple responders

A QR or code is meant to be scanned once. If, within one session, the receiving
side sees messages from **two or more distinct burner public keys** — two HELLOs
in Flow A, two REQUESTs in Flow B — someone other than the user probably scanned
it.

The client shows a soft, non-blocking notice on the device that displayed the
QR:

> Another device also responded to this code. If that wasn't you, someone nearby
> may have scanned it. Nothing was shared with them.

The session continues normally. The SAS comparison decides which responder is
real and the user confirms as usual; the notice is recorded in the transfer
event (§14) with the multiple-responder flag set.

To keep bugs from firing it, the following MUST NOT count as a second
responder: the same message delivered by more than one route; retransmissions
from the same burner; a message that fails to decrypt; and messages whose
sender-set timestamp falls outside the session's ten-minute window, widened at
each end by the `SLACK` of §11.4. Where the transport applies its own timestamp
for unlinkability, that timestamp MUST NOT be used for this test — see §11.4.

Out-of-window rumors are **discarded from the session entirely** — never shown,
never given a nonce exchange, never in the SAS list — not merely excluded from
the counter. Otherwise backdating the inner timestamp would bypass the notice
while still reaching the user.

## 14. Policy

- Any party holding a secret MAY act as Sender, subject to profile restrictions
  (§5).
- A party that received a secret by transfer defaults to **receive-only**. The
  toggle is one action, unguarded, and the transfer screen shows it inline
  ("This device is receive-only — allow sending?") rather than hiding it.
- **Enabling sending MUST expire.** It authorises the transfer at hand, or a
  bounded period the user is shown, and then reverts. It MUST NOT be a permanent
  setting. The toggle stays unguarded — §0 forbids putting a barrier in front of
  a user completing a legitimate transfer — but an unguarded action that grants a
  permanent capability is a permanent capability granted without thought, which
  is a different thing from a low-friction one.
- Every transfer MUST write a local record: timestamp, profile, transport, SAS,
  peer burner, and the multiple-responder flag.
- This mechanism has no remote revocation. A device list, if shown, MUST label
  removal as deleting the local copy only.

## 15. Security properties

- The transport never sees plaintext payload material.
- A photographed or substituted QR yields nothing: it carries a public key; the
  SAS is commit-then-reveal so an attacker in the middle cannot grind a match
  (§6); the Sender releases only after confirming the SAS on its own screen; and
  the Receiver accepts only from the burner it was told about, after the user
  selects the matching SAS.
- **A hostile party acting as Receiver is not stopped by the SAS.** It is stopped
  only by a user declining the release prompt of §9, which is why that prompt
  must name the claimed origin. This is the mechanism's principal residual risk
  and MUST be documented as such by implementations.
- **A Receiver may be hostile conditionally, and reputation is no defence against
  that.** A web origin serves whatever code it chooses to whichever visitor it
  chooses. It can behave correctly for every user who reviews it, builds a
  reputation on that behaviour, and exfiltrate on recognising one particular
  identity. Nothing in this specification — or in any key-transfer protocol —
  can observe which code a party is running at the moment a secret reaches it.

  Two consequences follow. First, the graduated friction of §9 is not
  paternalism about websites in general; it is the recognition that a site's
  good standing carries no information about how it will behave toward *this*
  user. Second, and more importantly, **the only structural answer is not to give
  such a party a usable secret at all.** A profile whose secret is a threshold
  share rather than a whole key converts this from permanent silent theft into
  bounded, logged, revocable use — which is why profiles exist and why §5 permits
  one to restrict who may act as Sender.

  Note also that the loss is not repairable after the fact. Splitting a key does
  not change it, so a party that obtained a whole secret keeps a working copy
  regardless of anything done afterwards. Protections of this kind have to be in
  place before the first release, never in response to a suspicion.
- **Pairing by copied URI widens the delivery channel for that risk.** A QR must
  be placed in front of the user; a URI can be sent in a message, which is how
  credential theft is already delivered at scale. The URI itself is not secret
  and copying it is sound (§12.1), but the attacker's cost of *reaching* a victim
  falls from physical presence to a message. §12.1 requires extra friction on
  the one direction where this matters — a pasted URI that makes the local
  device the Sender.
- The offline fallback (§10) forfeits every transport property; its security is
  the passphrase and the physical proximity of the two screens.
- Burners are per-session and destroyed, so a session cannot be linked to a
  long-lived identity by the transport (T4) — provided the same infrastructure
  is not also carrying that identity's other traffic in a correlatable way.
- A single small wrapped message is indistinguishable from ordinary encrypted
  traffic on the same infrastructure. This is why P2 forbids chunking: a burst
  is distinguishable, and distinguishability defeats T4.
- **Availability comes from interchangeability, not from any operator.** The QR
  carries several interchangeable operators, the local path is a live fallback,
  and none of the operators is party to the transfer. This is the property that makes the
  approach practical rather than merely possible, and it is deployment
  advice, not a conformance requirement.
- A compromised device yields whatever that device holds. Nothing here changes
  that.

## 16. What this rests on

Every other failure in this specification has a rung below it. No relay reachable
falls back to the local network (§11.3); no camera falls back to copying or a
typed code (§12); no network at all falls back to the offline QR (§10). The
cryptography has no rung below it, and because the secrets this moves are often
the whole of an identity, a failure there is total and permanent rather than
confined to one session. That asymmetry is worth stating rather than leaving for
a reader to notice.

What breaks, and what it costs:

| If this fails | Then | Attacker needs |
|---|---|---|
| The transport's encryption (NIP-44 under §11) | Any relay carrying the wrap reads the payload | Only to observe |
| SHA-256 preimage resistance | The commit of §6 stops binding, and the SAS can be ground offline as if the commit were absent | To be in the middle, live |
| SHA-256 collision resistance | Two distinct transcripts can display the same code | To be in the middle, live |
| secp256k1 | Attribution (T5) fails; messages can be forged as from a burner | To be in the middle, live |
| The commit construction, as designed | §6's entire argument | To be in the middle, live |

The distinction in the third column matters: a break in the encryption is
exploitable by anyone who stores relay traffic today and decrypts it later. Every
other row requires an active attacker present during a ten-minute session, which
is a far higher bar and one the user is watching a screen for.

**On the choice of primitives.** secp256k1 is a Koblitz curve with rigid,
explicable parameters, which is why it was chosen for Bitcoin over the NIST
curves and their unexplained seed constants. NIP-44 v2 uses ChaCha20 with
HMAC-SHA256. These are among the most examined constructions in use.

**No part of this specification depends on a trusted setup.** Every constant in
use has an account of where it came from. This was not true of earlier drafts,
which specified a password-authenticated key exchange requiring two fixed curve
points of unexplained provenance; that channel is no longer defined here (§12.2),
and with it went the only ingredient to which the question "what if the constants
are wrong" had a concrete object to attach.

**What this specification does not claim.** That the primitives are unbroken —
only that they are the best-examined available and that the design fails in
different ways depending on which one gives. Nothing here recovers from being
wrong about the mathematics, and no protocol of this shape can.

## 17. Relation to other systems

Nothing in §6 is new. The commit-then-reveal short authentication string is
ZRTP's, by way of Matrix, and is cited as such. What is unusual here is the
substrate, and the comparisons below are the honest way to show which is which.

They also establish something worth stating plainly: **there is no standard way
to move a credential between devices**, because the dominant standard is built on
the premise that credentials do not move. That is not an oversight in those
designs — it is their central commitment, and it is why none of them can be
borrowed here.

### WebAuthn hybrid transport (caBLE v2)

The closest deployed relative: the flow behind "scan this code with your phone to
sign in." It opens identically and then diverges completely.

| | Hybrid transport | This specification |
|---|---|---|
| QR carries | a shared secret | a public key only |
| A photographed QR | compromises the session | is harmless |
| Devices matched by | BLE proximity, automatic | a person comparing a code |
| Infrastructure | vendor-operated tunnel servers | public relays, no operator |
| What crosses | an assertion; the credential never moves | the secret itself |

The last row is an inversion of purpose, not a variation on it. WebAuthn exists
so that private keys never leave the device that created them, and hybrid
transport is the machinery for *using* a key without moving it. This
specification exists to move secrets between devices.

Their approach to matching the two devices is better where it can be used —
proximity is proven automatically and no one has to compare anything, removing
the human error the SAS depends on avoiding. It is not available here: BLE
requires Bluetooth at both ends, and a browser has none. A browser being a valid
party is central to this specification's purpose, so the SAS is not a weaker
stand-in for proximity but the only mechanism that works everywhere this must
work. An implementation of two native applications MAY add a proximity check as
an additional signal; it MUST NOT replace the SAS with one, because that would
make the guarantee depend on hardware some parties cannot have.

### Magic Wormhole

The nearest relative in intent: move a secret between two machines with no
accounts, authenticated by a short human-carried code. It depends on a mailbox
server for rendezvous, and in practice on one canonical instance, so it has an
operator and a single point of failure — which is precisely the dependency that
kept a code-based channel out of §12.

### Signal and WhatsApp device linking, Matrix device verification

All three pair devices through infrastructure the vendor operates and the user
holds an account with. Matrix is also the source, by way of ZRTP, of the
commit-then-reveal construction in §6.

### What is actually different

Every system above requires someone to operate infrastructure for the pairing: a
tunnel server, a mailbox server, a homeserver, a vendor. This specification
requires a transport meeting §3 and nothing else, and Nostr relays satisfy it as
a pre-existing commons that nobody stood up for this purpose and that any party
can substitute at any moment.

That is the claim worth defending, and it is a claim about the substrate rather
than about the cryptography. The cryptography is borrowed on purpose.

## Appendix A — References

NIP-11, NIP-40, NIP-42, NIP-44, NIP-49, NIP-59. BIP-340. ZRTP (RFC 6189) for the
commit-then-reveal construction of §6.

## Status

Version 1.0-draft. Two things are missing: the event kinds of §11.4 are
unregistered placeholders and will change, and the test vectors are incomplete —
the SAS of §6 is covered in `vectors/`, but the one at the declared payload
maximum that P1 requires is not.

Implementation has begun. Review is more useful than deployment at this stage.
