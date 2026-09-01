# Implementation Proposal

**Status:** proposal, not agreed. Nothing here is normative; where this document
disagrees with [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) or
[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md), the specifications win.

This proposes how the two specifications become code a site or an app can adopt
in three lines, what that code cannot honestly promise, and in what order to
build it.

---

## 1. What can be a drop-in, and what cannot

There are three products stacked here with very different adoption stories.
Saying so up front is what keeps the library's README from over-promising.

**QRST is a genuine drop-in, and is the whole product for most adopters.** The
burner handshake, the QR, the typed code, gift-wrapped transfer over relays, the
offline fallback. Self-contained client code with no infrastructure behind it and
nothing for an operator to run. This ships first and is marketed as the product.

**Storage and backup (NKM §2, §7) are a drop-in too**, and belong in the same
package — the storage ladder is what a key does *after* it arrives, and shipping
transfer without it means every adopter invents their own at-rest story.

**Threshold signing (NKM §11) cannot be a single drop-in, ever.** FROST at
`t = 2` with index 1 held by a server is not a client feature, it is a
distributed system. A package implementing the device half is inert without a
server to point at. So §11 is two deliverables — a client and a reference server
— and the honest framing is "run this, then enable that," not "install this."

**Native apps are a fourth thing.** A JavaScript package cannot serve the iOS and
Android clients the specs are largely written for, and hand-writing Swift and
Kotlin ports triples the review surface. The realistic answer is one canonical
TypeScript implementation plus a conformance vector suite that ports validate
against — which is also how the missing test vectors get produced (§6).

---

## 2. The integration surface

Three tiers, each a superset of the one above. Most adopters should never see
tier 2.

### Tier 0 — script tag

```html
<script src="https://unpkg.com/qrst-login"
        data-relays="wss://relay.damus.io,wss://nos.lol"
        data-app-name="Zapstr"></script>
```

Sets `window.nostr` to a NIP-07 signer and dispatches an event on login and
logout. An existing Nostr site that already talks to `window.nostr` integrates by
adding this line and deleting nothing. Deliberately the same shape as
`nostr-login`, because that shape is proven and a site evaluating both should not
have to restructure to try ours.

### Tier 1 — the module API

```ts
import { NostrKeys } from '@qrst/web'

const keys = await NostrKeys.open({
  relays: ['wss://relay.damus.io'],
  appName: 'Zapstr',
})

if (keys.status === 'empty') {
  await keys.login()        // draws the QR, runs QRST Flow A, resolves once stored
}

const pubkey = await keys.signer.getPublicKey()
const event  = await keys.signer.signEvent(draft)
```

`keys.signer` satisfies NIP-07 exactly, so `window.nostr = keys.signer` is a
valid line of user code and every existing library keeps working. `keys.login()`
is QRST Flow A — the browser is always the Receiver showing the QR, because a
browser cannot scan reliably and, per NKM §11.1, is always `restricted` anyway.

Everything else is progressive disclosure on the same object, and none of it is
required to log in:

```ts
keys.storageLevel                     // 1 | 2 | 3, per NKM §2.1
keys.lock                             // 'device' | 'launch' | `idle:${number}`
keys.export({ password })             // NKM §7.1, always ncryptsec, privileged
keys.backup.connect(url, password)    // NKM §11.2 → §7.2
keys.backup.recover(url, password)    // NKM §11.10 — throws in a browser, by spec
keys.devices.list() / .remove(id)     // NKM §11.1, §11.11
keys.threshold.enable() / .disable()  // NKM §11.5, §11.15 — trusted devices only
keys.on('lock', s => …)               // NKM §11.16 states, for the indicator
keys.on('alert', a => …)              // NKM §11.13 digests and alerts
```

Methods a browser may not perform are present on the type and reject at runtime
with a named error (`RestrictedRoleError`) rather than being absent. A missing
method reads as an incomplete library; a refusal citing NKM §11.13 teaches the
integrator what the role system is for.

### Tier 2 — headless

```ts
const session = createTransferSession({
  role: 'receiver', mode: 'offer', profile: 'nostr-nsec', …adapters
})
session.qrUri                          // QRST §11.2, and the https form of §11.2a
session.on('code', digits => …)        // display; the peer types it
session.on('verified', () => …)
```

For anyone drawing their own UI: React Native, a desktop app, an embedder who
wants the flow inside their own modal. Same state machine as tier 1 with the
screens removed.

**Profiles are a first-class parameter, not a hidden constant.** QRST carries an
opaque payload and `p=` names what it is. A library that hard-codes `nostr-nsec`
will need breaking changes the first time it moves anything else, so the profile
is an argument from the first commit even while only one exists.

---

## 3. Package layering

The layering serves one goal: **`core` is pure, so a Swift or Kotlin port has
exactly one thing to reimplement and exactly one suite to prove it against.**

| Package | Contains | Depends on |
|---|---|---|
| `@qrst/core` | Every derivation and state machine, as pure functions over injected randomness and clock. Commit/nonce/reveal and code derivation (QRST §6), URI parse and build (§11.2, §11.2a), message construction and validation (§11.4), Flow A/B state machines (§7, §8), profile registry (§5), blob-store key schedule (NKM §7.2), FROST wrappers, refresh algebra (NKM §11.9), epoch ordering. No I/O, no DOM, no `fetch`, no timers. | `@noble/curves`, `@noble/hashes`, `@scure/base` |
| `@qrst/web` | The adapters that make `core` run in a browser: storage per NKM §2.3, relay transport with the outbox of QRST §11.5, WebAuthn gate, `navigator.storage.persist()`, camera and fragment parsing. Exports `NostrKeys`. | `core` |
| `@qrst/ui` | The screens the specs write copy for: QR with the direction line of §11.2b, the code entry field with its visible length, the release prompt of §9 with the origin as punycode, the lock indicator (NKM §11.16). Framework-free custom elements. | `web` |
| `qrst-login` | Tier 0. One IIFE bundle, no build step for the adopter, sets `window.nostr`. | `ui` |
| `@qrst/server` | The reference blob store (NKM §7.2) and co-signer (§11.6) with the audit rules of §11.13. One codebase, two targets: Cloudflare Worker and Node. | `core` |
| `@qrst/vectors` | Generates the normative test vectors from `core`; runs them as a conformance suite any implementation can execute. | `core` |

`core` communicates with its host by returning **commands as data**, never by
calling out:

```ts
type Command =
  | { t: 'publish';  relays: string[]; event: NostrEvent }
  | { t: 'subscribe'; filter: Filter }
  | { t: 'store';    slot: 'nsec' | 'share' | 'E'; bytes: Uint8Array }
  | { t: 'prompt';   kind: 'release' | 'accept' | 'privileged'; text: string; claims: Claims }
  | { t: 'expect-code'; length: 5 }
  | { t: 'zeroize';  handle: Handle }
```

Two consequences make the indirection worth it. A test can drive an entire flow
with a fake clock and fixed randomness and assert on the exact byte sequence —
which is what a *vector* is. And a native port implements the adapters in its own
language while running the same command trace, so "interoperable" becomes
something CI checks rather than something two authors believe.

---

## 4. Repository layout

```
nostr-key-management/
├── README.md                      # pitch, then: the specs are here, the code is there
├── spec/
│   ├── QR_SECRET_TRANSFER.md
│   ├── NOSTR_KEY_MANAGEMENT.md
│   ├── OVERVIEW.md
│   ├── SPEC_ISSUES.md
│   └── vectors/                   # generated, committed, referenced normatively
│       ├── sas.json
│       ├── payload-ceiling.json
│       ├── blob-store.json
│       ├── ncryptsec.json
│       └── frost.json
├── packages/
│   ├── core/ web/ ui/ login/ server/ vectors/
├── examples/
│   ├── plain-html/                # the three-line integration, verbatim
│   ├── react/
│   └── worker/                    # deploy the reference server in one command
├── pnpm-workspace.yaml
└── .github/workflows/ci.yml       # typecheck, unit, conformance vectors, size budget
```

`git mv` for the existing documents; every current link is relative and `spec/`
keeps them adjacent, so only `README.md` needs editing.

---

## 5. One repo

**Settled: both stay here, and probably permanently.**

The earlier argument for splitting assumed QRST would have a different audience
as a general-purpose primitive. It doesn't. The transport is Nostr relays, so
anyone implementing QRST is already a Nostr developer — the same person who cares
about storage and threshold signing. The audiences don't diverge, so the repos
don't need to.

Keeping them together also has a positive reason: the implementation is what
*produces* the test vectors, and a vector living in a different repository from
the requirement it tests will drift the first time either side moves quickly.

The real cost is that a specification sharing a repository with its reference
implementation reads as a product's documentation rather than a standard. Handle
the adjacent problem — `SPEC_ISSUES.md` is designed for spec disagreements while a
library attracts "fails under Vite 7" — with issue templates and a `spec:` /
`impl:` label pair. If QRST is ever submitted as a NIP and wants its own issue
tracker, extraction is a `git subtree split`, and there is no need to organise
around that in advance.

---

## 6. The two gaps, closed by code

The specs name what is missing. Both remaining gaps close by writing code, which
is why "review is more useful than implementation" is now true of *deployment*
rather than of writing.

**Test vectors.** `@qrst/vectors` generates them from `core` with fixed
randomness: the code derivation from profile id, both burner keys and both nonces
through to the five digits; the payload ceiling at exactly the declared maximum,
where NIP-44's power-of-two padding makes an off-by-one-chunk error invisible
everywhere else; the NKM §7.2 ladder from password and salt through `K_pw`,
`K_enc`, `K_auth`, `K_wrap` to a decryptable blob; `ncryptsec` at both `log_n`
values; and for §11, a full activation, one refresh, and a joint issuance with
the parity case covered explicitly, since odd-y is where an independent
implementation will first diverge.

**Event kinds.** They stay unregistered until a NIP lands, so the mitigation is
containment: one `KINDS` constant module, the `v=1` check already required at
parse time, and a published `0.x` whose README says kinds will change and
interoperability is not promised before 1.0. Nothing is tagged 1.0 until the
kinds are real.

*(The third gap, the emoji table, closed by deletion rather than by code — the
comparison it served was replaced by typed entry, so there is no table to
specify.)*

---

## 7. Build order

Each milestone is useful to somebody on its own, which matters when the author
count is one.

**v0.1 — the actual drop-in.** NKM §2 storage ladder with silent probing and
in-place upgrade; QRST Flow A and B over relays; the typed code and its attempt
budget; the multiple-responder notice; the offline fallback; NKM §7.1 `ncryptsec`
export; NIP-07 signer; tier 0 bundle. No server, no account, nothing to run.
Ships the first vector files.

**v0.2 — backup.** NKM §7.2 blob store, `@qrst/server` on a Worker, §11.10
recovery in a native context only, and the recovery-delay notices. The server is
small and stateless and is what makes §11 credible later.

**v0.3 — device list.** NKM §11.1 enrollment keys, kind 30242, roles assigned by
the Sender's consent box, per-device settings, the transfer records of §3.3
surfaced. Still no threshold; this is the bookkeeping §11 needs and it has
standalone value as a "where am I logged in" screen.

**v0.4 — threshold.** NKM §11.4–§11.15. The largest step by a wide margin, and
the one that should not start until v0.1–v0.3 have been used by somebody.
**Blocked on a spec question:** the `frost-share` profile is marked
do-not-implement, because share issuance delivers two partials from two different
parties and QRST describes one Sender. That needs settling before any of v0.4 is
worth writing.

**1.0 — when the kinds are registered.**

---

## 8. Risks, stated honestly

**FROST in JavaScript.** There is no established, audited FROST implementation
over BIP-340 in JavaScript. `@noble/curves` provides the curve and Schnorr
primitives, not the threshold protocol. Writing RFC 9591 plus taproot parity
handling by hand is a reviewable-crypto project with a review budget attached.
The better move is to compile the ciphersuite NKM §11.4 already names —
`frost-secp256k1-tr`, Zcash Foundation, Rust, on crates.io — to WebAssembly and
use it in both browser and Node. That is byte-for-byte the construction the spec
points at rather than a reimplementation of it, and it removes the largest single
source of interoperability risk. Cost is a Rust toolchain in the build and a few
hundred kilobytes in the §11 bundle, acceptable because §11 is opt-in and lazily
loaded.

**scrypt at `log_n = 18` in a browser.** 256 MiB per guess is the point, but
pure-JS scrypt at that size is tens of seconds and may simply fail on mobile
Safari. It needs a WASM scrypt in a worker with progress reporting. NKM §11.10
already forbids browser recovery, which removes most of the exposure, but §7.1
export runs in browsers and the `log_n = 17` allowance for low-memory devices
must be wired to a real capability probe rather than a user-agent guess.

**A browser "device" can silently evaporate.** NKM §2.3 stores a wrapping key in
IndexedDB and calls `navigator.storage.persist()`, but persistence can be
declined and eviction is real. Integrators will report this as data loss. The
library should surface it as an explicit state (`keys.durability`) and the docs
should say plainly that a browser is a device that can disappear — which is
precisely why §11 makes browsers `restricted` and re-enrollable.

**The phishing residual is a library problem too.** QRST §15 is candid that a
hostile party acting as Receiver is stopped only by a user declining the release
prompt, and that prompt is UI — the part adopters most want to restyle.
`@qrst/ui` should let integrators theme the frame and refuse to let them alter,
hide, or shorten the claimed-origin line, the direction statement, or the
asymmetry between the decline and confirm controls. That copy is part of the
security argument, not part of the skin.

**The code entry field is load-bearing and looks trivial.** QRST §9 requires five
discrete character positions, exactly five digits accepted, no clipboard
autofill, and no pre-fill. Every one of those reads as a styling detail an
integrator would override without noticing. Ship it as a component that cannot be
replaced, only themed.

**The bounce page is infrastructure that must stay static.** QRST §11.2a puts the
URI in the fragment specifically so it never reaches a server. A landing page that
does anything server-side — analytics, a redirect, server-rendered anything —
risks reintroducing the operator the whole design avoids. It should be a static
file with a CI check that it makes no network calls.

**Bundle size is an adoption gate.** Tier 0 competes with a script tag people add
casually. Budget: base bundle under 60 KB gzipped with §11 in a separate async
chunk, enforced in CI, or the first bug report is "this doubled my bundle."

---

## 9. Decisions needed before scaffolding

1. **npm scope.** `@qrst/*` matches the `qrst://` scheme and is proposed
   throughout; availability is unverified. `@sybenx/*` is the fallback and needs
   no check.
2. **Rust in the build**, for the FROST WASM path. Reasonable to defer to v0.4,
   but it shapes the `core` API now: FROST calls should sit behind an async
   interface from the first commit so the backend can change without a breaking
   release.
3. **License.** The repository carries one; packages should state it explicitly
   per-package, and it is worth confirming it is the license you want on code as
   well as on prose.
4. **Whether §11's server is in scope for you at all.** A specification can name a
   server and let others build it. A library that promises §11 and ships no server
   is stuck. Deciding now changes the v0.2 milestone.
5. **What relationship this has to the existing client.** An implementation
   already exists and is where the notes that shaped these specs came from.
   Whether the library is extracted from it, written beside it, or never written
   at all changes everything above — including whether v0.1 is new work or a
   refactor.
