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
burner handshake, the QR (an `https` fragment link, no custom scheme), the typed
code, gift-wrapped transfer over relays. Self-contained client code with no
infrastructure behind it and nothing for an operator to run. This ships first and
is marketed as the product.

**Storage and backup (NKM §2, NKM §4) are a drop-in too**, and belong in the same
package — the storage ladder is what a key does *after* it arrives, and shipping
transfer without it means every adopter invents their own at-rest story.

**Threshold signing (NKM §7) is FROSTR, and this repository ships neither
client nor server for it.** NKM 10.0 adopted [bifrost](https://github.com/FROSTR-ORG/bifrost)
and the `igloo` clients whole; there is no `@qrst/threshold` package to build,
because the thing it would wrap already exists, is maintained elsewhere, and
this library has no business forking it. What this library ships instead is
narrower and more durable: §3.3's `frost-share` profile, which carries a
FROSTR credential pair (`bfshare1…` + `bfgroup1…`) inside QRST's SAS-gated
transfer instead of the plaintext QR FROSTR's own onboarding uses today. A
FROST co-signer is still a distributed system that needs somewhere to run, but
that somewhere is not this library's to build: [FROSTR-ORG/igloo-server](https://github.com/FROSTR-ORG/igloo-server)
is the reference co-signer, self-hosted on a machine the user controls, and a
Cloudflare Workers signer for people without one is its own repository under
this project's org, not a package here. Neither NKM nor QRST specifies either
server.

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
browser cannot scan reliably.

Everything else is progressive disclosure on the same object, and none of it is
required to log in:

```ts
keys.storageLevel                     // 1 | 2 | 3, per NKM §2.1
keys.lock                             // 'device' | 'launch' | `idle:${number}`
keys.export({ password })             // NKM §4.1, always ncryptsec, privileged
keys.backup.connect(url, password)    // NKM §4.2
keys.backup.recover(url, password)    // NKM §7.10 — throws in a browser, by spec
keys.devices.list() / .remove(id)     // local transfer records only, NKM §3.2 — not a protocol-level device list
keys.threshold.enable() / .disable()  // hands off to FROSTR's own dealer/onboarding; not specified by NKM
keys.on('frostr-peer-alert', a => …)  // surfaces whatever bifrost/igloo-core report; not an NKM construct
```

Methods a browser may not perform are present on the type and reject at runtime
with a named error (`UnsupportedInBrowserError`) rather than being absent — for
instance `keys.backup.recover()`, which NKM §7.10 forbids in a browser
outright. A missing method reads as an incomplete library; a refusal citing the
specific requirement teaches the integrator why the limit exists.

### Tier 2 — headless

```ts
const session = createTransferSession({
  role: 'receiver', mode: 'offer', profile: 'nostr-nsec', …adapters
})
session.qrUri                          // the https fragment link of QRST §11.2
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
| `@qrst/core` | Every derivation and state machine, as pure functions over injected randomness and clock. Commit/nonce/reveal and code derivation (QRST §6), URI parse and build (QRST §11.2), message construction and validation (QRST §11.4), Flow A/B state machines (QRST §7, §8), profile registry (QRST §5), blob-store key schedule (NKM §4.2), `frost-share` credential-pair verification (NKM §3.3) over bifrost's own bech32m encoder. No FROST signing or ECDH of its own — that stays inside bifrost, a peer dependency, not a wrapped one. No I/O, no DOM, no `fetch`, no timers. | `@noble/curves`, `@noble/hashes`, `@scure/base`, `@frostr/bifrost` (decode/verify only) |
| `@qrst/web` | The adapters that make `core` run in a browser: storage per NKM §2.3, relay transport with the outbox of QRST §11.5, WebAuthn gate, `navigator.storage.persist()`, camera and fragment parsing. Exports `NostrKeys`. | `core` |
| `@qrst/ui` | The screens the specs write copy for: QR with the direction line of QRST §11.2b, the code entry field with its visible length, the release prompt of QRST §9 with the origin as punycode. Framework-free custom elements. | `web` |
| `qrst-login` | Tier 0. One IIFE bundle, no build step for the adopter, sets `window.nostr`. | `ui` |
| `@qrst/server` | The reference **blob store only** (NKM §4.2) — one encrypted backup per identity, nothing else. Not a FROST co-signer: that role is [FROSTR-ORG/igloo-server](https://github.com/FROSTR-ORG/igloo-server) (self-hosted on a machine) or the Cloudflare Workers signer (a separate repository under this project's org, for people without one). Neither NKM nor QRST specifies either, so neither lives here. One codebase, two targets: Cloudflare Worker and Node. | `core` |
| `@qrst/vectors` | Generates the normative test vectors from `core`; runs them as a conformance suite any implementation can execute. | `core` |

`core` communicates with its host by returning **commands as data**, never by
calling out:

```ts
type Command =
  | { t: 'publish';  relays: string[]; event: NostrEvent }
  | { t: 'subscribe'; filter: Filter }
  | { t: 'store';    slot: 'nsec' | 'bfshare'; bytes: Uint8Array }
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
│       └── frost-share-max.json
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
everywhere else; the NKM §4.2 ladder from password and salt through `K_pw`,
`K_enc`, `K_auth`, `K_wrap` to a decryptable blob; `ncryptsec` at both `log_n`
values; and the NKM §3.3 `frost-share` credential pair at its true maximum
(`vectors/frost-share-max.json`), where a real dealt keyset is the only thing
that catches an encoder that silently truncates a large group.

**Event kinds.** They are provisional — chosen from the ephemeral range and
verified non-conflicting, but unregistered until a NIP lands — so the mitigation is
containment, not churn insurance: one `KINDS` constant module, the `v=1` check
already required at parse time, and a published `0.x` whose README says the kinds
are not NIP-reserved and interoperability is not promised before 1.0. Nothing is
tagged 1.0 until a NIP reserves them.

*(The third gap, the emoji table, closed by deletion rather than by code — the
comparison it served was replaced by typed entry, so there is no table to
specify.)*

---

## 7. Build order

Each milestone is useful to somebody on its own, which matters when the author
count is one.

**v0.1 — the actual drop-in.** NKM §2 storage ladder with silent probing and
in-place upgrade; QRST Flow A and B over relays; the typed code and its attempt
budget; the multiple-responder notice; NKM §4.1 `ncryptsec` export (which is also
`nostr-nsec`'s no-network path — the QRST §10 offline tier is profile-gated and
`nostr-nsec` does not use it); NIP-07 signer; tier 0 bundle. No server, no account,
nothing to run.
Ships the first vector files, including `vectors/frost-share-max.json` — it costs
nothing to run in CI from this release even though nothing signs with a FROSTR
key yet, since it only exercises the credential-pair encoding, not signing.

**v0.2 — backup.** NKM §4.2 blob store, `@qrst/server` on a Worker, NKM §7.10
recovery in a native context only, and the recovery-delay notices. The server is
small, stateless, and is not a step toward anything threshold-related — it is
the whole of what `@qrst/server` does; a FROST co-signer is a different
project entirely (see §1).

**v0.3 — transfer history.** The local `transfer_event` records of NKM §3.2,
surfaced as a "where has my key gone" screen. No protocol-level device list —
that was this document's own 9.x construct and NKM 10.0 dropped it along with
the threshold design it served (NKM §7.1).

**v0.4 — `frost-share` support.** The QRST side of NKM §3.3: encode and decode
the `bfshare1…`/`bfgroup1…` pair with bifrost's own encoder, run the P4/P5
checks, and move the pair through Flow A/B or the passphrase-encrypted offline
container. This library does not implement FROST signing, ECDH, peer policy,
or rotation — an integrator brings `@frostr/bifrost` (or an `igloo` client) for
that and uses this package only to get a share onto a new device without a
plaintext QR. Small relative to what a v0.4 building an actual co-signer would
have been, because that co-signer is no longer this project's to build.

**1.0 — when the kinds are registered.**

---

## 8. Risks, stated honestly

**FROST in JavaScript — no longer the blocker this section used to describe.**
**FROST correctness, `t = 3`, the parity trap, and Cloudflare Worker CPU
budgets for signing are no longer this repository's risks to carry.** All four
were about a FROST implementation and a co-signer server this project would
have built and audited itself; NKM 10.0 adopted FROSTR instead, so that
correctness surface — dealing, VSS, signing, rotation, the odd-y parity
behaviour, `t = 3`'s share-verification math — is `bifrost`'s (and, for a
self-hosted co-signer, `igloo-server`'s) to get right and to document risk
against, not this library's. `vectors/nkm-frost.json` remains in this
repository as the historical record of the `t = 3` and parity findings that
motivated the rotation proposal in NKM §7.9, but it tests a ciphersuite this
document no longer specifies, and CI need not gate on it. The risk that
replaces all four, and is this library's to own, is narrower: `@qrst/core`'s
`frost-share` verification (NKM §3.3, P4) must reject a malformed or
inconsistent `bfshare`/`bfgroup` pair using bifrost's real encoder, and
`vectors/frost-share-max.json` is what checks that at the size boundary where
an encoder is most likely to silently truncate.

**scrypt at `log_n = 18` in a browser.** 256 MiB per guess is the point, but
pure-JS scrypt at that size is tens of seconds and may simply fail on mobile
Safari. It needs a WASM scrypt in a worker with progress reporting. NKM §7.10
already forbids browser recovery, which removes most of the exposure, but NKM §4.1
export runs in browsers and the `log_n = 17` allowance for low-memory devices
must be wired to a real capability probe rather than a user-agent guess.

**A browser "device" can silently evaporate.** NKM §2.3 stores a wrapping key in
IndexedDB and calls `navigator.storage.persist()`, but persistence can be
declined and eviction is real. Integrators will report this as data loss. The
library should surface it as an explicit state (`keys.durability`) and the docs
should say plainly that a browser is a device that can disappear.

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

**The bounce page is infrastructure that must stay static.** QRST §11.2 puts every
parameter in the fragment specifically so it never reaches a server, and §11.2a
makes the bounce page the generic-camera fallback. A landing page that
does anything server-side — analytics, a redirect, server-rendered anything —
risks reintroducing the operator the whole design avoids. It should be a static
file with a CI check that it makes no network calls.

**Bundle size is an adoption gate.** Tier 0 competes with a script tag people add
casually. Budget: base bundle under 60 KB gzipped with `frost-share` verification
(NKM §3.3) — the only piece that touches `@frostr/bifrost` at all — in a separate
async chunk, enforced in CI, or the first bug report is "this doubled my bundle."

---

## 9. Decisions needed before scaffolding

1. **npm scope.** `@qrst/*` matches the QRST name and is proposed throughout;
   availability is unverified. `@sybenx/*` is the fallback and needs no check.
2. **`@frostr/bifrost` as a dependency of `core`'s `frost-share` verification
   only.** No Rust, no WASM, no FROST implementation of this project's own —
   settled by adopting FROSTR. What remains open is whether that dependency
   sits behind an async interface from the first commit, the way a future
   change of decoder library would want.
3. **License.** The repository carries one; packages should state it explicitly
   per-package, and it is worth confirming it is the license you want on code as
   well as on prose.
4. **~~Whether NKM §7's server is in scope for you at all.~~ Settled: it is not.**
   NKM 10.0 specifies neither a FROST co-signer nor its infrastructure.
   [FROSTR-ORG/igloo-server](https://github.com/FROSTR-ORG/igloo-server) is the
   reference co-signer for a self-hosted machine; a Cloudflare Workers signer
   for people without one is its own repository under this project's org. Both
   are out of scope for this repository.
5. **What relationship this has to the existing client.** An implementation
   already exists and is where the notes that shaped these specs came from.
   Whether the library is extracted from it, written beside it, or never written
   at all changes everything above — including whether v0.1 is new work or a
   refactor.
