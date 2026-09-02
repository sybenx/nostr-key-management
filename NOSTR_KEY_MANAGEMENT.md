# Nostr Key Transfer & Storage — Specification

Version 9.2-draft
Applies to: any client that holds a user's nsec (web, desktop, mobile)

> Transfer is specified in [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) (QRST).
> 9.1 added the **device-quorum** threshold mode (§7.18): a serverless 2-of-N across
> the user's own devices, alongside the server co-signer, chosen at §7.3. 9.2 gives
> `frost-share` a passphrase-encrypted offline container (§3.3) for the no-transport
> case, since a share has no `ncryptsec`. The load-bearing pieces from 9.0 remain:
> the index architecture of §7.4, the two-tier revocation of §7.9, and the
> passkey-default backup of §4.2.

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

The base experience is: **the nsec lives on the user's devices, and gets to a new
device by the transfer mechanism of QRST.** That works on any device with a
network connection and nothing else.

Everything in this document — at-rest encryption, platform sync, backup,
threshold signing — is an addition on top of that base. An addition MUST degrade
to the base when its prerequisites are absent, with one declared exception:
threshold signing (§7) requires a reachable co-signer by construction, and §7.3
states that trade on the screen where the user accepts it.

## 1. Overview

An identity is an nsec. This document defines how a client stores it, how it is
backed up, and how it may optionally be split so that no single party holds a
usable copy.

How it reaches a new device is specified in QRST; §3 registers the two payload
profiles this document uses. The nsec is never displayed except when the user
explicitly exports or views it (§2.2, §4.1, privileged).

Where the platform already syncs secrets between the user's own devices, the
client uses that first and skips the handshake.

---

## 2. Storage

### 2.1 At rest

The client stores the nsec using the strongest mechanism the device supports,
probing top to bottom. Every level is acceptable; the lowest is the base.

| Level | Platform | Mechanism |
|---|---|---|
| 3 | iOS / macOS | Keychain item under `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with **no** biometric ACL (reads are silent while unlocked); privileged actions call `LAContext.evaluatePolicy` separately |
| 3 | Android | Keystore AES key **without** `setUserAuthenticationRequired` (silent while unlocked, StrongBox where available); privileged actions use `BiometricPrompt` separately |
| 2 | Windows / Linux desktop | Credential Locker / Secret Service, bound to the OS user account, silent read; privileged actions use `UserConsentVerifier` / a keyring prompt. Not hardware-bound. Probed first on Windows; DPAPI file is the fallback if Locker is unavailable. |
| 2 | Windows | DPAPI-protected file (never prompts; privileged actions proceed with an in-app confirm only) |
| 2 | Browser | nsec wrapped by a non-extractable WebCrypto AES-GCM key in IndexedDB (silent use); a user-verifying WebAuthn assertion additionally gates privileged actions (§2.3). Never level 3: the browser has no authenticator-bound decryption. |
| 1 | Any | App-private storage, unencrypted |

Probing MUST be silent and MUST NOT add onboarding steps. If a level-3 mechanism
requires user enrollment, the client stores at the next available level and MAY
show a one-time, dismissible notice offering to upgrade later. The client MUST
re-probe on launch and upgrade in place when a higher level becomes available.

On desktop browsers, if a NIP-07 extension is present, the client SHOULD offer to
hand the key to the extension. The offer is dismissible.

### 2.2 Unlock policy

The unlock threshold is a per-identity setting, `lock`, chosen by the user and
carried to new devices on the payload message (§3.1):

| `lock` | Behaviour |
|---|---|
| `device` (default) | The device's own login is the unlock. The client never prompts for ordinary signing. |
| `launch` | One prompt when the app starts; none until it exits. |
| `idle:<seconds>` | Prompt after that many seconds without interaction. |

In browsers, `launch` and `idle` prompts are consent steps, not cryptographic
locks — `W` decrypts silently for any code on the origin (§2.3).

Ordinary signing never prompts under `device`. On every platform, "device" means
the device: one unlock covers every tab, window, and process of the client. The
enrollment key `E` (§7.1) is stored the same way, since it must authenticate
co-signing rounds silently.

**Privileged actions always prompt**, under every `lock` value, using the platform
authenticator. Levels 1–2 substitute the OS credential prompt where one exists and
otherwise proceed.

*Rule:* an action is privileged if and only if it touches the key itself — who
holds it, where a copy goes, or what protects it. Actions about content are never
privileged.

Privileged:
- Sending the key or a share to another device: acting as Sender (QRST §7 step 13, QRST §8 step 13, and §7.7 below).
- Showing or exporting the key: export (§4.1, always `ncryptsec`), viewing the nsec on screen (permitted, privileged, never written to disk), enrolling a server (§7.2 uploads a backup).
- Splitting or rotating it: enabling threshold signing, rotation, Offline mode on or off (and allowing it for another device), keep-key on or off, disabling threshold signing.
- Cutting a device off: revoking a device's `E`, removing a device, changing role.
- Changing `lock`, or changing the backup password or passkey.

Never privileged: posting, replying, reacting, reading or sending DMs,
decrypting, receiving a key as Receiver, and any signature a website requests.

The prompt MUST state what it guards in one line ("Confirm — this sends your key
to *Laptop*"). A prompt the user cannot attribute to an action they just took is a
defect.

### 2.3 Browser and passkey procedure

```
Storage:
  W  = crypto.subtle.generateKey(AES-GCM-256, extractable = false, [encrypt, decrypt]); persist W in IndexedDB
  call navigator.storage.persist() at first use; IndexedDB is evictable without it
  ct = AES-256-GCM(W, nsec)                        // usable by any tab on this origin without a prompt

Passkey registration (all platforms, not only browsers):
  navigator.credentials.create({
    authenticatorSelection: {
      authenticatorAttachment: "platform",         // REQUIRED — see below
      residentKey: "required",
      userVerification: "required"
    },
    extensions: { prf: { eval: { first: SALT_A, second: SALT_B } } }
  })
  store credentialId, SALT_A, SALT_B (random 32 B each)

  SALT_A → privileged-action gate (§2.2)
  SALT_B → backup key derivation (§4.2)

Obtaining a PRF value:
  PRF-on-create is recent (Firefox 148+, Chrome 147+). Where the create call does not
  return prf.results, the client MUST immediately perform a get() with the same eval
  salts to obtain them. Both shapes MUST be handled.

Privileged-action gate:
  navigator.credentials.get({ ..., extensions: { prf: { eval: { first: SALT_A } } } })
  a verified assertion is the consent; the nsec is then read from `W` as usual.
```

**`authenticatorAttachment: "platform"` is required, not cosmetic.** Without it the
credential may land on a roaming security key or a device-bound authenticator,
both of which are useless for §4.2 recovery — recovery is the case where the
device is gone. On desktop Chrome, only passkeys saved to Google Password Manager
return a PRF value at all.

**Fail closed on status.** The client MUST NOT record a passkey backup as
established until a PRF value has actually been returned by a real assertion and
the resulting wrap has been accepted by the server. Reporting a backup that does
not exist is worse than reporting none, because the error surfaces only when
recovery is already the last option.

The PRF gate is a **consent step, not a cryptographic boundary** for storage: `W`
decrypts the nsec silently, so a hostile script on the origin is not stopped by
the passkey. Its use in §4.2 is different and is a real boundary there, because
the PRF value is origin-bound by the platform and cannot be produced by another
origin's dialog.

`W` is origin-scoped by the browser. Under `lock = device` there is no expiry.

### 2.4 Platform sync

The client MUST enable platform sync of the encrypted nsec where the platform
provides it and the user has that feature on:

| Platform | Mechanism |
|---|---|
| iOS / macOS | Second Keychain item with `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked` (iCloud Keychain) |
| Android | Block Store (`BlockstoreClient`) with cloud backup enabled. Keystore keys do not sync. |
| Browser | None; a browser is re-enrolled by transfer (QRST) |
| Desktop native | None |

On first launch the client MUST check for a synced copy before showing onboarding.
If present it restores silently, onboarding is skipped, and the device
**self-enrolls**: it generates `E`, signs an updated device list adding its own
`E.pub`, and publishes it.

Before self-enrolling, the restored device fetches the epoch record (the plaintext
`epoch` tag suffices). If the fetch fails it MUST wait and retry — self-enrolling
on stale information is the dangerous branch. **Absence is only established** after
querying a relay the user controls or pays for, or otherwise after a 24-hour retry
window; a withholding relay can manufacture absence, and absence is what unlocks
self-enrollment with a full key.

If an **active threshold record exists**, a restored nsec is a stale full-device
backup taken before activation: the device **quarantines** the ciphertext
(retained encrypted, unusable, invisible to the UI), writes the threshold marker,
and shows the Receiver QR. The quarantined copy is deleted only once a co-signer
completes a round for this device or the record is re-confirmed after 7 days.

---

## 3. Transfer

Transfer is specified in QRST and is not restated here. This section defines the
two payload profiles and the transfer policy.

### 3.1 Profile `nostr-nsec`

Registered against QRST §5. Moves a whole identity key.

| QRST requirement | This profile |
|---|---|
| Payload encoding | 64 lowercase hex characters: the 32-byte private scalar. **Not bech32.** |
| Max size | Default (2048 B). A 32-byte payload is ~1.9 KB on the wire. |
| P4 check | 64 hex characters, decoding to a scalar in range for secp256k1 and yielding a valid x-only public key. |
| P5 rendering | Derive the npub, resolve a display name if cached, ask **"Log in as @name?"** |
| §5 prompt wording | "Send your key to *X*." The prompt MUST state that this is the identity itself and cannot be undone: there is no rotation in Nostr, and a party that receives this key keeps a working copy permanently. |
| Additional tags | `lock`, `enroll` — below. |

**`lock` tag**, on the payload message: `["lock", "<device|launch|idle:N>"]`.

**`enroll` tag**, on the request and acknowledgement messages:
`["enroll", "<E.pub hex>", "<label proposal>"]`. `E` is the receiving device's
stable enrollment keypair (§7.1), distinct from the QRST burner. The sending
device reads `E.pub` and adds it to the device list.

Enrollment happens during the transfer because every §7 operation must reach a
device long after the session is over and needs a stable address. The transfer is
the one moment when a channel authenticated by the SAS and a user paying attention
are both available.

**Sender restrictions.** In threshold mode a whole nsec may be sent only from a
keep-key device — the only device that legitimately holds one. An Offline-mode
device holds both indices and MUST NOT export.

This profile does **not** permit QRST's offline tier (QRST §10). To move a whole key
with no network — between two co-present screens — export it as NIP-49 `ncryptsec`
(§4.1) and import it on the other device; that standalone form is exactly why the
offline tier is unnecessary here (and why `frost-share`, which has no such form,
does permit it — §3.3).

### 3.2 Transfer policy

- Any device holding the nsec MAY act as Sender, subject to §3.1.
- A device that received its key by transfer defaults to **receive-only**. The
  toggle is one tap, unguarded, shown inline. Per QRST §14 it expires.
- Every transfer writes a local record
  `transfer_event { ts, profile, transport, sas, peer_burner, multi }`.
- There is no remote revocation in base mode. A "devices" list, if shown, MUST
  label removal as deleting the local copy only.

### 3.3 Profile `frost-share`

Registered against QRST §5. Gives a joining device a single threshold share — a
**generic** index-2 replica for the co-signer mode (§7.7), or a **unique** index
share for a device quorum (§7.18). One payload either way; the `index` field says
which, and the paste-delivered form uses the `frost://` carrier of QRST §12.3.

| QRST requirement | This profile |
|---|---|
| Payload encoding | The 32-byte share scalar, 64 lowercase hex characters, plus `index`, `group_pub`, `commitment`, `epoch`, `group_secret`, and `CK` only when the receiver is trusted (§7.7). `index = 2` is the co-signer replica; `index ≥ 1` unique is a quorum share. Carried in the QRST PAYLOAD (kind 24405). |
| Max size | Default (2048 B). |
| P4 check | `share·G == group_pub + commitment·index`. |
| P5 rendering | The identity the share belongs to, and that this device will hold **one share, not the key** — it cannot sign alone, and cannot sign at all until admitted (§7.1). For a quorum share it also names that two of your devices must be present to sign. |
| §5 prompt wording | "Give *X* a share of your key." Materially less severe than `nostr-nsec`: a share alone signs nothing, and the device can be revoked. |
| Additional tags | `enroll`, as above. |
| Offline tier (QRST §10) | Permitted, as the passphrase-encrypted container below. A raw, unencrypted share MUST NOT be shown or pasted. |

> **One Sender, either shard type.** The co-signer replica is a copy from one
> Sender by construction (every device holds the same index-2 share). A quorum share
> is unique, but is still delivered by a single Sender: two existing devices compute
> `f(k)` jointly *before* the transfer (§7.18), and one of them sends the finished
> share. QRST never sees two partials, so its one-Sender attribution check is
> satisfied in both modes and no carve-out is required.

**Offline container.** Where no transport is reachable (QRST §10), the share is
delivered as a passphrase-encrypted blob. A share is not a bare 32-byte key, so it
has no NIP-49 `ncryptsec` form — that format is fixed to a 32-byte payload, and a
share carries a second secret (`group_secret`) and the metadata to verify it. This
profile therefore defines its own container over NIP-49's construction:

- **KDF:** scrypt with `r = 8, p = 1, log_n = 18` (matching §4.1), over the
  passphrase and a random 16-byte salt.
- **Cipher:** XChaCha20-Poly1305 with a random 24-byte nonce; the version byte is
  the associated data.
- **Plaintext:** the entire QRST payload above — share scalar, `index`, `group_pub`,
  `commitment`, `epoch`, `group_secret`, and `CK` when the receiver is trusted.
  Sealing the whole payload, not only the scalar, also hides which identity the
  share belongs to.
- **Container:** `version (0x01) || log_n (1) || salt (16) || nonce (24) ||
  ciphertext || MAC (16)`, then bech32 with HRP `frostshare` (per NIP-19, no length
  limit). It is deliberately **not** an `ncryptsec1` string; the `frostshare1…`
  prefix and its checksum mark it as a share and catch paste errors.

The receiver decrypts, verifies `share·G == group_pub + commitment·index`, renders
P5, and confirms (QRST §10 step 3). Offline delivery has no admission-independent
gate beyond the passphrase, so it inherits the same reconstruction caveat as the
§12.3 light flow: an intercepted blob whose passphrase is guessed, plus one other
share, is the key.

---

## 4. Backup

### 4.1 When backup is offered

At the end of onboarding the client presents backup as the next step, with:

- Platform sync (§2.4), auto-detected and shown as already done if active,
- Blob-store backup (§4.2) — the default offer where a passkey is available,
- `ncryptsec` export (file or printable QR, `log_n = 18`).

The step is skippable ("Later"). If skipped, the client MUST NOT nag: no banner,
no scheduled reminders. Backup status is a passive line in settings.

**The client MUST offer backup again at activation (§7.5), before the local nsec
is wiped.** This is not a nag: the user has just chosen to split their key, is
reading a screen about it, and is one step from having no full copy on any device.
It is the same moment §3.1 relies on for enrollment — an authenticated context and
an attentive user — and it is the last one at which the nsec exists locally.

The export is always `ncryptsec`; the client MUST NOT export a raw nsec.

### 4.2 Blob store

A stateless HTTP service (reference: Cloudflare Worker + KV) that stores one
encrypted backup per identity. Used by §4.1 and reused by §7.2 / §7.10.

`CK` is wrapped independently under each enrolled recovery factor. **A passkey
factor is set up by default wherever a platform authenticator returns a PRF value;
a passphrase factor is always available and MUST NOT be omitted.** Either wrap
recovers the same `CK`.

```
Content, once per identity:
  CK          = random 32 B
  nsec_ct     = nonce || AES-256-GCM(CK, nonce, nsec)          // fixed for the identity's lifetime
  K_srv       = random 32 B, generated client-side, held by the server

Passphrase factor:
  salt_pw     = random 16 B
  K_pw        = scrypt(password, salt_pw, N = 2^18, r = 8, p = 1, dkLen = 64)
  K_auth_pw   = HKDF-SHA256(K_pw[32..64], salt = "auth-v1",      info = server base url)
  K_wrap_pw   = HKDF-SHA256(ikm = K_pw[0..32] XOR K_srv, salt = "blob-wrap-v1", info = npub_hex)
  ck_wrap_pw  = nonce || AES-256-GCM(K_wrap_pw, nonce, CK)

Passkey factor (default where available):
  prf         = PRF(credential, SALT_B)                          // 32 B, origin-bound by the platform
  K_auth_prf  = HKDF-SHA256(prf, salt = "prf-auth-v1",  info = server base url)
  K_wrap_prf  = HKDF-SHA256(ikm = HKDF(prf, "prf-enc-v1", npub_hex) XOR K_srv,
                            salt = "blob-wrap-v1", info = npub_hex)
  ck_wrap_prf = nonce || AES-256-GCM(K_wrap_prf, nonce, CK)

  blob = { nsec_ct, ck_wrap_pw, ck_wrap_prf? }

PUT  /v1/backup { npub, salt_pw, blob, k_srv, K_auth_pw, K_auth_prf? }
     auth: Schnorr sig over a server challenge by the user's key (base mode) or by a
     trusted E.pub on the current device list (threshold mode)
     server computes verifier_pw = HMAC-SHA256(k_srv, K_auth_pw), and verifier_prf likewise,
     then discards both K_auth values

GET  /v1/salt?npub=…   → { salt_pw, log_n, factors: ["pw"] | ["pw","prf"] }
     for unknown npubs returns HMAC(server_secret, npub) truncated to 16 B, always log_n = 18,
     always factors ["pw","prf"] — a factor list that varied would signal non-existence

POST /v1/recover { npub, K_auth }  → { blob, k_srv }
     the server compares K_auth constant-time against verifier_prf, then verifier_pw;
     the client does not declare which factor it used
```

**Release policy depends on which verifier matched, and this is the point of
having two.**

- **`verifier_prf` matched** → release immediately. The PRF value is origin-bound
  by the platform, so no other origin can produce it; there is no phishing path to
  delay against.
- **`verifier_pw` matched** → the server **MUST** hold release for a configurable
  delay (default 24 h) whenever it knows at least one `E.pub`, notifying every
  registered device by `RECOVERY_NOTICE` (kind 24316): "A recovery of your key
  started; it completes at …; approve or cancel from any trusted device." A
  trusted device can approve instantly or cancel. With no registered `E.pub` the
  delay elapses on its own.

The password branch is the phishable one (§7.13), so the friction sits there and
nowhere else. In 8.0 the delay was a blanket SHOULD; it is now a MUST on the
branch that needs it.

**Server storage.** Keys by `SHA-256(npub)`; stores `salt_pw`, `blob`, and the
verifiers in the data store, and `k_srv` in a separate secret store, never in the
same table as `blob`. `/recover`: constant-time compare; 10 attempts per hour and
30 per day per npub, 20 per hour per IP, exponential backoff; unknown npubs get the
same response time and shape as a wrong secret; no request logging beyond
rate-limit counters.

Properties:

- A leak of the data store alone is unbreakable: the verifiers are keyed by
  `k_srv`, so they cannot test guesses offline, and `blob` needs `k_srv` regardless.
- A leak of both stores reduces to the strength of the weakest enrolled factor. For
  a passkey factor that is 32 bytes of platform-held entropy; for a passphrase it is
  password strength at scrypt cost.
- The password is never sent; only `K_auth` is, over TLS to the enrolled URL.
- **A phished passphrase no longer yields the key on its own where a passkey factor
  is enrolled** — but it does yield it after the delay if the user approves the
  notice. The delay makes theft visible and cancellable; it does not make it
  impossible.

**Password screen.** Where a passphrase factor is being set up, the client MUST
pre-fill a generated six-word phrase (~96 bits) and the screen MUST carry: **"If
this server is ever hacked, this is the only thing protecting your key,"** and
**"Anyone who knows your npub and this server can try a few dozen guesses a day."**
In threshold mode the generated phrase MUST NOT be replaceable with free text: a
phrase the user has only ever seen inside this client is one a phishing dialog
cannot ask for convincingly, and a user-chosen password is one they will type
elsewhere and learn to type on request.

---

## 5. Security properties

Transfer properties are in QRST §15. The one that matters most here: a hostile
party acting as Receiver is not stopped by the code comparison, only by a user
declining the release prompt.

Base:

- The blob store never sees plaintext key material.
- Storage theft yields ciphertext bound to the device's secure hardware (level 3),
  to the OS user account or browser profile (level 2), or plaintext (level 1).
- A compromised unlocked device yields the key. Without §7, Nostr has no rotation.

Co-signer mode (§7.1–§7.17):

- **No two devices can sign, reconstruct, or conspire.** Every device holds a
  replica of index 2 (§7.4), and replicas of one index never combine. Any number of
  devices is one share. The only valid signing pair is server + device.
- **The device share grants no authority alone.** It is inert without a co-signer.
  What grants access is `E` (§7.1), which the co-signer authenticates on every
  round. This is why §7.6's allowlist, rate limits and audit thresholds are
  enforceable rather than advisory — a device cannot route around the server by
  asking another device, because no other device can answer.
- **Server compromise plus any one device share is the key.** Share 1 alone signs
  nothing, but a dumped share 1 combined with a share 2 taken from any device
  reconstructs. Remedy is §7.12.
- Revocation is two-tier and each tier fixes a different thing: revoking `E` (§7.9)
  stops a device signing immediately; rotation makes its retained share useless
  against the new share 1; Re-split (§7.11) is required only when share 1 itself may
  have leaked.
- Revocation is forward-only. A hostile device that read DM history before removal
  is not undone by removing it.
- A phished backup passphrase is the residual risk. §4.2's passkey factor removes
  the sole-factor path where a platform authenticator exists; the delay and notices
  bound the rest. A user who approves a phished recovery loses the key.
- Keep-key (§7.5a) and Offline mode (§7.14) are explicit exceptions the user creates
  with a second device's approval, shown in the lock state.
- Permanent `#p = E.pub` subscriptions let a relay count devices and see per-device
  timing under a stable key. Not mitigated.
- The server sees the plaintext of every event a device signs through it, and the
  peer pubkey of every conversation key it helps derive. It does not see DM contents.
- **No reachable co-signer means no signing.** This is a real availability cost,
  declared in §0 and stated on §7.3's screen. Self-hosting a server (§7.2) and
  Offline mode (§7.14) are the answers; both require the user to act in advance.

Device quorum (§7.18):

- **Any `t` devices are the key.** Each device holds a unique share, so any `t` of
  them (two by default) reconstruct by exchanging shares — intrinsic to threshold
  signing, not a defect. This is why shares go only on hardware the user owns, and
  why the mode has no restricted members.
- **No third party.** Nobody outside the user's devices sees an event or a
  conversation peer, and nothing but the user's own devices need be reachable. The
  price is the mirror of the co-signer's chokepoint: no server-enforced policy, no
  rate limits, no instant revocation — removal is rotation (§7.9), and revocation is
  forward-only.
- **A compromised device is worse here than under a co-signer.** It holds a real
  unique share and needs only one more; a second compromised or colluding device is
  the key, with no server round to refuse it. One lost device alone is inert — no
  honest device will co-sign with a revoked `E` — until a second is taken.
- **No reachable second device means no signing**, and below `t` surviving devices
  the only recovery is the §4 backup. A quorum with neither is unrecoverable.
- A phished backup passphrase is the residual risk here too, bounded by §4.2's
  factors exactly as in co-signer mode.

---

## 6. Out of scope for v1

NIP-46 remote signing, own-npub monitoring, identity migration tooling.

**On rotation of the identity itself.** There is none in protocol: the nsec cannot
be changed and old copies cannot be invalidated. There is a social one — announce a
new key from the old one while you still control it — which costs the follower
graph, the history's attribution and every existing reference. Threshold mode
reduces attack surface going forward; it repairs nothing backwards.

---

## 7. Threshold signing

Threshold signing is opt-in per §7.3, and comes in **two modes the user chooses
between**. They are mutually exclusive per key, because they use different
polynomials.

- **Co-signer** (§7.1–§7.17). A server holds one share and every signature needs
  it. This is a *better bunker*: the server never holds the whole key, a breached
  server cannot forge (it cannot complete a signature without a device) and cannot
  reconstruct alone (it needs a device's share too), and it still gives you what a
  bunker gives — web and restricted-device access, instant revocation, and
  enforceable server-side policy. A co-signer is required by construction once this
  mode is on. It is the upgrade to a remote signer or an extension.
- **Device quorum** (§7.18). The key is split across the user's own devices with
  **no server in the signing path**; any two co-sign. It removes the third party
  entirely — nobody sees your events, nothing must be reachable but your own
  devices — at the cost of needing two devices present to post and of
  rotation-based revocation. It is the upgrade to moving a whole nsec between your
  devices.

A user who never enables either is unaffected by this section. §7.1–§7.17 describe
the co-signer mode; §7.18 gives the device-quorum mode by its differences from it.

### 7.1 Enrollment keys and device list

Every device generates a stable secp256k1 **enrollment keypair** `E` at install
(stored per §2.1). `E` is the per-device secret: it is what a co-signer
authenticates, and revoking it is revocation (§7.9). No two devices share an `E`.

The client maintains a **device list** — `{E.pub, label, role, storage_level, mode,
admitted}` per device — in a replaceable event (kind 30242, `d = "devices"`). In
base mode it is NIP-44-encrypted to the user's own pubkey. In threshold mode it is
encrypted under a **group secret**: a random 32-byte value distributed alongside
every share and replaced on every rotation.

During every transfer the Sender reads the Receiver's `E.pub` from the `enroll` tag
and adds it to the list. Each device subscribes to `#p = E.pub` permanently for §7
wraps, with `since` = a persisted last-seen cursor minus 2 days, never less than 32
days back on first subscribe or after a gap.

**Roles.** `trusted` — native app on hardware the user owns; may act as Sender or
issuer, initiate rotation, approve requests, revoke and admit devices, hold Offline
mode. `restricted` — every browser-origin device; may sign ordinary content and
request rounds, nothing else. **A Receiver's role is chosen by the Sender's user,
never by the Receiver.** The Sender's consent prompt carries an unchecked box,
**"Trust this device — it's my own app on hardware I own,"** defaulting to
restricted. `origin` is unverified and informs the prompt, never the role.

**Admission.** A device that has received a share is `admitted: false` until a
trusted device or the server console admits it. **An unadmitted device holds an
inert share: co-signers MUST refuse every round for an `E.pub` that is not admitted
in the current epoch.** Enrollment gives the shard; admission gives access.

**Two-device approval (optional).** Available with two or more trusted devices, off
by default. When on, admitting a device, entering Offline mode, keep-key, and
disabling require an `APPROVAL` (kind 24311) signed by a second trusted `E.pub`
naming the operation, requester, a unique request-id and a 10-minute expiry.
Verifiers reject reuse and expiry.

**Labels** are written by the Sender at enrollment and edited only from trusted
devices. A Receiver MUST NOT set or change its own label.

### 7.2 Server enrollment

A server is a Nostr-speaking service with a stable enrollment keypair `S` and an
HTTPS base URL.

1. Server displays a QR, in QRST's `https` fragment form (QRST §11.2):
   `https://<host>/qrst#v=1&mode=server&npub=<S.npub>&url=<https base url>`.
2. Phone scans. Client sets up backup factors per §4.2 — passkey by default where
   available, passphrase always. Backup setup happens only on trusted devices; a
   restricted device MUST NOT present a passphrase field.
3. Client runs §4.2 setup against `<url>`.
4. Client shows the mode screen (§7.3).

Enrolling a second server repeats steps 1–3; the blob is uploaded to every server.

**A machine MUST NOT hold both indices.** A device that runs a server holds share
1; if it also enrolls as a device it holds share 2, and the pair is the key. Where a
user points server enrollment at software running on a machine that is already an
enrolled device, the client MUST refuse and say why. Self-hosting is supported and
recommended for offline availability, but the server must run somewhere the user is
not also signing from — a spare phone, a home server, a VPS.

**Two servers from one operator are one server.** Per §7.4 all server replicas hold
share 1, so a second Cloudflare deployment adds availability and no independence.
Where a user enrolls a second server the client SHOULD say so and offer a
different-operator or self-hosted option.

### 7.3 Mode screen (mandatory)

Reached from settings' "Turn on threshold signing," and shown automatically the
first time a server is enrolled. Shown only if the device list contains at least
one trusted device. Three options. **C is preselected.**

> **A — Device quorum (no server)**
> Your key is split across your own devices. Any two of them sign together; none can
> sign alone, and a lost device is a useless piece until a second is taken too.
> Nothing outside your devices is ever reachable, and nobody sees what you post. The
> trade: you need two of your devices present to post, and removing a device re-keys
> the rest. Best when every device is your own.
> *(Needs two or more trusted devices. No server.)*
>
> **B — Co-signer (a server)**
> Your key is split so that no device and no website holds a usable copy, and every
> signature needs your server — which is what lets you log in on the web, cut any
> device off instantly, and set rules the server enforces. Unlike a remote signer,
> the server never holds your whole key and a breached server cannot post as you. The
> trade: your server must be reachable to post, and it sees what you post. You can run
> it yourself. To use a device with nothing reachable, turn on **Offline mode** for
> it first.
> *(Enrolls a server now if none is enrolled.)*
>
> **C — Backup only (recommended)**
> Your key stays on all your devices as it is now. An encrypted backup you can
> restore with your passkey or passphrase.

The client MUST NOT enable threshold signing by any path other than the user
selecting A or B here or in settings. **A** activates the device quorum of §7.18;
**B** enrolls a server (§7.2) if none is present and activates the co-signer of
§7.5.

### 7.4 Threshold parameters

The ciphersuite, parity handling and epoch records below are shared by both modes.
The index scheme (server at 1, devices replicating index 2, "only valid pair is
server + device") is the **co-signer mode's**; §7.18 gives the device-quorum
variant, where each device holds a unique index and there is no server index.

- Scheme: FROST per RFC 9591 with the secp256k1 Taproot variant as implemented by
  `frost-secp256k1-tr`. If `pubkey(nsec)` has odd y, the dealer uses `a_0 = n − nsec`
  so the group key is even-y. On reconstruction the result is `n − nsec` for an
  odd-y key; the client MUST re-negate before storing or exporting. ECDH is
  unaffected because x-only.
- `t = 2`.
- **Index `1` is the server index.** Every enrolled server holds a replica of share 1.
- **Index `2` is the device index. Every device holds a replica of share 2,
  regardless of role.**
- **Replicas share an index and never combine.** Any number of servers is one share;
  any number of devices is one share. The only valid signing pair is **server +
  device**.
- Polynomial at activation:
  ```
  a_0 = nsec (parity-adjusted per above)
  a_1 = random mod n                       // MUST be fresh randomness; never derived from the nsec
  f(x) = a_0 + a_1·x
  share_1 = f(1)    share_2 = f(2)
  ```
  A deterministic `a_1` would let a re-activation reproduce an old polynomial and
  resurrect revoked shares; it is forbidden.
- Epoch: `{counter, id}`, `counter` incrementing, `id` random 128 bits. Members order
  by `counter`; on a tie the **lower `id` wins**. Members retain the previous-epoch
  share until an `EPOCH_FINALIZED` marker (kind 24319) arrives, 7 days elapse, or a
  newer verified epoch supersedes.
- **Epoch record**: kind 30242, `d = "frost"`, encrypted under the group secret with
  a plaintext tag `["epoch", counter]`, content
  `{epoch, t, group_pub, commitment: a_1·G, members: [{index, E.pub|S.pub, role, admitted}]}`,
  signed by the group key via FROST once active — which requires server **and** a
  device, so neither can publish a record alone.

**The architecture in one line.** The share grants no authority alone; `E` grants
access to the co-signer; revoking `E` removes access; rotation (§7.9) removes the
retained share's usefulness; Re-split (§7.11) removes the share.

### 7.5 Activation (user chose A)

Performed by the device that chose A, which still holds the nsec.

1. **Offer backup (§4.1) and complete it or record an explicit decline.**
2. Derive the epoch-1 polynomial. Compute share 1 and share 2.
3. Gift-wrap `KEY_SHARE {epoch: 1, t: 2, index, share, group_pub, commitment,
   group_secret, lock}` (kind 24305) to each server `S.pub` (index 1) and each
   device `E.pub` (index 2); store own share per §2.1.
4. Publish the epoch record, signed with the nsec directly.
5. Wipe the local nsec **and every synced copy** — delete the synchronizable
   Keychain item, delete the Block Store record — and write a synced **threshold
   marker** `{group_pub, epoch}` in their place.

Activation is journaled: the device writes `{stage, epoch, issued: [...]}` per §2.1
before each step, resumes idempotently after a crash, and performs step 5 only once
steps 1–4 are durably complete.

On receiving `KEY_SHARE`, a device verifies `group_pub` against the user's known
x-only pubkey **and** `share·G == group_pub + commitment·2`, stores the share, wipes
its nsec, and gift-wraps `SHARE_ACK {epoch}` (kind 24306). A device offline at
activation keeps its nsec and continues in base mode until its share arrives.

**Where the full key still exists after activation:**

- On any device that has not yet ACKed. It holds the nsec and cannot be revoked by
  rotation. The lock MUST be amber and the devices screen MUST mark it "still holds
  full key."
- In the §4.2 backup, by design.
- In any `ncryptsec` file or printed QR exported before activation.
- On a keep-key device, by explicit choice.

### 7.5a Reconstructing operations

**Disable (§7.15) and Re-split (§7.11) are the only operations that reconstruct.**
Rotation, share issuance, share-1 replication, changing a backup factor and server
enrollment never do. `CK` travels to trusted devices in `KEY_SHARE` and is stored
per §2.1; servers never hold `CK`.

**Keep-key option.** A user MAY mark one trusted device "Keep the full key on this
device," with a second trusted device's tap and the prompt "*Laptop* wants to keep
your full key permanently. Allow?" That device is a bunker: it keeps the nsec, signs
alone, and **cannot be revoked**. Off by default; the client says so.

### 7.6 Signing and what the co-signer sees

A FROST co-signer must see what it signs. **Every event a device signs is visible in
plaintext to the co-signer**, including DM envelopes (not their NIP-44-encrypted
contents).

- **Only a server co-signs.** Devices share index 2 and cannot complete rounds for
  each other. There is no device-to-device fallback; §7.14 Offline mode is the
  answer for a device that must work with nothing reachable.
- The requester sends the **full unsigned event**, not a digest; the co-signer
  serialises and hashes it itself (NIP-01). Requests carry the requester's `E.pub`
  signature.
- The co-signer MUST refuse any request whose `E.pub` is absent from the current
  epoch's member list, is not `admitted`, or is revoked.
- For a **restricted** requester the co-signer signs only kinds on an enumerated
  allowlist (reference set: 0, 1, 3, 5, 6, 7, **13**, 16, 30023) and refuses
  everything else — in particular 30242 and 10002. Kind 13 is required for NIP-17
  DMs. Kind 5 is signed only after checking its `e`/`a` tags: a deletion referencing
  any kind-30242 coordinate is refused. An allowlist is used because "alters the
  device list" is not evaluable for future kinds.
- **Per-kind additional factors (OPTIONAL).** Because the co-signer is mandatory in
  this mode, a server MAY be configured to require an additional factor before signing
  nominated kinds — a passkey assertion against the server, or an approval tap on a
  trusted device. This is only expressible because no device can route around the
  server. Defaults to off; when on, the affected kinds are shown on the devices
  screen.
- Requests are gift-wrapped between `E.pub` and `S.pub` over relays or
  `<url>/v1/sign` over HTTPS; both MUST be supported, HTTPS tried first.
- Nothing reachable: the draft is kept as an unsigned rumor with `created_at` fixed
  at compose time and signed at the first opportunity. The client shows **"Will post
  when your server is reachable"** and points to Offline mode.

### 7.6a Decryption (DMs and gift wraps)

FROST produces signatures only. NIP-04/44 conversation keys and NIP-59 seal
decryption need `ECDH(nsec, P)`, so a device cannot decrypt alone. Threshold ECDH is
one round:

```
Requester (index 2) → server (index 1):  { P }              wrapped to S.pub, or /v1/ecdh
Server → requester:                      { λ_1·s_1·P }      after verifying P is on-curve and not the identity
Requester aggregates:                    nsec·P = λ_1·s_1·P + λ_2·s_2·P
```

The server never learns `nsec·P`, only `P` and its own partial. Clients SHOULD
batch: one round can carry many `P` values. The server learns which `P` values the
user derives keys for — for NIP-04/44 that is the peer's pubkey; for NIP-59 wraps a
random one-time key. Keep-key and Offline-mode devices decrypt alone.

### 7.7 Adding a device after activation

A device is added by an ordinary QRST transfer with profile `frost-share` (§3.3).
The share travels as the QRST **PAYLOAD** (kind 24405) — the profile's encoding:
share 2 at index 2, `group_pub`, `commitment`, `epoch`, `group_secret`, and `CK` as
an additional field only when the Receiver is trusted. There is no separate
share-transfer kind; a share is an opaque QRST payload like any other.

The Receiver verifies `share·G == group_pub + commitment·2`, derives the npub from
`group_pub`, shows "Log in as @name?", stores on Yes, and ACKs. The Sender updates
the device list with the new `E.pub`, `admitted: false`.

**The new device cannot sign until admitted (§7.1)** — a separate privileged act on
a trusted device or the server console, where the user sees the device by label.
That admission gates *signing*, not *reconstruction*: an intercepted share plus one
other share (share 1, §7.12) is the key, and revocation does not undo a
reconstruction. So the enrollment channel is load-bearing. The transfer uses the SAS
(§6) unless the token reached the Receiver by a channel the user controls — its own
camera, or a local same-user paste — in which case the §12.3 light flow's returned
secret suffices. `nostr-nsec`, being irreversible, always uses the SAS.

Only trusted devices may act as Sender.

### 7.8 Adding a server replica

An existing server, on a gift-wrapped instruction from a trusted device, wraps share
1 directly to the new server's `S.pub`. Alternatively a trusted device that is
running §7.15 disable may issue it. One QR scan for the user. See §7.2 on
independence.

### 7.9 Revocation and rotation

Two tiers. The client presents them as one flow and performs both by default.

**Tier 1 — revoke `E` (immediate).** A trusted device or the server console marks an
`E.pub` revoked in the current epoch's member list and publishes the record. Every
co-signer MUST refuse all rounds for that `E.pub` from that moment. This takes
effect without touching any share and without contacting the revoked device. It is
the whole of revocation for a device that is merely retired.

**Tier 2 — rotate (makes the retained share useless).** A revoked device keeps its
copy of share 2 forever. Rotation puts the surviving members on a new polynomial so
that the retained share no longer pairs with share 1.

```
δ(x) = r·x,  r ← random mod n,  δ(0) = 0        // a_0 untouched: nothing is reconstructed
server:   share_1 ← share_1 + r
device:   share_2 ← share_2 + 2r                 // released only to an admitted, unrevoked E.pub
record:   commitment' = commitment + r·G,  epoch + 1,  fresh group secret
```

1. A trusted device or the server console initiates. The epoch record for `epoch + 1`
   is signed by the group key with **old** shares before any delta is applied, so it
   requires server and one device — neither can rotate alone.
2. The server releases `2r` to each admitted, unrevoked `E.pub`, authenticated by
   `E`. **The share is not proof of anything and MUST NOT be treated as one:** `2r`
   is inert without a valid share 2, so no proof-of-possession round is needed, and
   `E` remains the only credential in the flow.
3. Each device applies the delta, verifies `share·G == group_pub + commitment'·2`,
   and ACKs (kind 24306).
4. **The server MUST destroy the old-epoch share 1** — overwrite and verify, with no
   retained version history, snapshot, backup or log line. A revoked device's
   retained share 2 plus a surviving old share 1 is the key, so a store that keeps
   prior versions silently defeats rotation. On Cloudflare KV or a Durable Object
   this is not automatic; the rotation journal MUST record the overwrite and its
   verification.

Devices that miss the wrap receive it when next online (§7 wraps live 30 days).
Until then they cannot sign and the lock shows amber.

**What rotation does not do.** A surviving device can hand `r` to a revoked one;
that is the same trust already placed in it by giving it a share. And rotation does
not help when share 1 itself may have leaked, because the attacker sees the new
share 1 too — that case is §7.12.

Automatic rotation runs on device revocation, Offline-mode exit and after §7.10
recovery.

### 7.10 Recovery (all devices lost)

1. New device (native app; a browser MUST NOT offer recovery): enter server URL and
   present a recovery factor — the passkey where one is enrolled, otherwise the
   passphrase. A user who has forgotten the URL MAY have opted at enrollment to
   publish a plaintext `["backup-hint", "<url>"]` tag on the device list (off by
   default).
2. Recover per §4.2. A passkey factor releases immediately; a passphrase enters the
   delay with notices to any surviving device.
3. The device now holds the nsec in base mode. The client MUST prompt to **change
   the backup factors** and MUST offer to **drop or replace the server** it recovered
   from. No server is re-enrolled automatically.
4. If the epoch record shows threshold mode was on, the client offers to re-activate
   (§7.5) with a fresh `a_1` and a new device list.

**The passkey factor requires a synced platform credential.** Where the client is a
desktop native app with no sync fabric, or where the platform authenticator is
device-bound, the passkey factor is unavailable for recovery by construction and the
passphrase is the only path. The client MUST say which factors are actually usable
for recovery on the backup status line, not merely which are enrolled.

### 7.11 Device removal

Settings → device → **Remove**. The client asks: **"Do you still physically control
this device, and was it wiped?"**

- **Yes → retired.** Revoke `E` and rotate (§7.9).
- **No or unsure → lost, the default.** Revoke `E`, rotate, and offer **Re-split**.

**Re-split** is §7.15 disable plus §7.5 re-activation as one journaled operation on a
trusted device — reconstructing, privileged, subject to two-device approval. It draws
a fresh random `a_1`, severing the algebraic link to every old share. It is required
only when share 1 may have leaked (§7.12) or when a device that held both indices
(keep-key, Offline mode) is lost. For an ordinary device, tiers 1 and 2 of §7.9 are
sufficient, because a lost device's share 2 is useless against a rotated share 1.

A bunker device cannot be revoked at all (§7.5a); the client says so.

### 7.12 Server compromise

The attacker obtains share 1 and the blob. Share 1 alone signs nothing; the blob is
protected by the enrolled factors. But **share 1 plus any device's share 2 is the
key**, and rotation cannot help because the attacker sees each new share 1.

The remedy is **Remove server + Re-split**: exclude the server, then
disable-and-reactivate with a fresh `a_1`. The client performs Re-split, not
rotation, for any suspected server compromise. It then prompts to change the backup
factors and to delete the blob on the removed server.

**Blob and share 1 on one host.** A compromised server holding both, plus a weak
passphrase and no passkey factor, is the key. The client MUST offer at
second-server enrollment to place the blob on a different host than share 1, and
§4.2's generated-phrase rule applies.

### 7.13 Hostile device

A hostile origin holds share 2 — the same share every device holds. Alone it signs
nothing and decrypts nothing. Admitted, it can sign allowlisted kinds and request
ECDH through the server, and this is visible to the server and revocable in one act
(§7.9 tier 1).

It cannot: combine with any other device (same index); act as Sender or issuer;
initiate rotation; admit or revoke devices; enter Offline mode or keep-key; or see a
passphrase field from honest code. Holding the group secret, it **can read the device
list and epoch record** — device count, roles, `E.pub`s and user-written labels —
metadata a phishing page can weaponise.

Its worst case is **posting as the user and reading every DM the user has ever
received** until revoked, **plus a phishing path to the full key**: the hostile
origin is the client on that device, so "MUST NOT present a passphrase field" binds
honest code only. A pixel-perfect "confirm your backup passphrase" dialog plus the
npub and a knowable server URL is the key via `/v1/recover`. §4.2 answers this in
three ways and none is complete: a passkey factor means the passphrase alone no
longer suffices where one is enrolled; the recovery delay makes the theft visible and
cancellable; and the mandatory generated phrase means a user has only ever seen it
inside this client, so a website asking for it reads as wrong. Stated as residual
risk in §5.

**Audit surface.** Every co-signer keeps a per-requester log of signing and ECDH
rounds (kind, timestamp, peer pubkey for ECDH) and sends it to trusted devices as a
daily `AUDIT_DIGEST` (kind 24317; alerts are 24318). A server MUST notify trusted
devices when a restricted requester's ECDH peer count or signing rate in the last
hour exceeds both an absolute floor (25 distinct ECDH peers, or 50 signatures) and
five times its trailing-week hourly median. During the first 24 hours after
admission the same thresholds produce a differently worded, non-alarming notice
("*example.com* just synced *N* conversations") rather than silence.

Rate alerts alone can be boiled slowly, so there is also a **cumulative cap**. Every
incoming gift wrap uses a fresh random ephemeral key, so one-shot `P`s are ordinary
mail while **recurring `P`s are conversation keys**, and a burst of them is the
signature of a bulk history read. Co-signers refuse ECDH for a restricted origin
beyond 200 distinct *recurring* peers per rolling 7 days; exceeding it requires a
one-tap raise on a trusted device. The **hard ceiling** is 500 ECDH responses per
hour per requester, counted per `P`. Users MAY disable DM decryption for restricted
devices entirely ("Websites can read DMs" toggle, default on).

These limits are enforceable rather than advisory because no device can answer a
round for another (§7.6).

### 7.14 Offline mode

UI label: **Offline mode**. A toggle in every **trusted** device's settings. Never
required for any function. Not available to restricted devices: a device holding both
indices holds the key, and a device that has held the key cannot be un-given it by
rotation.

- **Enter.** The toggle sends an `OFFLINE_REQUEST` (kind 24308) to every other
  trusted device. The user taps **Allow** on one of them — a trusted device, never a
  server. The prompt names the requester and the consequence: **"*Laptop* wants to
  hold your full key offline. Allow?"** A server (or an approving trusted device)
  then issues the requester a replica of **share 1**. The epoch record gains
  `offline: {E.pub, since}`.
- **While on.** The device signs and decrypts alone with both shares.
- **Exit.** The device discards its share-1 replica and initiates rotation (§7.9),
  which requires reaching the server. The discarded replica is on the old polynomial
  and dead by construction. The device is **trusted to have discarded** it, which is
  why the mode is trusted-only.
- Ending Offline mode for a device you no longer trust is **Re-split** (§7.11), not
  rotation: the target still holds a share-1 replica and would receive its own delta.

### 7.15 Disabling threshold signing

Settings → "Turn off threshold signing." Trusted devices only. This is the one
operation that reconstructs the nsec: the device collects share 1 from a server (with
an `APPROVAL` where two-device approval is on), then:

0. **Pre-rotation.** Before reconstructing, run one §7.9 rotation whose member set
   excludes every revoked or unwanted device. Their shares are on a dead polynomial
   by construction, not by their cooperation, before deletion is even requested. Then
   reconstruct and **durably store the nsec per §2.1 before anything else** — a crash
   after members delete but before the key is stored is otherwise unrecoverable.
1. Wrap `DISABLE {epoch}` (kind 24314, 30-day TTL) to every member and publish the
   epoch record marked `disabled` with a plaintext `["epoch", counter]` tag. **Servers
   MUST delete share 1 and every device MUST delete its share, `CK` and the group
   secret** on receiving a `DISABLE` whose seal is from a trusted `E.pub` on the
   current list — and, where two-device approval is on, whose `APPROVAL` verifies.
2. Each trusted device replies `DISABLE_ACK` (kind 24315) carrying a fresh burner. The
   initiator wraps `KEY_TRANSFER` to **that burner** with QRST's 600 s TTL, never to
   `E.pub`, so no nsec ciphertext is addressed to a long-lived key on a relay.
3. Restricted devices are **not** sent the key by default; the screen lists them and
   lets the user tick any to include. The rest re-enroll by transfer when next used. A
   trusted device that misses the window comes back to a `disabled` record with its
   share deleted and shows the Receiver QR.

### 7.16 Lock indicator

Shown in settings and on the compose screen. Every state has a distinct **shape**, a
distinct **colour**, and a **text label always adjacent**; colour is never the only
channel.

| State | Colour | Glyph | Label |
|---|---|---|---|
| Split (default) | Green | Closed lock with checkmark | "No device holds your key on its own" |
| Keep-key | Green | Closed lock with phone silhouette | "Full key on *Phone*; other devices hold pieces" |
| Offline mode | Blue | Closed lock with single-figure badge | "Offline mode on *Laptop* since *date* — tap to end" |
| Pending | Amber | Half-open lock with three dots | "Waiting for *N* devices" |
| Unadmitted | Amber | Half-open lock with a plus | "*N* devices waiting to be allowed" |
| Flagged | Red | Lock with exclamation | "Rotate recommended: *reason*" |
| Off | Grey | Open outline lock | "Threshold signing off" |

Glyphs MUST remain distinguishable at 16 px in monochrome. The indicator is
informational; it MUST NOT emit notifications or block any action.

### 7.17 Rumor kinds

Transfer kinds are defined in QRST §11.4 and are not repeated here.

| Kind | Name | Direction |
|---|---|---|
| 24305 | KEY_SHARE | issuer → member (activation/rotation, to `E.pub`) |
| 24306 | SHARE_ACK | member → issuer |
| 24308 | OFFLINE_REQUEST | requester → trusted devices |
| 24309 | KEY_ROTATE | initiator or server → member |
| 24311 | APPROVAL | second trusted device → server (§7.1) |
| 24314 | DISABLE | initiator → member (§7.15) |
| 24315 | DISABLE_ACK | trusted member → initiator (§7.15) |
| 24316 | RECOVERY_NOTICE | server → registered devices (§4.2) |
| 24317 | AUDIT_DIGEST | co-signer → trusted devices (§7.13) |
| 24318 | ALERT | co-signer → trusted devices (§7.13) |
| 24319 | EPOCH_FINALIZED | initiator → members (§7.4) |

All provisional, in the ephemeral range (20000–29999) as befits gift-wrap rumors,
and verified non-conflicting against the registry as of 2026-09-02 (QRST §11.4);
`30242` (device list, epoch record) is addressable and keyed by its `d` tag.
Unregistered pending a NIP, not throwaway. 24301–24304, 24307, 24310, 24312 and
24313 are unused — 24307 (formerly `KEY_SHARE_PART`) was retired when share delivery
became an ordinary QRST `frost-share` payload (§7.7).

All are sealed and wrapped exactly as QRST §11.4 specifies, with one difference:
**§7 wraps use `expiration = now + 30 days`**, not the ten-minute transfer TTL, so
offline members can still receive them. A member offline longer than 30 days misses
the wrap; on return it finds a newer epoch record than its share and re-enrolls via
§7.7.

### 7.18 Device quorum (2-of-N, serverless)

The alternative to the co-signer mode of §7.1–§7.17, chosen at §7.3 and mutually
exclusive with it. The key is split across the user's own devices with **no server
in the signing path**; any two co-sign, none signs alone. It shares §7.1
enrollment, §7.4's ciphersuite and epoch records, and §4 backup, and differs as
below.

**Trusted devices only.** Every share is a **unique** point on the polynomial, so
any share plus any one other share is the key. A share therefore goes only on
hardware the user owns: a device quorum has **no `restricted` members**. A user who
needs web or restricted-device access uses co-signer mode instead.

**Parameters.**
- `t = 2` by default. A user with three or more independent trusted devices MAY
  choose `t = 3` — "any three present" in exchange for surviving any two devices
  being compromised. `t` is fixed at activation and changed only by re-activation.
- Each device holds a **unique index** `i ≥ 1`, never a replica. `share_i = f(i)`,
  verified `share_i·G == group_pub + commitment·i` (§7.4's check generalised from
  the co-signer's fixed `·2`). Indices are assigned by the activating device and
  recorded per member in the epoch record.
- No index is reserved for a server; there is none.

**Activation.** As §7.5, except the activating device evaluates `f` at a distinct
index per member and gift-wraps each `KEY_SHARE` accordingly. Backup (§4) MUST be
completed or explicitly declined first — it is the only recovery path, and the
client SHOULD warn that declining it makes the quorum the sole copy of the key.

**Signing.** Any two admitted, unrevoked devices run the two-round FROST signing of
RFC 9591 with each other directly, over gift-wrapped rounds or the local path,
combining with Lagrange coefficients over their two indices. No server is
contacted. The initiator is the Coordinator, the other the co-signer; a device with
no second device reachable cannot sign and the lock shows amber — the availability
cost of removing the third party. ECDH decryption (§7.6a) is the same one round
between two devices.

**Adding a device.** No single device holds `f`, so the new share is issued jointly
and QRST still sees one Sender:
1. Two existing admitted devices each compute their Lagrange-weighted contribution
   to `f(k)` at the new index `k` and combine them on one of the two — permissible
   because those two already reconstruct in this trust model, so nothing is exposed
   between them that the model did not already grant.
2. That device is the QRST Sender and delivers the finished `share_k` to the joining
   device as a single `frost-share` QRST payload (kind 24405) — under the SAS, or the
   §12.3 light flow (`frost://`) over a controlled channel, exactly as §7.7. The
   joining device verifies `share_k·G == group_pub + commitment·k`, stores it
   `admitted: false`, and is admitted by a trusted device (§7.1).

**Revocation is rotation.** With no server to refuse a revoked `E`, device-quorum
revocation is always the §7.9 rotation, computed jointly by any two surviving
devices: they move to a fresh `a_1`, so the removed device's retained share no
longer pairs with any surviving share. Honest devices also refuse to co-sign with a
revoked `E.pub` in the current epoch, but the retained share is neutralised only by
the rotation. One stolen device cannot sign — no honest co-signer will pair with it
— and is not the key until a second device is also taken; rotation closes even that
window going forward.

**Recovery.** With `t` or more surviving devices there is nothing to recover — they
hold the key. Below `t`, recovery is restoring the §4 backup (encrypted blob,
`ncryptsec`, or printed code); there is no server-based §7.10 path. A quorum with no
usable backup and fewer than `t` surviving devices is unrecoverable, which is why
activation gates on backup.

**Security.** Any `t` devices reconstruct the key by exchanging shares — intrinsic
to threshold signing, not a defect, and the reason shares go only on your own
hardware. There is no third party that sees your events or can deny signing, and no
chokepoint for policy, rate limits, or instant revocation. A hostile or compromised
device is more dangerous than under a co-signer: it holds a real unique share and
needs only one more, so a **second** compromised or colluding device is the key.
Keep the device count small, revoke-and-rotate promptly on any loss, and prefer
co-signer mode wherever a device is not fully trusted. Stated as residual risk in
§5.

## Appendix A — References

NIP-07, NIP-44, NIP-49, NIP-59. RFC 9591 (FROST). BIP-340. WebAuthn Level 3 (PRF
extension). Transfer: [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md).
