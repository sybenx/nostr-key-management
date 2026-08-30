# Nostr Key Transfer & Storage — Specification

Version 8.0-rc1
Applies to: any client that holds a user's nsec (web, desktop, mobile)

Key words MUST, MUST NOT, SHOULD, MAY are normative.

---

## 0. Design principle

The base experience is: **the nsec lives on the user's devices, and gets to a new device by QR + gift-wrap.** That works on any device with a network connection and nothing else.

Everything else in this spec — at-rest encryption, platform sync, backup, transfer policy — is an addition on top of the base. An addition MUST degrade to the base when its prerequisites are absent. Nothing in this spec may prevent a user from logging in, transferring, or using their key on a device that lacks a feature.

## 1. Overview

An identity is an nsec. This spec defines how a client stores it, how it reaches a new device, and how it is backed up.

Transfer uses one method: a burner-key handshake initiated by QR, with the nsec delivered inside a NIP-59 gift wrap. The wrap travels over public relays; when relays are unreachable it travels over the local network. The nsec is never displayed except in the off-grid case (§6) and when the user explicitly exports or views it (§2.2, privileged).

Where the platform already syncs secrets between the user's own devices, the client uses that first and skips the handshake.

---

## 2. Storage

### 2.1 At rest
The client stores the nsec using the strongest mechanism the device supports, probing top to bottom. Every level is acceptable; the lowest is the base.

| Level | Platform | Mechanism |
|---|---|---|
| 3 | iOS / macOS | Keychain item under `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with **no** biometric ACL (so reads are silent while the device is unlocked); privileged actions call `LAContext.evaluatePolicy` separately |
| 3 | Android | Keystore AES key **without** `setUserAuthenticationRequired` (silent while unlocked, StrongBox where available); privileged actions use `BiometricPrompt` separately |
| 2 | Windows / Linux desktop | Credential Locker / Secret Service, bound to the OS user account, silent read; privileged actions use `UserConsentVerifier` / a keyring prompt. Not hardware-bound; not level 3. Probed first on Windows; DPAPI file is the fallback if Locker is unavailable. |
| 2 | Windows | DPAPI-protected file (never prompts; privileged actions proceed with an in-app confirm only) |
| 2 | Browser | nsec wrapped by a non-extractable WebCrypto AES-GCM key in IndexedDB (silent use) — one storage path; when a platform authenticator exists, a user-verifying WebAuthn assertion additionally gates privileged actions as a consent step (§2.3). Never level 3: the browser has no authenticator-bound decryption. |
| 1 | Any | App-private storage, unencrypted |

Probing MUST be silent and MUST NOT add onboarding steps. If a level-3 mechanism requires user enrolment (e.g. no biometric set up, no passkey), the client stores at the next available level and MAY show a one-time, dismissible notice offering to upgrade later. The client MUST re-probe on launch and upgrade in place when a higher level becomes available.

On desktop browsers, if a NIP-07 extension is present, the client SHOULD offer to hand the key to the extension. The offer is dismissible.

### 2.2 Unlock policy
The unlock threshold is a per-identity setting, `lock`, chosen by the user and carried to new devices in the transfer rumor (§3.4):

| `lock` | Behaviour |
|---|---|
| `device` (default) | The device's own login is the unlock. The client never prompts for ordinary signing. |
| `launch` | One prompt when the app starts; none until it exits. |
| `idle:<seconds>` | Prompt after that many seconds without interaction. |

In browsers, `launch` and `idle` prompts are consent steps, not cryptographic locks — `W` decrypts silently for any code on the origin (§2.3); the same is already true of the privileged-action gate.

Ordinary signing never prompts under `device`. On every platform, including the browser, "device" means the device: one unlock covers every tab, window, and process of the client on that device. Level-3 storage is therefore configured so reads never prompt; the authenticator is invoked only by the privileged-action gate below. The enrolment key `E` (§11.1) is stored the same way, since it must sign co-signing rounds silently.

**Privileged actions always prompt**, under every `lock` value, using the platform authenticator (biometric/OS credential; PRF assertion in the browser). Levels 1–2 substitute the OS credential prompt where one exists and otherwise proceed.

*Rule:* an action is privileged if and only if it touches the key itself — who holds it, where a copy goes, or what protects it. Actions about content are never privileged.

Privileged:
- Sending the key or a share to another device: acting as Holder (§4 step 11, §5 step 12, §11.7).
- Showing or exporting the key: export (§7.1, always `ncryptsec`), viewing the nsec on screen (permitted, privileged, never written to disk), enrolling a server (§11.2 uploads a backup).
- Splitting or refreshing it: enabling threshold signing, refresh, Offline mode on or off (and allowing it for another device), keep-key on or off, disabling threshold signing.
- Cutting a device off: remove device, change role.
- Changing `lock`.

Never privileged: posting, replying, reacting, reading or sending DMs, decrypting, completing a signing round for another of the user's devices, receiving a key as Joiner, and any signature a website requests.

The prompt MUST state what it guards in one line ("Confirm — this sends your key to *Laptop*"). A prompt the user cannot attribute to an action they just took is a defect.

### 2.3 Browser procedure
```
Storage:
  W  = crypto.subtle.generateKey(AES-GCM-256, extractable = false, [encrypt, decrypt]); persist W in IndexedDB
  call navigator.storage.persist() at first use; IndexedDB is evictable without it
  ct = AES-256-GCM(W, nsec)                        // usable by any tab on this origin without a prompt

Privileged-action gate (level 2+ browsers):
  Registration: navigator.credentials.create({ ..., authenticatorSelection: { userVerification: "required" } })
                if no platform authenticator is available → plain level 2; privileged actions use an in-app confirm only
                store credentialId, SALT_A, SALT_B (random 32 B each)
  Gate:         navigator.credentials.get({ ..., extensions: { prf: { eval: { first: SALT_A, second: SALT_B } } } })
                a successful assertion (signature verified against the stored credential public key) is the consent;
                the nsec is then read from `W` as usual. `userVerification: "required"` is what makes the assertion
                a biometric/PIN event. PRF is not used in v1.
```
`SALT_B` is reserved and MUST NOT be used in v1.

The PRF gate is a **consent step, not a cryptographic boundary**: `W` decrypts the nsec silently, so a hostile script on the origin is not stopped by the passkey. The gate stops a person at an unlocked machine, which is its purpose; the origin itself is trusted by definition, and §11's restricted role exists because of exactly this.

`W` is origin-scoped by the browser: only this site's own code can use it. Other sites, other origins, and extensions without host permission for this origin cannot reach it. Under `lock = device` there is no expiry; a browser a user has logged into stays logged in until they remove the device or change `lock`.

### 2.4 Platform sync
The client MUST enable platform sync of the encrypted nsec where the platform provides it and the user has that platform feature turned on:

| Platform | Mechanism |
|---|---|
| iOS / macOS | Second Keychain item with `kSecAttrSynchronizable = true`, `kSecAttrAccessibleWhenUnlocked` (iCloud Keychain) |
| Android | Block Store (`BlockstoreClient`) with cloud backup enabled; the platform encrypts end-to-end under the lockscreen credential without the app seeing it. Keystore keys do not sync. |
| Browser | None; a browser is re-enrolled by §4 transfer |
| Desktop native | None |

On first launch the client MUST check for a synced copy before showing onboarding. If present, it restores silently and onboarding is skipped, and the device **self-enrols**: it generates `E`, signs an updated device list adding its own `E.pub` (label = platform + model, role = trusted, since it restored from the user's own platform account), and publishes it. Before self-enrolling, the restored device fetches the epoch record (the plaintext `epoch` tag suffices). If the fetch fails (offline, relays unreachable), it MUST wait and retry — self-enrolling on stale information is the dangerous branch; the key stays dormant until the record's presence or absence is established. **Absence is only established** after querying a relay the user controls or pays for (when configured) or, otherwise, after a 24-hour retry window — a withholding relay can manufacture absence, and absence is what unlocks self-enrolment with a full key. If an **active threshold record exists**, a restored nsec is a stale full-device backup taken before activation: the device **quarantines** the ciphertext (retained encrypted, unusable, invisible to the UI), writes the threshold marker, and shows the Joiner QR; the quarantined copy is deleted only once a co-signer completes a round for this device or the record is re-confirmed after 7 days — so a relay serving a stale *active* record (or withholding a `disabled` one) cannot trick the device into destroying the only key. Only when no active record exists does it self-enrol with the key. A restored device that does self-enrol therefore always appears on the list and is wiped at activation like any other. If instead it finds the §11.5 threshold marker, it holds no key: it shows the Joiner QR (§4) so an existing member can issue it a share.

---

## 3. Transfer: definitions

- **Holder** — device holding the nsec.
- **Joiner** — device receiving it.
- **Burner** — a fresh secp256k1 keypair created for one transfer session and destroyed after.
- **Session** — one transfer attempt. Lifetime 10 minutes. Burners MUST NOT be reused across sessions.

### 3.1 Transport selection
Before showing transfer UI, the client probes in parallel (timeout 3 s):
1. Relay reachability (WebSocket open + `AUTH`/`REQ` accepted on at least one configured relay).
2. Local network reachability (mDNS browse for `_nostrkeyxfer._tcp` or a `local=` endpoint from a scanned QR).

The transfer uses relays if reachable, else local network, else §6. Both relay and local paths MAY be attempted concurrently; the first wrap successfully received completes the session and the other path is cancelled.

Browsers cannot use the local path in either role (no mDNS; `ws://` to private IPs is blocked from `https://` for Holder and Joiner alike). A browser uses relays or §6.

### 3.2 QR URI
```
nostr+keyxfer://<npub>?v=1&mode=<offer|request|server>[&relay=<wss url>]*[&local=<ws url>][&plat=<platform>][&origin=<host>][&url=<https base url>]
```
- `npub` — bech32 burner public key of the device showing the QR.
- `mode=offer` — the showing device is the Joiner (Flow A).
- `mode=request` — the showing device is the Holder (Flow B).
- `relay` — 1–4 relay URLs the showing device is subscribed to.
- `local` — optional LAN endpoint, e.g. `ws://192.168.1.23:53317`.
- `url` — server base URL; `mode=server` only (§11.2).
- `plat` — self-attested platform: `ios|android|macos|windows|linux|web`. For `web`, `origin=<host>` is REQUIRED.

`plat` and `origin` are unverified claims by the Joiner. They exist so the Holder's consent prompt can say what the Joiner claims to be; a phishing page can lie, but must then lie in a way the user can read.

A client MUST reject URIs with unknown `v` or missing `mode`.

### 3.3 SAS (short authentication string) — commit, nonce, reveal
A short SAS is only safe if neither party can choose its inputs after seeing the other's. The **contacting** party (Holder in Flow A, Joiner in Flow B) therefore commits to a nonce before the other party reveals its own; the SAS is derived from both burners and both nonces.

```
contacting party:  nonce_C ← random 32 B;  commit = SHA-256("keyxfer-commit-v1" || C.pub || nonce_C)
                   sends { C.pub, commit }                      (C.pub is visible in the seal anyway)
other party:       nonce_O ← random 32 B;  sends { nonce_O }
contacting party:  sends { nonce_C }
both:              verify SHA-256("keyxfer-commit-v1" || C.pub || nonce_C) == commit
                   code = SHA-256("keyxfer-sas-v2" || H.pub || J.pub || nonce_H || nonce_J)
                   emoji[i] = EMOJI_TABLE[code[i] & 0x3f]  for i in 0..3
                   digits   = (code[4..8] as u32 BE) mod 1_000_000, zero-padded to 6
```
`H.pub`, `J.pub` are 32-byte x-only pubkeys in role order (Holder, Joiner). Mapping: in Flow A the contacting party `C` is the Holder (`nonce_C = nonce_H`); in Flow B it is the Joiner (`nonce_C = nonce_J`); `O` is the other side. `EMOJI_TABLE` is a fixed 64-entry list shipped with the client (Appendix A). Both emoji and digits MUST be shown.

**Why the commit.** Without it, an attacker in the middle (showing the Holder a QR for `J'` while talking to the real Joiner as `X`) learns the Holder's burner from the hello, fixes the Holder's SAS, and then grinds `X` offline until the Joiner's SAS matches — about 2^44 hashes, minutes on a few GPUs, while the user is waiting for the second screen. With the commit, each attacker-chosen value is fixed before the honest randomness it must match is revealed, so the attacker gets one 2^-44 shot per session and every failed shot is a visible mismatch. This is the ZRTP/Matrix construction; 44 bits is sufficient under it. In practice users may compare only the four emoji (~24 bits): even then the commit limits an attacker to one ~2^-24 online shot per session with a visible failure, which is still sound — the digits are for the cautious, not a requirement.

**Cost.** One extra message on the contacting side (commit, then reveal). Flow A is four messages before the key moves; Flow B is four.

### 3.4 Rumor kinds
```jsonc
// KEY_HELLO — Holder → Joiner (Flow A only): the Holder's commit
{ "kind": 24301, "content": "", "tags": [["burner", "<H.pub hex>"], ["commit", "<hex>"], ["v", "1"]] }

// KEY_REQUEST — Joiner → Holder (Flow B only): the Joiner's commit
{ "kind": 24302, "content": "", "tags": [["burner", "<J.pub hex>"], ["commit", "<hex>"], ["enrol", "<E.pub hex>", "<label proposal>"], ["v", "1"]] }

// SAS_NONCE — the non-contacting party's nonce (Joiner in Flow A, Holder in Flow B)
{ "kind": 24312, "content": "", "tags": [["burner", "<own burner hex>"], ["nonce", "<hex>"], ["v", "1"]] }

// SAS_REVEAL — the contacting party opens its commit
{ "kind": 24313, "content": "", "tags": [["burner", "<own burner hex>"], ["nonce", "<hex>"], ["v", "1"]] }

// TRANSFER_ACK — Joiner → Holder (both flows), sent after the nsec/share is stored
{ "kind": 24310, "content": "", "tags": [["burner", "<J.pub hex>"], ["enrol", "<E.pub hex>", "<label proposal>"], ["v", "1"]] }

// KEY_TRANSFER — Holder → Joiner
{ "kind": 24303, "content": "<64 lowercase hex chars: the 32-byte private scalar, not bech32>", "tags": [["burner", "<H.pub hex>"], ["lock", "<device|launch|idle:N>"], ["v", "1"]] }
```
Rumors are unsigned. They are sealed (kind 13, signed by the sender's burner, NIP-44 to the recipient burner) and gift-wrapped (kind 1059, random one-time key, `p` = recipient burner) exactly per NIP-59. The wrap MUST carry `["expiration", "<real wall-clock now + 600>"]` (NIP-40) — computed from the true current time, not from the wrap's NIP-59-randomised `created_at`, which may be up to two days in the past. On every received rumor the recipient MUST check that the `burner` tag equals the seal's signing key; a mismatch is discarded.

### 3.5 Relay subscription
Receiver subscribes: `{"kinds":[1059], "#p":["<own burner hex>"], "since": now - 172800}`. Dedupe by event id. The `since` window is required because NIP-59 randomises `created_at` up to two days back. If a relay rejects the publish (allowlist, paid, unknown burner), the client tries the next relay from the QR, then the local path.

If a relay returns `auth-required`, a device authenticates with its **burner** — the wrap is addressed to that burner, which is exactly what auth-gated relays check, and it reveals nothing. Neither side uses its real identity for NIP-42 in a transfer.

### 3.6 Local network path
- Joiner listens on a random port ≥ 49152 for WebSocket; advertises `_nostrkeyxfer._tcp` with TXT `npub=<burner npub>`.
- Holder connects and sends the wrap as a single text frame containing the kind 1059 event JSON.
- Same rumor, seal, wrap, SAS, and cleanup as the relay path. The LAN is untrusted; the wrap already assumes that.

### 3.7 Pairing code (no camera on either side)
Wherever a flow says "scan the QR," the scanning device MAY instead type a pairing code shown by the other device. The code replaces only the pairing step; burners, SAS, rumors, and cleanup are unchanged.

```
code       = <nameplate>-<word>-<word>
nameplate  = random 3-digit decimal, generated per session
words      = two words from the PGP word list (even list, then odd list) — 16 bits; adequate only because SPAKE2 allows one guess and a failure burns the code
rendezvous = SHA-256("keyxfer-rdv-v1" || nameplate || hour_bucket)  hour_bucket = floor(unix_ts / 3600)
             the answering side tries the current and previous hour
```
The nameplate is public and locates the session. The words are the SPAKE2 password and MUST NOT be used to derive the rendezvous tag or any other transmitted value.

SPAKE2 per RFC 9382 over P-256 with the RFC's `M`/`N` constants (P-256 so browsers can use WebCrypto). Identities: `A = "keyxfer-shower"`, `B = "keyxfer-typer"`. Password input `w = HKDF-SHA256(words, salt = nameplate, info = "keyxfer-spake2-v1")` reduced mod the group order. Key schedule and confirmation MACs exactly per RFC 9382 §3.3–3.4.

Kind 24304 is ephemeral (relays do not store it), so ordering matters: the **shower subscribes first and the typer initiates**.
1. On displaying the code, the shower subscribes to `#r = rendezvous` (current and previous hour).
2. The typer, after validating the words, subscribes to the same tag and then publishes its SPAKE2 message (kind 24304, **not wrapped**, tagged `["r", rendezvous]`).
3. The shower answers with its SPAKE2 message. Both derive `K` and exchange the RFC 9382 confirmation MACs.
4. Each sends its burner pubkey and the QR parameters (`mode`, `relay`, `local`, `plat`, `origin`) NIP-44-encrypted under `K` in a further kind 24304 event.
5. Flow A or B proceeds from the point after the QR scan.

**Input validation.** The typing device MUST autocomplete from the PGP word list and MUST NOT transmit until both words are valid list entries in the correct even/odd position. Most typos are therefore caught before any SPAKE2 message is sent.

**Failure handling.**
- No peer message received within 60 s: no guess has been consumed. The client MAY retry under the same code.
- A peer message received but key confirmation fails: the code is burned. Both sides abort, zeroize `K`, and the showing device immediately displays a fresh code (new nameplate, new words). The client MUST NOT run SPAKE2 again under a burned code.

A code is valid for one session and at most 10 minutes. On shared public relays, honest concurrent users may collide on a nameplate and burn each other's codes; clients SHOULD use a dedicated rendezvous relay where available. Collisions are a nuisance, not a compromise.

**Denial of service.** The nameplate space is small by design (typeable). An attacker who posts a bogus SPAKE2 message to every rendezvous burns every code on first contact. This is accepted: the effect is a nuisance, not a compromise, and the user falls back to a QR scan (§4/§5) or off-grid transfer (§6). Clients SHOULD show "Pairing codes are being interfered with on this relay — try a QR instead" after two consecutive burns.

### 3.8 Multiple-responder warning
A QR or code is meant to be scanned once. If, within one session, the receiving side sees messages from **two or more distinct burner pubkeys** — two `KEY_HELLO` wraps in Flow A, two `KEY_REQUEST` wraps in Flow B (each gets its own nonce exchange), two SPAKE2 responders in §3.7 — someone other than the user probably scanned it.

The client shows a soft, non-blocking notice on the device that displayed the QR:

> Another device also responded to this code. If that wasn't you, someone nearby may have scanned it. Nothing was shared with them.

The session continues normally: the SAS comparison (§3.3) is what decides which responder is real, and the user confirms it as usual. The notice is recorded in the `transfer_event` (§8) with `multi: true`.

To keep bugs from firing it, the following MUST NOT count as a second responder: the same event id seen on several relays; retransmissions from the same burner pubkey; a wrap that fails to unseal; and rumors whose (inner, un-randomised) `created_at` is outside the session's 10-minute window — the wrap's `created_at` is randomised by NIP-59 and MUST NOT be used for this test. Out-of-window rumors are **discarded from the session entirely** — never shown, never given a nonce exchange, never in the SAS list — not merely excluded from this counter; otherwise backdating the inner timestamp would bypass the notice while still reaching the user.

---

## 4. Transfer: Flow A (Joiner shows QR)

Used when the Joiner cannot scan (desktop, browser) or whenever the Holder is a phone.

Origins in the prompt are shown as punycode (`xn--…`) when they contain non-ASCII, so homoglyph domains read as what they are.

**What the SAS does and does not do.** The SAS proves the Holder and the party that showed the QR share an untampered channel. It defeats substitution: a MITM on relays, or a swapped QR. It does **not** defeat a phishing page that *is* the Joiner — such a page holds `J`, receives the hello, and shows a matching SAS. Against that, the only defence is the consent prompt at step 9, which MUST name what the Joiner claims to be (`plat`/`origin` from the QR) and MUST be a deliberate action on the Holder. The Holder MUST NOT send the key before that action.

```
Joiner                                      Holder
------                                      ------
1. gen burner J
2. subscribe #p=J.pub (relays), start local listener
3. show QR mode=offer
                                            4. scan QR; gen burner H, nonce_H
                                            5. wrap KEY_HELLO(H.pub, commit) → J.pub; publish
6. receive hello; unseal; verify burner == seal
   signer; gen nonce_J for this H
   (hello from a second distinct H → §3.8; keep
    every distinct H with its own nonce_J)
7. wrap SAS_NONCE(nonce_J) → H.pub; publish
                                            8. receive nonce_J; wrap SAS_REVEAL(nonce_H)
                                               → J.pub; publish
                                            9. sas = SAS(H, J, nonce_H, nonce_J); show
                                               "Send your key to a browser at
                                                example.com showing [emoji] [digits]?
                                                [ ] Trust this device (my own app)
                                                Send / Not mine"
10. receive reveal; verify commit; sas for this H
    show the SAS list (at most 3, newest first):
    "Tap the code your other device shows"
                                            11. user taps Send    → 12
                                                user taps Not mine → abort, zeroize H
                                            12. wrap KEY_TRANSFER(nsec, H.pub) → J.pub; publish
13. receive wrap(s); unseal each; verify burner ==
    seal signer; hold keyed by seal signer (do NOT store)
14. user taps the SAS matching the Holder's screen;
    Joiner IMPORTS only the held wrap whose signer is
    the tapped H; derives npub, shows
    "Log in as @name?  Yes / No"
15. Yes → store nsec (§2.1); wrap TRANSFER_ACK → H.pub;
    zeroize J and every other pending wrap
    No  → discard all, abort
                                            16. zeroize H on TRANSFER_ACK or after 60 s
```

Step 11 authorises release on the device that holds the key. Steps 14–15 authorise *import* on the device that receives it: without them, anyone who photographed the QR could race the real Holder and plant their own key on the Joiner — a login-substitution attack. The Joiner therefore never stores a key without the user picking the SAS and confirming the resulting identity. A substituted QR, with or without a grinding attacker in the middle, yields a SAS the real Joiner's screen doesn't show (§3.3). A phishing page acting as Joiner shows a matching SAS; what the user has left is the prompt text at step 9, which is why it names the claimed origin.

---

## 5. Transfer: Flow B (Holder shows QR)

Used when the Holder cannot scan (camera-less desktop, browser).

```
Holder                                      Joiner
------                                      ------
1. gen burner H
2. subscribe #p=H.pub, start local listener
3. show QR mode=request
                                            4. scan QR; gen burner J, nonce_J
                                            5. wrap KEY_REQUEST(J.pub, commit, enrol) → H.pub
                                            6. publish to QR relays and/or local
7. receive request; unseal; verify burner ==
   seal signer; gen nonce_H for this J
8. wrap SAS_NONCE(nonce_H) → J.pub; publish
                                            9. receive nonce_H; wrap SAS_REVEAL(nonce_J)
                                               → H.pub; publish
                                            10. sas = SAS(H, J, nonce_H, nonce_J); show
                                                "Waiting — other device should
                                                 show [emoji] [digits]"
11. receive reveal; verify commit; sas; show
    "Approve login for device showing
     [emoji] [digits]?
     [ ] Trust this device (my own app)"
12. user taps Approve
    (Deny → discard this J; show the next
     distinct pending request, if any, or
     keep waiting; abort only at 10 min)
13. wrap KEY_TRANSFER(nsec, H.pub) → J.pub
14. publish
                                            15. receive wrap; unseal; verify
                                                tag burner == H.pub from QR
                                                and == seal signer (else discard)
                                            16. derive npub; show "Log in as
                                                @name?"; Yes → store nsec
                                            17. wrap TRANSFER_ACK → H.pub; zeroize J
18. zeroize H on TRANSFER_ACK or after 60 s
```

Requests are queued by distinct `J.pub` in arrival order, capped at **5 pending per session** (further distinct requests are dropped with the §3.8 notice); each queued request runs its own nonce exchange, and only one is shown for approval at a time. Deny advances to the next or returns to waiting; the session ends on approval or at the 10-minute limit. Under the cap, a flooder costs the user at most a handful of denials, so delay-not-denial actually holds.

---

## 6. Off-grid transfer

Shown only when §3.1 probing found no relay and no local endpoint, and the user confirms "I'm offline." **In threshold mode, off-grid transfer is unavailable toward restricted targets and available only from a keep-key device** (the only device that legitimately holds the nsec; an Offline-mode device's two shares are the polynomial and MUST NOT be exported) — handing an origin the full nsec off-grid would bypass every §11 invariant at once. Browsers cannot act as Holder here (no screenshot-block flag); a browser Joiner MAY scan-by-camera or type the ncryptsec.

1. Holder prompts for a passphrase — no floor, same rule as §11.2 — with the line **"Anyone who photographs this code can try passwords against it forever; this passphrase is the only protection."** It displays a QR of `ncryptsec` (NIP-49, `log_n = 18`, KSB `0x02`).
2. The screen sets the platform screenshot-block flag (`FLAG_SECURE`, `SetWindowDisplayAffinity`, `isSecureTextEntry`-equivalent) and auto-dismisses after 60 s. Linux desktop has no reliable flag (X11 none; Wayland compositor-dependent): a Linux Holder proceeds with an explicit warning line that screenshots cannot be blocked.
3. Joiner scans, prompts for the same passphrase, decrypts, stores (§2.1).
4. Holder records a `transfer_event` with `rung = offgrid`.

---

## 7. Backup

### 7.1 Onboarding prompt
At the end of onboarding the client presents backup as the next step, with one of:
- Platform sync (§2.4), auto-detected and shown as already done if active,
- ncryptsec export (file or printable QR, `log_n = 18`),
- Blob-store backup (§7.2).

The step is skippable ("Later"). If skipped, the client MUST NOT nag: no banner, no scheduled reminders. Backup status is shown as a passive line in settings ("Backup: none / iCloud Keychain / server"). The client MAY show the offer once more, dismissibly, immediately after the user completes a transfer as Holder. The client MUST NOT block login, posting, or transfer on backup status.

The export is always `ncryptsec`; the client MUST NOT export a raw nsec.

### 7.2 Blob store
A stateless HTTP service (reference: Cloudflare Worker + KV) that stores one encrypted backup per identity. Used directly by §7.1 and reused unchanged by §11.2/§11.10.

```
Client (setup, on a trusted device):
  salt     = random 16 B
  K_pw     = scrypt(password, salt, N = 2^log_n, r = 8, p = 1, dkLen = 64)    log_n = 18, fixed for the blob store (a 17 option would make its bearer enumerable via §7.2 anti-enumeration); local-only §6/§7.1 exports MAY use 17 on low-memory devices. Recovery needs ~512 MiB free; the client says so if the device lacks it
  K_enc    = K_pw[0..32]                                     // never leaves the device
  K_auth   = HKDF-SHA256(K_pw[32..64], salt = "auth-v1", info = server base url)   // per-server: a removed server's credential is useless elsewhere
  K_srv    = random 32 B                                     // generated client-side, held by server
  K_wrap   = HKDF-SHA256(ikm = K_enc XOR K_srv, salt = "blob-wrap-v1", info = npub_hex)
  CK       = random 32 B                                     // content key, generated once per identity
  nsec_ct  = nonce || AES-256-GCM(CK, nonce, nsec)            // fixed for the identity's lifetime
  ck_wrap  = nonce || AES-256-GCM(K_wrap, nonce, CK)          // per server / per password
  blob     = { nsec_ct, ck_wrap }                            // nonces random 96 bits; the §7.1 file export is separately ncryptsec
  PUT  /v1/backup   { npub, salt, blob, k_srv, K_auth }   auth: Schnorr sig over a server challenge by the user's key
                    (base mode), or by a trusted E.pub on the current device list (threshold mode — the server holds the
                    group secret and can read the list; group-key digest signing is unavailable by design, §11.6)
                    server computes verifier = HMAC-SHA256(key = k_srv, K_auth) and discards K_auth

Client (recovery, on a trusted device, nothing else available):
  GET  /v1/salt?npub=…                        → { salt, log_n }   for unknown npubs returns HMAC(server_secret, npub) truncated to 16 B as salt and always log_n = 18 (matching the overwhelming real-user value; a mixed fake distribution would itself signal non-existence)
  derive K_pw from password + salt
  POST /v1/recover { npub, K_auth }           → { blob, k_srv } only if HMAC-SHA256(k_srv, K_auth) == verifier
  K_wrap as above → decrypt

Server:
  keys by SHA-256(npub); stores salt, blob, verifier in the data store
  stores k_srv in a separate secret store (e.g. Worker secret binding / per-user KV in a second namespace), never in the same table as blob
  /recover: constant-time compare; 10 attempts per hour and 30 per day per npub, 20 per hour per IP, exponential backoff
            unknown npubs get the same response time and shape as a wrong password
            an attacker who knows the URL and npub can exhaust the per-npub quota and delay a user's recovery by hours; this DoS is accepted
            30 online guesses a day, with no password floor, is enough to find a top-few-hundred password in weeks without any breach; the password screen says so
  no request logging beyond rate-limit counters
```
Why the indirection: changing the password or adding a server only re-wraps `CK` under a new `K_wrap`. In threshold mode `CK` is distributed to trusted devices alongside their shares (§11.5), so those operations never reconstruct the nsec. A trusted device holding `CK` plus the server's `nsec_ct` is the key — which is already true of trusted device + server per §9, so nothing is lost.

Properties, honestly stated:
- A leak of the data store alone (salt, blob, verifier) is unbreakable: `verifier` is keyed by `k_srv`, so it cannot be used to test password guesses offline, and `blob` needs `k_srv` regardless. (A plain hash verifier would have let a data-store leak be cracked offline and then redeemed with a single correct online call.)
- A leak of both stores reduces to password strength at scrypt cost. No single-server construction avoids this; OPAQUE does not either, since the server's OPRF key would be in the same leak.
- An attacker with only a URL and npub gets rate-limited online guesses, never the ciphertext.
- The password is never sent; only `K_auth` is, over TLS to the enrolled URL.

**Recovery delay (SHOULD; default on whenever the server knows at least one `E.pub` to notify — backup-only users are equally phishable, so enrolment registers the enrolling device's `E.pub`, and later devices register on first contact; this leaks device count to the server, which threshold servers already see).** Notices are `RECOVERY_NOTICE` wraps (kind 24316) to each registered `E.pub`. On a correct `/recover`, the server holds release for a configurable delay (default 24 h), immediately notifying every enrolled member ("A recovery of your key started; it completes at …; approve or cancel from any trusted device"). A trusted device can approve instantly or cancel; with no devices left, the delay simply elapses. This converts a phished password from an instant key into a raced, visible one.

Because there is no password floor (§11.2), the password screen MUST show the two warning lines in §11.2 step 2.

---

## 8. Transfer policy

- Any device holding the nsec MAY act as Holder, at any storage level.
- A device that received its key by transfer defaults to **receive-only** in settings. The toggle is one tap, unguarded, and the transfer screen shows it inline ("This device is receive-only — allow sending?") rather than hiding the option.
- Every transfer (all rungs) writes a local `transfer_event { ts, rung, sas, peer_burner, multi }` visible in settings.
- There is no remote revocation. A "devices" list, if shown, MUST label removal as deleting the local copy only.

---

## 9. Security properties

Base (§1–8):
- Relays, LAN peers, and the blob store never see plaintext key material.
- A photographed or substituted QR yields nothing: it is a pubkey; the SAS is commit-then-reveal so an attacker in the middle cannot grind a match (§3.3); the Holder sends only after confirming the SAS on its own screen; and the Joiner accepts only from the burner it was told about.
- A hostile enrolled website can phish the backup password with a fake dialog; the recovery delay makes the resulting theft visible and cancellable, but a user who confirms a phished recovery loses the key. Residual risk.
- A phishing page acting as Joiner is **not** stopped by the SAS. It is stopped only by the user declining a consent prompt that names the claimed origin. This is the base flow's residual risk, and §11's restricted role is what bounds its damage once threshold mode is on.
- Storage theft yields ciphertext bound to the device's secure hardware (level 3), to the OS user account or browser profile (level 2), or plaintext (level 1, by the user's choice).
- Blob store: a dumped database is unbreakable without `K_enc`; a URL and npub buy rate-limited guesses; a fully compromised server reduces to password strength at scrypt cost.
- A compromised unlocked device yields the key. Without §11, Nostr has no rotation; this is out of scope.

Threshold mode (§11):
- Once every device has ACKed, no device, site, or server holds a usable key: each holds one share; replicas of the same index never combine; the backup holds the key under the password. Until every device has ACKed, the non-ACKed devices still hold the full key and are shown as such.
- A hostile site is limited per §11.13. A compromised server is limited per §11.12.
- Refresh (§11.9) invalidates every old share without reconstructing; only §11.15 disable reconstructs, on a trusted device, at the user's request.
- Keep-key (§11.5) and Offline mode (§11.14) are explicit exceptions the user creates with a second device's approval; they are shown in the lock state. Both are trusted-device-only, because a device that has held two shares cannot be un-trusted by refresh.
- Permanent `#p = E.pub` subscriptions let a relay count a user's devices and see per-device activity timing under a stable key. Not mitigated in v1.
- The server (or any trusted co-signer) sees the plaintext of every event a share-only device signs through it, and the peer pubkey of every NIP-04/44 conversation key it helps derive. It does not see DM contents.
- A compromised trusted device can start a refresh war; the resolution is recovery from backup on a clean device (§11.10).
- **A compromised trusted device plus a reachable server is the key.** It can enrol a Joiner it controls (§11.7) or run disable (§11.15), and share + share reconstructs. Threshold mode therefore protects against hostile sites, hostile or compromised servers, and lost *restricted* devices; it does not protect against a rooted trusted device, which is the same threat as a rooted phone in base mode. Users with two or more trusted devices MAY turn on **two-device approval** (§11.1), after which issuance, disable, keep-key, and reconstructing operations require a tap on a second trusted device and a single compromised trusted device is limited to co-signing.

---

## 10. Out of scope for v1
NIP-46 remote signing, own-npub monitoring, identity migration tooling. These do not change any decision above; a later version may add them.

---

## 11. Server: backup and optional threshold signing

Additive per §0. Nothing in this section alters §1–10. A user who never enrols a server is unaffected.

**Server independence.** Every operation in this section — signing, share issuance, refresh, Offline mode, disabling — MUST be completable with two of the user's own devices and no server reachable. A server is a replica of share 1 that happens to be always on; it is never a requirement.

### 11.1 Enrolment keys and device list
Every device generates a stable secp256k1 **enrolment keypair** `E` at install (stored per §2.1). The client maintains a **device list** — `{E.pub, label, role, storage_level, mode}` per device — in a parameterised replaceable event (kind 30242, `d = "devices"`), signed by the user's key. In base mode it is NIP-44-encrypted to the user's own pubkey. In threshold mode a share-only device cannot compute `nsec·P` without a round, so the content is instead encrypted (NIP-44 v2 payload format with a symmetric conversation key) under a **group secret**: a random 32-byte value distributed alongside every share in `KEY_SHARE` and `KEY_SHARE_PART` and replaced by a fresh one carried in every `KEY_REFRESH`. The epoch record (§11.4) is encrypted the same way. During every §4/§5 transfer the Holder reads the Joiner's `E.pub` from the `enrol` tag of `KEY_REQUEST` or `TRANSFER_ACK` and adds it to the list; the label proposal is a default the Holder's user may override. Each device subscribes to `#p = E.pub` permanently for §11 wraps, with `since` = a persisted last-seen cursor minus 2 days, and never less than 32 days back on first subscribe or after a gap — §3.5's 2-day window is for burners only. This costs the user nothing and is required for §11.4 onward.

**Roles.** `trusted` — native app on a device the user owns; may sign, refresh, issue shares, act as helper, approve requests, remove devices. `restricted` — every browser-origin device; may sign ordinary content and send requests, nothing else: never Holder, never helper, never refresh initiator. **A Joiner's role is chosen by the Holder's user, never by the Joiner.** `plat`/`origin` are unverified, so they inform the prompt but never the role. The Holder's consent prompt (§4 step 9, §5 step 11) carries an unchecked box, **"Trust this device — it's my own app on hardware I own,"** defaulting to restricted for everything. Ticking it assigns trusted. When two-device approval (below) is on, ticking it additionally requires an `APPROVAL` from a second trusted device. Role can later be changed only from a trusted device. A phishing page that claims `plat=linux` therefore still lands on index 2 unless the user affirmatively ticks the box. Servers enforce role on every privileged endpoint; devices enforce it on every privileged wrap.

**Two-device approval (optional).** A setting on the devices screen, available when two or more trusted devices are enrolled, off by default. When on, every operation that issues a new index, releases share 1, or reconstructs (§11.7, §11.14 enter, §11.15, and the reconstructing operations in §11.5a) requires an `APPROVAL` (kind 24311) signed by a second trusted `E.pub` naming the operation, the requester, a unique request-id, and a 10-minute expiry — verifiers reject reuse and expiry, so an APPROVAL cannot be replayed within the 30-day wrap window; servers and helper devices MUST verify it before contributing. The prompt on the approving device names the operation and consequence in one line. The toggle itself says: "With exactly two trusted devices, losing one means recovering from backup." Without this setting, one trusted device plus a server suffices, and §9 states what that means.

**Labels** are written by the Holder at enrolment (defaulting to platform + model, or origin for browsers) and edited only from trusted devices. A Joiner MUST NOT be able to set or change its own label.

### 11.2 Server enrolment
A server is a Nostr-speaking service with a stable enrolment keypair `S` and an HTTPS base URL.

1. Server displays a QR: `nostr+keyxfer://<S.npub>?v=1&mode=server&url=<https base url>` (or a §3.7 code).
2. Phone scans. Client prompts: **"Backup password"** — pre-filled with a generated six-word PGP phrase (~96 bits) the user may keep or replace with anything; no minimum, no rules. The screen carries two lines: **"If this server is ever hacked, this password is the only thing protecting your key,"** and **"Anyone who knows your npub and this server can try a few dozen passwords a day."** Server enrolment, and any entry of the backup password, happens only on trusted devices; a restricted device MUST NOT present a backup-password field. A strength meter MAY be shown; it MUST NOT block.
3. Client runs §7.2 setup against `<url>` with the password entered in step 2. The server stores `salt`, `blob`, `k_srv`, `verifier`; nothing else about the key.
4. Client shows the **mode screen** (§11.3).

Enrolling a second server repeats steps 1–3; the blob is uploaded to every enrolled server. In threshold mode a trusted device re-wraps `CK` for the new server (§11.5a); no reconstruction.

### 11.3 Mode screen (mandatory, shown once per server enrolment)
Shown only if the device list contains **at least two devices, at least one of them trusted** (a native app). With fewer, threshold signing is not offered and the enrolment is backup-only. Two browsers alone do not qualify: both would hold index 2 and neither could refresh, help, or disable. With exactly one trusted device, losing it means recovery is via the backup (§11.10); the client says so on this screen.

Exactly two options. **B is preselected.**

> **A — Threshold signing**
> Your key is split into pieces so no device or website holds a usable copy; the only full copy is your encrypted backup. Any device can post and read DMs while your server or another of your devices is reachable, and any device can be revoked. Your server sees what your other devices post (not the contents of DMs). To use a device with nothing reachable, turn on **Offline mode** for it first — it needs a tap from one of your other devices.
>
> **B — Backup only (recommended)**
> Your key stays on all your devices as it is now. The server holds an encrypted backup you can restore with your password.

The client MUST NOT enable threshold signing by any path other than the user selecting A on this screen or in settings. Selecting A later from settings shows the same text and the same two-device requirement.

### 11.4 Threshold parameters
- Scheme: FROST per RFC 9591 with the secp256k1 Taproot variant as implemented by `frost-secp256k1-tr` (Zcash Foundation). Concretely: if `pubkey(nsec)` has odd y, the dealer uses `a_0 = n − nsec` so the group key is even-y; group nonce commitment parity is handled per that ciphersuite at each signing round. Implementations MUST use that ciphersuite or one interoperable with it. On reconstruction (§11.5a, §11.15) the result is `n − nsec` for an odd-y key; the client MUST re-negate before storing or exporting. ECDH is unaffected because x-only.
- `t = 2`.
- Index `1` is the **server index**. Every enrolled server holds a replica of share 1.
- Index `2` is the **restricted index**. Every restricted-role device holds a replica of share 2.
- Trusted devices hold indices `3..N`, one per trusted `E.pub` in the device list.
- Replicas share an index and therefore never combine: any number of servers is one share; any number of restricted devices is one share. Valid signing pairs are server + restricted, server + trusted, restricted + trusted, trusted + trusted.
- Polynomial at activation:
  ```
  a_0 = nsec (parity-adjusted per above)
  a_1 = random mod n                       // MUST be fresh randomness; never derived from the nsec
  f(x) = a_0 + a_1·x
  share_j = f(j)
  ```
  A deterministic `a_1` would let a re-activation reproduce an old polynomial and resurrect revoked shares; it is forbidden.
- Epoch: `{counter, id}` where `counter` increments and `id` is random 128 bits. A member orders epochs by `counter`. Two honest refreshes racing produce the same `counter` with different `id`s: the **lower `id` wins**; a member that has applied the loser discards that share (it kept the pre-refresh share until both ACKs cleared — see §11.9) and applies the winner; the losing initiator, on seeing the winner, re-initiates on top of it if its purpose (a removal, an exit) is still unmet. Members retain the previous-epoch share until they see an **epoch-finalized marker** (`EPOCH_FINALIZED`, kind 24319, wrapped to members; group-key-signed) listing ACKed indices — or 7 days elapse, or a newer verified epoch supersedes, whichever first; ACKs flow only member→initiator, so the marker is what makes retention observable to everyone else. A re-activation (§11.10) sets `counter = max(any record found, unix_time)` + 1.
- **Epoch record**: kind 30242, `d = "frost"`, encrypted under the group secret (§11.1) with a **plaintext tag `["epoch", counter]`** so a member holding a stale group secret can still tell that a newer epoch exists, content `{epoch, t, group_pub, commitment: a_1·G, members: [{index, E.pub|S.pub, role}]}`, signed by the group key (via FROST once active). `commitment` lets any member verify any share or partial: `share_j·G == group_pub + commitment·j`. It is updated on every refresh (§11.9).

### 11.5 Activation (user chose A)
Performed by the device that chose A, which still holds the nsec. Every device, including this one, receives a share; no device keeps the nsec.
1. Derive epoch-1 polynomial. Compute share 1 and one share per device in the device list.
2. Gift-wrap `KEY_SHARE {epoch: 1, t: 2, index, share, group_pub, lock}` (kind 24305) to each server `S.pub` and each other device `E.pub`; store own share per §2.1.
3. Publish the epoch record (signed with the nsec directly; this device still holds it).
Activation is journaled: the device writes `{stage, epoch, issued: [...]}` per §2.1 before each step and resumes idempotently after a crash — re-sending unACKed shares, re-publishing the record — and performs step 4 only after steps 1–3 are durably complete.
4. Wipe the local nsec **and every synced copy**: delete the `kSecAttrSynchronizable` Keychain item, delete the Block Store record. Write in their place a small synced **threshold marker** `{group_pub, epoch}` so a device restored from platform backup knows to enrol for a share (§2.4) rather than expect a key.
(Blob upload, if a server is being enrolled at the same time, happens in §11.2 step 3 *before* this activation, while the nsec is still present.)

**Where the full key still exists after activation**, stated so §9 does not overclaim:
- On any device that has not yet ACKed the epoch. Such a device holds the nsec and **cannot be revoked by refresh**; removing it from the list only stops future shares. The lock MUST be amber until every device ACKs, and the devices screen MUST mark each non-ACKed device "still holds full key."
- In the §7.2 backup, by design, under the user's password.
- In any §7.1 ncryptsec file or printed QR the user exported before activation; those survive by definition and the activation screen reminds the user they exist.
- On a keep-key device, by the user's explicit choice.

### 11.5a Reconstructing operations
With the §7.2 content-key indirection, changing the backup password and enrolling an additional server re-wrap `CK` on a trusted device and never reconstruct. **Disable (§11.15), and Re-split (§11.11, which is disable + re-activate), are the only reconstructing operations.** It is privileged: one prompt on the device; with two-device approval on (§11.1), also one tap elsewhere. Refresh, joint issuance, share-1 replication, password change, and server enrolment never reconstruct.

`CK` travels to trusted devices in `KEY_SHARE` / `KEY_SHARE_PART` (trusted indices only; never to index 2 or to servers) and is stored per §2.1.

**Keep-key option.** A user MAY mark one device "Keep the full key on this device" in settings. Approval: the same second-trusted-device tap as Offline mode entry (§11.14), with the prompt "*Laptop* wants to keep your full key permanently. Allow?" — required regardless of the two-device-approval setting. That device is a **bunker**: it keeps the nsec, signs alone, and can issue and refresh alone. A bunker **cannot be revoked** — refresh changes shares, not the nsec — and the client says so when the option is chosen. This is off by default.

On receiving `KEY_SHARE`, a device verifies that `group_pub` equals the user's known x-only pubkey **and** `share·G == group_pub + commitment·index`, stores the share per §2.1, wipes its nsec, and gift-wraps `SHARE_ACK {epoch}` (kind 24306) to the activating device's `E.pub`. A device offline at activation keeps its nsec and continues in base mode until it receives its share.

The **lock indicator** is green only when every device in the device list has ACKed the current epoch. Until then it is amber with the count ("2 of 3 devices").

### 11.6 Signing and what the co-signer sees
A FROST co-signer must see the message it signs. **Every event a share-only device signs through the server is visible to the server in plaintext**, including DM envelopes (not their contents, which are NIP-44-encrypted before signing). Trusted-device co-signers see the same. §11.3 discloses this.

- Default: device share + server share. The requester sends the **full unsigned event**, not a 32-byte digest; the co-signer serialises and hashes it itself (NIP-01), so it knows the kind and content it is signing. Every co-signer — server **or trusted device** — MUST check the requester's role before completing a round: for a restricted requester it signs only kinds on an **enumerated allowlist** shipped with the client and server (reference set: 0, 1, 3, 5, 6, 7, **13**, 16, 30023; deployments may extend it deliberately) and refuses everything else — in particular 30242 and 10002. Kind 13 is required: NIP-17 DMs are sent by group-key-signing the *seal* (the 1059 wrap is signed by a one-time key, so 1059 never legitimately reaches a co-signer). Kind 10002 is refused for restricted requesters because rewriting the relay list assists the record-withholding attacks §2.4 and §11.9 defend against. Kind 5 is signed only after checking its `e`/`a` tags: a deletion referencing any kind-30242 coordinate is refused, since it would let an origin destroy the device list or epoch record and manufacture the §2.4 "absence" branch. An allowlist is used because "alters the device list or backup" is not evaluable for future kinds; a denylist here fails open as the ecosystem adds kinds. (§11 rumors are sealed by `E`, not the group key, so a co-signer never sees or signs them; the guard for those is §11.9 step 4(a).) `/v1/sign` and the relay path both carry the requester's `E.pub` signature so this can be applied. Requests and rounds are gift-wrapped between `E.pub` and `S.pub` over relays or `<url>/v1/sign` over HTTPS; both MUST be supported, HTTPS tried first.
- Server unreachable (timeout 5 s on all replicas): the client tries any trusted device in the list — a keep-key or Offline-mode device first, since those need no round — over relays, LAN (§3.6), or BLE (native apps only; the same single-message wrap bytes over a GATT characteristic — profile UUIDs live in an implementation companion, not this spec). Trusted devices and servers complete rounds for **trusted** members silently (§2.2). A trusted device completes rounds for a **restricted** requester only if it has itself probed every enrolled server in the last 60 s and none answered; otherwise it refuses with "use the server," so a site cannot route around the server's audit by asking a phone instead. With **zero servers enrolled** the condition is vacuously satisfied by design: trusted devices are then the normal co-signers for everyone. Trusted co-signers keep the same per-requester log and apply the same alert rule as servers (§11.13). A restricted device completes a *signing* round only for a **trusted** requester and only for kinds 30242 and ordinary content, as a last resort when no server or trusted device answered; it never completes rounds for restricted requesters and never ECDH for anyone. This is what lets the minimum §11.3 configuration (one trusted device, one browser, one server) remove a compromised server: the phone initiates the refresh, the browser co-signs the epoch record. The requesting client shows **"Signing via *Phone*…"**.
- Nothing reachable: the draft is kept as an unsigned rumor with `created_at` fixed at compose time and signed at the first opportunity. The client shows **"Will post when your server or another device is reachable."** For local-only relays, the client points to Offline mode (§11.14).

### 11.6a Decryption (DMs and gift wraps)
FROST produces signatures only. NIP-04/NIP-44 conversation keys and NIP-59 seal decryption need `ECDH(nsec, P) = nsec·P`, so a share-only device cannot decrypt alone. Threshold ECDH is one round:

```
Requester (index d) → co-signer (index c):  { P }                     wrapped to E.pub / S.pub, or /v1/ecdh
Co-signer → requester:                      { λ_c·s_c·P }         after verifying P is on-curve and not the identity. (Each partial is a static-DH answer whose aggregate targets the *group* key, which refresh never changes — so the §11.13 hard ceiling, not refresh, is the control; at those query counts Cheon-style attacks on secp256k1 remain impractical.)
Requester:                                  nsec·P = λ_d·s_d·P + λ_c·s_c·P
```
The **requester aggregates**; the co-signer never learns `nsec·P`, only `P` and its own partial. Consequences, which §11.3 discloses:
- Reading DMs and unwrapping NIP-59 gift wraps on a share-only device requires a co-signer reachable, exactly like posting. Clients SHOULD batch: one round can carry many `P` values.
- The co-signer learns which `P` values the user is deriving keys for — for NIP-04/44 that is the peer's pubkey (DM metadata); for NIP-59 wraps it is a random one-time key (nothing).
- Keep-key and Offline-mode devices decrypt alone.
- The role rules apply: restricted devices may request; trusted devices and servers respond; restricted devices never respond to ECDH.

### 11.7 Adding a device after activation (joint issuance)
Flows A/B run unchanged through the SAS step. The Joiner's index `j` is `2` if its role is restricted, otherwise the next unused index ≥ 3. Instead of one `KEY_TRANSFER`, the Joiner receives two `KEY_SHARE_PART` (kind 24307) wraps for `j`:
```
Holder device (index h):  r ← random mod n
                          sends Joiner:  λ_h(j)·s_h − r
                          sends Server:  r          (wrapped to S.pub)
Server (index 1):         sends Joiner:  λ_1(j)·s_1 + r     (wrapped to the Joiner's burner `J.pub` from the QR, which the Holder forwards with `r`)
Both parts also carry:    group_pub, commitment, epoch, group_secret   (so a fresh Joiner can verify without first reading the encrypted epoch record)
Trusted Joiner only:      CK rides in the trusted helper's part — servers never hold CK (§11.5a)
Joiner:                   share_j = sum of the two parts; verify share_j·G == group_pub + commitment·j, derive npub from group_pub, show "Log in as @name?" (a first-time Joiner has no prior pubkey to compare) — Yes → store
```
If the server is unreachable, any second **trusted** online device plays the server's role with its own index. Helpers are trusted devices and servers only; a restricted device MUST NOT act as Holder or helper. The Joiner ACKs; the Holder updates the device list and epoch record.

### 11.8 Adding a server replica
Same as §11.7 with `j = 1`. Alternatively an existing server, on a gift-wrapped instruction from a device, wraps share 1 directly to the new server's `S.pub`. Either path is one QR scan for the user.

### 11.9 Refresh (one tap; replaces rotation)
Triggered from settings ("Rotate keys") on a trusted device, and automatically on device removal, Offline-mode exit, and after §11.10 recovery. No share is released and nothing is reconstructed.

1. The initiating trusted device picks random `r` mod n and sets `epoch + 1`. It first obtains a group signature over the new epoch record with **old** shares (it and a co-signer, before any delta is applied), so the record can be signed while everyone still shares a polynomial.
2. It gift-wraps `KEY_REFRESH {epoch, delta: r·j}` (kind 24309) to each member `j` still on the list (one wrap per replica, same `delta` for replicas of one index), (its own delta is applied in step 3).
3. It publishes the already-signed epoch record with `commitment' = commitment + r·G` and the new group secret, then applies `r·own_index` to its own share.
4. Each member verifies (a) the wrap's seal is signed by a **trusted** `E.pub` present on the member's current device list, and (b) `(share + delta)·G == group_pub + commitment'·j`; only then replaces its share and ACKs (kind 24306). Device-list updates MUST be published before any refresh wrap that depends on them. A member whose list does not contain the sender first re-fetches the list (once, up to 5 minutes) before deciding; a `KEY_REFRESH` still failing (a) MUST be discarded and MUST raise the red lock state ("a refresh was attempted by *example.com*").

The group key is unchanged. Old shares are on a different polynomial and cannot combine with new ones. A removed member is simply not sent a delta. Members that miss the wrap receive it when next online (wraps live 30 days, §11.17, subject to relay retention — clients SHOULD publish §11 wraps to at least one relay the user controls or pays for); until then they cannot sign and the lock shows amber. A member holding shares from two epochs MUST discard the older once the newer verifies.

**Removing a restricted device.** All restricted devices share index 2, so a hostile origin with two browsers enrolled keeps share 2 if only one is removed. Removal is therefore **per origin**: removing a site removes every restricted entry with that origin, and the delta for index 2 goes only to surviving origins. (Sending survivors a delta is fine: an honest survivor does not leak `r` to a removed device, and a hostile one already held the share.)

**Refresh war.** A compromised trusted device can refresh with itself and a server as the only members, excluding the rest; another trusted device can do the same back. There is no in-protocol resolution. The resolution is §11.10 recovery from the backup on a clean device, followed by re-activation with a list that excludes the compromised device.

The initiator learns nothing about any other member's share. Note that `delta = r·j` with `j` public, so **every member learns `r`**, and a removed member's old share plus `r` is a valid new share. This has a lasting consequence: **a share from any past epoch, plus every `r` since, is a current share** — and every current member has seen every `r`. So a lost trusted device's stale share stays dangerous forever to any current member that obtains it, including a hostile site, silently and without the server. Refresh cannot fix this at `t = 2` with linear deltas. The fix is **Re-split** (§11.11): disable and re-activate in one flow, which draws a fresh random `a_1` and severs the algebraic link to every old share. The client recommends Re-split, not refresh, when the removed member is a trusted device that may have been lost rather than merely retired. Only trusted devices may initiate; servers and restricted devices never do, and members enforce this per step 4(a). An epoch record is authoritative only if it is accompanied by a `KEY_REFRESH` (or `KEY_SHARE` at activation) that passed step 4(a); a kind-30242 event on its own is not trusted. §11.6's refusal and this rule are deliberately redundant: the first stops an honest server from helping, the second stops a dishonest one from mattering.

### 11.10 Recovery (all devices lost)
1. New device (native app; a browser MUST NOT offer recovery): enter server URL and backup password (or scan a server QR that carries the URL). A user who has forgotten the URL MAY have opted, at enrolment, to publish a plaintext `["backup-hint", "<url>"]` tag on the device list (off by default; it tells the world where to aim online guesses, per §7.2).
2. Recover per §7.2 (password proof, rate-limited) → backup blob. Decrypt locally (roughly one to three seconds at `log_n = 18`, 256 MiB).
3. The device now holds the nsec in base mode. The client MUST then prompt to **change the backup password** (re-running §7.2 setup) and MUST offer to **drop or replace the server** it just recovered from, since a compromised server is a common reason to be recovering. No server is re-enrolled automatically.
4. If the epoch record shows threshold mode was on, the client offers to re-activate (§11.5) with a fresh epoch and the new device list; old members are excluded because they are not on it, and only servers the user kept in step 3 receive share 1.

### 11.11 Device removal
Settings → device → **Remove**. In threshold mode the client asks: **"Do you still physically control this device, and was it wiped?"** Yes → retired. No or unsure (lost, stolen, sold, traded in) → lost, the default; extractable storage on a sold device is "lost" in every way that matters. Retired → refresh (§11.9) with the device excluded. Lost (default) → **Re-split**: §11.15 disable and §11.5 re-activation as one journaled operation on a trusted device (reconstructing, privileged, subject to two-device approval), which makes the lost device's share algebraically useless rather than merely stale. Restricted removal is per origin (§11.9). A bunker device cannot be revoked this way (§11.5); the client says so. In backup-only mode the label reads "Forget device (its copy of your key is not affected)" per §8.

### 11.12 Server compromise
Attacker obtains share 1 and the backup blob. Share 1 alone signs nothing. The blob is protected by the password at `log_n = 18`; its strength is the user's choice per §11.2. By the spec's own algebra (§11.9), a plain refresh cannot revoke a share that has already been exfiltrated: the dumped share 1, plus the stream of future `r` values that every current member sees, remains a current share — and a hostile restricted origin that obtains the dump can then reconstruct silently. The remedy is therefore **Remove server + Re-split** (§11.11): exclude the server, then disable-and-reactivate with a fresh random `a_1`, severing the algebraic link to the stolen share. The client performs Re-split, not refresh, for server compromise whenever any restricted device is enrolled, and recommends it even when none is. It then prompts to change the backup password (a `CK` re-wrap, §11.5a) and to delete the blob on the removed server.

**Blob and share 1 on one host.** In threshold mode a compromised server holding both, plus a weak password, is the key — undercutting "no server holds a usable key" for exactly the users who chose weak passwords. The client MUST offer, at second-server enrolment, to place the blob on a different host than share 1 ("Keep backup and signing on separate servers"), and MUST offer at first enrolment a generated recovery phrase (six PGP words, ~96 bits) as the password, pre-filled and editable. Neither is required; the §11.2 warning line stays.

### 11.13 Hostile restricted device
A hostile site holds share 2. Alone it signs nothing. With the server it can sign — as can any enrolled device — and this is visible to the server and revocable by refresh. It cannot: combine with other sites (same index); act as Holder or helper; request share 1; enter Offline mode, keep-key, or disable without a tap on a trusted device that names it and the consequence; or see a backup-password field (from honest code — see the phishing path below). Holding the group secret, it **can read the device list and epoch record**: device count, roles, `E.pub`s, and user-written labels ("Dana's laptop") — metadata a phishing page can weaponize for convincing prompts. Its worst case is **posting as the user and reading every DM the user has ever received** (via §11.6a ECDH with the server) until it is removed — **plus a phishing path to the full key**: the hostile origin *is* the client on that device, so "MUST NOT present a backup-password field" binds honest code only. A pixel-perfect "confirm your backup password" dialog, plus the user's npub and a knowable server URL, is the key via `/v1/recover` — the site gets the password right, not guessed, so rate limits don't apply. This cannot be prevented in-protocol; it is bounded by the recovery delay (§7.2), which makes the theft visible and cancellable from any trusted device, and softened by the generated six-word phrase: a user who kept it has only ever typed it on a trusted device, so a website asking for it reads as wrong. Stated as residual risk in §9. It cannot enter Offline mode at all (§11.14).

**Audit surface.** Every co-signer (server or trusted device) keeps a per-requester log of signing and ECDH rounds (kind, timestamp, peer pubkey for ECDH) and sends it to trusted devices as a daily `AUDIT_DIGEST` wrap (24317; alerts are 24318); the devices screen shows it per device. A server MUST notify trusted devices when index 2's ECDH peer count or signing rate in the last hour exceeds both an absolute floor (25 distinct ECDH peers, or 50 signatures, in an hour) and five times its trailing-week hourly median ("*example.com* is decrypting your DMs in bulk — remove it?"). During the first 24 hours after an origin's enrolment the same thresholds produce a differently worded, non-alarming notice ("*example.com* just synced *N* conversations") rather than silence — the first sync is exactly when a hostile site would read everything, and the user should see that it happened. Rate alerts alone can be boiled slowly, so there is also a **cumulative cap** — sized against NIP-59 mechanics: every incoming gift wrap uses a fresh random ephemeral key, so one-shot `P`s are ordinary mail, while **recurring `P`s (seen in two or more rounds) are conversation keys**, and a burst of them is the signature of a bulk history read. The cap counts only recurring `P`s: co-signers refuse ECDH for a restricted origin beyond 200 distinct *recurring* peers per rolling 7 days; exceeding it requires a one-tap raise on a trusted device ("*example.com* wants to read more of your conversation history"). Never-repeating `P`s are bounded by the hourly ceiling alone. The **hard ceiling** is 500 ECDH responses per hour per requester, counted **per `P`** (a batch of n peers consumes n), bounding the §11.6a static-DH oracle quantitatively. Users MAY disable DM decryption for restricted devices entirely in settings ("Websites can read DMs" toggle, default on).

### 11.14 Offline mode (a trusted device temporarily holds a threshold)
UI label: **Offline mode**. A toggle in every **trusted** device's settings. Never required for any function. Not available to restricted devices: two shares at `t = 2` is the key, and a device that has held the key cannot be un-given it by refresh — so granting Offline mode to a website would be granting it the key permanently. The toggle on a restricted device is shown disabled with "Not available in a browser."
- **Enter.** The toggle sends an `OFFLINE_REQUEST` to every other trusted device in the list. The user taps **Allow** on any one of them — a trusted device, never a server. The prompt names the requester by its Holder-set label and states the consequence in one line: **"*Laptop* wants to hold your full key offline. Allow?"** That device and the server (or a third trusted device) then jointly issue the requesting device a second index, taken from the trusted range `≥ 3` (§11.7). The epoch record gains `offline: {index_pair, E.pub, since}`. The toggle explains: "Needs a tap on one of your other devices. Turn this on before you go offline."
- **While on.** The device signs and decrypts alone with its two shares.
- **Exit.** The device runs a refresh (§11.9) as initiator and discards its second index, sending no delta for it. No other device's *approval* is required, but relays (or LAN/BLE reach to the members) are: the deltas must be delivered, so exit completes when the device is back in contact. The discarded share is on the old polynomial and dead by construction. The device is **trusted to have discarded** the reconstructable key — this is the same trust already placed in it as a trusted device, and it is why the mode is trusted-only.
- Any trusted device may end a *cooperative* device's Offline mode by refreshing without a delta for the second index. Against a **suspect** device this is a no-op: the target keeps its primary membership, receives its primary delta, learns `r` from it, and can update the retained second share. Ending Offline mode for a device you no longer trust is therefore **Re-split** (§11.11, "lost"), same as any other suspect trusted device.

### 11.15 Disabling threshold signing
Settings → "Turn off threshold signing." Available only on trusted devices. This is the one operation that reconstructs the nsec: the device collects one other share (a server releases share 1 to a trusted requester; with two-device approval on, only with an `APPROVAL`), then:
0. **Pre-refresh.** Before reconstructing, the client runs one §11.9 refresh whose member set is only the trusted devices and unflagged servers — every restricted origin (and any server the user flags on the disable screen) is excluded and receives no delta. Their shares are now on a dead polynomial *by construction*, not by their cooperation, before deletion is even requested. Then the device collects one other share, reconstructs, and **durably stores the nsec per §2.1 before anything else** — a crash after members delete but before the key is stored would otherwise be unrecoverable in a serverless deployment with no export on file.
1. Wraps `DISABLE {epoch}` (kind 24314, 30-day TTL) to every member, and publishes the epoch record marked `disabled` with a plaintext `["epoch", counter]` tag. **Servers MUST delete share 1 and every member MUST delete its share, `CK`, and the group secret** on receiving a `DISABLE` whose seal is from a trusted `E.pub` on the current list — and, when two-device approval is on, whose attached `APPROVAL` verifies; without it members MUST NOT delete, or a single compromised trusted device gets a remote wipe that bypasses the setting. For the remaining (trusted + server) members, deletion is what kills the final-epoch shares; the pre-refresh in step 0 already ensured that no share outside that set survives algebraically, so a website that never processes the notice holds nothing.
2. Each trusted device replies `DISABLE_ACK` (kind 24315) carrying a fresh burner. The initiator wraps `KEY_TRANSFER` to **that burner** with the §3.4 600 s TTL — never to `E.pub`, so no nsec ciphertext is ever addressed to a long-lived key on a relay.
3. Restricted devices are **not** sent the key by default — the screen lists them and lets the user tick any to include (those also go via a burner); the rest re-enrol by §4 when next used. A trusted device that misses the 600 s window comes back to a `disabled` record with its share deleted; it shows the Joiner QR and re-enrols by §4 from any device that now holds the key. Trusted devices store the nsec per §2.1 on receipt. Re-enabling is §11.5.

### 11.16 Lock indicator
Shown in settings and on the compose screen. Every state has a distinct **shape**, a distinct **colour**, and a **text label always adjacent**; colour is never the only channel.

| State | Colour | Glyph | Label |
|---|---|---|---|
| Split (default) | Green | Closed lock with checkmark | "No single device holds your key" |
| Keep-key | Green | Closed lock with phone silhouette | "Full key on *Phone*; other devices hold pieces" |
| Offline mode | Blue | Closed lock with single-figure badge | "Offline mode on *Laptop* since *date* — tap to end" |
| Pending | Amber | Half-open lock with three dots | "Waiting for *N* devices" |
| Flagged | Red | Lock with exclamation | "Rotate recommended: *reason*" |
| Off | Grey | Open outline lock | "Threshold signing off" |

Glyphs MUST remain distinguishable at 16 px in monochrome. The indicator is informational; it MUST NOT emit notifications or block any action.

### 11.17 Rumor kinds (complete list)
| Kind | Name | Direction |
|---|---|---|
| 24301 | KEY_HELLO | Holder → Joiner (§4) |
| 24302 | KEY_REQUEST | Joiner → Holder (§5) |
| 24303 | KEY_TRANSFER | Holder → Joiner (§4, §5, §11.15) |
| 24304 | PAIR (SPAKE2 / encrypted pairing params) | either (§3.7, bare ephemeral) |
| 24305 | KEY_SHARE | issuer → member |
| 24306 | SHARE_ACK | member → issuer |
| 24307 | KEY_SHARE_PART | helper → Joiner |
| 24308 | OFFLINE_REQUEST | requester → trusted devices |
| 24309 | KEY_REFRESH | initiator → member |
| 24310 | TRANSFER_ACK | Joiner → Holder (§4, §5) |
| 24311 | APPROVAL | second trusted device → server / helper (§11.1) |
| 24312 | SAS_NONCE | non-contacting party → contacting party (§3.3) |
| 24313 | SAS_REVEAL | contacting party → other (§3.3) |
| 24314 | DISABLE | initiator → member (§11.15) |
| 24315 | DISABLE_ACK | trusted member → initiator, carries a fresh burner (§11.15) |
| 24316 | RECOVERY_NOTICE | server → registered devices (§7.2) |
| 24317 | AUDIT_DIGEST | co-signer → trusted devices (§11.13) |
| 24318 | ALERT | co-signer → trusted devices (§11.13) |
| 24319 | EPOCH_FINALIZED | initiator → members (§11.4) |

All placeholders. All are wrapped per §3.4 except 24304, which is a bare ephemeral event (§3.7). **§11 wraps use `expiration = now + 30 days`**, not the 10-minute transfer TTL, so offline members can still receive them. A member offline longer than 30 days misses the wrap; on return it finds a newer epoch record than its share and re-enrols via joint issuance (§11.7), which any trusted device can do from the devices screen.

## Appendix A — EMOJI_TABLE
64 visually distinct emoji, fixed order, shipped with the client. Choose glyphs that render identically across iOS, Android, Windows, and common browsers; avoid skin-tone modifiers, flags, and pairs that differ only by colour.

## Appendix B — References
NIP-07, NIP-40, NIP-42, NIP-44, NIP-49, NIP-59. RFC 9591 (FROST). RFC 9382 (SPAKE2). BIP-340. PGP word list.
