# Nostr Key Management

Your Nostr account is one secret key. This project keeps that key safe
while still letting apps post for you.

It is written as three specifications. This page explains the idea and
assumes you have never heard of any of it. [OVERVIEW.md](OVERVIEW.md) is
the technical summary.

## 1. Today

Your whole account is a single secret. Nostr calls it an nsec.

To use a Nostr app, you usually paste that secret into it.

```
               your secret key
                      |
        +-------------+-------------+
        |             |             |
        v             v             v
   +---------+   +---------+   +---------+
   |  app A  |   |  app B  |   |  app C  |
   +---------+   +---------+   +---------+
    can do        can do        can do
    anything      anything      anything
    forever       forever       forever
```

Every app you paste it into now holds your whole account.

It can post as you. It can delete your posts. It can change your
profile.

It can keep doing that forever. There is nothing to take back, and no way
to learn that it happened.

Keeping the key in a notes file is no better.

## 2. The votes

Instead of one secret that does everything, split the power to sign into
votes.

Signing needs 4 votes.

```
 +----------+  +----------+  +----------+
 |  your    |  | server A |  | server B |
 |  phone   |  |          |  |          |
 | 2 votes  |  |  1 vote  |  |  1 vote  |
 +----------+  +----------+  +----------+

 +----------+  +----------+
 | server C |  | app pass |
 |          |  |          |
 |  1 vote  |  |  1 vote  |
 +----------+  | expires  |
               +----------+

          signing needs 4 votes
```

Your phone has 2 votes.

Each server has 1 vote. The three servers are run separately, and none
of them is run by the app.

A temporary app pass has 1 vote, and it expires. You can have one pass
at a time.

Any device of yours that runs a native app can hold 2 votes, the same as
your phone. A browser tab never can.

These combinations reach 4, so they can sign:

```
 SIGNS
 phone + server A + server B   2 + 1 + 1 = 4
 phone + server A + server C   2 + 1 + 1 = 4
 phone + server B + server C   2 + 1 + 1 = 4
 phone + pass + any server     2 + 1 + 1 = 4
 phone + your other phone      2 + 2     = 4
```

These do not:

```
 DOES NOT SIGN
 phone alone                   2
 phone + one server            2 + 1     = 3
 phone + pass                  2 + 1     = 3
 all three servers             1 + 1 + 1 = 3
 pass + two servers            1 + 1 + 1 = 3
```

Your phone alone cannot sign. It always needs two more votes. Normally
they come from servers, and a server can say no.

Your phone cannot get around that by making itself a pass. Phone plus
pass is 3, still one short, and the servers refuse a second pass.

No server, and no set of servers, can sign without someone else.

Two of your own devices can sign with no server at all. That is how you
keep your account when every server is gone. It also means the servers'
rules do not apply to that pair.

That last point is a default, not a law. At setup you can choose a
stricter layout where even two of your devices need a server. The price
is that nothing signs when the servers are unreachable.
[OVERVIEW.md](OVERVIEW.md) explains both.

### When votes collude

One set reaches 4 with no phone in it. Here it is, labelled honestly.

```
 NO PHONE, STILL REACHES 4
 pass + server A + server B + server C
                               1 + 1 + 1 + 1 = 4

   honest servers:  sign only what the rules allow
   servers that
   break the rules: COLLUSION - can sign anything,
                    can rebuild your whole key
```

That line is how an app with a pass posts for you while your phone is in
your pocket. Honest servers check every request, so the app can only do
what the rules allow.

If all three servers stop following the rules on purpose, that set can
sign anything. It can even rebuild your whole key. The maths does not
prevent it.

What bounds it: a pass expires and is dropped at the next key refresh,
and every one of the three servers has to deliberately stop refusing
dangerous actions.

A key refresh re-cuts every vote, so old copies stop counting. Every
change to who holds votes is one.

Use no pass at all, and even that line disappears.

Now that the idea is in place, here are the words the specifications use.
Splitting signing power into votes is *threshold signing*. A vote is a
*share*. Your phone is a *trusted device*. A server is a *co-signer*. A
pass is a *grant*. The layout above is the *reference configuration* of
[TIERS.md](TIERS.md) §4.4.

## 3. Logging in

```
    app on your laptop            your phone
   +-----------------+         +--------------+
   |                 |         |              |
   |    [QR code]    |<--scan--|   camera     |
   |                 |         |              |
   +-----------------+         | "Let this    |
                               |  app post?"  |
                               |              |
                               | [ Approve ]  |
                               +--------------+
```

An app shows a QR code. Your phone scans it and asks you once. You
approve.

By default that is all. The app gets no votes. It sends each post to
your phone, your phone checks it against what you allowed, and then your
phone signs with the servers as it does for itself.

```
   +---------+
   |   app   |  0 votes
   +---------+
        |  "post this"
        v
   +---------+
   |  phone  |  2 votes,
   +---------+  checks it
        |
        v
   +-------------+
   | two servers |  1 vote each,
   +-------------+  check it too

        2 + 1 + 1 = 4   -->   posted
```

This is called a *session*. Nothing is handed to the app, so there is
nothing for it to keep. You end it on your phone, and it ends at once.

Its one cost: your phone has to be on and reachable for the app to post.

### A pass, for posting while your phone is off

When an app has to post with your phone switched off, you give it a pass
instead.

```
    app on your laptop            your phone
   +-----------------+         +--------------+
   |                 |         |              |
   |    [QR code]    |<--scan--|   camera     |
   |                 |         |              |
   |  code: 48213    |--read-->| type code:   |
   |                 |         | [4][8][2][1] |
   +-----------------+         | [3]          |
            ^                  |              |
            |                  | [ Approve ]  |
            |                  +--------------+
            |                         |
            +--- pass: 1 vote, -------+
                 ends when you say
```

The app shows a 5-digit code as well. You type it into your phone. A
vote is actually being handed over, so this proves your phone is talking
to the screen in front of you, not to someone in between.

The app receives a pass. It is worth 1 vote, and it ends at a time you
set. It is ready at once.

```
   later, phone switched off

   +--------+                +----------+
   |  app   |--"post this"-->| server A |  checks
   | 1 vote |       |        | 1 vote   |  the rules
   +--------+       |        +----------+
                    |        +----------+
                    +------->| server B |  checks
                    |        | 1 vote   |  the rules
                    |        +----------+
                    |        +----------+
                    +------->| server C |  checks
                             | 1 vote   |  the rules
                             +----------+

        1 + 1 + 1 + 1 = 4   -->   posted
```

From then on, the app posts on its own.

Each post needs the pass plus all three servers. Each server reads the
post and checks it against the rules before adding its vote.

The cost, stated up front: if any server is down, the app cannot post
until your phone is back in the set.

## 4. The rules

A server never signs blind. It is handed the whole post, not just a
fingerprint of it, and checks it before voting.

```
        app asks a server to sign
                    |
                    v
   +----------------------------------+
   | pass still valid?           yes  |
   | this kind of post allowed?  yes  |
   | not profile, contacts,           |
   | relay list or a delete?     yes  |
   | under the hourly limit?     yes  |
   | account not frozen?         yes  |
   +----------------------------------+
          |                    |
       all yes              any no
          |                    |
          v                    v
     adds 1 vote            refuses
```

A pass can never:

- **Change your profile.** Your name and picture are who people think you
  are. A fake one signed with your own key cannot be told from the real
  thing.
- **Change your contacts.** Your follow list could be emptied or replaced
  in one silent step.
- **Change your relay list.** That list tells people where to find you.
  Changing it can make you unreachable, and send your future posts where
  an attacker reads them.
- **Delete posts.** One app could delete everything you ever wrote in
  seconds. Relays act on deletions, and there is no undo.

Anything else that overwrites instead of adding is also off-limits,
unless you named it when you made the pass.

A pass can post notes, repost, react and send direct messages. Reading
your direct messages is off unless you allowed it.

The servers also count. A pass gets a limited number of signatures per
hour and per day. Going over alerts your devices.

Any device of yours can freeze the servers. They then refuse everything
until a device of yours lifts it. A freeze does not stop two of your own
devices signing together, and the app says so.

Your phone is not exempt, and neither is an app in a session with it.
For those four things, the servers look at what a change actually does:

```
 GOES THROUGH                     WAITS A DAY
 following someone                removing many follows at once
 unfollowing a few                removing a relay
 adding a relay                   changing your name and
 changing your name, or             your picture together
   your picture, alone            deleting many posts
   (your devices are told)
 deleting a few posts
```

Removing many follows at once waits a day; following someone doesn't.
Small removals add up over the day, so doing it five at a time waits too.

While a change waits, the server tells your other devices. Any of them
can cancel. Nothing is signed during the wait, so a cancel means it never
happened. A pass never gets any of the four, waiting or not.

## 5. Losing your phone

The lost phone is locked. Its votes sit in the phone's hardware key
store, behind its screen lock. Whoever finds it has to unlock it first.

If you have another device, it can tell the servers to stop answering the
lost phone right away.

Then there are three ways back.

### The backup path

```
   new phone
      |
      |  1. enter the recovery code
      |     you wrote on paper
      v
   +-----------------------------+
   | public relays               |
   | sealed backup of your       |
   | phone's 2 votes             |
   +-----------------------------+
      |
      |  2. the code finds it
      |     and opens it
      v
   new phone has 2 votes again
      |
      |  3. refresh the key, so the
      |     lost phone's copy is dead
      v
   done
```

At setup, your phone's 2 votes are sealed and stored on public relays.
Relays are the servers Nostr already uses to carry posts. They cannot
read the backup or tell whose it is.

Only your recovery code can find and open it. A passkey can stand in for
the paper code.

A new phone plus that code gets the 2 votes back. Then it refreshes the
key, so the copy on the lost phone stops counting. Dropping a phone waits
a day, and the lost phone could cancel it only if someone has unlocked
it.

Treat the paper like the phone. Whoever holds the code holds your phone's
votes.

The backup must be current. Every refresh republishes it, and a refresh
is not finished until the new backup has been checked.

### The recovery-phrase path

At setup, one more vote is sealed under a recovery phrase (or a passkey)
and stored where your servers or relays can hand it back. Nobody holds it
while it is sealed.

Opened, it is worth 1 vote and does exactly one thing: together with all
three servers, it replaces your devices.

```
   new phone + recovery phrase
      |
      |  opens the sealed vote
      v
   1 + 1 + 1 + 1 = 4 with all three servers
      |
      |  a day's wait; your old devices
      |  are told but cannot cancel
      v
   new phone holds 2 votes, old ones dropped
```

Your old devices cannot cancel this, because the point is to work when
they are the problem. Someone holding both a device of yours and the
phrase can overrule it, and so can you, if you still have both.

Treat the phrase as your whole account. Together with any one device of
yours, it is as good as the key.

Setup does not finish until you have at least one of the two: the sealed
backup of your phone's votes, or the recovery phrase. With neither, losing
your only phone would lose the account for good, which is worse than a
pasted nsec.

### The waiting-period path

```
   new phone
      |
      |  1. backup server address
      |     + recovery phrase
      v
   +------------------+
   | backup server    |      your other devices:
   | starts a 1-day   |----> "a recovery started.
   | wait             |       cancel?"
   +------------------+
      |
      |  2. nobody cancels,
      |     or a device approves
      v
   your key comes back,
   then is split into votes again
```

This path uses a backup server that holds your whole key, sealed.

You type your recovery phrase on a new device. The server does not hand
the key over straight away. It waits a day and tells every device of
yours that a recovery started. Any of them can cancel it, or approve it
early.

If no device of yours is left, nobody cancels, and the wait simply ends.

A passkey instead of the phrase skips the wait. A passkey only works for
the site it was made for, so there is no phishing to wait out.

This backup holds the whole key. If you have one, it matters more than
any vote count. The app shows it next to the votes backup and never
treats the two as equal.

## 6. What QRST is for

Moving a secret between two screens is the dangerous moment.

The easy way puts the secret inside the QR code.

```
   THE QR IS THE SECRET

   +----------+               +------------+
   | [QR]     |    photo      | stranger   |
   | = your   |-------------->| now has    |
   |   key    |               | your key   |
   +----------+               +------------+
```

Anyone who photographs that QR has the secret. So does anyone who sees
it over your shoulder, or finds it in a screenshot.

QRST does it differently.

```
   THE QR IS ONLY AN ADDRESS

   +------------+    scan    +------------+
   | [QR]       |<-----------| phone      |
   | = address  |            |            |
   +------------+            +------------+
         ^                         |
         |    secret, sealed,      |
         +--- over public relays --+
              only after you type
              the 5-digit code

   photo of the QR --> opens nothing
```

The QR carries only an address. It is a throwaway key made for this one
handover and destroyed after, plus a few relay addresses.

The secret travels by a different road. It is sealed so that only the
other device can open it, then sent over public relays.

The relays cannot read it. They cannot tell who sent it. They cannot
tell that the two devices are related. Nobody runs a server for this,
and any relay can be swapped for another mid-transfer.

The secret is sent only after you type the 5-digit code. Both devices
build the code together, so someone in the middle cannot make theirs
match.

QRST is how your phone hands a pass to an app. It also moves a whole key
between two of your devices, or votes to a new device of yours.

One exception exists for when there is no network. A vote can travel
inside the QR itself, locked with a passphrase. Then the passphrase is
all that protects it, and the screen says so.

## 7. What FROSTR is for

```
    phone   server A   server B   pass
     [2]      [1]        [1]       [1]
       \       |          |        /
        +------+----------+-------+
                     |
             +---------------+
             |    FROSTR     |
             | counts votes  |
             +---------------+
                     |
          one ordinary signature
```

[FROSTR](https://github.com/FROSTR-ORG) is the voting machinery; this
project decides who gets votes and delivers them safely.

## Why this is not NIP-46

NIP-46 lets an app ask a remote signer to sign. The signer holds your
whole key. Its per-app limits are its own code.

If the signer is breached, the limits go with it. The limits and the key
live in the same place.

Here, no app and no server ever holds enough votes to sign alone. The
rules run on servers the app does not control.

A session looks like NIP-46 from the app's side: it asks your phone to
sign. The difference is that your phone holds 2 of the 4 votes, not the
whole key, so its signatures still go past the servers' rules.

NIP-46 also does not say how a key reaches a device, how it is stored,
whether it is backed up, or what happens when the device is lost. This
project covers those too.

The honest cost: NIP-46 has no collusion case, because one party holds
everything. Splitting votes this way creates the collusion set of
section 2.
[TIERS.md](TIERS.md) §4.5 and §7.3 price it rather than hide it.

## What else is in here

The app stores your key in the strongest place the device offers, and
quietly upgrades when a better one appears. If the device offers none,
nothing stops you logging in.

Where a sensible default can be picked without giving something up, it is
picked for you.

Backing up your whole key is offered once, at the end of setup. Skip it
and the app never nags. Turning on votes is different: it needs one of
the ways back in section 5 first.

These live in [NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md). It also
registers the two things QRST carries for Nostr: `nostr-nsec`, a whole
key, and `frost-share`, one vote.

It also defines two simpler layouts where any two votes sign: your own
devices with no server, and one device with one server. A key uses the
tiers of TIERS.md instead of those, never mixed with them.

## What this project is not

The transfer is not new cryptography. The code comparison comes from
ZRTP, by way of Matrix, and is cited as such. What is unusual is running
it over relays that nobody operates for the purpose.

Splitting a key does not undo a leak. If an app already has a whole copy,
turning on votes afterwards does nothing. Protection has to be in place
before the first time you hand anything over.

## Status

All three specifications are drafts.

[QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) is version 1.4-draft. It
adds the `frost://` scheme and the light returned-secret flow (§12.3) for
revocable shares, and a profile-gated offline tier (§10) that is
passphrase-encrypted and uses no relay. The event kinds are provisional:
chosen from the ephemeral range and verified non-conflicting, but not yet
reserved by a NIP. The test vectors are incomplete: the §6 short code is
covered in [vectors/](vectors/), and the payload ceiling that P1 requires
is not.

[NOSTR_KEY_MANAGEMENT.md](NOSTR_KEY_MANAGEMENT.md) is version 9.2-draft.
It has the serverless device-quorum mode (§7.18) alongside the server
co-signer, and a passphrase-encrypted offline container for `frost-share`
(§3.3), the one payload with no `ncryptsec` of its own.

[TIERS.md](TIERS.md) is version 1.0-draft. Its §4 membership vectors are
in [vectors/](vectors/), and [tiers_check.py](tiers_check.py) enumerates
signing sets and is tested against them. It
needs three things FROSTR does not expose today; its Status section
writes each as a proposal for upstream, and all three are filed in
[SPEC_ISSUES.md](SPEC_ISSUES.md).

[IMPLEMENTATION.md](IMPLEMENTATION.md) proposes how the specifications
become a library, and in what order. It is a proposal, not agreed.

This project benefits from developers and users pressure testing the
claims of the specs. Failure modes will be handled within reason to
improve them. Structural robustness increases the convenience and
security of users as far as the specs are widely deployed and followed,
across various hardware and software conditions. Disagreements and
suspected errors belong in [SPEC_ISSUES.md](SPEC_ISSUES.md); pull
requests and issue submissions should be used where possible.

## Map

- [TIERS.md](TIERS.md) decides who gets votes.
- [QR_SECRET_TRANSFER.md](QR_SECRET_TRANSFER.md) moves votes safely.
- [FROSTR](https://github.com/FROSTR-ORG) counts them.
