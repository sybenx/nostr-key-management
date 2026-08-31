# Nostr Key Transfer & Storage

This spec is a method to send and recieve Nostr secrets by utilizing QR-codes and gift-wrap. 

The primary purpose of this project is to allow for increased security of key transfer and storage than the typical copy and paste method. We then attempt to upgrade security where possible, within reasonable constraints, to keep the user key safe and help the user to avoid needing the copy-paste method. 

#This project benefits from more eyes and more implementations. Devs and users are encouraged to build code modules that can be deployed widely in various software conditions. Pull requests and issue submissions are welcome.#

NKTS is a tiered system utilizing the most secure method of key management where available first: FROST, iCloud Storage, Google secure sync, secure gift-wrap over public relays, and is compatible with Bluetooth and LAN transfer. It is fully compatible with FROST and can silently upgrade  once paired with a compatible FROST server. When FROST is activated, there are protections from various angles of attack including device compromise and server compromise. Even before FROST is activated, there is strong shoulder surfing resistance. 

Users are made as secure as their preferences allow and where robust defaults can be chosen automatically without major compromise, they are. 

## Why this is not NIP-46

NIP-46 is a signing protocol. A remote
signer has to be reachable for every single signature, whereas a device that
has received a key under this specification needs nothing reachable at all. NIP-46 says nothing about how the signer's own key arrived on that machine, how it is stored there, whether it is backed up, or what happens when the machine is lost. That gap is where this project sits. 

## Status

Version 8.0-rc1 is a release candidate rather than a finished standard, and
review is more useful right now than implementation, because three things are
genuinely missing: the event kinds are unregistered placeholders that will
change, there are no test vectors for any of the derivations, and Appendix A
specifies the constraints on the 64-entry emoji table without containing the
table, so the short authentication string is not yet reproducible across
implementations. Disagreements and suspected errors belong in
[SPEC_ISSUES.md](SPEC_ISSUES.md).
