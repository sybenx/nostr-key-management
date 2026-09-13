"""Check a TIERS.md membership against §4's constraints and enumerate its signing sets.

    python3 tiers_check.py membership.json          # or - for stdin
    python3 tiers_check.py --json membership.json

A membership is the current epoch, not just its parameters:

    {"k": 4, "T": 2, "s": 1, "W_cap": 1,
     "trusted_devices": ["D1", "D2"],
     "co_signers": ["C1", "C2", "C3"],
     "grants": [{"party": "G1", "weight": 1}]}

`s` is the slack constraint (3) is checked at, as §4.4 and §4.6 declare it; it
defaults to 0. `W_cap` is the co-signer-enforced cap on total live grant weight and
is required. Trusted devices weigh `T` and co-signers 1 (§3.1, §3.2); a grant weighs
what it says.

Constraints (1), (2), (3) and (6) are required (§4.2); (4) is optional and on by
default (§3.5); (5) is §4.6's condition that every signing set contains a co-signer.
The script also checks the MUSTs the inequalities assume: k >= 3 and N <= 255 (§2.2),
T > 1 (§3.1), T < k and every grant's weight below T (§4.3), at least one trusted
device (§3.2), and live grant weight within W_cap (§4.2).

Slack for a trusted device is T + n_s - k: how many co-signers may be down while one
trusted device still signs with the rest (§4.3). Slack for a grant is w + n_s - k, the
same count for a set of that grant and co-signers only; 0 means every co-signer is
needed, and a negative slack means the grant cannot finish against co-signers at all.

Every minimal authorised set is listed with one label, tested in this order:

    no-co-signer  no co-signer in the set, so §6 policy never runs
    collusion     no trusted device in the set
    mixed         a trusted device, a co-signer and a grant
    trusted       trusted devices and co-signers only

so (5) holds exactly when no set is labelled no-co-signer.

Exit 0 when every required constraint holds, 1 when one fails, 2 on unreadable input.
(4) and (5) never change the exit status.
"""
import json, sys

TRUSTED, COSIGNER, GRANT = "trusted", "cosigner", "grant"

def load(path):
    f = sys.stdin if path == "-" else open(path)
    with f:
        m = json.load(f)
    for key in ("k", "T"):
        if type(m.get(key)) is not int:
            raise ValueError(f"{key} must be an integer")
    s = m.get("s", 0)
    if type(s) is not int or s < 0:
        raise ValueError("s must be a non-negative integer")
    W_cap = m.get("W_cap")
    if type(W_cap) is not int or W_cap < 0:
        raise ValueError("W_cap must be a non-negative integer")
    parties = []
    for name in m.get("trusted_devices", []):
        parties.append((name, TRUSTED, m["T"]))
    for name in m.get("co_signers", []):
        parties.append((name, COSIGNER, 1))
    for g in m.get("grants", []):
        if type(g.get("weight")) is not int or g["weight"] < 1:
            raise ValueError(f"grant {g.get('party')!r} needs a positive integer weight")
        parties.append((g.get("party"), GRANT, g["weight"]))
    names = [p[0] for p in parties]
    if not all(isinstance(n, str) and n for n in names):
        raise ValueError("every party needs a non-empty string name")
    if len(set(names)) != len(names):
        raise ValueError("party names must be unique across tiers")
    return m["k"], m["T"], s, W_cap, parties

def minimal_sets(k, parties):
    """Every authorised set with no authorised proper subset.

    Parties are taken heaviest first and a branch stops the moment it reaches k. The
    party that tipped it over is the lightest in the set, so dropping any member leaves
    at most the weight before it was added, which was under k: every set found is
    minimal, and every minimal set is found once, along its heaviest-first order.
    """
    order = sorted(range(len(parties)), key=lambda i: -parties[i][2])
    found = []
    def walk(start, chosen, weight):
        for j in range(start, len(order)):
            i = order[j]
            w = weight + parties[i][2]
            if w >= k:
                found.append((sorted(chosen + [i]), w))
            else:
                walk(j + 1, chosen + [i], w)
    if k > 0:
        walk(0, [], 0)
    return found

def label(tiers):
    if COSIGNER not in tiers: return "no-co-signer"
    if TRUSTED not in tiers:  return "collusion"
    if GRANT in tiers:        return "mixed"
    return "trusted"

def check(k, T, s, W_cap, parties):
    D   = sum(1 for p in parties if p[1] == TRUSTED)
    n_s = sum(1 for p in parties if p[1] == COSIGNER)
    grants = [p for p in parties if p[1] == GRANT]
    W_g = sum(p[2] for p in grants)
    N   = sum(p[2] for p in parties)

    rows = [
        # (group, id, section, statement, arithmetic, holds)
        ("precondition", "k>=3", "§2.2", "k >= 3", f"{k} >= 3", k >= 3),
        ("precondition", "N<=255", "§2.2", "N <= 255", f"{N} <= 255", N <= 255),
        ("precondition", "T>1", "§3.1", "T > 1", f"{T} > 1", T > 1),
        ("precondition", "T<k", "§4.3", "T < k", f"{T} < {k}", T < k),
        ("precondition", "D>=1", "§3.2", "at least one trusted device", f"D = {D}", D >= 1),
    ]
    heavy = [p for p in grants if p[2] >= T]
    rows.append(("precondition", "w<T", "§4.3", "every grant weight < T",
                 ", ".join(f"{p[0]} w={p[2]}" for p in heavy) or "all below T", not heavy))
    rows.append(("precondition", "W_g<=W_cap", "§4.2", "W_g <= W_cap", f"{W_g} <= {W_cap}", W_g <= W_cap))
    rows += [
        ("required", "1", "§4.2", "n_s < k", f"{n_s} < {k}", n_s < k),
        ("required", "2", "§4.2", "W_g < k", f"{W_g} < {k}", W_g < k),
        ("required", "3", "§4.2", "T + n_s - s >= k",
         f"{T} + {n_s} - {s} = {T + n_s - s} >= {k}", T + n_s - s >= k),
        ("required", "6", "§4.2", "T + W_cap < k",
         f"{T} + {W_cap} = {T + W_cap} < {k}", T + W_cap < k),
        ("optional", "4", "§4.2", "2T >= k", f"2*{T} = {2 * T} >= {k}", 2 * T >= k),
        ("optional", "5", "§4.6", "D*T + W_g < k",
         f"{D}*{T} + {W_g} = {D * T + W_g} < {k}", D * T + W_g < k),
    ]

    sets = []
    for members, weight in minimal_sets(k, parties):
        tiers = [parties[i][1] for i in members]
        key = (-tiers.count(TRUSTED), -tiers.count(COSIGNER), tiers.count(GRANT), members)
        sets.append((key, {"parties": [parties[i][0] for i in members],
                           "weight": weight, "label": label(tiers)}))
    sets = [entry for _, entry in sorted(sets, key=lambda e: e[0])]

    def group(g):
        return {r[1]: r[5] for r in rows if r[0] == g}
    return {
        "k": k, "T": T, "s": s, "W_cap": W_cap, "D": D, "n_s": n_s, "W_g": W_g, "N": N,
        "preconditions": group("precondition"),
        "required": group("required"),
        "optional": group("optional"),
        "slack": {"trusted_device": T + n_s - k,
                  "grants": {p[0]: p[2] + n_s - k for p in grants}},
        "sets": sets,
        "ok": all(r[5] for r in rows if r[0] != "optional"),
        "_rows": rows,
        "_grant_weights": {p[0]: p[2] for p in grants},
    }

def report(r):
    out = [f"k={r['k']} T={r['T']} s={r['s']} W_cap={r['W_cap']}   D={r['D']} n_s={r['n_s']} "
           f"W_g={r['W_g']} N={r['N']}"]
    for g, title in (("precondition", "preconditions"),
                     ("required", "required constraints"),
                     ("optional", "optional constraints (do not affect exit status)")):
        out.append(f"\n{title}")
        for _, cid, sec, stmt, arith, holds in (x for x in r["_rows"] if x[0] == g):
            tag = f"({cid})" if g != "precondition" else ""
            out.append(f"  {tag:4} {sec:5} {stmt:28} {arith:32} {'holds' if holds else 'FAILS'}")
    out.append("\nslack")
    out.append(f"  trusted device        T + n_s - k = {r['slack']['trusted_device']}")
    for name, sl in r["slack"]["grants"].items():
        out.append(f"  grant {name:15} w + n_s - k = {sl}   (w={r['_grant_weights'][name]})")
    out.append(f"\nminimal signing sets ({len(r['sets'])})")
    width = max([len(" + ".join(e["parties"])) for e in r["sets"]] + [3])
    for n, e in enumerate(r["sets"], 1):
        out.append(f"  {n:4}  {' + '.join(e['parties']):{width}}  {e['weight']:3}  {e['label']}")
    out.append("\n" + ("all required constraints hold" if r["ok"]
                       else "REJECTED: a required constraint fails"))
    return "\n".join(out)

def main(argv):
    args = [a for a in argv if a != "--json"]
    if len(args) != 1:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        r = check(*load(args[0]))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"tiers_check: {e}", file=sys.stderr)
        return 2
    if "--json" in argv:
        print(json.dumps({x: v for x, v in r.items() if not x.startswith("_")}, indent=2))
    else:
        print(report(r))
    return 0 if r["ok"] else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
