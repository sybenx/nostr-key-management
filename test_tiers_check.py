"""Run tiers_check.py against vectors/tiers-*.json.

    python3 -m unittest test_tiers_check
"""
import itertools, json, os, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "tiers_check.py")

def vector(name):
    with open(os.path.join(HERE, "vectors", name)) as f:
        return json.load(f)

def run(membership):
    p = subprocess.run([sys.executable, SCRIPT, "--json", "-"], input=json.dumps(membership),
                       capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout) if p.stdout else None

def tiers_of(membership):
    t = {d: "trusted" for d in membership["trusted_devices"]}
    t.update({c: "cosigner" for c in membership["co_signers"]})
    t.update({g["party"]: "grant" for g in membership["grants"]})
    return t

class Vectors(unittest.TestCase):
    def check_case(self, case):
        m, want = case["membership"], case["expect"]
        code, got = run(m)
        self.assertEqual(code, want["exit"])
        for key in ("preconditions", "required", "optional", "slack"):
            self.assertEqual(got[key], want[key], key)
        if "sets" in want:
            self.assertEqual([{k: s[k] for k in ("parties", "weight", "label")} for s in want["sets"]],
                             got["sets"])
        if "set_counts" in want:
            counts = {label: 0 for label in want["set_counts"]}
            for s in got["sets"]:
                counts[s["label"]] += 1
            self.assertEqual(counts, want["set_counts"])

        # The enumeration and the inequalities are separate code paths; they must agree.
        tiers = tiers_of(m)
        kinds = [{tiers[p] for p in s["parties"]} for s in got["sets"]]
        self.assertEqual(got["optional"]["5"], all("cosigner" in k for k in kinds))
        self.assertEqual(not got["required"]["1"], {"cosigner"} in kinds)
        self.assertEqual(not got["required"]["2"], {"grant"} in kinds)
        if len(tiers) <= 14:
            self.assertEqual(sorted(sorted(s["parties"]) for s in got["sets"]), brute_force(m))

    def test_profile_a(self):
        cases = vector("tiers-profile-a.json")["cases"]
        self.assertEqual(len(cases[0]["expect"]["sets"]), 13)
        for case in cases:
            with self.subTest(case["name"]):
                self.check_case(case)

    def test_profile_b(self):
        for case in vector("tiers-profile-b.json")["cases"]:
            with self.subTest(case["name"]):
                self.check_case(case)

    def test_rejected(self):
        for case in vector("tiers-rejected.json")["cases"]:
            with self.subTest(case["name"]):
                v = case["violates"]
                group = {"precondition": "preconditions"}.get(v["group"], v["group"])
                self.assertIs(case["expect"][group][v["constraint"]], False)
                self.check_case(case)

class MembershipChange(unittest.TestCase):
    """§4.6: (5) is a property of the membership, so admitting a device can break it."""

    def test_third_trusted_device_breaks_5(self):
        m = {"k": 5, "T": 2, "s": 1, "trusted_devices": ["D1", "D2"],
             "co_signers": ["C1", "C2", "C3", "C4"], "grants": []}
        code, before = run(m)
        self.assertEqual(code, 0)
        self.assertIs(before["optional"]["4"], False)
        self.assertIs(before["optional"]["5"], True)
        self.assertNotIn("no-co-signer", {s["label"] for s in before["sets"]})

        m["trusted_devices"].append("D3")
        code, after = run(m)
        self.assertEqual(code, 0, "(5) is optional and must not change the exit status")
        self.assertEqual(after["required"], {"1": True, "2": True, "3": True})
        self.assertIs(after["optional"]["5"], False)
        self.assertIn({"parties": ["D1", "D2", "D3"], "weight": 6, "label": "no-co-signer"},
                      after["sets"])

class Boundaries(unittest.TestCase):
    """Each inequality at equality, where the vectors' odd k and small N never land."""

    def test_4_holds_at_2T_equal_k(self):
        code, r = run({"k": 4, "T": 2, "s": 0, "trusted_devices": ["D1", "D2"],
                       "co_signers": ["C1", "C2"], "grants": []})
        self.assertEqual(code, 0)
        self.assertIs(r["optional"]["4"], True)
        self.assertIn({"parties": ["D1", "D2"], "weight": 4, "label": "no-co-signer"}, r["sets"])

    def test_N_255_is_the_last_index(self):
        m = {"k": 3, "T": 2, "s": 1, "trusted_devices": [f"D{i}" for i in range(1, 127)],
             "co_signers": ["C1", "C2"], "grants": [{"party": "G1", "weight": 1}]}
        code, r = run(m)
        self.assertEqual((code, r["N"], r["preconditions"]["N<=255"]), (0, 255, True))
        m["grants"].append({"party": "G2", "weight": 1})
        code, r = run(m)
        self.assertEqual((code, r["N"], r["preconditions"]["N<=255"]), (1, 256, False))

    def test_unreadable_input_exits_2(self):
        for bad in ({"k": "3", "T": 2}, {"k": 3, "T": 2, "grants": [{"party": "G1"}]},
                    {"k": 3, "T": 2, "trusted_devices": ["X"], "co_signers": ["X"]}):
            p = subprocess.run([sys.executable, SCRIPT, "-"], input=json.dumps(bad),
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 2, bad)

def brute_force(m):
    w = {d: m["T"] for d in m["trusted_devices"]}
    w.update({c: 1 for c in m["co_signers"]})
    w.update({g["party"]: g["weight"] for g in m["grants"]})
    names = list(w)
    out = []
    for r in range(1, len(names) + 1):
        for combo in itertools.combinations(names, r):
            total = sum(w[p] for p in combo)
            if total >= m["k"] and all(total - w[p] < m["k"] for p in combo):
                out.append(sorted(combo))
    return sorted(out)

if __name__ == "__main__":
    unittest.main()
