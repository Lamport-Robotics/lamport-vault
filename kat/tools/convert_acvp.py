"""Convert NIST ACVP-Server LMS gen-val JSON (internalProjection.json) into kat/acvp_lms.json.
Usage: python3 -I convert_acvp.py <acvp_dir> <commit> <out.json>
"""
import json, os, sys
acvp, commit, out = sys.argv[1:4]
LMS = {"LMS_SHA256_M24_H5": (10, 5, 24), "LMS_SHA256_M24_H10": (11, 10, 24), "LMS_SHA256_M24_H15": (12, 15, 24),
       "LMS_SHA256_M24_H20": (13, 20, 24), "LMS_SHA256_M24_H25": (14, 25, 24),
       "LMS_SHA256_M32_H5": (5, 5, 32), "LMS_SHA256_M32_H10": (6, 10, 32), "LMS_SHA256_M32_H15": (7, 15, 32),
       "LMS_SHA256_M32_H20": (8, 20, 32), "LMS_SHA256_M32_H25": (9, 25, 32)}
OTS = {"LMOTS_SHA256_N24_W1": (5, 1, 24, 200, 8), "LMOTS_SHA256_N24_W2": (6, 2, 24, 101, 6),
       "LMOTS_SHA256_N24_W4": (7, 4, 24, 51, 4), "LMOTS_SHA256_N24_W8": (8, 8, 24, 26, 0),
       "LMOTS_SHA256_N32_W1": (1, 1, 32, 265, 7), "LMOTS_SHA256_N32_W2": (2, 2, 32, 133, 6),
       "LMOTS_SHA256_N32_W4": (3, 4, 32, 67, 4), "LMOTS_SHA256_N32_W8": (4, 8, 32, 34, 0)}
def load(d): return json.load(open(os.path.join(acvp, d, "internalProjection.json")))
def u32(h, o): return int(h[o*2:o*2+8], 16)
used_lms, used_ots = set(), set()
sig_ver, sig_gen, key_gen = [], [], []
def check_key(pk, lms_mode, ots_mode):
    t, h, m = LMS[lms_mode]; o, w, n, p, ls = OTS[ots_mode]
    assert u32(pk, 0) == t and u32(pk, 4) == o, (pk[:16], lms_mode, ots_mode)
    assert len(pk) // 2 == 4 + 4 + 16 + m, (len(pk) // 2, lms_mode)
    used_lms.add(lms_mode); used_ots.add(ots_mode)
    return 4 + (4 + n * (p + 1)) + 4 + m * h
for d in ["LMS-sigVer-1.0", "LMS-sigVer-SP800-208"]:
    j = load(d); assert j["algorithm"] == "LMS" and j["mode"] == "sigVer"
    for g in j["testGroups"]:
        pk = g["publicKey"].lower(); siglen = check_key(pk, g["lmsMode"], g["lmOtsMode"])
        for tc in g["tests"]:
            sig = tc["signature"].lower()
            # 'modify signature header' cases may change the typecodes/q; the length is still the nominal one.
            assert len(sig) // 2 == siglen, (d, tc["tcId"], len(sig) // 2, siglen)
            sig_ver.append({"id": f"{d}/tg{g['tgId']}/tc{tc['tcId']}", "lms_mode": g["lmsMode"], "lmots_mode": g["lmOtsMode"],
                            "public_key_hex": pk, "message_hex": tc["message"].lower(), "signature_hex": sig,
                            "expected_valid": bool(tc["testPassed"]), "reason": tc["reason"]})
for d in ["LMS-sigGen-1.0", "LMS-sigGen-SP800-208"]:
    j = load(d); assert j["algorithm"] == "LMS" and j["mode"] == "sigGen"
    for g in j["testGroups"]:
        pk = g["publicKey"].lower(); siglen = check_key(pk, g["lmsMode"], g["lmOtsMode"])
        for tc in g["tests"]:
            sig = tc["signature"].lower(); assert len(sig) // 2 == siglen
            if "messageLength" in tc: assert tc["messageLength"] == len(tc["message"]) * 4
            sig_gen.append({"id": f"{d}/tg{g['tgId']}/tc{tc['tcId']}", "lms_mode": g["lmsMode"], "lmots_mode": g["lmOtsMode"],
                            "public_key_hex": pk, "message_hex": tc["message"].lower(), "signature_hex": sig, "q": u32(sig, 0)})
j = load("LMS-keyGen-1.0"); assert j["algorithm"] == "LMS" and j["mode"] == "keyGen"
for g in j["testGroups"]:
    for tc in g["tests"]:
        pk = tc["publicKey"].lower(); check_key(pk, g["lmsMode"], g["lmOtsMode"])
        assert not tc["deferred"]
        assert len(tc["seed"]) // 2 == OTS[g["lmOtsMode"]][2], "seed is n bytes"
        assert pk[16:48] == tc["i"].lower()
        key_gen.append({"id": f"LMS-keyGen-1.0/tg{g['tgId']}/tc{tc['tcId']}", "lms_mode": g["lmsMode"], "lmots_mode": g["lmOtsMode"],
                        "seed_hex": tc["seed"].lower(), "I_hex": tc["i"].lower(), "public_key_hex": pk})
base = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{commit}/gen-val/json-files/"
result = {
    "source": "NIST ACVP-Server gen-val sample vectors for LMS (SP 800-208 / RFC 8554), converted from internalProjection.json",
    "commit": commit,
    "urls": [base + d + "/internalProjection.json" for d in ["LMS-keyGen-1.0", "LMS-sigGen-1.0", "LMS-sigGen-SP800-208", "LMS-sigVer-1.0", "LMS-sigVer-SP800-208"]],
    "note": ("Every LMS test group published in ACVP-Server at this commit uses the SP 800-208 SHA-256/192 parameter sets "
             "(LMS_SHA256_M24_H5/H10 with LMOTS_SHA256_N24_W1/W2, typecodes 0x0A/0x0B and 0x05/0x06). There are no "
             "SHA256/M32 (RFC 8554 Table 1/2) cases. The M32-only verifiers in this repository must reject every key here "
             "(48-byte public key, foreign typecodes); the tests additionally check the vectors with a test-only n = m = 24 "
             "instantiation of the same algorithms. Seeds are n = 24 bytes and keys follow RFC 8554 Appendix A."),
    "parameter_sets": {
        "lms": {k: {"typecode": v[0], "h": v[1], "m": v[2]} for k, v in LMS.items() if k in used_lms},
        "lmots": {k: {"typecode": v[0], "w": v[1], "n": v[2], "p": v[3], "ls": v[4]} for k, v in OTS.items() if k in used_ots},
    },
    "sig_ver": sig_ver, "sig_gen": sig_gen, "key_gen": key_gen,
}
json.dump(result, open(out, "w"), indent=2); open(out, "a").write("\n")
print("sig_ver", len(sig_ver), "valid", sum(1 for s in sig_ver if s["expected_valid"]), "invalid", sum(1 for s in sig_ver if not s["expected_valid"]))
print("sig_gen", len(sig_gen), "key_gen", len(key_gen), "lms sets", sorted(used_lms), "ots sets", sorted(used_ots))
