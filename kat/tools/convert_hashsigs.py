"""Convert hash-sigs demo output (keyname.pub, keyname.file.sig, file) into KAT JSON.
Usage: python3 -I convert_hashsigs.py <vecdir> <commit> <out_w4.json> <out_other.json>
"""
import json, os, sys, glob
vec, commit, out_w4, out_other = sys.argv[1:5]
LMS_H = {5: 5, 6: 10, 7: 15, 8: 20}
OTS_P = {1: 265, 2: 133, 3: 67, 4: 34}
OTS_NAME = {1: "W1", 2: "W2", 3: "W4", 4: "W8"}
def u32(b, o): return int.from_bytes(b[o:o+4], "big")
vectors = []
for pubf in sorted(glob.glob(os.path.join(vec, "*.pub"))):
    name = os.path.basename(pubf)[:-4]
    pub = open(pubf, "rb").read()
    assert len(pub) == 60 and u32(pub, 0) == 1, (name, len(pub))  # HSS levels = 1
    lms_pub = pub[4:]
    lms_type, ots_type = u32(lms_pub, 0), u32(lms_pub, 4)
    h, p = LMS_H[lms_type], OTS_P[ots_type]
    sig_len = 4 + (4 + 32 * (p + 1)) + 4 + 32 * h
    sigs = []
    for sigf in sorted(glob.glob(os.path.join(vec, name + ".*.sig"))):
        sig = open(sigf, "rb").read()
        assert u32(sig, 0) == 0, "Nspk must be 0 for a one-level HSS key"
        lms_sig = sig[4:]
        assert len(lms_sig) == sig_len, (sigf, len(lms_sig), sig_len)
        msg = open(sigf[:-4], "rb").read()
        sigs.append({"q": u32(lms_sig, 0), "message_hex": msg.hex(), "signature_hex": lms_sig.hex()})
    sigs.sort(key=lambda s: s["q"])
    vectors.append({
        "name": f"hash-sigs LMS_SHA256_M32_H{h} / LMOTS_SHA256_N32_{OTS_NAME[ots_type]}",
        "lms_type": lms_type, "lmots_type": ots_type, "height": h,
        "I_hex": lms_pub[8:24].hex(), "public_key_hex": lms_pub.hex(),
        "hss_public_key_hex": pub.hex(),
        "signatures": sigs,
    })
src = ("Cisco hash-sigs reference implementation (https://github.com/cisco/hash-sigs, C), commit " + commit +
       ", `demo genkey <name> <h>/<w>` + `demo sign` (+ `demo advance` to reach the last leaves). One-level HSS keys: "
       "the 60-byte .pub is u32 levels=1 || LMS public key, the .sig is u32 Nspk=0 || LMS signature; both prefixes are "
       "stripped here. hash-sigs private keys are not in the RFC 8554 Appendix A form, so only public keys and "
       "signatures are recorded (no SEED). Messages are arbitrary file contents, empty to 4096 bytes.")
w4 = [v for v in vectors if v["lmots_type"] == 3]
other = [v for v in vectors if v["lmots_type"] != 3]
json.dump({"source": src, "commit": commit, "vectors": w4}, open(out_w4, "w"), indent=2); open(out_w4, "a").write("\n")
json.dump({"source": src, "commit": commit, "vectors": other}, open(out_other, "w"), indent=2); open(out_other, "a").write("\n")
for v in vectors: print(v["name"], "sigs", len(v["signatures"]), "q", [s["q"] for s in v["signatures"]])
