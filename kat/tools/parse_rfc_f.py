"""Parse RFC 8554 Appendix F into kat/rfc8554_appendix_f.json.

Usage: python3 -I parse_rfc_f.py <rfc8554.txt> <out.json>
"""
import json, re, sys

src, out = sys.argv[1], sys.argv[2]
lines = open(src, encoding="utf-8").read().split("\n")

# Appendix F spans from its heading to "Acknowledgements".
start = next(i for i, l in enumerate(lines) if l.startswith("Appendix F.  Test Cases"))
end = next(i for i, l in enumerate(lines) if i > start and l.startswith("Acknowledgements"))
body = lines[start:end]

HEX = re.compile(r"^[0-9a-f]+$")
tokens = []  # (kind, text): ("section", title) | ("label", name, hex) | ("hex", hex)
for l in body:
    if not l.strip() or l.startswith("McGrew") or l.startswith("RFC 8554"):
        continue
    m = re.match(r"^   Test Case (\d) (Public Key|Message|Signature|Private Key)\s*$", l)
    if m:
        tokens.append(("section", f"{m.group(1)} {m.group(2)}"))
        continue
    if not tokens:
        continue  # heading and the introductory paragraph
    if l.strip().startswith("---") or l.strip() in ("HSS public key", "HSS signature", "LMS signature", "LMOTS signature", "LMS public key", "Top level LMS tree", "Second level LMS tree", "(note: procedure in Appendix A is used)"):
        continue
    if l.strip() in ("sig[0]:", "final_signature:"):
        tokens.append(("marker", l.strip()))
        continue
    # labelled line:  "   NAME        hexhex   # comment" or "   NAME   hex  |ascii|"
    m = re.match(r"^   (\S+(?: type)?)\s+([0-9a-f]+)(?:\s+(?:#.*|\|.*\|))?\s*$", l)
    if m:
        tokens.append(("label", m.group(1), m.group(2)))
        continue
    m = re.match(r"^\s{15}([0-9a-f]+)(?:\s+\|.*\|)?\s*$", l)
    if m:
        tokens.append(("hex", m.group(1)))
        continue
    raise SystemExit(f"unparsed line: {l!r}")

# Fold continuation hex into the preceding label.
items = []
for t in tokens:
    if t[0] == "hex":
        assert items[-1][0] == "label", t
        items[-1] = ("label", items[-1][1], items[-1][2] + t[1])
    else:
        items.append(t)

# Walk sections.
cases = {}
cur = None
for it in items:
    if it[0] == "section":
        n, kind = it[1].split(" ", 1)
        cur = cases.setdefault(int(n), {"items": {}})
        cur["items"].setdefault(kind, [])
        cur_kind = kind
    elif it[0] == "marker":
        cur["items"][cur_kind].append(("marker", it[1]))
    else:
        cur["items"][cur_kind].append(("label", it[1], it[2]))

def u32(h): return int(h, 16)

def parse_lms_sig(seq, pos):
    """seq[pos:] starts with q; returns (dict, bytes, newpos)."""
    assert seq[pos][1] == "q", seq[pos]
    q = u32(seq[pos][2]); pos += 1
    assert seq[pos][1] == "LMOTS type"; ots_type = u32(seq[pos][2]); pos += 1
    assert seq[pos][1] == "C"; C = seq[pos][2]; pos += 1
    y = []
    while pos < len(seq) and seq[pos][0] == "label" and seq[pos][1].startswith("y["):
        assert seq[pos][1] == f"y[{len(y)}]", seq[pos]
        y.append(seq[pos][2]); pos += 1
    assert seq[pos][1] == "LMS type"; lms_type = u32(seq[pos][2]); pos += 1
    path = []
    while pos < len(seq) and seq[pos][0] == "label" and seq[pos][1].startswith("path["):
        assert seq[pos][1] == f"path[{len(path)}]", seq[pos]
        path.append(seq[pos][2]); pos += 1
    hexsig = f"{q:08x}{ots_type:08x}{C}{''.join(y)}{lms_type:08x}{''.join(path)}"
    return {"q": q, "lmots_type": ots_type, "C_hex": C, "y_count": len(y), "lms_type": lms_type, "path_count": len(path), "signature_hex": hexsig}, pos

def parse_lms_pub(seq, pos):
    assert seq[pos][1] == "LMS type"; lms_type = u32(seq[pos][2]); pos += 1
    assert seq[pos][1] == "LMOTS type"; ots = u32(seq[pos][2]); pos += 1
    assert seq[pos][1] == "I"; I = seq[pos][2]; pos += 1
    assert seq[pos][1] == "K"; K = seq[pos][2]; pos += 1
    return {"lms_type": lms_type, "lmots_type": ots, "I_hex": I, "T1_hex": K, "public_key_hex": f"{lms_type:08x}{ots:08x}{I}{K}"}, pos

result = {"source": "RFC 8554 Appendix F (https://www.rfc-editor.org/rfc/rfc8554.txt), test cases 1 and 2, parsed verbatim", "test_cases": []}
for n in sorted(cases):
    c = cases[n]["items"]
    pub = c["Public Key"]
    assert pub[0][1] == "levels"; levels = u32(pub[0][2])
    top, _ = parse_lms_pub(pub, 1)
    msg = c["Message"]; assert len(msg) == 1 and msg[0][1] == "Message"
    message_hex = msg[0][2]
    sig = c["Signature"]
    assert sig[0][1] == "Nspk"; nspk = u32(sig[0][2]); pos = 1
    layers = []
    pubs = [top]
    for i in range(nspk):
        assert sig[pos] == ("marker", "sig[0]") or sig[pos][0] == "marker"; pos += 1
        s, pos = parse_lms_sig(sig, pos)
        p, pos = parse_lms_pub(sig, pos)
        layers.append({"layer": i, "signature": s, "signed_public_key": p})
        pubs.append(p)
    assert sig[pos] == ("marker", "final_signature:"); pos += 1
    fin, pos = parse_lms_sig(sig, pos)
    assert pos == len(sig)
    tc = {"test_case": n, "levels": levels, "hss_public_key_hex": f"{levels:08x}" + top["public_key_hex"], "message_hex": message_hex, "nspk": nspk}
    if "Private Key" in c:
        pk = c["Private Key"]
        keys = []
        for i in range(0, len(pk), 2):
            assert pk[i][1] == "SEED" and pk[i+1][1] == "I"
            keys.append({"level": i // 2, "seed_hex": pk[i][2], "I_hex": pk[i+1][2]})
        tc["private_keys"] = keys
    # Flatten into one LMS verification per layer: (public key, message, signature).
    lms = []
    for i, L in enumerate(layers):
        lms.append({"layer": i, "description": f"sig[{i}] over the level-{i+1} LMS public key", "public_key_hex": pubs[i]["public_key_hex"], "lms_type": pubs[i]["lms_type"], "lmots_type": pubs[i]["lmots_type"], "I_hex": pubs[i]["I_hex"], "message_hex": pubs[i+1]["public_key_hex"], "q": L["signature"]["q"], "signature_hex": L["signature"]["signature_hex"]})
    lms.append({"layer": nspk, "description": "final signature over the message", "public_key_hex": pubs[nspk]["public_key_hex"], "lms_type": pubs[nspk]["lms_type"], "lmots_type": pubs[nspk]["lmots_type"], "I_hex": pubs[nspk]["I_hex"], "message_hex": message_hex, "q": fin["q"], "signature_hex": fin["signature_hex"]})
    tc["lms_layers"] = lms
    tc["hss_signature_hex"] = f"{nspk:08x}" + "".join(L["signature"]["signature_hex"] + L["signed_public_key"]["public_key_hex"] for L in layers) + fin["signature_hex"]
    result["test_cases"].append(tc)

json.dump(result, open(out, "w"), indent=2)
open(out, "a").write("\n")
for tc in result["test_cases"]:
    print("test case", tc["test_case"], "levels", tc["levels"], "msg bytes", len(tc["message_hex"])//2, "hss sig bytes", len(tc["hss_signature_hex"])//2)
    for L in tc["lms_layers"]:
        print("  layer", L["layer"], "lms", L["lms_type"], "ots", L["lmots_type"], "q", L["q"], "sig bytes", len(L["signature_hex"])//2, "msg bytes", len(L["message_hex"])//2)
