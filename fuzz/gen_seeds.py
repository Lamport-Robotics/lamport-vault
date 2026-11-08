#!/usr/bin/env python3
"""Seed corpora for the fuzz targets from the known-answer vectors in ../kat.

    cd fuzz && python3 gen_seeds.py

Fixture order mirrors src/lib.rs: lms_sha256_w4.json, hashsigs_w4.json,
hashsigs_w1w2w8.json (file order), then the RFC 8554 Appendix F LMS layers.
"""
import json, os, struct
here = os.path.dirname(os.path.abspath(__file__))
kat = os.path.join(here, "..", "kat")
fixtures = []  # (name, pk bytes, [(msg, sig)])
for f in ["lms_sha256_w4.json", "hashsigs_w4.json", "hashsigs_w1w2w8.json"]:
    for v in json.load(open(os.path.join(kat, f)))["vectors"]:
        fixtures.append((v["name"], bytes.fromhex(v["public_key_hex"]), [(bytes.fromhex(s["message_hex"]), bytes.fromhex(s["signature_hex"])) for s in v["signatures"]]))
for tc in json.load(open(os.path.join(kat, "rfc8554_appendix_f.json")))["test_cases"]:
    for l in tc["lms_layers"]:
        fixtures.append((f"rfc tc{tc['test_case']} layer {l['layer']}", bytes.fromhex(l["public_key_hex"]), [(bytes.fromhex(l["message_hex"]), bytes.fromhex(l["signature_hex"]))]))

def write(target, name, data):
    d = os.path.join(here, "seeds", target); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(data)

for i, (name, pk, sigs) in enumerate(fixtures):
    write("lms_parse", f"pk{i}", pk)
    write("lms_parse", f"sel{i}_sig0", bytes([i]) + sigs[0][1])
    write("lms_parse", f"pk{i}_sig0", pk + sigs[0][1])
    write("lms_verify", f"k{i}s0_valid", bytes([i, 0, 0]) + sigs[0][1])
    for j, (msg, sig) in enumerate(sigs[:2]):
        write("lms_verify", f"k{i}s{j}_mutate", bytes([i, j, 1]) + struct.pack(">HB", 40, 0x01))
        write("lms_verify", f"k{i}s{j}_noop", bytes([i, j, 1]))
        write("lms_verify", f"k{i}s{j}_trunc", bytes([i, j, 2, 0, 0]))
        write("lms_verify", f"k{i}s{j}_msg", bytes([i, j, 3]) + struct.pack(">HB", 0, 0x80))
        write("lms_verify", f"k{i}s{j}_key", bytes([i, j, 4, (i + 1) % len(fixtures), 1, 0x80]))

# Borsh Action encodings (variant byte, little-endian integers).
pk32 = bytes(range(32)); pk56 = bytes(range(56))
# Every variant ends in issued_slot, expiry_slot.
write("action_decode", "transfer_sol", bytes([0]) + pk32 + struct.pack("<QQQ", 1_000_000, 123_000, 123_456))
write("action_decode", "transfer_token", bytes([1]) + pk32 + pk32[::-1] + struct.pack("<QQQ", 42, 90, 99))
write("action_decode", "rotate", bytes([2]) + pk56 + struct.pack("<QQ", 6, 7))
write("action_decode", "close", bytes([3]) + pk32 + struct.pack("<QQ", 7, 8))
write("action_decode", "bad_variant", bytes([4]) + pk32)
write("action_decode", "short", bytes([0]) + pk32[:10])
# Arbitrary-driven targets: a few byte patterns so libFuzzer starts somewhere.
for i, pat in enumerate([bytes(range(256)), bytes([0] * 64), bytes([0xff] * 64), bytes([1, 2, 3, 4, 5, 6, 7, 8] * 16)]):
    write("key_history", f"seed{i}", pat)
    write("leaf_bitmap", f"seed{i}", pat)
print(f"{len(fixtures)} fixtures; seeds written under {os.path.join(here, 'seeds')}")
