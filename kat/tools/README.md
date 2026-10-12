# Vector tooling

Scripts that produced the independent vector files in `kat/`; see
`docs/VECTORS.md` for sources, commits and coverage. Run them with
`python3 -I` from outside any downloaded directory.

| Script | Produces |
|--------|----------|
| `parse_rfc_f.py <rfc8554.txt> <out.json>` | `kat/rfc8554_appendix_f.json` from the RFC text (rfc-editor.org) |
| `gen_hashsigs.sh <dir>` | hash-sigs keys/signatures: `<dir>/src` must hold a built clone of cisco/hash-sigs (`make demo`), output goes to `<dir>/vec` |
| `convert_hashsigs.py <dir>/vec <commit> kat/hashsigs_w4.json kat/hashsigs_w1w2w8.json` | the two hash-sigs vector files |
| `convert_acvp.py <acvp_dir> <commit> kat/acvp_lms.json` | from the five `LMS-*/internalProjection.json` files of usnistgov/ACVP-Server |
