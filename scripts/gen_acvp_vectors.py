#!/usr/bin/env python3
# Copyright (c) 2026 The fips203-mlkem-esp32 authors
# SPDX-License-Identifier: Apache-2.0
"""
Generate a C header with NIST ACVP ML-KEM (FIPS 203) test vectors.

The vectors come from the official NIST ACVP server repository:
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
    ML-KEM-keyGen-FIPS203/{prompt,expectedResults}.json
    ML-KEM-encapDecap-FIPS203/{prompt,expectedResults}.json

Byte strings are emitted as hex string literals exactly as they appear in
the JSON files (so any test case can be cross-checked by its tcId). Large
expected outputs (ek/dk of keyGen, c of encapsulation) are replaced by their
SHA-256 digest to keep the header small.

Usage:
  scripts/gen_acvp_vectors.py --download --out examples/mlkem_test_vectors/acvp_vectors.h
  scripts/gen_acvp_vectors.py --acvp-dir DIR --all --out acvp_all.h
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

RAW_BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
            "{ref}/gen-val/json-files/")
FILES = [
    "ML-KEM-keyGen-FIPS203/prompt.json",
    "ML-KEM-keyGen-FIPS203/expectedResults.json",
    "ML-KEM-encapDecap-FIPS203/prompt.json",
    "ML-KEM-encapDecap-FIPS203/expectedResults.json",
]
LEVELS = ("512", "768", "1024")


def download(acvp_dir: Path, ref: str) -> None:
    for f in FILES:
        dst = acvp_dir / f
        if dst.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        url = RAW_BASE.format(ref=ref) + f
        print(f"downloading {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=60) as r:
            dst.write_bytes(r.read())


def load(acvp_dir: Path, name: str):
    prompt = json.loads((acvp_dir / name / "prompt.json").read_text())
    expected = json.loads((acvp_dir / name / "expectedResults.json").read_text())
    exp = {t["tcId"]: t for g in expected["testGroups"] for t in g["tests"]}
    return prompt, exp


def sha256_hex(h: str) -> str:
    return hashlib.sha256(bytes.fromhex(h)).hexdigest().upper()


def level_of(group) -> str:
    return group["parameterSet"].split("-")[-1]


def balanced(tests, exp, n):
    """Pick up to n key-check tests, alternating valid and invalid keys."""
    if n is None:
        return tests
    good = [t for t in tests if exp[t["tcId"]]["testPassed"]]
    bad = [t for t in tests if not exp[t["tcId"]]["testPassed"]]
    out = []
    while len(out) < n and (good or bad):
        for pool in (good, bad):
            if pool and len(out) < n:
                out.append(pool.pop(0))
    return sorted(out, key=lambda t: t["tcId"])


def emit_array(lines, ctype, name, rows):
    lines.append(f"static const {ctype} {name}[] = {{")
    for r in rows:
        lines.append("  {" + ", ".join(r) + "},")
    lines.append("};")
    lines.append("")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--acvp-dir", type=Path, default=Path(".acvp-data"),
                    help="directory containing the ACVP json-files subset")
    ap.add_argument("--download", action="store_true",
                    help="fetch missing JSON files from GitHub first")
    ap.add_argument("--ref", default="master", help="ACVP-Server git ref")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--keygen", type=int, default=None, help="keyGen tests per level (default: all)")
    ap.add_argument("--encap", type=int, default=5, help="encapsulation tests per level")
    ap.add_argument("--decap", type=int, default=5, help="decapsulation tests per level")
    ap.add_argument("--keycheck", type=int, default=4,
                    help="ek/dk check tests per level (half valid, half invalid)")
    ap.add_argument("--all", action="store_true", help="include every test case")
    a = ap.parse_args()
    if a.all:
        a.keygen = a.encap = a.decap = a.keycheck = None

    if a.download:
        download(a.acvp_dir, a.ref)

    kg_prompt, kg_exp = load(a.acvp_dir, "ML-KEM-keyGen-FIPS203")
    ed_prompt, ed_exp = load(a.acvp_dir, "ML-KEM-encapDecap-FIPS203")

    def q(s):
        return f'"{s}"'

    def take(tests, n):
        return tests if n is None else tests[:n]

    L = []
    L.append("/*")
    L.append(" * NIST ACVP ML-KEM (FIPS 203) test vectors -- AUTO-GENERATED, do not edit.")
    L.append(" *")
    L.append(" * Generator: scripts/gen_acvp_vectors.py")
    L.append(" * Source:    https://github.com/usnistgov/ACVP-Server (gen-val/json-files)")
    L.append(f" *            ML-KEM-keyGen-FIPS203     vsId={kg_prompt.get('vsId')}")
    L.append(f" *            ML-KEM-encapDecap-FIPS203 vsId={ed_prompt.get('vsId')}")
    L.append(" *")
    L.append(" * Hex strings are copied verbatim from the JSON files; *_sha256 fields are")
    L.append(" * SHA-256 digests of the corresponding (large) expected value.")
    L.append(" */")
    L.append("")
    L.append("#ifndef ACVP_VECTORS_H")
    L.append("#define ACVP_VECTORS_H")
    L.append("")
    L.append("#include <stdbool.h>")
    L.append("#include <stdint.h>")
    L.append("")
    L.append("typedef struct { uint16_t tcId; const char *d, *z, *ek_sha256, *dk_sha256; } acvp_keygen_t;")
    L.append("typedef struct { uint16_t tcId; const char *ek, *m, *c_sha256, *k; } acvp_encap_t;")
    L.append("typedef struct { uint16_t tcId; const char *dk, *c, *k; } acvp_decap_t;")
    L.append("typedef struct { uint16_t tcId; bool valid; const char *key; } acvp_keycheck_t;")
    L.append("")

    counts = {}
    for g in kg_prompt["testGroups"]:
        lvl = level_of(g)
        rows = []
        for t in take(g["tests"], a.keygen):
            e = kg_exp[t["tcId"]]
            rows.append([str(t["tcId"]), q(t["d"]), q(t["z"]),
                         q(sha256_hex(e["ek"])), q(sha256_hex(e["dk"]))])
        emit_array(L, "acvp_keygen_t", f"acvp_keygen_{lvl}", rows)
        counts.setdefault(lvl, {})["keygen"] = len(rows)

    for g in ed_prompt["testGroups"]:
        lvl, fn = level_of(g), g["function"]
        if fn == "encapsulation":
            rows = []
            for t in take(g["tests"], a.encap):
                e = ed_exp[t["tcId"]]
                rows.append([str(t["tcId"]), q(t["ek"]), q(t["m"]),
                             q(sha256_hex(e["c"])), q(e["k"])])
            emit_array(L, "acvp_encap_t", f"acvp_encap_{lvl}", rows)
            counts[lvl]["encap"] = len(rows)
        elif fn == "decapsulation":
            rows = []
            for t in take(g["tests"], a.decap):
                e = ed_exp[t["tcId"]]
                rows.append([str(t["tcId"]), q(t["dk"]), q(t["c"]), q(e["k"])])
            emit_array(L, "acvp_decap_t", f"acvp_decap_{lvl}", rows)
            counts[lvl]["decap"] = len(rows)
        elif fn in ("encapsulationKeyCheck", "decapsulationKeyCheck"):
            field = "ek" if fn.startswith("encap") else "dk"
            rows = []
            for t in balanced(g["tests"], ed_exp, a.keycheck):
                valid = "true" if ed_exp[t["tcId"]]["testPassed"] else "false"
                rows.append([str(t["tcId"]), valid, q(t[field])])
            emit_array(L, "acvp_keycheck_t", f"acvp_{field}check_{lvl}", rows)
            counts[lvl][f"{field}check"] = len(rows)

    L.append("#endif /* ACVP_VECTORS_H */")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("\n".join(L) + "\n")
    for lvl in LEVELS:
        print(f"ML-KEM-{lvl}: {counts.get(lvl)}", file=sys.stderr)
    print(f"wrote {a.out} ({a.out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
