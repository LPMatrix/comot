"""Command line: run the demo, verify an exported bundle, print a schema."""
from __future__ import annotations

import argparse
import json
import sys
from importlib import resources

from .bundle import load_bundle, verify_bundle
from .demo import run_demo
from .langpack import PackError, load_pack

SCHEMAS = {"consent": "consent_record.schema.json", "log": "log_entry.schema.json"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="comot", description="Consent and withdrawal layer for voice data (v0.0).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="run the synthetic-data lineage and withdrawal demo")
    demo.add_argument("--export", metavar="FILE", help="also write the signed audit bundle to FILE")

    verify = sub.add_parser("verify", help="check the hash chains of an exported bundle")
    verify.add_argument("bundle", help="path to a bundle JSON file")
    verify.add_argument("--key-hex", help="hex HMAC key, to check the signature too")

    schema = sub.add_parser("schema", help="print a JSON Schema")
    schema.add_argument("which", choices=sorted(SCHEMAS))

    pack = sub.add_parser("pack", help="check a language pack and list what blocks its release")
    pack.add_argument("path")

    args = parser.parse_args(argv)

    if args.cmd == "demo":
        comot = run_demo()
        if args.export:
            with open(args.export, "w", encoding="utf-8") as f:
                json.dump(comot.export_bundle(), f, indent=2)
            print(f"\nbundle written to {args.export}")
            print(f"verify it with: comot verify {args.export} --key-hex {comot.signer.key.hex()}")
        return 0

    if args.cmd == "verify":
        key = bytes.fromhex(args.key_hex) if args.key_hex else None
        problems = verify_bundle(load_bundle(args.bundle), key)
        if problems:
            print("NOT INTACT")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("intact: consent chain and audit log verify" + (", signature valid" if key else " (signature not checked)"))
        return 0

    if args.cmd == "schema":
        print(resources.files("comot").joinpath("schema", SCHEMAS[args.which]).read_text(encoding="utf-8"))
        return 0

    if args.cmd == "pack":
        try:
            p = load_pack(args.path)
        except PackError as e:
            print(f"invalid pack: {e}")
            return 2
        missing = p.missing_for_release()
        print(f"{p.language} {p.pack_version}: {'releasable' if not missing else 'not releasable'}")
        for m in missing:
            print(f"  - {m}")
        return 0 if not missing else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
