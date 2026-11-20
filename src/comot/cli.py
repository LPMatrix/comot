"""Command line: run the demo, keep a database healthy, verify exports, print a schema."""
from __future__ import annotations

import argparse
import json
import sys
from importlib import resources

from .anchor import FileAnchorSink, read_anchor_file
from .bundle import load_bundle, verify_bundle
from .core import Comot
from .demo import run_demo
from .errors import StoreIntegrityError
from .langpack import PackError, load_pack
from .receipt import HmacSigner
from .store import StoreError
from .vault import generate_key_file

SCHEMAS = {"consent": "consent_record.schema.json", "log": "log_entry.schema.json"}


def _open(db: str, key_file: str) -> Comot:
    return Comot.open(db, signer=HmacSigner.from_file(key_file))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="comot", description="Consent and withdrawal layer for voice data.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="create a new random key file, readable only by you")
    keygen.add_argument("path")

    demo = sub.add_parser("demo", help="run the synthetic-data lineage and withdrawal demo")
    demo.add_argument("--db", metavar="FILE", help="keep the demo in a new SQLite database")
    demo.add_argument("--key-file", metavar="FILE", help="signing key for --db (created if missing)")
    demo.add_argument("--export", metavar="FILE", help="also write the signed audit bundle to FILE")

    check = sub.add_parser("check", help="open a database, verify its hash chains and anchors")
    check.add_argument("db")
    check.add_argument("--key-file", required=True)
    check.add_argument("--anchors", metavar="FILE", help="an anchor file kept outside the database")

    export = sub.add_parser("export", help="write a signed audit bundle from a database")
    export.add_argument("db")
    export.add_argument("--key-file", required=True)
    export.add_argument("--out", required=True)

    anchor = sub.add_parser("anchor", help="publish the audit log's head hash to an anchor file")
    anchor.add_argument("db")
    anchor.add_argument("--key-file", required=True)
    anchor.add_argument("--out", required=True, help="anchor file to append to; keep it where the database's writers cannot edit it")

    verify = sub.add_parser("verify", help="check an exported bundle")
    verify.add_argument("bundle")
    verify.add_argument("--key-file", help="signing key, to check the signature too")
    verify.add_argument("--key-hex", help="signing key as hex, to check the signature too")
    verify.add_argument("--anchors", metavar="FILE", help="an anchor file kept outside the bundle's source")

    schema = sub.add_parser("schema", help="print a JSON Schema")
    schema.add_argument("which", choices=sorted(SCHEMAS))

    pack = sub.add_parser("pack", help="check a language pack and list what blocks its release")
    pack.add_argument("path")

    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        generate_key_file(args.path)
        print(f"key written to {args.path}. Back it up: without it receipts and exports cannot be verified.")
        return 0

    if args.cmd == "demo":
        comot = run_demo(db=args.db, key_file=args.key_file)
        if args.db:
            print(f"\ndatabase written to {args.db}")
        if args.export:
            with open(args.export, "w", encoding="utf-8") as f:
                json.dump(comot.export_bundle(), f, indent=2)
            print(f"\nbundle written to {args.export}")
            print(f"verify it with: comot verify {args.export} --key-hex {comot.signer.key.hex()}")
        return 0

    if args.cmd in ("check", "export", "anchor"):
        try:
            comot = _open(args.db, args.key_file)
        except StoreIntegrityError as e:
            print("NOT INTACT")
            for p in e.problems:
                print(f"  - {p}")
            return 1
        except (StoreError, FileNotFoundError) as e:
            print(f"cannot open: {e}")
            return 2
        if args.cmd == "check":
            problems = comot.verify_integrity(read_anchor_file(args.anchors) if args.anchors else [])
            if problems:
                print("NOT INTACT")
                for p in problems:
                    print(f"  - {p}")
                return 1
            print(f"intact: {len(comot.log.entries)} log entries, {len(comot.consents)} consent records, "
                  f"{len(comot.anchors)} stored anchors" + (", external anchors agree" if args.anchors else ""))
        elif args.cmd == "export":
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(comot.export_bundle(), f, indent=2)
            print(f"bundle written to {args.out}")
        else:
            a = comot.anchor(FileAnchorSink(args.out))
            print("nothing new to anchor" if a is None else f"anchored log head at entry {a.seq} to {a.sink}")
        comot.close()
        return 0

    if args.cmd == "verify":
        key = None
        if args.key_file:
            key = HmacSigner.from_file(args.key_file).key
        elif args.key_hex:
            key = bytes.fromhex(args.key_hex)
        anchors = read_anchor_file(args.anchors) if args.anchors else None
        problems = verify_bundle(load_bundle(args.bundle), key, anchors)
        if problems:
            print("NOT INTACT")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("intact: consent chain and audit log verify"
              + (", external anchors agree" if anchors else "")
              + (", signature valid" if key else " (signature not checked)"))
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
