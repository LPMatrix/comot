"""Command line: run the demo, keep a database healthy, rotate keys, verify exports."""
from __future__ import annotations

import argparse
import json
import sys
from importlib import resources

from .access import AccessPolicy, Actor
from .anchor import FileAnchorSink, read_anchor_file
from .bundle import load_bundle, verify_bundle
from .core import Comot
from .demo import run_demo
from .errors import StoreIntegrityError
from .langpack import PackError, load_pack
from .signing import (
    ALG_ED25519,
    Ed25519Signer,
    HmacSigner,
    KeyRing,
    SigningError,
    generate_signer_file,
    load_signer,
    load_verifier,
)
from .store import StoreError
from .vault import IdentityVault, VaultError, generate_key_file, load_key_file

SCHEMAS = {"consent": "consent_record.schema.json", "log": "log_entry.schema.json"}


def default_algorithm() -> str:
    """Ed25519 when it is available, so an outside auditor can verify with a public key alone."""
    try:
        Ed25519Signer()
        return ALG_ED25519
    except SigningError:
        return "hmac"


def _signer(key_file: str, retired: list[str] | None):
    current = load_signer(key_file)
    if not retired:
        return current
    return KeyRing(current, [load_verifier(r) for r in retired])


def _open(db: str, key_file: str, retired: list[str] | None = None, **kwargs) -> Comot:
    return Comot.open(db, signer=_signer(key_file, retired), **kwargs)


def _add_key_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key-file", required=True, help="the current signing key")
    p.add_argument("--retired-key", action="append", default=[], metavar="FILE",
                   help="an earlier signing key (its public half is enough for Ed25519); repeat for each")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="comot", description="Consent and withdrawal layer for voice data.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="create a new random key file, readable only by you")
    keygen.add_argument("path")
    keygen.add_argument("--kind", choices=["signing", "vault"], default="signing")
    keygen.add_argument("--algorithm", choices=["ed25519", "hmac"], default=None,
                        help="for signing keys. Default ed25519: auditors verify with the public key and hold no secret")

    pubkey = sub.add_parser("pubkey", help="print the public key of an Ed25519 signing key, safe to give to auditors")
    pubkey.add_argument("path")

    demo = sub.add_parser("demo", help="run the synthetic-data lineage and withdrawal demo")
    demo.add_argument("--db", metavar="FILE", help="keep the demo in a new SQLite database")
    demo.add_argument("--key-file", metavar="FILE", help="signing key for --db (created if missing)")
    demo.add_argument("--export", metavar="FILE", help="also write the signed audit bundle to FILE")

    check = sub.add_parser("check", help="open a database, verify its hash chains, objects and anchors")
    check.add_argument("db")
    _add_key_args(check)
    check.add_argument("--anchors", metavar="FILE", help="an anchor file kept outside the database")

    export = sub.add_parser("export", help="write a signed audit bundle from a database")
    export.add_argument("db")
    _add_key_args(export)
    export.add_argument("--out", required=True)

    anchor = sub.add_parser("anchor", help="publish the audit log's head hash to an anchor file")
    anchor.add_argument("db")
    _add_key_args(anchor)
    anchor.add_argument("--out", required=True, help="anchor file to append to; keep it where the database's writers cannot edit it")

    rotate = sub.add_parser("rotate-key", help="switch a database to a new signing key, keeping the old ones for verification")
    rotate.add_argument("db")
    _add_key_args(rotate)

    vrot = sub.add_parser("vault-rotate", help="re-encrypt the identity vault under a new key, and log that it happened")
    vrot.add_argument("db")
    vrot.add_argument("vault")
    _add_key_args(vrot)
    vrot.add_argument("--vault-key", required=True, help="the vault's current key file")
    vrot.add_argument("--new-vault-key", required=True, help="the new key file (make one with: comot keygen --kind vault)")

    verify = sub.add_parser("verify", help="check an exported bundle")
    verify.add_argument("bundle")
    verify.add_argument("--key-file", help="signing key file, to check the signature too")
    verify.add_argument("--key-hex", help="HMAC key as hex, to check the signature too")
    verify.add_argument("--public-key", metavar="KEY", help="an Ed25519 public key (ed25519:<hex>) or a file holding one")
    verify.add_argument("--anchors", metavar="FILE", help="an anchor file kept outside the bundle's source")

    schema = sub.add_parser("schema", help="print a JSON Schema")
    schema.add_argument("which", choices=sorted(SCHEMAS))

    pack = sub.add_parser("pack", help="check a language pack and list what blocks its release")
    pack.add_argument("path")

    args = parser.parse_args(argv)

    try:
        return _run(args)
    except (SigningError, VaultError, OSError, ValueError) as e:
        print(f"error: {e}")
        return 2


def _run(args: argparse.Namespace) -> int:
    if args.cmd == "keygen":
        if args.kind == "vault":
            generate_key_file(args.path)
            print(f"vault key written to {args.path}. Back it up: without it the vault cannot be read.")
            return 0
        signer = generate_signer_file(args.path, args.algorithm or default_algorithm())
        print(f"{signer.algorithm} signing key {signer.key_id} written to {args.path}. Back it up.")
        if isinstance(signer, Ed25519Signer):
            print(f"public key, safe to share with auditors: {signer.public_key_text}")
        else:
            print("this key is a shared secret: anyone who can verify with it can also forge. Prefer ed25519 for outside auditors.")
        return 0

    if args.cmd == "pubkey":
        signer = load_signer(args.path)
        if not isinstance(signer, Ed25519Signer):
            print("only Ed25519 keys have a public key; an HMAC key is a shared secret")
            return 2
        print(signer.public_key_text)
        return 0

    if args.cmd == "demo":
        comot = run_demo(db=args.db, key_file=args.key_file)
        if args.db:
            print(f"\ndatabase written to {args.db}")
        if args.export:
            with open(args.export, "w", encoding="utf-8") as f:
                json.dump(comot.export_bundle(actor=Actor("cli_demo", {"auditor"})), f, indent=2)
            print(f"\nbundle written to {args.export}")
            s = comot.signer
            how = f"--public-key {s.public_key_text}" if isinstance(s, Ed25519Signer) else f"--key-hex {s.key.hex()}"
            print(f"verify it with: comot verify {args.export} {how}")
        return 0

    if args.cmd in ("check", "export", "anchor", "rotate-key", "vault-rotate"):
        try:
            kwargs = {}
            if args.cmd == "vault-rotate":
                kwargs["vault"] = IdentityVault(args.vault, load_key_file(args.vault_key))
            comot = _open(args.db, args.key_file, args.retired_key, **kwargs)
        except StoreIntegrityError as e:
            print("NOT INTACT")
            for p in e.problems:
                print(f"  - {p}")
            return 1
        except (StoreError, FileNotFoundError) as e:
            print(f"cannot open: {e}")
            return 2
        try:
            return _after_open(args, comot)
        finally:
            comot.close()

    if args.cmd == "verify":
        verifier = None
        if args.key_file:
            verifier = load_verifier(args.key_file)
        elif args.key_hex:
            verifier = bytes.fromhex(args.key_hex)
        elif args.public_key:
            verifier = load_verifier(args.public_key)
        anchors = read_anchor_file(args.anchors) if args.anchors else None
        problems = verify_bundle(load_bundle(args.bundle), verifier, anchors)
        if problems:
            print("NOT INTACT")
            for p in problems:
                print(f"  - {p}")
            return 1
        print("intact: consent chain, audit log and every stored object verify"
              + (", external anchors agree" if anchors else "")
              + (", signature valid" if verifier else " (signature not checked)"))
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


def _after_open(args: argparse.Namespace, comot: Comot) -> int:
    if args.cmd == "check":
        problems = comot.verify_integrity(read_anchor_file(args.anchors) if args.anchors else [])
        if problems:
            print("NOT INTACT")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"intact: {len(comot.log.entries)} log entries, {len(comot.consents)} consent records, "
              f"{len(comot.graph.artifacts)} artifacts, {len(comot.anchors)} stored anchors"
              + (", external anchors agree" if args.anchors else ""))
    elif args.cmd == "export":
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(comot.export_bundle(), f, indent=2)
        print(f"bundle written to {args.out}")
    elif args.cmd == "anchor":
        a = comot.anchor(FileAnchorSink(args.out), actor="cli")
        print("nothing new to anchor" if a is None else f"anchored log head at entry {a.seq} to {a.sink}")
    elif args.cmd == "rotate-key":
        rotations = [e for e in comot.log.entries if e.event_type == "signing_key_rotated"]
        ids = comot.signer.key_ids
        print(f"signing key {ids[0]} is current; {len(rotations)} rotation(s) on record; keys still held: {', '.join(ids)}")
    elif args.cmd == "vault-rotate":
        comot.rotate_vault_key(load_key_file(args.new_vault_key), actor="cli")
        print("identity vault re-encrypted under the new key. Destroy old backups if they should stop being readable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
