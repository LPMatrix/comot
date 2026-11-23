import json
import os
import stat

import pytest

pytest.importorskip("cryptography")

from comot import (
    Comot,
    Ed25519Signer,
    Ed25519Verifier,
    HmacSigner,
    KeyRing,
    SigningError,
    StoreError,
    generate_signer_file,
    load_signer,
    load_verifier,
    verify_bundle,
)
from comot.hashing import canonical
from conftest import PROJECT, make_chain, make_person

DATA = b"a receipt body"


# ----------------------------------------------------------------- the signers


def test_hmac_signs_and_verifies_and_names_its_key():
    s = HmacSigner(b"k" * 32)
    sig = s.sign(DATA)
    assert sig.startswith(f"hmac-sha256:{s.key_id}:")
    assert s.verify(DATA, sig)
    assert not s.verify(DATA + b"x", sig)
    assert not HmacSigner(b"j" * 32).verify(DATA, sig)


@pytest.mark.parametrize("bad", ["", "nonsense", "a:b", "ed25519:x:y", "hmac-sha256::abc", None, 7])
def test_malformed_signatures_are_simply_false(bad):
    assert HmacSigner(b"k" * 32).verify(DATA, bad) is False
    assert Ed25519Signer().verify(DATA, bad) is False


def test_an_hmac_key_that_is_too_short_is_refused():
    with pytest.raises(SigningError):
        HmacSigner(b"short")


def test_ed25519_lets_anyone_with_the_public_key_verify_and_nobody_forge():
    signer = Ed25519Signer()
    auditor = Ed25519Verifier.from_text(signer.public_key_text)
    sig = signer.sign(DATA)
    assert auditor.verify(DATA, sig)
    assert not auditor.verify(DATA + b"x", sig)
    assert not Ed25519Signer().verifier().verify(DATA, sig)  # someone else's public key
    assert auditor.key_id == signer.key_id
    assert not hasattr(auditor, "sign") and auditor.can_sign is False


def test_the_signature_names_a_key_so_a_swapped_key_is_not_tried():
    a, b = Ed25519Signer(), Ed25519Signer()
    sig = a.sign(DATA)
    forged = sig.replace(a.key_id, b.key_id)  # claims to be b, carries a's bytes
    assert not b.verify(DATA, forged)


def test_a_signature_whose_label_names_another_key_is_refused_even_if_the_bytes_are_good():
    h1, h2 = HmacSigner(b"a" * 32), HmacSigner(b"b" * 32)
    assert not h1.verify(DATA, h1.sign(DATA).replace(h1.key_id, h2.key_id))
    e1, e2 = Ed25519Signer(), Ed25519Signer()
    assert not e1.verify(DATA, e1.sign(DATA).replace(e1.key_id, e2.key_id))


def test_hmac_and_ed25519_do_not_verify_each_other():
    h, e = HmacSigner(b"k" * 32), Ed25519Signer()
    assert not h.verify(DATA, e.sign(DATA)) and not e.verify(DATA, h.sign(DATA))


@pytest.mark.parametrize("text", ["", "ed25519:", "ed25519:zz", "ed25519:" + "ab" * 31, "hmac:abcd", "plain"])
def test_bad_public_keys_are_refused(text):
    with pytest.raises(SigningError):
        Ed25519Verifier.from_text(text)


# ------------------------------------------------------------------ key files


@pytest.mark.parametrize("algorithm,cls", [("ed25519", Ed25519Signer), ("hmac", HmacSigner)])
def test_key_files_are_private_refuse_overwrite_and_round_trip(tmp_path, algorithm, cls):
    path = tmp_path / "k.key"
    made = generate_signer_file(path, algorithm)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    loaded = load_signer(path)
    assert isinstance(loaded, cls) and loaded.key_id == made.key_id
    assert loaded.verify(DATA, made.sign(DATA))
    with pytest.raises(FileExistsError):
        generate_signer_file(path, algorithm)


def test_an_unknown_algorithm_is_refused(tmp_path):
    with pytest.raises(SigningError):
        generate_signer_file(tmp_path / "k", "rot13")


def test_the_wrong_loader_gives_a_clear_error(tmp_path):
    path = tmp_path / "e.key"
    generate_signer_file(path, "ed25519")
    with pytest.raises(SigningError, match="load_signer"):
        HmacSigner.from_file(path)
    hpath = tmp_path / "h.key"
    generate_signer_file(hpath, "hmac")
    with pytest.raises(SigningError):
        Ed25519Signer.from_file(hpath)


def test_a_verifier_loads_from_public_text_a_private_file_or_an_hmac_file(tmp_path):
    e = generate_signer_file(tmp_path / "e.key", "ed25519")
    h = generate_signer_file(tmp_path / "h.key", "hmac")
    assert load_verifier(e.public_key_text).verify(DATA, e.sign(DATA))
    from_private = load_verifier(tmp_path / "e.key")
    assert from_private.verify(DATA, e.sign(DATA)) and not hasattr(from_private, "sign")
    (tmp_path / "pub.key").write_text(e.public_key_text + "\n")
    assert load_verifier(tmp_path / "pub.key").verify(DATA, e.sign(DATA))
    assert load_verifier(tmp_path / "h.key").verify(DATA, h.sign(DATA))
    with pytest.raises(SigningError):
        load_verifier(str(tmp_path / "missing"))


# ----------------------------------------------------------------- the key ring


def test_a_key_ring_signs_with_the_current_key_and_verifies_the_retired_ones():
    old, new = Ed25519Signer(), Ed25519Signer()
    ring = KeyRing(new, retired=[old.verifier()])
    assert ring.key_id == new.key_id and ring.key_ids == [new.key_id, old.key_id]
    assert ring.verify(DATA, old.sign(DATA)) and ring.verify(DATA, ring.sign(DATA))
    assert ring.sign(DATA) == new.sign(DATA) or ring.verify(DATA, ring.sign(DATA))
    assert not ring.verify(DATA, Ed25519Signer().sign(DATA))  # a key it has never held


def test_a_key_ring_needs_a_current_key_that_can_sign():
    with pytest.raises(SigningError):
        KeyRing(Ed25519Signer().verifier())


def test_a_ring_can_mix_algorithms():
    ring = KeyRing(Ed25519Signer(), retired=[HmacSigner(b"o" * 32)])
    assert ring.verify(DATA, HmacSigner(b"o" * 32).sign(DATA))


# ------------------------------------------------- receipts and bundles in use


@pytest.fixture
def ed(clock, tmp_path):
    return Comot(clock=clock, signer=Ed25519Signer())


def withdrawn(c):
    pid, code = make_person(c)
    make_chain(c, pid)
    return c.withdraw(PROJECT, code=code, scope="all", channel="chw", actor="chw1")


def test_an_auditor_with_only_the_public_key_can_check_a_receipt(ed):
    w = withdrawn(ed)
    receipt = ed.receipts[w.receipt_id]
    auditor = Ed25519Verifier.from_text(ed.signer.public_key_text)
    assert auditor.verify(canonical(receipt.body()), receipt.signature)
    receipt.items[0]["status"] = "done"
    assert not auditor.verify(canonical(receipt.body()), receipt.signature)


def test_an_auditor_checks_a_whole_bundle_with_only_the_public_key(ed):
    withdrawn(ed)
    bundle = ed.export_bundle()
    pub = ed.signer.public_key_text
    assert verify_bundle(bundle, pub) == []
    assert verify_bundle(bundle, Ed25519Signer().public_key_text) != []
    assert verify_bundle(bundle, ed.signer.verifier()) == []


def test_a_bundle_checked_with_the_wrong_kind_of_key_says_so(ed):
    withdrawn(ed)
    problems = verify_bundle(ed.export_bundle(), b"k" * 32)
    assert any("does not hold" in p for p in problems)
    assert any("cannot use" in p for p in verify_bundle(ed.export_bundle(), "ed25519:zz"))


def test_a_tampered_receipt_inside_a_bundle_is_named(ed):
    w = withdrawn(ed)
    bundle = ed.export_bundle()
    bundle["receipts"][0]["items"][0]["status"] = "done"
    problems = verify_bundle(bundle, ed.signer.public_key_text)
    assert any(f"receipt {w.receipt_id}" in p for p in problems)


def test_hmac_bundles_still_verify_with_the_shared_key(comot):
    withdrawn(comot)
    assert verify_bundle(comot.export_bundle(), comot.signer.key) == []


def test_old_format_bundles_are_refused_not_misread(comot):
    bundle = comot.export_bundle()
    bundle["format"] = "comot-bundle/0"
    assert "unsupported bundle format" in verify_bundle(bundle)[0]


# --------------------------------------------------------------------- rotation


def rotation_events(c):
    return [e for e in c.log.entries if e.event_type == "signing_key_rotated"]


def test_rotating_keeps_old_receipts_verifiable_and_logs_the_change_once(open_db, dbpath, signer, clock):
    a = Ed25519Signer()
    first = Comot.open(dbpath, signer=a, clock=clock)
    w = withdrawn(first)
    old_receipt = first.receipts[w.receipt_id]
    first.close()

    b = Ed25519Signer()
    second = Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock)
    assert [e.object_id for e in rotation_events(second)] == [b.key_id]
    assert second.verify_receipt(old_receipt)  # signed by the retired key
    pid, code = make_person(second)
    make_chain(second, pid)
    w2 = second.withdraw(PROJECT, code=code, scope="all", channel="chw", actor="chw1")
    assert second.receipts[w2.receipt_id].signature.split(":")[1] == b.key_id
    second.close()

    third = Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock)
    assert len(rotation_events(third)) == 1  # opening again is not a new rotation
    assert third.verify_receipt(old_receipt) and third.verify_integrity() == []
    third.close()


def test_a_bundle_after_rotation_needs_the_ring_to_check_older_receipts(dbpath, clock):
    a, b = Ed25519Signer(), Ed25519Signer()
    first = Comot.open(dbpath, signer=a, clock=clock)
    withdrawn(first)
    first.close()
    c = Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock)
    bundle = c.export_bundle()
    assert verify_bundle(bundle, KeyRing(b, [a.verifier()])) == []
    problems = verify_bundle(bundle, b.verifier())  # only the new key
    assert any("receipt" in p for p in problems)
    c.close()


def test_a_store_will_not_open_with_an_unrelated_key(dbpath, clock):
    Comot.open(dbpath, signer=Ed25519Signer(), clock=clock).close()
    with pytest.raises(StoreError, match="different signing key"):
        Comot.open(dbpath, signer=Ed25519Signer(), clock=clock)
    with pytest.raises(StoreError, match="different signing key"):
        Comot.open(dbpath, signer=KeyRing(Ed25519Signer(), [Ed25519Signer().verifier()]), clock=clock)


def test_after_rotating_the_ring_must_keep_every_earlier_key(dbpath, clock):
    a, b, c = Ed25519Signer(), Ed25519Signer(), Ed25519Signer()
    Comot.open(dbpath, signer=a, clock=clock).close()
    Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock).close()
    with pytest.raises(StoreError, match="lacks earlier signing keys"):
        Comot.open(dbpath, signer=KeyRing(c, [b.verifier()]), clock=clock)  # forgot a
    Comot.open(dbpath, signer=KeyRing(c, [b.verifier(), a.verifier()]), clock=clock).close()
    with pytest.raises(StoreError, match="lacks earlier signing keys"):
        Comot.open(dbpath, signer=c, clock=clock)  # the new key alone
    assert Comot.open(dbpath, signer=c, clock=clock, verify=False)  # an auditor may still look


def test_a_retired_key_cannot_be_made_current_again(dbpath, clock):
    a, b = Ed25519Signer(), Ed25519Signer()
    Comot.open(dbpath, signer=a, clock=clock).close()
    Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock).close()
    with pytest.raises(StoreError, match="retired"):
        Comot.open(dbpath, signer=KeyRing(a, [b.verifier()]), clock=clock)


def test_switching_from_hmac_to_ed25519_is_a_rotation_too(dbpath, clock):
    h, e = HmacSigner(b"h" * 32), Ed25519Signer()
    first = Comot.open(dbpath, signer=h, clock=clock)
    w = withdrawn(first)
    old = first.receipts[w.receipt_id]
    first.close()
    second = Comot.open(dbpath, signer=KeyRing(e, [h]), clock=clock)
    assert second.verify_receipt(old) and rotation_events(second)[0].payload_hash
    second.close()


def test_every_key_in_a_chain_of_rotations_must_be_kept(dbpath, clock):
    a, b, c, d = (Ed25519Signer() for _ in range(4))
    Comot.open(dbpath, signer=a, clock=clock).close()
    Comot.open(dbpath, signer=KeyRing(b, [a.verifier()]), clock=clock).close()
    Comot.open(dbpath, signer=KeyRing(c, [b.verifier(), a.verifier()]), clock=clock).close()
    with pytest.raises(StoreError, match="lacks earlier signing keys"):
        Comot.open(dbpath, signer=KeyRing(d, [c.verifier(), a.verifier()]), clock=clock)  # forgot b, in the middle
    Comot.open(dbpath, signer=KeyRing(d, [c.verifier(), b.verifier(), a.verifier()]), clock=clock).close()
