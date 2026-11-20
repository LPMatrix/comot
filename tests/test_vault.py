import sqlite3
import stat

import pytest

pytest.importorskip("cryptography")

from comot import Comot, ComotError, IdentityVault, UnknownObject, VaultError, generate_key_file, load_key_file
from conftest import PROJECT, make_chain, make_person

KEY = b"v" * 32


@pytest.fixture
def vault(tmp_path):
    v = IdentityVault(tmp_path / "vault.db", KEY)
    yield v
    v.close()


def raw_bytes(path):
    out = b""
    for suffix in ("", "-wal"):
        try:
            out += (path.parent / (path.name + suffix)).read_bytes()
        except FileNotFoundError:
            pass
    return out


def test_round_trip_and_nothing_readable_on_disk(vault, tmp_path):
    vault.put("p_1", name="Amina Bello", phone="+2348012345678", guardian_name="Hauwa Bello")
    assert vault.get("p_1") == {"name": "Amina Bello", "phone": "+2348012345678", "guardian_name": "Hauwa Bello"}
    data = raw_bytes(tmp_path / "vault.db")
    assert b"Amina" not in data and b"2348012345678" not in data and b"Hauwa" not in data


def test_wrong_key_cannot_open(tmp_path):
    IdentityVault(tmp_path / "v.db", KEY).close()
    with pytest.raises(VaultError, match="wrong key"):
        IdentityVault(tmp_path / "v.db", b"w" * 32)


def test_unknown_fields_are_refused(vault):
    with pytest.raises(VaultError, match="unknown identity fields"):
        vault.put("p_1", diagnosis="x")  # the vault must never become a place for health data


def test_delete_is_separate_and_final(vault):
    vault.put("p_1", name="A")
    vault.put("p_2", name="B")
    assert vault.delete("p_1") is True and vault.delete("p_1") is False
    assert vault.get("p_1") is None and vault.get("p_2") == {"name": "B"}
    assert vault.ids() == ["p_2"]


def test_a_ciphertext_moved_to_another_participant_does_not_open(vault, tmp_path):
    vault.put("p_1", name="A")
    vault.put("p_2", name="B")
    db = sqlite3.connect(tmp_path / "vault.db")
    n, c = db.execute("SELECT nonce, ciphertext FROM identities WHERE participant_id='p_1'").fetchone()
    db.execute("UPDATE identities SET nonce=?, ciphertext=? WHERE participant_id='p_2'", (n, c))
    db.commit()
    db.close()
    with pytest.raises(VaultError, match="cannot decrypt"):
        vault.get("p_2")


def test_key_files_are_private_and_never_overwritten(tmp_path):
    f = tmp_path / "k"
    key = generate_key_file(f)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert load_key_file(f) == key
    with pytest.raises(FileExistsError):
        generate_key_file(f)


# ------------------------------------------------------------ with Comot

def test_identity_never_enters_the_consent_database(open_db, dbpath, vault):
    c = open_db(vault=vault)
    pid, code = make_person(c)
    c.store_identity(pid, actor="chw1", name="Amina Bello", phone="+2348012345678")
    make_chain(c, pid)
    c.close()
    data = raw_bytes(dbpath)
    assert b"Amina" not in data and b"2348012345678" not in data


def test_the_log_records_that_identity_was_touched_not_what_it_was(open_db, vault):
    c = open_db(vault=vault)
    pid, _ = make_person(c)
    c.store_identity(pid, actor="chw1", name="Amina Bello")
    assert c.read_identity(pid, actor="dpo_1") == {"name": "Amina Bello"}
    kinds = [(e.event_type, e.actor_id, e.object_id) for e in c.log.entries if e.event_type.startswith("identity")]
    assert kinds == [("identity_stored", "chw1", pid), ("identity_read", "dpo_1", pid)]
    assert "Amina" not in str([e.to_dict() for e in c.log.entries])


def test_deleting_identity_leaves_consent_and_audit_intact(open_db, vault):
    c = open_db(vault=vault)
    pid, code = make_person(c)
    c.store_identity(pid, actor="chw1", name="Amina Bello", phone="+234")
    make_chain(c, pid)
    assert c.delete_identity(pid, actor="dpo_1") is True
    assert vault.get(pid) is None
    assert c.verify_integrity() == []
    w = c.withdraw(PROJECT, code=code, channel="participant_code", actor="chw1")  # still works
    assert c.coverage(w.withdrawal_id) == 1.0


def test_identity_calls_need_a_vault_and_a_known_participant(comot, vault):
    pid, _ = make_person(comot)
    with pytest.raises(ComotError, match="no identity vault"):
        comot.store_identity(pid, actor="chw1", name="x")
    comot.vault = vault
    with pytest.raises(UnknownObject):
        comot.store_identity("p_missing", actor="chw1", name="x")


def test_a_bundle_export_holds_no_identity(open_db, vault):
    c = open_db(vault=vault)
    pid, code = make_person(c)
    c.store_identity(pid, actor="chw1", name="Amina Bello", phone="+2348012345678")
    text = str(c.export_bundle())
    assert "Amina" not in text and "2348012345678" not in text
