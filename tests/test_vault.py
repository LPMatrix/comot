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


# ------------------------------------------------------------------ key rotation

NEW = b"n" * 32


def test_rotation_moves_every_record_to_the_new_key_and_the_old_key_opens_nothing(tmp_path):
    path = tmp_path / "v.db"
    v = IdentityVault(path, KEY)
    v.put("p_1", name="Amina Bello", phone="0801")
    v.put("p_2", name="Chidi Okeke")
    assert v.rotate(NEW) == 2
    assert v.get("p_1") == {"name": "Amina Bello", "phone": "0801"} and v.get("p_2") == {"name": "Chidi Okeke"}
    v.close()
    with pytest.raises(VaultError, match="wrong key"):
        IdentityVault(path, KEY)
    again = IdentityVault(path, NEW)
    assert again.get("p_1")["name"] == "Amina Bello" and again.ids() == ["p_1", "p_2"]
    again.close()


def test_rotation_leaves_no_readable_trace_and_changes_every_ciphertext(tmp_path):
    path = tmp_path / "v.db"
    v = IdentityVault(path, KEY)
    v.put("p_1", name="Amina Bello")
    before = sqlite3.connect(path).execute("SELECT nonce, ciphertext FROM identities WHERE participant_id='p_1'").fetchone()
    v.rotate(NEW)
    after = sqlite3.connect(path).execute("SELECT nonce, ciphertext FROM identities WHERE participant_id='p_1'").fetchone()
    assert before != after and b"Amina" not in raw_bytes(path)
    v.close()


def test_a_record_that_cannot_be_read_stops_the_whole_rotation(tmp_path):
    path = tmp_path / "v.db"
    v = IdentityVault(path, KEY)
    v.put("p_1", name="Amina")
    v.put("p_2", name="Chidi")
    db = sqlite3.connect(path)
    db.execute("UPDATE identities SET ciphertext = randomblob(length(ciphertext)) WHERE participant_id = 'p_2'")
    db.commit()
    db.close()
    with pytest.raises(VaultError):
        v.rotate(NEW)
    assert v.get("p_1") == {"name": "Amina"}  # still under the old key: nothing changed
    v.close()
    IdentityVault(path, KEY).close()  # and the old key still opens it


def test_rotating_to_a_key_of_the_wrong_size_is_refused(vault):
    vault.put("p_1", name="Amina")
    with pytest.raises(VaultError):
        vault.rotate(b"short")
    assert vault.get("p_1") == {"name": "Amina"}


def test_an_empty_vault_rotates_and_the_new_key_is_the_one_that_works(tmp_path):
    path = tmp_path / "v.db"
    v = IdentityVault(path, KEY)
    assert v.rotate(NEW) == 0
    v.close()
    IdentityVault(path, NEW).close()
    with pytest.raises(VaultError):
        IdentityVault(path, KEY)


def test_comot_logs_the_rotation_without_any_key_material(vault, comot):
    comot.vault = vault
    pid, _ = make_person(comot)
    comot.store_identity(pid, actor="chw1", name="Amina")
    comot.rotate_vault_key(NEW, actor="dpo_1")
    entry = [e for e in comot.log.entries if e.event_type == "vault_key_rotated"]
    assert [(e.actor_id, e.object_id) for e in entry] == [("dpo_1", "vault")]
    assert NEW.hex() not in str(comot.log.entries) and comot.read_identity(pid, actor="dpo_1") == {"name": "Amina"}


def test_a_comot_without_a_vault_cannot_rotate_one(comot):
    with pytest.raises(ComotError, match="no identity vault"):
        comot.rotate_vault_key(NEW, actor="dpo_1")


def test_a_failure_part_way_through_leaves_every_record_under_the_old_key(tmp_path, monkeypatch):
    import comot.vault as vault_module

    path = tmp_path / "v.db"
    v = IdentityVault(path, KEY)
    for i in range(4):
        v.put(f"p_{i}", name=f"person {i}")
    real = vault_module.AESGCM

    class FailsOnTheThird:
        def __init__(self, key):
            self._real, self._n = real(key), 0

        def encrypt(self, *a):
            self._n += 1
            if self._n == 3:
                raise OSError("disk went away")
            return self._real.encrypt(*a)

    monkeypatch.setattr(vault_module, "AESGCM", FailsOnTheThird)
    with pytest.raises(OSError):
        v.rotate(NEW)
    monkeypatch.undo()
    assert [v.get(f"p_{i}")["name"] for i in range(4)] == [f"person {i}" for i in range(4)]
    v.close()
    reopened = IdentityVault(path, KEY)  # still the old key, nothing half-done
    assert reopened.ids() == ["p_0", "p_1", "p_2", "p_3"]
    reopened.close()
