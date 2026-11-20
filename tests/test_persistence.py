import sqlite3

import pytest

from comot import Comot, ConsentRefused, HmacSigner, StoreError, StoreIntegrityError, TrainingBlocked
from conftest import PROJECT, make_chain, make_person


def busy(c):
    pid, code = make_person(c)
    rec, tr, ds, model = make_chain(c, pid)
    other, _ = make_person(c, {"record": True, "research": True})
    orec = c.register_recording(other, PROJECT, content=b"o", actor="chw1")
    with pytest.raises(ConsentRefused):
        c.register("dataset_version", [orec.artifact_id], "model_training", actor="pipeline")  # logged refusal
    w = c.withdraw(PROJECT, code=code, scope=["model_training"], channel="chw", actor="chw1")
    c.complete_action(c.actions_for(w.withdrawal_id)[0].action_id, actor="dt", evidence="e")
    return pid, code, w


def test_everything_survives_a_reopen(open_db):
    c = open_db()
    pid, code, w = busy(c)
    before = c.export_bundle()  # consents, log, artifacts, edges, withdrawals, actions, receipts, refusals
    c.close()

    c2 = open_db()
    assert c2.export_bundle() == before
    assert c2.participant_for_code(code) == pid
    assert c2.coverage(w.withdrawal_id) == 1.0
    assert c2.verify_receipt(c2.receipts[w.receipt_id])
    assert c2.verify_integrity() == []


def test_decisions_are_the_same_after_a_reopen(open_db):
    c = open_db()
    pid, code, w = busy(c)
    ids = list(c.graph.artifacts)
    expected = {(a, p): c.check_use(a, p).allowed for a in ids for p in ("research", "model_training")}
    c.close()
    c2 = open_db()
    assert {(a, p): c2.check_use(a, p).allowed for a in ids for p in ("research", "model_training")} == expected
    assert any(not v for v in expected.values()) and any(expected.values())


def test_work_continues_after_a_reopen(open_db):
    c = open_db()
    pid, code = make_person(c)
    rec, tr, ds, model = make_chain(c, pid)
    c.close()
    c2 = open_db()
    w = c2.withdraw(PROJECT, code=code, channel="participant_code", actor="chw1")
    assert c2.coverage(w.withdrawal_id) == 1.0
    assert c2.verify_integrity() == []
    assert c2.graph.artifacts[model.artifact_id].status == "tainted"


def test_a_failed_withdrawal_leaves_nothing_behind(open_db, monkeypatch):
    c = open_db()
    pid, code = make_person(c)
    make_chain(c, pid)
    before = c.export_bundle()

    import comot.core

    real, calls = comot.core.plan_actions, []

    def flaky(artifact, policy):
        calls.append(artifact)
        if len(calls) == 2:
            raise ValueError("boom halfway through")
        return real(artifact, policy)

    monkeypatch.setattr(comot.core, "plan_actions", flaky)
    with pytest.raises(ValueError, match="boom"):
        c.withdraw(PROJECT, code=code, channel="chw", actor="chw1")

    # Memory and database both look as if it never happened. Check memory first,
    # before any call that would reload by itself.
    assert c.latest_consent(pid, PROJECT).choices["research"] is True
    assert not c.withdrawals and not c.actions and len(c.consents) == 1
    assert c.export_bundle() == before
    c.close()
    assert open_db().export_bundle() == before

    monkeypatch.setattr(comot.core, "plan_actions", real)
    assert open_db().withdraw(PROJECT, code=code, channel="chw", actor="chw1")


def test_unexpected_store_error_resyncs_memory(open_db, monkeypatch):
    c = open_db()
    pid, code = make_person(c)
    make_chain(c, pid)
    before = c.export_bundle()
    monkeypatch.setattr(c.store, "add_receipt", lambda r: (_ for _ in ()).throw(sqlite3.OperationalError("disk full")))
    with pytest.raises(sqlite3.OperationalError):
        c.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    assert c.export_bundle() == before


def test_refusals_and_blocked_training_checks_are_kept(open_db):
    c = open_db()
    pid, _ = make_person(c, {"record": True, "research": True})
    rec = c.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    with pytest.raises(ConsentRefused):
        c.register("dataset_version", [rec.artifact_id], "model_training", actor="pipeline")
    with pytest.raises(TrainingBlocked):
        c.check_training_run([rec.artifact_id], actor="pipeline")
    c.close()
    c2 = open_db()
    assert len(c2.refusals) == 1
    kinds = [e.event_type for e in c2.log.entries]
    assert "registration_refused" in kinds and "training_check" in kinds


def test_a_rejected_call_writes_nothing(open_db):
    c = open_db()
    pid, code = make_person(c)
    n = len(c.log.entries)
    with pytest.raises(ValueError):
        c.withdraw(PROJECT, code=code, scope=["nonsense"], channel="chw", actor="chw1")
    with pytest.raises(ValueError):
        c.complete_action("act_missing", actor="x", evidence=" ")
    assert len(c.log.entries) == n and c.store.log_length() == n


def test_a_store_remembers_its_signing_key(open_db, dbpath, clock):
    c = open_db()
    make_person(c)
    c.close()
    with pytest.raises(StoreError, match="different signing key"):
        Comot.open(dbpath, signer=HmacSigner(b"x" * 32), clock=clock)


def test_a_newer_schema_is_refused(dbpath, signer, clock):
    Comot.open(dbpath, signer=signer, clock=clock).close()
    db = sqlite3.connect(dbpath)
    db.execute("PRAGMA user_version = 99")
    db.commit()
    db.close()
    with pytest.raises(StoreError, match="schema version"):
        Comot.open(dbpath, signer=signer, clock=clock)


def test_the_database_file_is_private(open_db, dbpath):
    open_db()
    assert oct(dbpath.stat().st_mode & 0o777) == "0o600"


# ------------------------------------------------------ the database protects itself

@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE consents SET choices = '{}'",
        "DELETE FROM consents",
        "UPDATE log_entries SET actor_id = 'x'",
        "DELETE FROM log_entries",
        "UPDATE edges SET purpose = 'research'",
        "DELETE FROM receipts",
        "UPDATE refusals SET body = '{}'",
        "DELETE FROM participants",
    ],
)
def test_append_only_tables_refuse_edits_and_deletes(open_db, dbpath, sql):
    c = open_db()
    busy(c)
    c.close()
    db = sqlite3.connect(dbpath)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute(sql)
    db.close()


def _raw_edit(dbpath, *statements):
    db = sqlite3.connect(dbpath)
    for t in ("consents", "log_entries"):  # an attacker with file access drops the triggers first
        for verb in ("update", "delete"):
            db.execute(f"DROP TRIGGER IF EXISTS {t}_no_{verb}")
    for s in statements:
        db.execute(s)
    db.commit()
    db.close()


def test_a_database_edited_behind_comots_back_is_refused(open_db, dbpath, signer, clock):
    c = open_db()
    busy(c)
    c.close()
    _raw_edit(dbpath, "UPDATE consents SET choices = replace(choices, '\"external_share\": true', '\"external_share\": false') WHERE seq = 1")
    with pytest.raises(StoreIntegrityError) as e:
        Comot.open(dbpath, signer=signer, clock=clock)
    assert any("contents do not match hash" in p for p in e.value.problems)
    # An auditor can still look at it deliberately.
    assert Comot.open(dbpath, signer=signer, clock=clock, verify=False).verify_integrity()


def test_a_deleted_log_entry_is_refused(open_db, dbpath, signer, clock):
    c = open_db()
    busy(c)
    c.close()
    _raw_edit(dbpath, "DELETE FROM log_entries WHERE seq = 3")
    with pytest.raises(StoreIntegrityError):
        Comot.open(dbpath, signer=signer, clock=clock)


# -------------------------------------------------------------- two processes

def test_a_second_process_sees_a_withdrawal_at_once(open_db):
    a, b = open_db(), open_db()
    pid, code = make_person(a)
    rec, tr, ds, model = make_chain(a, pid)
    assert b.check_use(tr.artifact_id, "model_training").allowed
    b.withdraw(PROJECT, code=code, channel="participant_code", actor="chw2")
    # `a` never reloaded by hand, but its next check must not use stale consent.
    assert not a.check_use(tr.artifact_id, "model_training").allowed
    with pytest.raises(TrainingBlocked):
        a.check_training_run([tr.artifact_id], actor="pipeline")


def test_interleaved_writers_keep_the_chains_intact(open_db):
    a, b = open_db(), open_db()
    for i in range(3):
        make_person(a)
        make_person(b)
    assert a.verify_integrity() == [] and b.verify_integrity() == []
    assert len(open_db().consents) == 6


def test_demo_can_run_into_a_database(tmp_path):
    from comot.demo import run_demo

    db, key = tmp_path / "demo.db", tmp_path / "demo.key"
    c = run_demo(lambda _: None, db=db, key_file=key)
    c.close()
    c2 = Comot.open(db, signer=HmacSigner.from_file(key))
    assert c2.verify_integrity() == [] and c2.withdrawals
    with pytest.raises(FileExistsError):
        run_demo(lambda _: None, db=db, key_file=key)


def test_a_writer_holds_the_lock_from_the_start(open_db):
    # Reading first and locking later would let two writers both act on stale state.
    a, b = open_db(), open_db()
    b.store._db.execute("PRAGMA busy_timeout = 50")
    with a._txn():
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            b.create_participant(actor="chw")
