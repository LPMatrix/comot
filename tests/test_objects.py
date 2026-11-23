"""Every stored object must be what the audit log recorded."""
import copy
import sqlite3

import pytest

from comot import Comot, ConsentRefused, StoreIntegrityError, verify_bundle
from conftest import ALL, PROJECT, make_chain, make_person


def busy(comot, clock):
    """A system that has done a bit of everything."""
    pa, code_a = make_person(comot)
    pb, _ = make_person(comot, {"record": True, "research": True})
    _, tr_a, ds_a, model_a = make_chain(comot, pa)
    rec_b = comot.register_recording(pb, PROJECT, content=b"b", storage_uri="s3://secret/b.wav", actor="chw1")
    tr_b = comot.register("transcript", [rec_b.artifact_id], "research", actor="asr")
    comot.register("transcript", [tr_a.artifact_id], "external_share", holder="lic_1",
                   destination_country="NG", transfer_basis="within_nigeria", actor="dt")
    with pytest.raises(ConsentRefused):
        comot.register("model_version", [tr_b.artifact_id], "model_training", actor="dt")  # logged refusal
    w = comot.withdraw(PROJECT, code=code_a, scope="all", channel="chw", actor="chw1")
    acts = comot.actions_for(w.withdrawal_id)
    comot.complete_action(acts[0].action_id, actor="dt", evidence="ticket-1")
    clock.advance(days=8)
    comot.escalate_overdue(actor="board")
    comot.issue_receipt(w.withdrawal_id, actor="chw1")  # a second receipt
    return w


@pytest.fixture
def system(comot, clock):
    busy(comot, clock)
    return comot


def tampered(comot, change):
    bundle = copy.deepcopy(comot.export_bundle())
    change(bundle)
    return verify_bundle(bundle)  # no key: only what needs none


def test_an_honest_system_verifies_everywhere(system):
    assert system.verify_integrity() == []
    assert verify_bundle(system.export_bundle(), system.signer.key) == []


def test_the_export_holds_no_storage_location_only_its_hash(system):
    text = str(system.export_bundle())
    assert "s3://secret" not in text and "storage_uri_hash" in text


CASES = {
    "content hash edited": (lambda b: b["artifacts"][0].update(content_hash="0" * 64), "does not match what the audit log recorded"),
    "holder edited": (lambda b: b["artifacts"][-1].update(holder="lic_evil"), "does not match what the audit log recorded"),
    "location hash edited": (lambda b: b["artifacts"][1].update(storage_uri_hash="0" * 64), "does not match what the audit log recorded"),
    "artifact removed": (lambda b: b["artifacts"].pop(2), "the audit log records it but it is missing"),
    "artifact invented": (lambda b: b["artifacts"].append({**b["artifacts"][0], "artifact_id": "a_forged"}), "not in the audit log"),
    "deleted copy shown active": (lambda b: [a.update(status="active") for a in b["artifacts"] if a["status"] == "deleted"], "status is 'active'"),
    "live copy shown deleted": (lambda b: b["artifacts"][-1].update(status="deleted"), "status is 'deleted'"),
    "model shown untainted": (lambda b: [a.update(status="active") for a in b["artifacts"] if a["status"] == "tainted"], "status is 'active'"),
    "edge removed": (lambda b: b["edges"].pop(0), "does not match what the audit log recorded"),
    "edge purpose edited": (lambda b: b["edges"][0].update(purpose="external_share"), "does not match what the audit log recorded"),
    "edge to nowhere": (lambda b: b["edges"].append({**b["edges"][0], "child_id": "a_nowhere"}), "unknown artifact"),
    "action marked done": (lambda b: b["actions"][-1].update(done_at="2030-01-01T00:00:00Z", done_by="me", evidence="trust me"), "does not match the last state"),
    "action deadline moved": (lambda b: b["actions"][0].update(due_at="2099-01-01T00:00:00Z"), "does not match the last state"),
    "action removed": (lambda b: b["actions"].pop(), "the audit log records it but it is missing"),
    "action invented": (lambda b: b["actions"].append({**b["actions"][0], "action_id": "act_forged"}), "not in the audit log"),
    "completion erased": (lambda b: b["actions"][0].update(done_at=None, done_by=None, evidence=None), "does not match the last state"),
    "receipt item edited": (lambda b: b["receipts"][0]["items"][0].update(status="done"), "does not match what the audit log recorded"),
    "receipt removed": (lambda b: b["receipts"].pop(), "the audit log records it but it is missing"),
    "receipt limits removed": (lambda b: b["receipts"][-1].update(limits=[]), "does not match what the audit log recorded"),
    "withdrawal scope edited": (lambda b: b["withdrawals"][0].update(scope=["research"]), "does not match what the audit log recorded"),
    "withdrawal points at the first receipt": (lambda b: b["withdrawals"][0].update(receipt_id=b["receipts"][0]["receipt_id"]), "points at the wrong receipt"),
    "withdrawal points at no receipt": (lambda b: b["withdrawals"][0].update(receipt_id=None), "points at the wrong receipt"),
    "withdrawal removed": (lambda b: b["withdrawals"].clear(), "the audit log records it but it is missing"),
    "refusal edited": (lambda b: b["refusals"][0].update(blockers=[]), "does not match what the audit log recorded"),
    "refusal removed": (lambda b: b["refusals"].clear(), "the audit log records it but it is missing"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_each_kind_of_tampering_with_a_bundle_is_named(system, name):
    change, expected = CASES[name]
    problems = tampered(system, change)
    assert any(expected in p for p in problems), (name, problems)


def test_the_cases_cover_something_real(system):
    b = system.export_bundle()
    assert any(a["status"] == "deleted" for a in b["artifacts"]) and any(a["status"] == "tainted" for a in b["artifacts"])
    assert len(b["receipts"]) == 2 and b["refusals"] and any(a["escalated"] for a in b["actions"])


# ------------------------------------------------- the same check on an open database


def edit(dbpath, sql, *params):
    db = sqlite3.connect(dbpath)
    db.execute(sql, params)
    db.commit()
    db.close()


@pytest.fixture
def stored(dbpath, signer, clock):
    c = Comot.open(dbpath, signer=signer, clock=clock)
    busy(c, clock)
    c.close()
    return dbpath


def reopen_problems(dbpath, signer, clock):
    with pytest.raises(StoreIntegrityError) as e:
        Comot.open(dbpath, signer=signer, clock=clock)
    return e.value.problems


def test_an_honest_database_opens(stored, signer, clock):
    assert Comot.open(stored, signer=signer, clock=clock).verify_integrity() == []


@pytest.mark.parametrize(
    "sql,expected",
    [
        ("UPDATE artifacts SET status = 'active' WHERE status = 'deleted'", "status is 'active'"),
        ("UPDATE artifacts SET holder = 'lic_evil' WHERE holder = 'lic_1'", "does not match what the audit log recorded"),
        ("UPDATE artifacts SET storage_uri = 's3://elsewhere/x.wav' WHERE storage_uri IS NOT NULL", "does not match what the audit log recorded"),
        ("UPDATE actions SET done_at = '2030-01-01T00:00:00Z', done_by = 'me', evidence = 'x' WHERE done_at IS NULL", "does not match the last state"),
        ("UPDATE actions SET due_at = '2099-01-01T00:00:00Z'", "does not match the last state"),
        ("UPDATE withdrawals SET scope = '[\"research\"]'", "does not match what the audit log recorded"),
        ("UPDATE withdrawals SET receipt_id = NULL", "points at the wrong receipt"),
    ],
)
def test_a_database_edited_behind_comots_back_is_refused_at_open(stored, signer, clock, sql, expected):
    edit(stored, sql)
    assert any(expected in p for p in reopen_problems(stored, signer, clock))
    audit = Comot.open(stored, signer=signer, clock=clock, verify=False)
    assert any(expected in p for p in audit.verify_integrity())


def test_a_row_inserted_without_a_log_entry_is_refused(stored, signer, clock):
    edit(
        stored,
        "INSERT INTO artifacts (artifact_id, type, content_hash, storage_uri, holder, sharded, created_by, created_at, status)"
        " VALUES ('a_smuggled', 'transcript', NULL, NULL, 'internal', 0, 'x', '2026-01-01T00:00:00Z', 'active')",
    )
    assert any("not in the audit log" in p for p in reopen_problems(stored, signer, clock))
