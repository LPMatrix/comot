import pytest

from comot import ConsentRefused, TrainingBlocked, WithdrawalPolicy, render_receipt
from conftest import PROJECT, make_chain, make_person


def kinds(comot, w):
    return sorted((comot.graph.artifacts[a.artifact_id].type, a.kind) for a in comot.actions_for(w.withdrawal_id))


def test_full_withdrawal_reaches_every_copy(comot):
    pid, code = make_person(comot)
    rec, tr, ds, model = make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, channel="participant_code", actor="chw1")
    assert kinds(comot, w) == [
        ("dataset_version", "exclude"),
        ("model_version", "retire"),
        ("recording", "delete"),
        ("transcript", "delete"),
    ]
    assert comot.coverage(w.withdrawal_id) == 1.0
    assert comot.graph.artifacts[model.artifact_id].status == "tainted"


def test_deadlines_follow_the_policy(comot, clock):
    comot.policy = WithdrawalPolicy(delete_days=3, model_days=90)
    pid, code = make_person(comot)
    make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    by = {(comot.graph.artifacts[a.artifact_id].type): a.due_at for a in comot.actions_for(w.withdrawal_id)}
    assert by["recording"].startswith("2027-06-04")
    assert by["model_version"].startswith("2027-08-30")


def test_partial_withdrawal_keeps_other_uses(comot):
    pid, code = make_person(comot)
    rec, tr, ds, model = make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, scope=["model_training"], channel="participant_code", actor="chw1")
    # The transcript was made for research, so it stays. The dataset and model were made for training.
    assert kinds(comot, w) == [("dataset_version", "exclude"), ("model_version", "retire")]
    assert comot.check_use(tr.artifact_id, "research").allowed
    assert not comot.check_use(tr.artifact_id, "model_training").allowed
    assert comot.latest_consent(pid, PROJECT).choices["research"] is True


def test_withdrawing_record_withdraws_everything(comot):
    pid, code = make_person(comot)
    make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, scope=["record"], channel="status_line", actor="line")
    assert w.scope == ["all"]
    assert not any(comot.latest_consent(pid, PROJECT).choices.values())


def test_new_work_is_blocked_after_withdrawal_even_before_deletion(comot):
    pid, code = make_person(comot)
    rec, tr, ds, model = make_chain(comot, pid)
    comot.withdraw(PROJECT, code=code, channel="participant_code", actor="chw1")
    with pytest.raises(TrainingBlocked):
        comot.check_training_run([tr.artifact_id], actor="pipeline")
    with pytest.raises(ConsentRefused):
        comot.register("clip", [rec.artifact_id], "research", actor="pipeline")


def test_outside_holder_gets_a_notice_not_a_delete(comot):
    pid, code = make_person(comot)
    rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", actor="pipeline")
    comot.register("transcript", [tr.artifact_id], "external_share", holder="lic_9", actor="pipeline")
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    assert ("transcript", "notify") in kinds(comot, w)
    notice = next(a for a in comot.actions_for(w.withdrawal_id) if a.kind == "notify")
    assert notice.due_at.startswith("2027-06-15")  # 14 days


def test_sharded_model_is_retrained_not_retired(comot):
    pid, code = make_person(comot)
    rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", actor="pipeline")
    comot.register("model_version", [tr.artifact_id], "model_training", sharded=True, actor="pipeline")
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    assert ("model_version", "retrain") in kinds(comot, w)


def test_complete_action_needs_evidence_and_updates_status(comot):
    pid, code = make_person(comot)
    rec, *_ = make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    act = next(a for a in comot.actions_for(w.withdrawal_id) if a.artifact_id == rec.artifact_id)
    with pytest.raises(ValueError):
        comot.complete_action(act.action_id, actor="dt", evidence="  ")
    comot.complete_action(act.action_id, actor="dt", evidence="ticket-1")
    assert comot.graph.artifacts[rec.artifact_id].status == "deleted"
    with pytest.raises(ValueError):
        comot.complete_action(act.action_id, actor="dt", evidence="again")


def test_overdue_actions_escalate_once(comot, clock):
    pid, code = make_person(comot)
    make_chain(comot, pid)
    comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    assert comot.overdue_actions() == []
    clock.advance(days=8)
    first = comot.escalate_overdue(actor="system")
    assert first and {a.kind for a in first} <= {"delete", "exclude"}  # the model has months
    assert comot.escalate_overdue(actor="system") == []
    assert len(comot.log.of_type("action_overdue")) == len(first)


def test_second_withdrawal_skips_copies_already_gone(comot):
    pid, code = make_person(comot)
    rec, tr, *_ = make_chain(comot, pid)
    w1 = comot.withdraw(PROJECT, code=code, scope=["model_training"], channel="chw", actor="chw1")
    for a in comot.actions_for(w1.withdrawal_id):
        comot.complete_action(a.action_id, actor="dt", evidence="e")
    w2 = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    assert kinds(comot, w2) == [("recording", "delete"), ("transcript", "delete")]
    assert comot.coverage(w2.withdrawal_id) == 1.0
    assert len(w2.already_gone) == 2


def test_receipt_is_signed_honest_and_neutral(comot):
    pid, code = make_person(comot)
    make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    receipt = comot.receipts[w.receipt_id]
    assert comot.verify_receipt(receipt)
    text = render_receipt(receipt)
    assert "cannot take your recording out of a model that was already trained" in text
    assert "cannot be changed" in text
    assert not any(w in text.lower() for w in ("mental", "health", "study", "depress", "project"))
    receipt.items[0]["status"] = "done"  # tampering breaks the signature
    assert not comot.verify_receipt(receipt)


def test_receipt_updates_as_work_is_done(comot):
    pid, code = make_person(comot)
    rec, *_ = make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, channel="chw", actor="chw1")
    act = next(a for a in comot.actions_for(w.withdrawal_id) if a.artifact_id == rec.artifact_id)
    comot.complete_action(act.action_id, actor="dt", evidence="e")
    later = comot.issue_receipt(w.withdrawal_id, actor="system")
    assert "A copy of your recording has been deleted." in render_receipt(later)
    assert w.receipt_id == later.receipt_id


def test_withdrawal_needs_exactly_one_identifier(comot):
    pid, code = make_person(comot)
    with pytest.raises(ValueError):
        comot.withdraw(PROJECT, channel="chw", actor="chw1")
    with pytest.raises(ValueError):
        comot.withdraw(PROJECT, participant_id=pid, code=code, channel="chw", actor="chw1")


def test_open_action_blocks_new_use_even_when_consent_still_allows_it(comot):
    # Withdraw research only. Training is still consented, but the transcript
    # was made for research and is awaiting deletion, so nothing may be built on it.
    pid, code = make_person(comot)
    rec, tr, ds, model = make_chain(comot, pid)
    comot.withdraw(PROJECT, code=code, scope=["research"], channel="chw", actor="chw1")
    assert comot.latest_consent(pid, PROJECT).choices["model_training"] is True
    decision = comot.check_use(tr.artifact_id, "model_training")
    assert not decision.allowed
    assert "open action" in decision.blockers[0][1]


def test_deleted_source_blocks_new_use(comot):
    pid, code = make_person(comot)
    rec, tr, *_ = make_chain(comot, pid)
    w = comot.withdraw(PROJECT, code=code, scope=["research"], channel="chw", actor="chw1")
    for a in comot.actions_for(w.withdrawal_id):
        if a.artifact_id == tr.artifact_id:
            comot.complete_action(a.action_id, actor="dt", evidence="e")
    decision = comot.check_use(tr.artifact_id, "model_training")
    assert [b[1] for b in decision.blockers] == ["copy is deleted"]
