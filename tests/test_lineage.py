import pytest

from comot import ConsentRefused, TrainingBlocked
from conftest import PROJECT, make_chain, make_person


def test_register_walks_back_to_consent(comot):
    pid, _ = make_person(comot)
    rec, tr, ds, model = make_chain(comot, pid)
    assert comot.graph.source_recordings(model.artifact_id) == [rec.artifact_id]
    assert comot.graph.ancestors(model.artifact_id) == [ds.artifact_id, tr.artifact_id, rec.artifact_id]
    assert comot.check_use(model.artifact_id, "model_training").allowed


def test_recording_needs_consent_to_record(comot):
    pid, _ = make_person(comot, {})
    with pytest.raises(ConsentRefused):
        comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    assert comot.log.of_type("registration_refused")


def test_refusal_is_logged_and_nothing_is_registered(comot):
    pid, _ = make_person(comot, {"record": True, "research": True})
    rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    before = len(comot.graph.artifacts)
    with pytest.raises(ConsentRefused) as e:
        comot.register("dataset_version", [rec.artifact_id], "model_training", actor="pipeline")
    assert e.value.blockers == [(rec.artifact_id, "consent does not allow model_training")]
    assert len(comot.graph.artifacts) == before
    assert len(comot.refusals) == 1 and len(comot.log.of_type("registration_refused")) == 1


def test_a_model_always_needs_training_consent(comot):
    pid, _ = make_person(comot, {"record": True, "research": True})
    rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", actor="pipeline")
    with pytest.raises(ConsentRefused):
        comot.register("model_version", [tr.artifact_id], "research", actor="pipeline")  # purpose cannot hide training


def test_outside_holder_needs_sharing_consent(comot):
    pid, _ = make_person(comot, {"record": True, "research": True, "model_training": True})
    rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", actor="pipeline")
    with pytest.raises(ConsentRefused):
        comot.register("transcript", [tr.artifact_id], "research", holder="lic_1", actor="pipeline")


def test_strictest_consent_wins_in_a_mixed_dataset(comot):
    yes, _ = make_person(comot)
    no, _ = make_person(comot, {"record": True, "research": True})
    trs = []
    for pid in (yes, no):
        rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
        trs.append(comot.register("transcript", [rec.artifact_id], "research", actor="pipeline"))
    mixed = comot.register("dataset_version", [t.artifact_id for t in trs], "research", actor="pipeline")
    assert not comot.check_use(mixed.artifact_id, "model_training").allowed
    allowed = comot.filter_allowed([t.artifact_id for t in trs], "model_training")
    assert allowed == [trs[0].artifact_id]


def test_training_gate_raises_loudly_or_reports(comot):
    yes, _ = make_person(comot)
    no, _ = make_person(comot, {"record": True})
    ids = []
    for pid in (yes, no):
        rec = comot.register_recording(pid, PROJECT, content=b"x", actor="chw1")
        ids.append(rec.artifact_id)
    with pytest.raises(TrainingBlocked):
        comot.check_training_run(ids, actor="pipeline")
    result = comot.check_training_run(ids, strict=False, actor="pipeline")
    assert not result.ok and result.allowed == [ids[0]]
    assert len(comot.log.of_type("training_check")) == 2


def test_find_by_hash_matches_a_copy_found_later(comot):
    pid, _ = make_person(comot)
    rec = comot.register_recording(pid, PROJECT, content=b"same bytes", actor="chw1")
    from comot.hashing import sha256_hex
    assert comot.find_by_hash(sha256_hex(b"same bytes")) == [rec]


def test_parents_must_exist(comot):
    from comot import UnknownObject
    with pytest.raises(UnknownObject):
        comot.register("transcript", ["a_nope"], "research", actor="pipeline")
