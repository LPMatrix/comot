import pytest

from comot import ConsentRefused, UnknownObject
from conftest import PROJECT, make_person

datasets = pytest.importorskip("datasets")
from comot.huggingface import filter_allowed, register_split


def recordings(comot):
    ids = []
    for answers in (None, {"record": True, "research": True}):
        pid, code = make_person(comot, answers)
        rec = comot.register_recording(pid, PROJECT, content=b"fictional", actor="chw")
        ids.append((rec.artifact_id, code))
    return ids


def test_register_and_filter_a_formatted_split(comot):
    (yes, code), (no, _) = recordings(comot)
    ds = datasets.Dataset.from_dict({"source": [yes, no, yes], "feature": [2, 3, 5]})
    # No format/transform belonging to the caller should run during registration.
    ds = ds.with_transform(lambda batch: pytest.fail("unexpected payload read"))
    full = register_split(comot, ds, "research", actor="dt", id_column="source")
    assert full.dataset is ds
    assert set(comot.graph.source_recordings(full.artifact.artifact_id)) == {yes, no}
    subset = filter_allowed(comot, ds, "model_training", actor="dt", id_column="source")
    assert subset.dataset.with_format(None).to_dict() == {"source": [yes, yes], "feature": [2, 5]}
    assert comot.graph.source_recordings(subset.artifact.artifact_id) == [yes]
    assert len(comot.graph.ancestors(subset.artifact.artifact_id)) == 1
    comot.withdraw(PROJECT, code=code, channel="participant_code", actor="chw")
    assert not comot.check_use(subset.artifact.artifact_id, "model_training").allowed


def test_refused_split_and_no_allowed_rows_include_blockers(comot):
    (_, _), (no, _) = recordings(comot)
    ds = datasets.Dataset.from_dict({"artifact_id": [no]})
    before = set(comot.graph.artifacts)
    for operation in (register_split, filter_allowed):
        with pytest.raises(ConsentRefused) as exc:
            operation(comot, ds, "model_training", actor="dt")
        assert exc.value.blockers == [(no, "consent does not allow model_training")]
    assert set(comot.graph.artifacts) == before


def test_withdrawal_between_selection_and_registration(comot, monkeypatch):
    (yes, code), _ = recordings(comot)
    register = comot.register

    def withdraw_then_register(*args, **kwargs):
        comot.withdraw(PROJECT, code=code, channel="participant_code", actor="chw")
        return register(*args, **kwargs)

    monkeypatch.setattr(comot, "register", withdraw_then_register)
    ds = datasets.Dataset.from_dict({"artifact_id": [yes]})
    with pytest.raises(ConsentRefused) as exc:
        filter_allowed(comot, ds, "model_training", actor="dt")
    assert exc.value.blockers
    assert not any(a.type == "dataset_version" for a in comot.graph.artifacts.values())


@pytest.mark.parametrize("rows,error", [({"x": [1]}, ValueError), ({"artifact_id": []}, ValueError),
                                        ({"artifact_id": [None]}, ValueError), ({"artifact_id": ["unknown"]}, UnknownObject)])
def test_invalid_lineage_cannot_create_a_copy(comot, rows, error):
    with pytest.raises(error):
        register_split(comot, datasets.Dataset.from_dict(rows), "research", actor="dt")
    assert not comot.graph.artifacts
