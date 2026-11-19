import pytest

from comot import Comot, ManualClock

PROJECT = "proj-test"
ALL = {"record": True, "research": True, "model_training": True, "external_share": True}


@pytest.fixture
def clock():
    return ManualClock()


@pytest.fixture
def comot(clock):
    return Comot(clock=clock)


def make_person(comot, answers=None, **extra):
    pid, code = comot.create_participant("chw1")
    comot.record_consent(
        pid,
        PROJECT,
        ALL if answers is None else answers,
        script_version="t-1",
        language="pcm",
        capture_method="spoken_yes_no",
        chw_id="chw1",
        device_id="dev1",
        teach_back_score="5/5",
        **extra,
    )
    return pid, code


def make_chain(comot, pid, content=b"audio"):
    """recording -> transcript -> dataset -> model"""
    rec = comot.register_recording(pid, PROJECT, content=content, created_by="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", created_by="asr")
    ds = comot.register("dataset_version", [tr.artifact_id], "model_training", created_by="dt")
    model = comot.register("model_version", [ds.artifact_id], "model_training", created_by="dt")
    return rec, tr, ds, model
