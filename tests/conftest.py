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


@pytest.fixture
def signer():
    from comot import HmacSigner

    return HmacSigner(b"s" * 32)


@pytest.fixture
def dbpath(tmp_path):
    return tmp_path / "comot.db"


@pytest.fixture
def open_db(dbpath, signer, clock):
    """Open the same database again, as a new process would. Closes everything at the end."""
    opened = []

    def _open(**kwargs):
        c = Comot.open(dbpath, signer=signer, clock=clock, **kwargs)
        opened.append(c)
        return c

    yield _open
    for c in opened:
        try:
            c.close()
        except Exception:
            pass


class ListSink:
    """An anchor sink that keeps anchors in a list, standing in for somewhere external."""

    def __init__(self):
        self.anchors = []

    def publish(self, anchor):
        self.anchors.append(anchor)
        return "list"
