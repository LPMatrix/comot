import pytest

from comot import ConsentError, USES
from comot.consent import normalize_choices
from conftest import PROJECT, make_person


def test_silence_is_no():
    c = normalize_choices({"record": True, "research": None})
    assert c["research"] is False
    assert c["model_training"] is False  # never answered
    assert set(c) == set(USES)


def test_truthy_strings_are_rejected():
    with pytest.raises(ConsentError):
        normalize_choices({"record": "yes"})


def test_unknown_choice_is_rejected():
    with pytest.raises(ConsentError):
        normalize_choices({"record": True, "reserch": True})


def test_nothing_else_without_record():
    with pytest.raises(ConsentError):
        normalize_choices({"record": False, "research": True})


def test_records_are_versioned_and_chained(comot):
    pid, _ = make_person(comot, {"record": True})
    comot.record_consent(
        pid, PROJECT, {"record": True, "research": True}, script_version="t-1", language="pcm",
        capture_method="button_press", actor="chw1", device_id="dev1",
    )
    v1, v2 = comot.consents
    assert (v1.version, v2.version) == (1, 2)
    assert v1.consent_id == v2.consent_id
    assert v2.prev_hash == v1.hash
    assert v1.choices["research"] is False  # the old version is untouched
    assert comot.latest_consent(pid, PROJECT) is v2


def test_taking_a_use_away_must_go_through_withdraw(comot):
    pid, _ = make_person(comot)
    with pytest.raises(ConsentError, match="withdraw"):
        comot.record_consent(
            pid, PROJECT, {"record": True}, script_version="t-1", language="pcm",
            capture_method="button_press", actor="chw1", device_id="dev1",
        )


def test_minor_needs_guardian_and_assent(comot):
    for kwargs in ({}, {"guardian_consent": True}, {"guardian_consent": True, "assent": False}):
        pid, _ = comot.create_participant(actor="chw1")
        with pytest.raises(ConsentError):
            comot.record_consent(
                pid, PROJECT, {"record": True}, script_version="t-1", language="pcm",
                capture_method="spoken_yes_no", actor="chw1", device_id="d", is_minor=True, **kwargs,
            )
    make_person(comot, {"record": True}, is_minor=True, guardian_consent=True, assent=True)


def test_minor_who_refuses_everything_is_recorded(comot):
    make_person(comot, {}, is_minor=True)  # all "no" needs no guardian answer


def test_withdrawal_capture_method_cannot_be_forged(comot):
    pid, _ = comot.create_participant(actor="chw1")
    with pytest.raises(ConsentError):
        comot.record_consent(
            pid, PROJECT, {"record": True}, script_version="t-1", language="pcm",
            capture_method="withdrawal_chw", actor="chw1", device_id="d",
        )
