import json

import pytest

from comot import verify_bundle
from comot.log import verify_entries
from conftest import PROJECT, make_chain, make_person

jsonschema = pytest.importorskip("jsonschema")


def busy(comot):
    pid, code = make_person(comot)
    make_chain(comot, pid)
    comot.withdraw(PROJECT, code=code, scope=["model_training"], channel="chw", actor="chw1")


def test_log_chain_is_intact_and_detects_edits(comot):
    busy(comot)
    assert verify_entries(comot.log.entries) == []
    import dataclasses
    entries = list(comot.log.entries)
    entries[3] = dataclasses.replace(entries[3], actor_id="someone_else")
    assert verify_entries(entries)
    del entries[3]
    assert verify_entries(entries)


def test_log_holds_no_payload_or_personal_data(comot):
    busy(comot)
    for e in comot.log.entries:
        assert set(e.to_dict()) == {"seq", "time", "actor_id", "event_type", "object_id", "payload_hash", "prev_hash", "hash"}


def test_every_withdrawal_step_is_logged(comot):
    busy(comot)
    kinds = {e.event_type for e in comot.log.entries}
    assert {"consent_recorded", "consent_changed", "withdrawal_received", "action_created", "receipt_issued"} <= kinds


def test_bundle_verifies_and_signature_needs_the_key(comot):
    busy(comot)
    bundle = json.loads(json.dumps(comot.export_bundle()))  # as a file would carry it
    assert verify_bundle(bundle) == []
    assert verify_bundle(bundle, comot.signer.key) == []
    assert verify_bundle(bundle, b"wrong key")


def test_bundle_leaves_out_storage_locations_and_codes(comot):
    pid, code = make_person(comot)
    comot.register_recording(pid, PROJECT, content=b"x", storage_uri="s3://secret/path.wav", actor="chw1")
    text = json.dumps(comot.export_bundle())
    assert "secret/path" not in text
    assert "participant_code" not in text and "code" not in " ".join(comot.export_bundle()["consents"][0])


@pytest.mark.parametrize("tamper", ["choice", "delete_record", "reorder"])
def test_bundle_detects_tampering(comot, tamper):
    busy(comot)
    bundle = json.loads(json.dumps(comot.export_bundle()))
    if tamper == "choice":
        bundle["consents"][0]["choices"]["external_share"] = False
    elif tamper == "delete_record":
        del bundle["consents"][0]
    else:
        bundle["consents"].reverse()
    assert verify_bundle(bundle)


def test_records_and_log_validate_against_the_published_schemas(comot):
    from importlib import resources

    busy(comot)

    def load(name):
        return json.loads(resources.files("comot").joinpath("schema", name).read_text(encoding="utf-8"))

    for rec in comot.consents:
        jsonschema.validate(rec.to_dict(), load("consent_record.schema.json"))
    for entry in comot.log.entries:
        jsonschema.validate(entry.to_dict(), load("log_entry.schema.json"))
