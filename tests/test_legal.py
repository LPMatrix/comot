"""Rules that come from the Nigeria Data Protection Act 2023: see docs/legal-notes.md."""
import dataclasses
import json
from pathlib import Path

import pytest

from comot import ConsentError, ConsentRefused, StoreError
from comot.consent import GUARDIAN_VERIFICATION
from comot.langpack import NOTICE_ITEMS, load_pack
from comot.lineage import TRANSFER_BASES

from conftest import ALL, PROJECT, make_chain, make_person

PACK = Path(__file__).parent.parent / "language_packs" / "pcm" / "pack.json"
MINOR = dict(is_minor=True, guardian_consent=True, assent=True)


def consent(comot, pid, **kw):
    return comot.record_consent(
        pid, PROJECT, kw.pop("answers", {"record": True}), script_version="t", language="pcm",
        capture_method="spoken_yes_no", device_id="d", actor="chw1", **kw,
    )


# ------------------------------------------------- guardian verification (s.31)


def test_a_guardians_consent_needs_a_stated_way_it_was_checked(comot):
    pid, _ = comot.create_participant(actor="chw1")
    with pytest.raises(ConsentError, match="how the child's age"):
        consent(comot, pid, **MINOR)
    with pytest.raises(ConsentError, match="how the child's age"):
        consent(comot, pid, guardian_verification="trust_me", **MINOR)
    assert consent(comot, pid, guardian_verification="government_id_seen", **MINOR).guardian_verification == "government_id_seen"


@pytest.mark.parametrize("method", GUARDIAN_VERIFICATION)
def test_every_listed_way_is_accepted(comot, method):
    pid, _ = comot.create_participant(actor="chw1")
    assert consent(comot, pid, guardian_verification=method, **MINOR).guardian_verification == method


def test_verification_is_refused_where_there_is_no_guardian_consent(comot):
    pid, _ = comot.create_participant(actor="chw1")
    with pytest.raises(ConsentError, match="only when a guardian consented"):
        consent(comot, pid, guardian_verification="government_id_seen")  # an adult
    with pytest.raises(ConsentError, match="only when a guardian consented"):
        consent(comot, pid, answers={}, is_minor=True, guardian_verification="guardian_present")


def test_a_guardian_who_says_no_needs_no_verification_and_cannot_have_one(comot):
    pid, _ = comot.create_participant(actor="chw1")
    rec = consent(comot, pid, answers={}, is_minor=True, guardian_consent=False, assent=False)
    assert rec.guardian_verification is None
    with pytest.raises(ConsentError, match="only when a guardian consented"):
        consent(comot, pid, answers={}, is_minor=True, guardian_consent=False, guardian_verification="guardian_present")


def test_the_verification_is_part_of_what_the_hash_protects(comot):
    pid, _ = make_person(comot, {"record": True}, guardian_verification="government_id_seen", **MINOR)
    rec = comot.latest_consent(pid, PROJECT)
    forged = dataclasses.replace(rec, guardian_verification="guardian_present")
    assert forged.compute_hash() != rec.hash == rec.compute_hash()


def test_a_withdrawal_keeps_the_verification_of_the_version_it_follows(comot):
    pid, code = make_person(comot, {"record": True, "research": True}, guardian_verification="facility_record", **MINOR)
    comot.withdraw(PROJECT, code=code, scope=["research"], channel="chw", actor="chw1")
    assert comot.latest_consent(pid, PROJECT).guardian_verification == "facility_record"


def test_verification_survives_a_reopen_and_reaches_the_export(open_db):
    a = open_db()
    pid, _ = make_person(a, {"record": True}, guardian_verification="guardian_present", **MINOR)
    b = open_db()
    assert b.latest_consent(pid, PROJECT).guardian_verification == "guardian_present"
    assert b.export_bundle()["consents"][0]["guardian_verification"] == "guardian_present"
    assert b.verify_integrity() == []


def test_new_consent_fields_validate_against_the_schema(comot):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).parent.parent / "src/comot/schema/consent_record.schema.json").read_text())
    pid, _ = make_person(comot, {"record": True}, transfer_risk_explained=True, guardian_verification="guardian_present", **MINOR)
    jsonschema.validate(comot.latest_consent(pid, PROJECT).to_dict(), schema)
    bad = {**comot.latest_consent(pid, PROJECT).to_dict(), "guardian_verification": "trust_me"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


# ----------------------------------------------- transfers out of Nigeria (ss.41-43)


def share(comot, source, **kw):
    kw.setdefault("holder", "lic_1")
    return comot.register("transcript", [source], "external_share", actor="data_team", **kw)


@pytest.fixture
def sharer(comot):
    """A participant who accepts sharing, with a recording and transcript."""
    def _make(told: bool):
        pid, _ = make_person(comot, ALL, transfer_risk_explained=told)
        rec, tr, *_ = make_chain(comot, pid)
        return tr
    return _make


def test_an_internal_copy_carries_no_transfer_details(comot, sharer):
    tr = sharer(True)
    with pytest.raises(ValueError, match="only to copies held outside"):
        comot.register("clip", [tr.artifact_id], "research", destination_country="NG", actor="x")
    assert comot.graph.artifacts[tr.artifact_id].destination_country is None
    with pytest.raises(ValueError, match="only to copies held outside"):
        comot.register("clip", [tr.artifact_id], "research", transfer_basis="adequacy_decision", actor="x")


@pytest.mark.parametrize(
    "country,basis,message",
    [
        (None, "adequacy_decision", "destination_country"),
        ("ng", "within_nigeria", "destination_country"),
        ("NGA", "within_nigeria", "destination_country"),
        ("G1", "adequacy_decision", "destination_country"),
        ("GH", None, "transfer_basis"),
        ("GH", "because_i_said", "transfer_basis"),
        ("GH", "within_nigeria", "within_nigeria"),
        ("NG", "adequacy_decision", "within_nigeria"),
        ("NG", "consent_after_risk_notice", "within_nigeria"),
    ],
)
def test_a_copy_held_outside_needs_a_valid_destination_and_basis(comot, sharer, country, basis, message):
    tr = sharer(True)
    before = len(comot.graph.artifacts)
    with pytest.raises(ValueError, match=message):
        share(comot, tr.artifact_id, destination_country=country, transfer_basis=basis)
    assert len(comot.graph.artifacts) == before


def test_the_basis_is_recorded_on_the_copy_and_exported(comot, sharer):
    tr = sharer(True)
    out = share(comot, tr.artifact_id, destination_country="GH", transfer_basis="consent_after_risk_notice")
    assert (out.destination_country, out.transfer_basis) == ("GH", "consent_after_risk_notice")
    exported = [a for a in comot.export_bundle()["artifacts"] if a["artifact_id"] == out.artifact_id][0]
    assert (exported["destination_country"], exported["transfer_basis"]) == ("GH", "consent_after_risk_notice")


def test_the_basis_survives_a_reopen(open_db):
    a = open_db()
    pid, _ = make_person(a, ALL, transfer_risk_explained=True)
    _, tr, *_ = make_chain(a, pid)
    out = share(a, tr.artifact_id, destination_country="KE", transfer_basis="adequacy_decision")
    got = open_db().graph.artifacts[out.artifact_id]
    assert (got.destination_country, got.transfer_basis) == ("KE", "adequacy_decision")


def test_consent_as_the_basis_needs_the_risk_notice(comot, sharer):
    tr = sharer(False)
    with pytest.raises(ConsentRefused) as e:
        share(comot, tr.artifact_id, destination_country="GH", transfer_basis="consent_after_risk_notice")
    assert any("not told the risks" in reason for _, reason in e.value.blockers)
    refusals = [x for x in comot.log.entries if x.event_type == "registration_refused"]
    assert refusals, "the refusal is logged"


def test_one_participant_not_told_blocks_a_mixed_dataset(comot, sharer):
    told, not_told = sharer(True), sharer(False)
    with pytest.raises(ConsentRefused):
        comot.register(
            "dataset_version", [told.artifact_id, not_told.artifact_id], "external_share", holder="lic_1",
            destination_country="GH", transfer_basis="consent_after_risk_notice", actor="dt",
        )
    ok = comot.register(
        "dataset_version", [told.artifact_id], "external_share", holder="lic_1",
        destination_country="GH", transfer_basis="consent_after_risk_notice", actor="dt",
    )
    assert ok.transfer_basis == "consent_after_risk_notice"


@pytest.mark.parametrize("basis", ["adequacy_decision", "approved_instrument"])
def test_other_bases_do_not_need_the_notice(comot, sharer, basis):
    tr = sharer(False)
    assert share(comot, tr.artifact_id, destination_country="GH", transfer_basis=basis).transfer_basis == basis


def test_a_domestic_holder_needs_no_notice(comot, sharer):
    tr = sharer(False)
    assert share(comot, tr.artifact_id, destination_country="NG", transfer_basis="within_nigeria")


def test_the_notice_still_needs_the_sharing_choice(comot):
    pid, _ = make_person(comot, {"record": True, "research": True}, transfer_risk_explained=True)
    rec = comot.register_recording(pid, PROJECT, content=b"a", actor="chw1")
    tr = comot.register("transcript", [rec.artifact_id], "research", actor="asr")
    with pytest.raises(ConsentRefused):
        share(comot, tr.artifact_id, destination_country="GH", transfer_basis="consent_after_risk_notice")


def test_a_withdrawal_keeps_the_notice_flag_and_a_new_session_must_say_it_again(comot):
    pid, code = make_person(comot, ALL, transfer_risk_explained=True)
    comot.withdraw(PROJECT, code=code, scope=["research"], channel="chw", actor="chw1")
    assert comot.latest_consent(pid, PROJECT).transfer_risk_explained is True
    again = consent(comot, pid, answers={**ALL, "research": False})
    assert again.transfer_risk_explained is False


def test_the_flag_must_be_a_real_boolean(comot):
    pid, _ = comot.create_participant(actor="chw1")
    with pytest.raises(ConsentError):
        consent(comot, pid, transfer_risk_explained="yes")


def test_every_basis_is_tested():
    assert set(TRANSFER_BASES) == {"within_nigeria", "adequacy_decision", "approved_instrument", "consent_after_risk_notice"}


def test_a_database_from_before_these_fields_is_refused_not_misread(dbpath, signer, clock):
    from comot import Comot

    Comot.open(dbpath, signer=signer, clock=clock).close()
    import sqlite3

    db = sqlite3.connect(dbpath)
    db.execute("PRAGMA user_version = 1")
    db.close()
    with pytest.raises(StoreError, match="schema version 1"):
        Comot.open(dbpath, signer=signer, clock=clock)


# ------------------------------------------- what a participant must hear (ss.26-27)


def _pack(tmp_path, fn):
    raw = json.loads(PACK.read_text(encoding="utf-8"))
    raw["status"] = "signed_off"
    raw["review"]["signed_off_by"] = ["r1", "r2"]
    for i in raw["items"]:
        i["text"], i["audio"] = "approved", f"audio/{i['id']}.ogg"
    fn(raw)
    p = tmp_path / "pack.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    return load_pack(p)


def test_the_shipped_draft_has_every_required_explanation_in_the_right_place():
    assert load_pack(PACK).notice_problems() == []


def test_a_finished_pack_with_every_explanation_is_releasable(tmp_path):
    assert _pack(tmp_path, lambda raw: None).releasable


@pytest.mark.parametrize("item_id", sorted(NOTICE_ITEMS))
def test_a_pack_missing_a_required_explanation_cannot_be_released(tmp_path, item_id):
    pack = _pack(tmp_path, lambda raw: raw.update(items=[i for i in raw["items"] if i["id"] != item_id]))
    assert not pack.releasable
    assert any(r.startswith(f"{item_id}: missing") for r in pack.missing_for_release())


@pytest.mark.parametrize("item_id", [i for i in sorted(NOTICE_ITEMS) if i != "explain.transfer_risk"])
def test_an_explanation_heard_after_the_first_choice_is_too_late(tmp_path, item_id):
    def move(raw):
        item = next(i for i in raw["items"] if i["id"] == item_id)
        raw["items"].remove(item)
        raw["items"].insert([i["id"] for i in raw["items"]].index("choice.record") + 1, item)
    pack = _pack(tmp_path, move)
    assert not pack.releasable
    assert f"{item_id}: must come before the first choice" in pack.missing_for_release()


def test_the_transfer_risk_must_come_before_the_sharing_choice(tmp_path):
    def move(raw):
        item = next(i for i in raw["items"] if i["id"] == "explain.transfer_risk")
        raw["items"].remove(item)
        raw["items"].insert([i["id"] for i in raw["items"]].index("choice.external_share") + 1, item)
    pack = _pack(tmp_path, move)
    assert "explain.transfer_risk: must come before choice.external_share" in pack.missing_for_release()


def test_the_transfer_risk_may_come_after_the_first_choice(tmp_path):
    """It only has to come before the sharing choice, so it can sit next to it."""
    assert not [p for p in load_pack(PACK).notice_problems() if "transfer_risk" in p]
