import json

import pytest

from comot import (
    DEFAULT_POLICY,
    OPERATIONS,
    AccessDenied,
    AccessPolicy,
    Actor,
    Comot,
    IdentityVault,
    verify_bundle,
)

from conftest import ALL, PROJECT

pytest.importorskip("cryptography")

CHW = Actor("chw_1", {"health_worker"})
TEAM = Actor("team_1", {"data_team"})
BOARD = Actor("board_1", {"board"})
AUDITOR = Actor("aud_1", {"auditor"})
DPO = Actor("dpo_1", {"dpo"})
NOBODY = Actor("nobody", set())


@pytest.fixture
def secured(clock, tmp_path):
    """A Comot with the default policy, an identity vault, one participant and a recording."""
    vault = IdentityVault(tmp_path / "vault.db", b"k" * 32)
    c = Comot(clock=clock, access=AccessPolicy.default(), vault=vault)
    pid, code = c.create_participant(actor=CHW)
    c.record_consent(
        pid, PROJECT, ALL, script_version="t-1", language="pcm", capture_method="spoken_yes_no",
        device_id="d1", actor=CHW,
    )
    rec = c.register_recording(pid, PROJECT, content=b"audio", actor=CHW)
    tr = c.register("transcript", [rec.artifact_id], "research", actor=TEAM)
    c.store_identity(pid, actor=CHW, name="Ada")
    c.pid, c.code, c.rec, c.tr = pid, code, rec, tr
    yield c
    vault.close()


def denials(c):
    return [e for e in c.log.entries if e.event_type == "access_denied"]


# ------------------------------------------------------------------ the policy


def test_default_policy_only_grants_known_operations():
    policy = AccessPolicy.default()
    granted = set().union(*policy.roles.values())
    assert granted <= set(OPERATIONS)
    assert set(OPERATIONS) <= granted, "an operation no role can perform is dead"


def test_an_unknown_operation_in_a_policy_is_an_error_not_a_silent_miss():
    with pytest.raises(ValueError, match="unknown operations"):
        AccessPolicy({"dpo": ["read_identty"]})


@pytest.mark.parametrize(
    "bad",
    [{}, {"version": 2, "roles": {"a": []}}, {"version": 1}, {"version": 1, "roles": {}}, {"version": 1, "roles": {"a": "withdraw"}}],
)
def test_malformed_policies_are_refused(bad):
    with pytest.raises(ValueError):
        AccessPolicy.from_dict(bad)


def test_a_policy_loads_from_a_file_a_board_can_read(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"version": 1, "roles": {"line": ["withdraw"]}}))
    policy = AccessPolicy.load(f)
    assert policy.allows(Actor("svc", {"line"}), "withdraw")
    assert not policy.allows(Actor("svc", {"line"}), "register")


def test_the_policy_hash_changes_when_any_grant_changes():
    base = AccessPolicy.default()
    d = json.loads(json.dumps(DEFAULT_POLICY))
    assert AccessPolicy.from_dict(d).hash() == base.hash()
    d["roles"]["auditor"].append("anchor")
    assert AccessPolicy.from_dict(d).hash() != base.hash()
    d["roles"]["auditor"].remove("anchor")
    d["roles"]["auditor"].reverse()  # order of grants is not a change
    assert AccessPolicy.from_dict(d).hash() == base.hash()


def test_actors_need_an_id_and_a_lone_role_string_is_one_role():
    with pytest.raises(ValueError):
        Actor("  ")
    assert Actor("a", "dpo").roles == frozenset({"dpo"})


# ---------------------------------------------------------- who may do what


@pytest.mark.parametrize(
    "actor,operation,allowed",
    [
        (CHW, "record_consent", True),
        (CHW, "withdraw", True),
        (CHW, "store_identity", True),
        (CHW, "read_identity", False),
        (CHW, "register", False),
        (CHW, "complete_action", False),
        (TEAM, "register", True),
        (TEAM, "check_training_run", True),
        (TEAM, "complete_action", True),
        (TEAM, "record_consent", False),
        (TEAM, "withdraw", False),
        (TEAM, "read_identity", False),
        (TEAM, "export_bundle", False),
        (BOARD, "view_actions", True),
        (BOARD, "escalate_overdue", True),
        (BOARD, "register", False),
        (BOARD, "read_identity", False),
        (AUDITOR, "export_bundle", True),
        (AUDITOR, "verify_integrity", True),
        (AUDITOR, "read_identity", False),
        (AUDITOR, "withdraw", False),
        (AUDITOR, "anchor", False),
        (DPO, "read_identity", True),
        (DPO, "delete_identity", True),
        (DPO, "anchor", True),
        (DPO, "withdraw", True),
        (DPO, "register", False),
        (DPO, "store_identity", False),
        (NOBODY, "view_actions", False),
    ],
)
def test_the_default_roles(actor, operation, allowed):
    assert AccessPolicy.default().allows(actor, operation) is allowed


def test_an_unknown_role_grants_nothing():
    assert not AccessPolicy.default().allows(Actor("x", {"root", "admin"}), "withdraw")


def test_roles_add_up():
    both = Actor("x", {"auditor", "data_team"})
    p = AccessPolicy.default()
    assert p.allows(both, "export_bundle") and p.allows(both, "register")


# ------------------------------------------- every operation is really enforced

# One call per operation, made as an actor with no roles. If a method forgets to
# authorize, its row here fails, so a new method cannot slip through.
CALLS = {
    "create_participant": lambda c, a: c.create_participant(actor=a),
    "record_consent": lambda c, a: c.record_consent(
        c.pid, "p2", ALL, script_version="t", language="pcm", capture_method="spoken_yes_no", device_id="d", actor=a
    ),
    "register_recording": lambda c, a: c.register_recording(c.pid, PROJECT, content=b"x", actor=a),
    "register": lambda c, a: c.register("clip", [c.rec.artifact_id], "research", actor=a),
    "check_use": lambda c, a: c.check_use(c.tr.artifact_id, "research", actor=a),
    "check_training_run": lambda c, a: c.check_training_run([c.tr.artifact_id], actor=a),
    "withdraw": lambda c, a: c.withdraw(PROJECT, code=c.code, scope="all", channel="chw", actor=a),
    "view_actions": lambda c, a: c.overdue_actions(actor=a),
    "complete_action": lambda c, a: c.complete_action("act_none", actor=a, evidence="x"),
    "escalate_overdue": lambda c, a: c.escalate_overdue(actor=a),
    "issue_receipt": lambda c, a: c.issue_receipt("w_none", actor=a),
    "anchor": lambda c, a: c.anchor(object(), actor=a),
    "verify_integrity": lambda c, a: c.verify_integrity(actor=a),
    "export_bundle": lambda c, a: c.export_bundle(actor=a),
    "store_identity": lambda c, a: c.store_identity(c.pid, actor=a, name="x"),
    "read_identity": lambda c, a: c.read_identity(c.pid, actor=a),
    "delete_identity": lambda c, a: c.delete_identity(c.pid, actor=a),
    "rotate_vault_key": lambda c, a: c.rotate_vault_key(b"n" * 32, actor=a),
}


def test_the_table_covers_every_operation():
    assert set(CALLS) == set(OPERATIONS)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_an_actor_without_the_role_is_refused_and_it_is_logged(secured, operation):
    before = len(secured.log.entries)
    with pytest.raises(AccessDenied) as e:
        CALLS[operation](secured, NOBODY)
    assert e.value.operation == operation and e.value.actor_id == "nobody"
    new = secured.log.entries[before:]
    assert [(x.event_type, x.actor_id, x.object_id) for x in new] == [("access_denied", "nobody", operation)]


@pytest.mark.parametrize("operation", OPERATIONS)
def test_a_plain_string_is_not_an_authenticated_actor_under_a_policy(secured, operation):
    with pytest.raises(AccessDenied, match="authenticated Actor"):
        CALLS[operation](secured, "chw_1")
    assert denials(secured)[-1].actor_id == "chw_1"


@pytest.mark.parametrize("operation", ["check_use", "view_actions", "verify_integrity", "export_bundle"])
def test_leaving_the_actor_out_is_refused_under_a_policy(secured, operation):
    with pytest.raises(AccessDenied):
        CALLS[operation](secured, None)
    assert denials(secured)[-1].actor_id == "unauthenticated"


# -------------------------------------------------------- a refusal does nothing


def test_a_refused_withdrawal_changes_nothing(secured):
    consents, actions = len(secured.consents), len(secured.actions)
    with pytest.raises(AccessDenied):
        secured.withdraw(PROJECT, code=secured.code, scope="all", channel="chw", actor=TEAM)
    assert (len(secured.consents), len(secured.actions)) == (consents, actions)
    assert secured.check_use(secured.tr.artifact_id, "research", actor=TEAM).allowed
    assert [e.event_type for e in secured.log.entries[-1:]] == ["access_denied"]


def test_a_refused_identity_read_reads_nothing_and_logs_no_read(secured):
    with pytest.raises(AccessDenied):
        secured.read_identity(secured.pid, actor=CHW)
    assert not [e for e in secured.log.entries if e.event_type == "identity_read"]
    assert secured.read_identity(secured.pid, actor=DPO)["name"] == "Ada"
    assert [e.actor_id for e in secured.log.entries if e.event_type == "identity_read"] == ["dpo_1"]


def test_the_denial_entry_holds_no_content(secured):
    with pytest.raises(AccessDenied):
        secured.read_identity(secured.pid, actor=CHW)
    entry = denials(secured)[-1]
    assert "Ada" not in json.dumps(entry.to_dict())
    assert entry.object_id == "read_identity"


def test_the_log_still_verifies_with_denials_in_it(secured):
    with pytest.raises(AccessDenied):
        secured.withdraw(PROJECT, code=secured.code, scope="all", channel="chw", actor=TEAM)
    assert secured.verify_integrity(actor=AUDITOR) == []
    assert verify_bundle(secured.export_bundle(actor=AUDITOR), secured.signer.key) == []


# --------------------------------------------------------- what is allowed works


def test_each_role_can_do_its_job_end_to_end(secured):
    w = secured.withdraw(PROJECT, code=secured.code, scope=["research"], channel="chw", actor=CHW)
    acts = secured.actions_for(w.withdrawal_id, actor=TEAM)
    assert acts
    for a in acts:
        secured.complete_action(a.action_id, actor=TEAM, evidence="ticket-1")
    assert secured.coverage(w.withdrawal_id, actor=BOARD) == 1.0
    assert secured.issue_receipt(w.withdrawal_id, actor=CHW)
    assert secured.delete_identity(secured.pid, actor=DPO) is True


def test_internal_steps_do_not_need_extra_grants(clock):
    """A role that may only withdraw still gets the receipt and actions its withdrawal creates."""
    line = Actor("status_line", {"line"})
    policy = AccessPolicy({"health_worker": ["create_participant", "record_consent", "register_recording"],
                           "data_team": ["register"], "line": ["withdraw"]})
    c = Comot(clock=clock, access=policy)
    pid, code = c.create_participant(actor=Actor("c", {"health_worker"}))
    c.record_consent(pid, PROJECT, ALL, script_version="t", language="pcm", capture_method="spoken_yes_no",
                     device_id="d", actor=Actor("c", {"health_worker"}))
    rec = c.register_recording(pid, PROJECT, content=b"a", actor=Actor("c", {"health_worker"}))
    c.register("transcript", [rec.artifact_id], "research", actor=Actor("t", {"data_team"}))
    w = c.withdraw(PROJECT, code=code, scope="all", channel="status_line", actor=line)
    assert w.receipt_id and len(c.actions) == 2
    with pytest.raises(AccessDenied):
        c.issue_receipt(w.withdrawal_id, actor=line)  # asking for a new one is a different grant


def test_the_acting_person_is_what_the_log_and_consent_record(secured):
    rec = secured.latest_consent(secured.pid, PROJECT)
    assert rec.chw_id == "chw_1"
    assert {e.actor_id for e in secured.log.entries if e.event_type == "artifact_registered"} == {"chw_1", "team_1"}


def test_everything_a_withdrawal_creates_is_logged_against_who_made_it(secured):
    w = secured.withdraw(PROJECT, code=secured.code, scope="all", channel="chw", actor=CHW)
    mine = [e for e in secured.log.entries if e.object_id == w.withdrawal_id or e.event_type in ("action_created", "receipt_issued", "consent_changed")]
    assert {e.event_type for e in mine} >= {"withdrawal_received", "action_created", "receipt_issued", "consent_changed"}
    assert {e.actor_id for e in mine} == {"chw_1"}


# ----------------------------------------------------------------- the policy log


def policy_entries(c):
    return [e for e in c.log.entries if e.event_type == "access_policy_set"]


def test_the_policy_in_force_is_logged_once(clock):
    c = Comot(clock=clock, access=AccessPolicy.default())
    assert [e.object_id for e in policy_entries(c)] == [f"policy:{AccessPolicy.default().hash()}"]


def test_no_policy_means_no_policy_entry_and_no_checks(clock):
    c = Comot(clock=clock)
    pid, _ = c.create_participant(actor="anyone")
    assert not policy_entries(c) and pid


def test_reopening_with_the_same_policy_adds_nothing_and_a_changed_one_is_logged(open_db):
    a = open_db(access=AccessPolicy.default())
    a.create_participant(actor=CHW)
    n = len(a.log.entries)
    b = open_db(access=AccessPolicy.default())
    assert len(b.log.entries) == n
    stricter = AccessPolicy({"health_worker": ["create_participant"]})
    c = open_db(access=stricter)
    assert [e.object_id for e in policy_entries(c)][-1] == f"policy:{stricter.hash()}"
    assert len(policy_entries(c)) == 2
    d = open_db(access=AccessPolicy.default())  # going back is a change too, and shows
    assert len(policy_entries(d)) == 3


def test_denials_and_policy_changes_survive_a_reopen(open_db):
    a = open_db(access=AccessPolicy.default())
    with pytest.raises(AccessDenied):
        a.create_participant(actor=TEAM)
    b = open_db()  # an auditor opening without a policy still reads the record
    assert [e.actor_id for e in b.log.entries if e.event_type == "access_denied"] == ["team_1"]
    assert b.verify_integrity() == []


def test_a_denial_in_one_process_is_visible_in_another(open_db):
    a = open_db(access=AccessPolicy.default())
    b = open_db(access=AccessPolicy.default())
    with pytest.raises(AccessDenied):
        a.create_participant(actor=TEAM)
    with pytest.raises(AccessDenied):
        b.create_participant(actor=TEAM)
    assert len(denials(b)) == 2 and b.verify_integrity(actor=AUDITOR) == []
