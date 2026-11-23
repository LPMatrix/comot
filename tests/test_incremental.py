"""Catching up with another process by reading only what changed must give exactly what a full reload gives."""
import random

import pytest

from comot import Comot, ConsentRefused, TrainingBlocked
from comot.core import Comot as _Comot  # noqa: F401
from conftest import ALL, PROJECT, ListSink

MORE = {"record": True, "research": True}


def snapshot(c):
    return {
        "participants": sorted(c._participants.items()),
        "consents": [r.to_dict() for r in c.consents],
        "log": [e.to_dict() for e in c.log.entries],
        "artifacts": {k: v.to_dict() for k, v in sorted(c.graph.artifacts.items())},
        "edges": [e.to_dict() for e in c.graph.edges],
        "withdrawals": {k: v.to_dict() for k, v in sorted(c.withdrawals.items())},
        "actions": {k: v.to_dict() for k, v in sorted(c.actions.items())},
        "receipts": {k: v.to_dict() for k, v in sorted(c.receipts.items())},
        "refusals": c.refusals,
        "anchors": [a.to_dict() for a in c.anchors],
    }


def diff(a, b):
    return [k for k in a if a[k] != b[k]]


class World:
    """Two processes on one database, taking turns at random."""

    def __init__(self, dbpath, signer, clock, rng):
        self.rng, self.clock, self.dbpath, self.signer = rng, clock, dbpath, signer
        self.procs = [Comot.open(dbpath, signer=signer, clock=clock) for _ in range(2)]
        self.people, self.artifacts, self.withdrawals = [], [], []
        self.sink = ListSink()

    def fresh(self):
        return Comot.open(self.dbpath, signer=self.signer, clock=self.clock)  # a full load, with verification

    def step(self):
        c, rng = rng_pick(self.rng, self.procs), self.rng
        ops = [self.new_person, self.new_person, self.record, self.derive, self.derive, self.withdraw, self.complete,
               self.escalate, self.anchor, self.receipt, self.refused, self.training, self.tick]
        rng.choice(ops)(c)

    def new_person(self, c):
        pid, code = c.create_participant(actor="w")
        c.record_consent(pid, PROJECT, self.rng.choice([ALL, MORE]), script_version="t", language="pcm",
                         capture_method="spoken_yes_no", device_id="d", actor="w", transfer_risk_explained=True)
        self.people.append((pid, code))

    def record(self, c):
        if self.people:
            pid, _ = self.rng.choice(self.people)
            self.artifacts.append(c.register_recording(pid, PROJECT, content=self.rng.randbytes(8), storage_uri="s3://x", actor="w").artifact_id)

    def derive(self, c):
        if not self.artifacts:
            return
        parent = self.rng.choice(self.artifacts)
        kind, purpose = self.rng.choice([("transcript", "research"), ("dataset_version", "model_training"), ("model_version", "model_training")])
        try:
            self.artifacts.append(c.register(kind, [parent], purpose, actor="w").artifact_id)
        except ConsentRefused:
            pass

    def withdraw(self, c):
        if self.people and self.rng.random() < 0.4:
            pid, code = self.rng.choice(self.people)
            try:
                w = c.withdraw(PROJECT, code=code, scope=self.rng.choice(["all", ["research"], ["model_training"]]), channel="chw", actor="w")
            except Exception:
                return
            self.withdrawals.append(w.withdrawal_id)

    def complete(self, c):
        c.refresh()
        open_ = [a for a in c.actions.values() if a.done_at is None]
        if open_:
            c.complete_action(self.rng.choice(open_).action_id, actor="w", evidence="e")

    def escalate(self, c):
        c.escalate_overdue(actor="w")

    def anchor(self, c):
        c.anchor(self.sink, actor="w")

    def receipt(self, c):
        if self.withdrawals:
            c.issue_receipt(self.rng.choice(self.withdrawals), actor="w")

    def refused(self, c):
        if self.artifacts:
            try:
                c.register("dataset_version", [self.rng.choice(self.artifacts)], "external_share", holder="lic", destination_country="NG", transfer_basis="within_nigeria", actor="w")
            except ConsentRefused:
                pass

    def training(self, c):
        if self.artifacts:
            c.check_training_run(self.rng.sample(self.artifacts, min(3, len(self.artifacts))), actor="w", strict=False)

    def tick(self, c):
        self.clock.advance(days=self.rng.choice([1, 5, 30]))


def rng_pick(rng, items):
    return rng.choice(items)


COVERED: set[str] = set()


@pytest.mark.parametrize("seed", range(12))
def test_catching_up_incrementally_equals_a_full_reload(seed, dbpath, signer, clock):
    world = World(dbpath, signer, clock, random.Random(seed))
    for n in range(70):
        world.step()
        other = world.fresh()
        want = snapshot(other)
        for i, proc in enumerate(world.procs):
            proc.refresh()  # the incremental path
            assert diff(snapshot(proc), want) == [], f"seed {seed}, step {n}, process {i}"
        assert other.verify_integrity() == []
        other.close()
    COVERED.update(e.event_type for e in world.procs[0].log.entries)
    assert len(world.procs[0].log.entries) > 20  # it did a fair amount


def test_the_random_runs_between_them_exercised_every_kind_of_change():
    wanted = {"participant_created", "consent_recorded", "artifact_registered", "registration_refused", "training_check",
              "withdrawal_received", "action_created", "action_completed", "action_overdue", "receipt_issued", "anchor_published"}
    assert wanted <= COVERED, wanted - COVERED


def test_a_process_that_only_reads_stays_current_without_a_full_reload(dbpath, signer, clock):
    writer, reader = Comot.open(dbpath, signer=signer, clock=clock), Comot.open(dbpath, signer=signer, clock=clock)
    calls = []
    original = reader.store.load_since
    reader.store.load_since = lambda cursor: (calls.append(cursor), original(cursor))[1]
    for _ in range(5):
        writer.create_participant(actor="w")
        reader.refresh()
    assert len(calls) == 5 and all(c is not None for c in calls)  # always a delta, never "everything"


def test_the_amount_read_follows_the_change_not_the_database(dbpath, signer, clock):
    writer, reader = Comot.open(dbpath, signer=signer, clock=clock), Comot.open(dbpath, signer=signer, clock=clock)
    for _ in range(200):
        writer.create_participant(actor="w")
    reader.refresh()
    seen = []
    original = reader.store.load_since
    reader.store.load_since = lambda cursor: (seen.append(original(cursor)), seen[-1])[1]
    writer.create_participant(actor="w")
    reader.refresh()
    assert [len(d.log) for d in seen] == [1] and [len(d.participants) for d in seen] == [1]


def test_own_writes_are_not_read_back_and_duplicated(dbpath, signer, clock):
    a, b = Comot.open(dbpath, signer=signer, clock=clock), Comot.open(dbpath, signer=signer, clock=clock)
    a.create_participant(actor="w")
    a.create_participant(actor="w")
    b.create_participant(actor="w")  # b catches up with a, then writes
    a.refresh()  # a must read only b's write
    assert len(a.log.entries) == 3 and len({e.seq for e in a.log.entries}) == 3 and len(a._participants) == 3
    assert snapshot(a) == snapshot(b)


def test_a_tampered_chain_is_noticed_while_catching_up(dbpath, signer, clock):
    import sqlite3
    from comot import StoreIntegrityError

    a, b = Comot.open(dbpath, signer=signer, clock=clock), Comot.open(dbpath, signer=signer, clock=clock)
    a.create_participant(actor="w")
    b.refresh()
    a.create_participant(actor="w")
    db = sqlite3.connect(dbpath)
    db.execute("DROP TRIGGER log_entries_no_update")
    db.execute("UPDATE log_entries SET prev_hash = ? WHERE seq = (SELECT MAX(seq) FROM log_entries)", ("0" * 64,))
    db.commit()
    db.close()
    with pytest.raises(StoreIntegrityError, match="do not continue the chain"):
        b.refresh()
