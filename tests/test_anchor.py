import dataclasses
import json

import pytest

from comot import Anchor, Comot, FileAnchorSink, StoreIntegrityError, read_anchor_file, verify_bundle
from comot.anchor import verify_anchors
from comot.log import verify_entries
from conftest import PROJECT, ListSink, make_chain, make_person


def rewrite_from(entries, k, **changes):
    """What an attacker with write access does: change entry k, then recompute every hash after it."""
    out = list(entries)
    out[k] = dataclasses.replace(out[k], **changes)
    out[k] = dataclasses.replace(out[k], hash=out[k].compute_hash())
    for i in range(k + 1, len(out)):
        out[i] = dataclasses.replace(out[i], prev_hash=out[i - 1].hash)
        out[i] = dataclasses.replace(out[i], hash=out[i].compute_hash())
    return out


def test_anchor_publishes_the_head_and_logs_it(comot):
    pid, _ = make_person(comot)
    sink = ListSink()
    a = comot.anchor(sink)
    assert [(x.seq, x.head, x.time) for x in sink.anchors] == [(a.seq, a.head, a.time)]
    assert a.seq == len(comot.log.entries) - 1  # the anchor's own log entry comes after it
    assert comot.log.entries[-1].event_type == "anchor_published"
    assert comot.anchors == [a]


def test_a_quiet_system_does_not_anchor_itself_in_circles(comot):
    make_person(comot)
    sink = ListSink()
    assert comot.anchor(sink)
    assert comot.anchor(sink) is None
    make_person(comot)
    assert comot.anchor(sink)
    assert len(sink.anchors) == 2


def test_a_failed_publish_records_nothing(comot):
    make_person(comot)
    n = len(comot.log.entries)

    class Broken:
        def publish(self, anchor):
            raise OSError("anchor volume is not mounted")

    with pytest.raises(OSError):
        comot.anchor(Broken())
    assert comot.anchors == [] and len(comot.log.entries) == n


def test_a_consistent_rewrite_passes_the_chain_check_but_not_the_anchor(comot):
    pid, code = make_person(comot)
    make_chain(comot, pid)
    sink = ListSink()
    comot.anchor(sink)
    make_person(comot)

    forged = rewrite_from(comot.log.entries, 2, actor_id="someone_else")
    assert verify_entries(forged) == []  # the chain alone cannot see this
    problems = verify_anchors(forged, sink.anchors)
    assert problems and "rewritten" in problems[0]
    assert verify_anchors(comot.log.entries, sink.anchors) == []


def test_a_rewrite_after_the_last_anchor_is_not_caught_yet(comot):
    # Honest about the limit: an anchor only protects what came before it.
    make_person(comot)
    sink = ListSink()
    comot.anchor(sink)
    make_person(comot)
    forged = rewrite_from(comot.log.entries, len(comot.log.entries) - 1, actor_id="someone_else")
    assert verify_anchors(forged, sink.anchors) == []


def test_truncation_is_caught(comot):
    make_person(comot)
    make_person(comot)
    sink = ListSink()
    comot.anchor(sink)
    problems = verify_anchors(comot.log.entries[:2], sink.anchors)
    assert problems and "truncated" in problems[0]


def test_an_empty_log_anchors_to_genesis(comot):
    a = comot.anchor(ListSink())
    assert a.seq == 0 and verify_anchors([], [a]) == []


def test_bundle_checks_external_anchors(comot):
    pid, _ = make_person(comot)
    make_chain(comot, pid)
    sink = ListSink()
    comot.anchor(sink)
    bundle = json.loads(json.dumps(comot.export_bundle()))
    assert verify_bundle(bundle, comot.signer.key, sink.anchors) == []

    # Someone rewrites the log inside the bundle and recomputes all the hashes.
    entries = [dataclasses.asdict(e) for e in rewrite_from(comot.log.entries, 1, actor_id="x")]
    bundle["log"], bundle["log_head"] = entries, entries[-1]["hash"]
    bundle["anchors"] = []  # and drops the anchors carried inside
    assert verify_bundle(bundle) == []  # alone, it looks fine
    assert verify_bundle(bundle, anchors=sink.anchors)  # the external anchors give it away


def test_file_sink_appends_json_lines(tmp_path, comot):
    f = tmp_path / "anchors.jsonl"
    make_person(comot)
    comot.anchor(FileAnchorSink(f))
    make_person(comot)
    comot.anchor(FileAnchorSink(f))
    read = read_anchor_file(f)
    assert [a.seq for a in read] == [a.seq for a in comot.anchors]
    assert verify_anchors(comot.log.entries, read) == []
    assert comot.anchors[0].sink == f"file:{f}"


def test_anchor_file_rejects_garbage(tmp_path):
    f = tmp_path / "bad.jsonl"
    f.write_text("not json\n")
    with pytest.raises(ValueError, match="not a valid anchor"):
        read_anchor_file(f)


def test_stored_anchors_catch_a_rewritten_database_on_open(open_db, dbpath, signer, clock):
    import sqlite3

    c = open_db()
    pid, _ = make_person(c)
    make_chain(c, pid)
    c.anchor(ListSink())
    c.close()

    # Rewrite the log consistently and drop the triggers, leaving the anchors table alone.
    c2 = Comot.open(dbpath, signer=signer, clock=clock, verify=False)
    forged = rewrite_from(c2.log.entries, 1, actor_id="someone_else")
    c2.close()
    db = sqlite3.connect(dbpath)
    db.execute("DROP TRIGGER log_entries_no_update")
    for e in forged:
        db.execute("UPDATE log_entries SET actor_id=?, prev_hash=?, hash=? WHERE seq=?", (e.actor_id, e.prev_hash, e.hash, e.seq))
    db.commit()
    db.close()
    with pytest.raises(StoreIntegrityError) as e:
        Comot.open(dbpath, signer=signer, clock=clock)
    assert any("rewritten" in p for p in e.value.problems)
