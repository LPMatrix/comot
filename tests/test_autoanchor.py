import pytest

from comot import AccessPolicy, Actor, Comot
from conftest import ALL, PROJECT, ListSink, make_chain, make_person
from test_anchor import rewrite_from


class Flaky:
    """A sink that fails until it is told to work."""

    def __init__(self):
        self.up, self.anchors = False, []

    def publish(self, anchor):
        if not self.up:
            raise OSError("anchor volume is not mounted")
        self.anchors.append(anchor)
        return "flaky"


def pending(c):
    covered = c.anchors[-1].seq + 1 if c.anchors else 0
    return len(c.log.entries) - covered


def test_every_change_is_anchored_by_default(clock):
    sink = ListSink()
    c = Comot(clock=clock, anchor_sink=sink)
    make_person(c)  # a participant and a consent: two changes
    assert len(sink.anchors) == 2 and pending(c) == 0
    assert c.log.entries[-1].event_type == "anchor_published"
    # each anchor covers everything before it
    assert [a.seq for a in sink.anchors] == [1, 3]


def test_the_anchor_does_not_anchor_itself_in_circles(clock):
    sink = ListSink()
    c = Comot(clock=clock, anchor_sink=sink)
    c.create_participant(actor="chw1")
    n = len(c.log.entries)
    c.verify_integrity()  # reading changes nothing
    assert len(c.log.entries) == n and len(sink.anchors) == 1


@pytest.mark.parametrize("every", [1, 3, 5])
def test_after_every_change_fewer_than_the_setting_are_unanchored(clock, every):
    sink = ListSink()
    c = Comot(clock=clock, anchor_sink=sink, anchor_every=every)
    pid, code = c.create_participant(actor="chw1")
    assert pending(c) < every
    c.record_consent(pid, PROJECT, ALL, script_version="t", language="pcm", capture_method="spoken_yes_no",
                     device_id="d", actor="chw1")
    assert pending(c) < every
    rec = c.register_recording(pid, PROJECT, content=b"a", actor="chw1")
    assert pending(c) < every
    c.register("transcript", [rec.artifact_id], "research", actor="asr")
    assert pending(c) < every
    c.withdraw(PROJECT, code=code, scope="all", channel="chw", actor="chw1")  # several entries in one change
    assert pending(c) < every
    assert sink.anchors and sink.anchors[-1].seq <= len(c.log.entries)


def test_a_larger_window_anchors_less_often(clock):
    one, five = ListSink(), ListSink()
    a, b = Comot(clock=clock, anchor_sink=one, anchor_every=1), Comot(clock=clock, anchor_sink=five, anchor_every=50)
    for c in (a, b):
        for _ in range(3):
            make_person(c)
    assert len(one.anchors) > len(five.anchors)


def test_a_rewrite_of_anything_before_the_last_change_is_caught(clock):
    sink = ListSink()
    c = Comot(clock=clock, anchor_sink=sink)
    pid, code = make_person(c)
    make_chain(c, pid)
    c.withdraw(PROJECT, code=code, scope="all", channel="chw", actor="chw1")
    entries = [e for e in c.log.entries]
    forged = rewrite_from(entries, len(entries) // 2, actor_id="someone_else")
    from comot.anchor import verify_anchors
    from comot.log import verify_entries

    assert verify_entries(forged) == []  # the chain alone is fooled
    assert verify_anchors(forged, sink.anchors)  # the anchors are not


def test_a_failing_sink_never_fails_the_work_and_is_reported(clock):
    sink = Flaky()
    c = Comot(clock=clock, anchor_sink=sink)
    pid, _ = make_person(c)  # the work succeeds
    assert c.latest_consent(pid, PROJECT) is not None
    assert c.anchor_errors and "OSError" in c.anchor_errors[0]
    assert c.anchors == [] and not [e for e in c.log.entries if e.event_type == "anchor_published"]
    assert c.verify_integrity() == []  # nothing half-written
    errors = len(c.anchor_errors)
    sink.up = True
    c.create_participant(actor="chw1")  # the next change catches up with one anchor covering everything
    assert len(c.anchors) == 1 and c.anchors[0].seq == len(c.log.entries) - 1
    assert len(c.anchor_errors) == errors and pending(c) == 0


def test_a_failing_sink_is_retried_on_every_change_until_it_works(clock):
    sink = Flaky()
    c = Comot(clock=clock, anchor_sink=sink)
    for _ in range(3):
        c.create_participant(actor="chw1")
    assert len(c.anchor_errors) == 3 and not sink.anchors


def test_it_works_under_an_access_policy_without_a_role_for_it(clock):
    sink = ListSink()
    c = Comot(clock=clock, access=AccessPolicy({"health_worker": ["create_participant"]}), anchor_sink=sink)
    c.create_participant(actor=Actor("c", {"health_worker"}))
    assert sink.anchors and not [e for e in c.log.entries if e.event_type == "access_denied"]


def test_anchors_are_kept_in_the_store_and_agree_with_the_sink(open_db):
    sink = ListSink()
    c = open_db(anchor_sink=sink)
    pid, _ = make_person(c)
    make_chain(c, pid)
    again = open_db()  # a new process, with no sink of its own
    key = lambda a: (a.seq, a.head, a.time)  # the sink's copy does not yet know where it went
    assert [key(a) for a in again.anchors] == [key(a) for a in sink.anchors] and again.verify_integrity() == []


def test_the_window_must_be_positive(clock):
    with pytest.raises(ValueError):
        Comot(clock=clock, anchor_sink=ListSink(), anchor_every=0)
