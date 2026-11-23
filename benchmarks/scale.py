"""How Comot behaves as the database grows. Run: uv run python benchmarks/scale.py [participants ...]

Each participant gets a consent record, a recording, a transcript and a dataset item, so
every participant adds about eight log entries and four artifacts. The numbers depend on the
disk, so run it on the hardware you plan to use. SQLite is told to fsync on every commit.
"""
from __future__ import annotations

import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

from comot import Comot, HmacSigner

CHOICES = {"record": True, "research": True, "model_training": True}


def timed(fn, n=1):
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t) / n


def run(n: int) -> None:
    with tempfile.TemporaryDirectory() as d:
        db, signer = Path(d) / "c.db", HmacSigner(b"b" * 32)
        c = Comot.open(db, signer=signer)
        codes = []
        t0 = time.perf_counter()
        for i in range(n):
            pid, code = c.create_participant(actor="bench")
            c.record_consent(pid, "p", CHOICES, script_version="1", language="pcm", capture_method="spoken_yes_no",
                             device_id="d", actor="bench")
            rec = c.register_recording(pid, "p", content_hash=f"{i:064x}", actor="bench")
            c.register("transcript", [rec.artifact_id], "research", actor="bench")
            codes.append(code)
        write = time.perf_counter() - t0
        probe = c.register("transcript", [c.graph.artifacts[next(iter(c.graph.artifacts))].artifact_id], "research", actor="bench")
        check = timed(lambda: c.check_use(probe.artifact_id, "research"), 200)
        wd = []
        for code in codes[:20]:
            wd.append(timed(lambda: c.withdraw("p", code=code, scope="all", channel="chw", actor="bench")))
        entries = len(c.log.entries)
        c.close()
        size = sum(f.stat().st_size for f in Path(d).iterdir())
        open_verify = timed(lambda: Comot.open(db, signer=signer).close())
        open_fast = timed(lambda: Comot.open(db, signer=signer, verify=False).close())
        a, b = Comot.open(db, signer=signer), Comot.open(db, signer=signer)
        a.create_participant(actor="bench")
        refresh = timed(lambda: (b.refresh(), None)[1])  # b sees a's write: one full reload
        a.create_participant(actor="bench")
        refresh = timed(b.refresh)
        a.close(), b.close()
        print(
            f"{n:>7} participants | {entries:>8} log entries | {size / 1e6:7.1f} MB | "
            f"write {n * 4 / write:6.0f} ops/s | check_use {check * 1e3:6.2f} ms | "
            f"withdraw {statistics.median(wd) * 1e3:6.1f} ms | open+verify {open_verify:6.2f} s | "
            f"open {open_fast:5.2f} s | another process's write seen after {refresh * 1e3:7.0f} ms"
        )


if __name__ == "__main__":
    for size in [int(a) for a in sys.argv[1:]] or [500, 2000, 8000]:
        run(size)
