"""A lineage and withdrawal demo on synthetic data. No real recordings or people."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .clock import ManualClock
from .core import Comot
from .errors import ConsentRefused, TrainingBlocked
from .receipt import HmacSigner, render_receipt

PROJECT = "demo-synthetic"


def run_demo(
    out: Callable[[str], None] = print, *, db: str | Path | None = None, key_file: str | Path | None = None
) -> Comot:
    """Run the demo in memory, or into a new SQLite file when ``db`` is given."""
    clock = ManualClock()
    if db is None:
        comot = Comot(clock=clock)
    else:
        if Path(db).exists():
            raise FileExistsError(f"{db} already exists; the demo needs a new database")
        signer = HmacSigner.from_file(key_file, create=True) if key_file else HmacSigner()
        comot = Comot.open(db, signer=signer, clock=clock)

    def say(title: str) -> None:
        out(f"\n== {title}")

    def consent(answers: dict[str, bool | None], **extra):
        pid, code = comot.create_participant("chw_demo")
        comot.record_consent(
            pid,
            PROJECT,
            answers,
            script_version="demo-0",
            language="pcm",
            capture_method="spoken_yes_no",
            chw_id="chw_demo",
            device_id="dev_demo",
            teach_back_score="4/5",
            **extra,
        )
        return pid, code

    say("1. Four synthetic participants give different consent")
    everything = {"record": True, "research": True, "model_training": True, "external_share": True}
    people = {
        "A (all uses)": consent(everything),
        "B (research only, no training)": consent({"record": True, "research": True, "model_training": False}),
        "C (no outside sharing)": consent({"record": True, "research": True, "model_training": True}),
        "D (minor, guardian + assent)": consent(
            {"record": True, "research": True, "model_training": True},
            is_minor=True,
            guardian_consent=True,
            assent=True,
        ),
    }
    for name in people:
        out(f"   {name}")
    out("   Silence counts as no: nobody was defaulted to yes.")

    say("2. Recordings, transcripts, and one dataset for research")
    recs, transcripts = {}, {}
    for name, (pid, _) in people.items():
        rec = comot.register_recording(
            pid, PROJECT, content=f"audio:{name}".encode(), storage_uri=f"s3://demo/{name[0]}.wav", created_by="chw_demo"
        )
        recs[name] = rec
        transcripts[name] = comot.register(
            "transcript", [rec.artifact_id], "research", content=f"text:{name}".encode(), created_by="asr"
        )
    research_set = comot.register(
        "dataset_version", [t.artifact_id for t in transcripts.values()], "research", created_by="data_team"
    )
    out(f"   registered {len(recs)} recordings, {len(transcripts)} transcripts, dataset {research_set.artifact_id}")

    say("3. A model on the whole dataset is refused, because B said no to training")
    try:
        comot.register("model_version", [research_set.artifact_id], "model_training", created_by="data_team")
    except ConsentRefused as e:
        out(f"   refused: {e}")
        for who, reason in e.blockers:
            out(f"     - {who}: {reason}")

    say("4. Pre-training check, then a training set filtered by consent")
    try:
        comot.check_training_run([t.artifact_id for t in transcripts.values()])
    except TrainingBlocked as e:
        out(f"   run blocked: {len(e.blockers)} item(s) may not be used")
    ok = comot.filter_allowed([t.artifact_id for t in transcripts.values()], "model_training")
    train_set = comot.register("dataset_version", ok, "model_training", created_by="data_team")
    model = comot.register("model_version", [train_set.artifact_id], "model_training", created_by="data_team")
    out(f"   training set has {len(ok)} of {len(transcripts)} transcripts; model {model.artifact_id} registered")

    say("5. A copy goes to an outside team under licence")
    shared = comot.register(
        "dataset_version",
        [transcripts["A (all uses)"].artifact_id],
        "external_share",
        holder="lic_0001",
        created_by="data_team",
    )
    out(f"   outside copy {shared.artifact_id} held by lic_0001")
    try:
        comot.register(
            "dataset_version", [transcripts["C (no outside sharing)"].artifact_id], "external_share", holder="lic_0001"
        )
    except ConsentRefused:
        out("   C's transcript cannot go to an outside team: C said no to sharing")

    say("6. A withdraws from model training only (partial withdrawal)")
    pid_a, code_a = people["A (all uses)"]
    w1 = comot.withdraw(PROJECT, code=code_a, scope=["model_training"], channel="participant_code", actor_id="chw_demo")
    for act in comot.actions_for(w1.withdrawal_id):
        out(f"   {act.kind:8} {comot.graph.artifacts[act.artifact_id].type:16} due {act.due_at[:10]}")
    out(f"   coverage: {comot.coverage(w1.withdrawal_id):.0%}")
    try:
        comot.check_training_run([transcripts["A (all uses)"].artifact_id])
    except TrainingBlocked:
        out("   A's transcript is now blocked from any new training run")
    out("   A's research use is untouched: " + str(comot.check_use(transcripts["A (all uses)"].artifact_id, "research").allowed))

    say("7. C withdraws everything through a community health worker")
    pid_c, code_c = people["C (no outside sharing)"]
    w2 = comot.withdraw(PROJECT, code=code_c, scope="all", channel="chw", actor_id="chw_demo")
    out(f"   {len(comot.actions_for(w2.withdrawal_id))} actions, coverage {comot.coverage(w2.withdrawal_id):.0%}")
    for act in comot.actions_for(w2.withdrawal_id)[:2]:
        comot.complete_action(act.action_id, done_by="data_team", evidence="storage-deletion-ticket-0042")

    say("8. Eight days pass: overdue actions go to the board")
    clock.advance(days=8)
    for act in comot.escalate_overdue():
        out(f"   overdue {act.kind:8} on {comot.graph.artifacts[act.artifact_id].type} {act.artifact_id}")

    say("9. C's receipt, as the participant would hear it (English source wording)")
    receipt = comot.issue_receipt(w2.withdrawal_id)
    out("   " + render_receipt(receipt).replace("\n", "\n   "))
    out(f"   signature valid: {comot.verify_receipt(receipt)}")
    return comot
