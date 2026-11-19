# Comot

**Consent that follows the recording.** An open-source layer that records what each speaker agreed to for each voice recording, and makes a withdrawal reach every transcript, dataset and model built from it.

*Comot* is Nigerian Pidgin for "leave" or "come out". It is built first for voice data in Pidgin, Hausa and Yoruba, but nothing in the core is specific to one language or project.

> **Status: v0.0, early prototype.** A Python library with an in-memory store. APIs will change. Do not use it to hold real participants' consent yet. See [Status](#status).

## Why

Teams that collect voice recordings, for example of people talking about their health to train screening tools, usually handle consent as a one-time form. Three things go wrong after that:

- **Consent is vague.** A signature or thumbprint does not say which uses the person understood and accepted.
- **Copies escape the record.** One recording becomes a transcript, a cleaned clip, a feature file, a slice of a training set and part of a model. None of them points back to the consent that allowed it.
- **Withdrawal stops at the raw file.** A team can delete the original and still hold transcripts, dataset splits and models built from it.

Comot keeps a record of each person's choices, tracks every derived copy back to its source, and turns a withdrawal into a tracked action on every copy.

## Install and try it

Requires Python 3.10+. There are no runtime dependencies.

```bash
git clone <this repo> && cd comot
uv sync                  # or: pip install -e .
uv run comot demo        # lineage and withdrawal on synthetic data
uv run pytest
```

## Use it

```python
from comot import Comot

comot = Comot()
pid, code = comot.create_participant("chw_17")      # no name or phone number is stored here

comot.record_consent(
    pid, "my-project",
    {"record": True, "research": True, "model_training": False},   # silence counts as no
    script_version="pcm-1.0", language="pcm", capture_method="spoken_yes_no",
    chw_id="chw_17", device_id="dev_3", teach_back_score="4/5",
)

rec = comot.register_recording(pid, "my-project", content=audio_bytes, created_by="chw_17")

# The one call a data team makes for every derived copy.
# Refused, and the refusal logged, if the consent behind any parent does not allow the use.
transcript = comot.register("transcript", [rec.artifact_id], "research", created_by="asr")

# Call before every training run. Raises TrainingBlocked here, because training was refused.
comot.check_training_run([transcript.artifact_id])

# Withdrawal: a new consent version, an action per affected copy, and a signed receipt.
w = comot.withdraw("my-project", code=code, scope=["research"], channel="participant_code", actor_id="chw_17")
for action in comot.actions_for(w.withdrawal_id):
    print(action.kind, action.artifact_id, action.due_at)
```

## How it works

**Consent record.** One per participant per project, with six separate choices: record, research, model training, external sharing, keep after the project, contact again. Each is an explicit yes or no, and silence is stored as no. Records are append-only: a change is a new version that points at the hash of the one before it. Participants under 18 need both guardian consent and their own assent. The JSON Schemas are in [`src/comot/schema/`](src/comot/schema/).

**Lineage.** Every recording, transcript, clip, feature file, dataset version and model version is a node. Each derived copy is registered with its parents and the use it was made for. `check_use` walks back to every source recording and the strictest consent wins: one person who said no blocks the use for the whole dataset. `filter_allowed` returns the subset that is allowed.

**Withdrawal.** Participants can withdraw everything or one use, by code, through a health worker, or by a status line, with no reason asked. The engine walks the lineage graph and creates one action per affected copy. The default deadlines are a starting point and live in `WithdrawalPolicy`, so a community board can set its own.

| Copy | Action | Default deadline |
| --- | --- | --- |
| Recording, transcript, clip, feature file | Delete | 7 days |
| Dataset version | Remove the item, publish a new version | 7 days |
| Model in use | Mark tainted, keep the item out of new runs, retire when a retrained model ships | 180 days |
| Sharded model | Retrain the affected shard | 30 days |
| Copy held outside under licence | Notify the holder and require confirmation | 14 days to confirm |

Every action is tracked to done with who did it and evidence. Overdue ones escalate once to the board. A signed receipt says what is done, what is pending, and what cannot be done.

**What a withdrawal does not do.** It guarantees removal from every stored copy and from every future training run. It does **not** erase a person's influence from a model that is already trained, and the receipt says so in plain words. Already-published aggregate results are not changed either. Research on removing data from trained speech models is young, so Comot promises traceability and retraining triggers instead of a guarantee it cannot keep.

**Audit log.** Every consent, registration, refusal, withdrawal and action goes into a hash-chained, append-only log of pseudonymous ids and payload hashes. It never holds names, phone numbers or recording content. `comot verify` checks an exported bundle's hash chains without trusting the service that produced it:

```bash
uv run comot demo --export demo.bundle.json
uv run comot verify demo.bundle.json
```

## Design principles

1. **The participant can leave.** A feature that makes withdrawal harder does not ship.
2. **Promise only what the system can prove.** No telling someone their data is "deleted" from a model when it is not.
3. **Speech first, in the speaker's language.** Consent is heard, not read.
4. **Rules the community can read.** Access and withdrawal terms are data a board sets, not code.
5. **Minimum data.** The consent system stores what proves consent and drives withdrawal, and nothing about what a recording says.
6. **Small surface.** Registering a derived copy is one function call. If tracking is hard, teams skip it.

## Language packs

A language pack holds a consent script as data: explanation items, the six choices and the teach-back questions. Adding a language means adding a pack, not changing code. See [`language_packs/`](language_packs/).

The Nigerian Pidgin pack in this repo is a **draft skeleton**, not a usable script. It has plain-English source text for native speakers to redraft, and empty `text` and `audio` fields. A pack is only releasable once community reviewers have signed it off and every item has native-speaker audio. `uv run comot pack language_packs/pcm/pack.json` lists what still blocks release.

## Status

What exists today:

- consent records, hash-chained, with JSON Schemas
- lineage graph, consent-checked registration, pre-training check
- partial and full withdrawal, per-copy actions, overdue escalation, signed receipts
- hash-chained audit log, signed export, bundle verifier
- language pack loader and release gate
- a synthetic-data demo and 47 tests

Known limits:

- Receipts and exports are signed with HMAC, which only proves integrity to someone holding the key. An asymmetric signature is needed for independent auditors.
- The audit log is not yet anchored to an external store, so someone with write access could rewrite a whole chain.
- `verify_bundle` cross-checks consent records against the log. It does not yet cross-check artifacts, actions or receipts.
- Everything is in memory. There is no persistence, no access roles and no separate identity vault.
- Nothing here is legal advice. Check any deployment against the data protection law that applies to you. The design assumes spoken consent is lawful and treats voice and health data as sensitive by default.

Planned:

- a service with PostgreSQL storage, and a documented API
- an offline field app for collecting spoken consent on low-cost Android phones
- board-owned access policy and a request-and-licence flow for outside teams
- status checks by USSD, WhatsApp or a health worker, with messages that reveal nothing on a shared phone
- pipeline plug-ins: Hugging Face Datasets, pandas manifests, DVC
- notice endpoints for outside holders, and a scan for unregistered copies
- Hausa and Yoruba packs, and packs from partners for other languages

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contributions right now are:

- feedback from people who run voice data collection or review it as an ethics board
- native speakers willing to help draft, record and review consent scripts
- a security review of the hash chain, signing and export format
- try registering your own pipeline's artifacts and tell us what was awkward

## Layout

```
src/comot/
  consent.py     consent record, choices, capture methods
  lineage.py     artifacts, edges, graph walks
  withdrawal.py  actions, deadline policy, planning per copy type
  receipt.py     signed receipts, plain-language rendering
  log.py         hash-chained audit log
  core.py        the Comot service object
  bundle.py      verify an exported bundle
  langpack.py    language pack loader and release gate
  demo.py cli.py
  schema/        JSON Schema for consent records and log entries
language_packs/  draft Pidgin skeleton
tests/
```

## Licence

Code is Apache 2.0, see [LICENSE](LICENSE). Consent scripts, audio, schemas and documentation are intended for CC BY 4.0, subject to what the community reviewers decide about the audio.
