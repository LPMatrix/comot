# Comot

**Consent that follows the recording.** An open-source layer that records what each speaker agreed to for each voice recording, and makes a withdrawal reach every transcript, dataset and model built from it.

*Comot* is Nigerian Pidgin for "leave" or "come out". It is built first for voice data in Pidgin, Hausa and Yoruba, but nothing in the core is specific to one language or project.

> **Status: v0.1, early prototype.** A Python library backed by SQLite. APIs will change. Do not use it to hold real participants' consent yet. See [Status](#status).

## Why

Teams that collect voice recordings, for example of people talking about their health to train screening tools, usually handle consent as a one-time form. Three things go wrong after that:

- **Consent is vague.** A signature or thumbprint does not say which uses the person understood and accepted.
- **Copies escape the record.** One recording becomes a transcript, a cleaned clip, a feature file, a slice of a training set and part of a model. None of them points back to the consent that allowed it.
- **Withdrawal stops at the raw file.** A team can delete the original and still hold transcripts, dataset splits and models built from it.

Comot keeps a record of each person's choices, tracks every derived copy back to its source, and turns a withdrawal into a tracked action on every copy.

## Install and try it

Requires Python 3.10+. The core has no runtime dependencies. The identity vault needs `cryptography`, installed with `pip install -e ".[vault]"`.

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
pid, code = comot.create_participant(actor="chw_17")   # no name or phone number is stored here

comot.record_consent(
    pid, "my-project",
    {"record": True, "research": True, "model_training": False},   # silence counts as no
    script_version="pcm-1.0", language="pcm", capture_method="spoken_yes_no",
    device_id="dev_3", teach_back_score="4/5", actor="chw_17",
)

rec = comot.register_recording(pid, "my-project", content=audio_bytes, actor="chw_17")

# The one call a data team makes for every derived copy.
# Refused, and the refusal logged, if the consent behind any parent does not allow the use.
transcript = comot.register("transcript", [rec.artifact_id], "research", actor="asr")

# Call before every training run. Raises TrainingBlocked here, because training was refused.
comot.check_training_run([transcript.artifact_id], actor="asr")

# Withdrawal: a new consent version, an action per affected copy, and a signed receipt.
w = comot.withdraw("my-project", code=code, scope=["research"], channel="participant_code", actor="chw_17")
for action in comot.actions_for(w.withdrawal_id):
    print(action.kind, action.artifact_id, action.due_at)
```

Every call that changes something says who is acting with `actor=`. That name goes into the audit log next to what was done.

### Keep it in a database

`Comot()` is a plain in-memory object, good for tests and notebooks. To keep state, open a SQLite file:

```bash
uv run comot keygen signing.key        # a new Ed25519 key, readable only by you. Back it up.
```

```python
from comot import Comot, load_signer

comot = Comot.open("comot.db", signer=load_signer("signing.key"))
# ... use it exactly as above. Every call is committed before it returns.
comot.close()
```

The signing key is required, because receipts signed last month must still verify. The database remembers which keys it has used and refuses an unrelated one. An Ed25519 key lets an auditor check receipts and exports with a public key alone, and a key can be rotated without breaking what it signed earlier.

See [Operating it](#operating-it) for integrity checks, the identity vault and anchoring.

### Who may do what

By default any named actor may do anything. Give Comot an access policy and each call needs an `Actor` your own system has authenticated, and one of its roles must allow the call:

```python
from comot import AccessPolicy, Actor, Comot

comot = Comot(access=AccessPolicy.default())    # or AccessPolicy.load("policy.json")

chw = Actor("chw_17", {"health_worker"})
team = Actor("data_team_2", {"data_team"})

comot.create_participant(actor=chw)             # fine
comot.withdraw("my-project", code=code, scope="all", channel="chw", actor=team)
# AccessDenied: data_team_2 may not withdraw. The refusal is in the audit log.
```

The default roles are health worker, data team, board, auditor and data protection officer. The role table is a small JSON file that a board can read and change, and the audit log records which table was in force. As a library Comot takes the `Actor` you give it at your word. For network callers, `comot serve` turns a bearer token into the `Actor`, so the roles are enforced at a real boundary. See [docs/operations.md](docs/operations.md#access-control) for the table and what it does not cover.

## How it works

**Consent record.** One per participant per project, with six separate choices: record, research, model training, external sharing, keep after the project, contact again. Each is an explicit yes or no, and silence is stored as no. Records are append-only: a change is a new version that points at the hash of the one before it. Participants under 18 need both guardian consent and their own assent, and the record says how the child's age and the guardian's consent were checked. The JSON Schemas are in [`src/comot/schema/`](src/comot/schema/).

**Lineage.** Every recording, transcript, clip, feature file, dataset version and model version is a node. Each derived copy is registered with its parents and the use it was made for. `check_use` walks back to every source recording and the strictest consent wins: one person who said no blocks the use for the whole dataset. `filter_allowed` returns the subset that is allowed. A copy held outside also records its destination country and the basis for sending it, and if that basis is the participant's consent, every source participant must have been told the risks of a transfer abroad.

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

## Operating it

Comot keeps everything in one SQLite file, keeps names and phone numbers in a separate encrypted vault, and can publish the audit log's head hash outside the database so a rewrite is detectable. Each is covered in [docs/operations.md](docs/operations.md):

- [Persistence](docs/operations.md#persistence): atomic calls, append-only triggers, integrity checks on open, several processes.
- [Identity vault](docs/operations.md#identity-vault): encrypted, kept apart from consent records, erasable on its own.
- [Anchoring the audit log](docs/operations.md#anchoring-the-audit-log): what a hash chain alone cannot catch, and the command that closes the gap.
- [Signing keys](docs/operations.md#signing-keys): Ed25519 so auditors need no secret, and rotation.
- [Access control](docs/operations.md#access-control): the default roles, writing your own, and what is logged.
- [Serving it over HTTP](docs/operations.md#serving-it-over-http): bearer tokens, TLS, and the endpoints.

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
- SQLite persistence with atomic operations, append-only triggers, and integrity checks on open
- an encrypted identity vault, separate from the consent database
- role-based access control with a policy a board can read, and every refusal logged
- audit log anchoring to an external file, automatic after each change if you like, and verification against it
- Ed25519 signatures, so an auditor verifies with a public key, and key rotation for both the signing and vault keys
- an exported bundle that checks every artifact, edge, withdrawal, action, receipt and refusal against the audit log
- an HTTP API with bearer-token authentication, TLS, and the access policy enforced per request
- incremental catch-up between processes, with scale measured in `benchmarks/scale.py`
- language pack loader and release gate, which also requires the explanations the law says a person must hear
- a record of how guardian consent was verified, and of the basis for every transfer outside Nigeria
- a synthetic-data demo and 395 tests

What it does not do:

Comot makes tampering detectable and misuse refusable. It cannot stop someone who owns the database file from deleting it, or code in the same process from reading its memory, so run it behind `comot serve` and keep anchors somewhere the database's writers cannot reach. It runs on one host with one SQLite file, measured to 30,000 participants. Nothing here is legal advice: the design follows the Nigeria Data Protection Act 2023 and the Commission's 2025 directive, which allow spoken consent, and it treats health-related voice data as sensitive. [docs/legal-notes.md](docs/legal-notes.md) shows how each rule is met and which readings still need a lawyer, and a deployment still owes its own impact assessment and registration. The full list, with what to do about each, is in [docs/operations.md](docs/operations.md#what-this-does-and-does-not-protect-against).

Planned:

- a PostgreSQL store behind the same interface, for several hosts writing to one database
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
  store.py       SQLite store (and the no-op in-memory store)
  anchor.py      publish and verify audit log anchors
  access.py      actors, roles and the access policy
  signing.py     HMAC and Ed25519 signers, key rings for rotation
  auth.py        bearer tokens turned into actors
  server.py      the HTTP API
  vault.py       encrypted identity vault
  core.py        the Comot service object
  bundle.py      verify an exported bundle
  langpack.py    language pack loader and release gate
  demo.py cli.py
  schema/        JSON Schema for consent records and log entries
language_packs/  draft Pidgin skeleton
docs/            operator notes, and how the design meets Nigerian law
benchmarks/      scale.py: how Comot behaves as a database grows
tests/
```

## Licence

Code is Apache 2.0, see [LICENSE](LICENSE). Consent scripts, audio, schemas and documentation are intended for CC BY 4.0, subject to what the community reviewers decide about the audio.
