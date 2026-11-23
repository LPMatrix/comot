# Running Comot

Notes for whoever operates a Comot database: how it is stored, which keys it needs and how to replace them, how identity is kept apart, how to make tampering with the audit log detectable, and how to put an authenticated API in front of it. For what Comot is and how to use it from code, see the [README](../README.md).

## Persistence

Everything lives in one SQLite file. It is in the standard library, easy to back up, and measured below. The store sits behind a small interface (`SqliteStore` in `store.py`), so another backend can be written against it.

- **Atomic.** Each Comot call is one transaction. A withdrawal that fails halfway leaves no new consent version, no half-made actions and no stray log entries, and the in-memory state is rebuilt to match.
- **Append-only in the database itself.** Triggers abort any `UPDATE` or `DELETE` on consent versions, the audit log, lineage edges, receipts, refusals, anchors and participants. They stop mistakes and casual edits. They do not stop someone who owns the file and can drop a trigger, which is what the hash chains and anchors are for.
- **Checked when opened.** Opening a database re-verifies the consent chain, the audit log, any stored anchors, and that every artifact, edge, withdrawal, action, receipt and refusal is exactly what the audit log recorded (so a status flipped or a deadline moved in the file is caught). A store that fails is refused with `StoreIntegrityError`. `Comot.open(..., verify=False)` opens it anyway so an auditor can look.
- **More than one process.** Each write takes SQLite's write lock before it reads. A process that finds the log has moved reads only what changed since, so catching up costs the size of the change and not the size of the database. The chain is checked as it joins.
- **Private by default.** The database and key files are created readable only by their owner.
- **Threads.** A `Comot` is not thread-safe. Use it from one thread, or serialise calls as the HTTP server does.

```bash
uv run comot demo --db demo.db --key-file demo.key   # the demo, kept in a database
uv run comot check demo.db --key-file demo.key       # verify chains, objects and anchors
uv run comot export demo.db --key-file demo.key --out demo.bundle.json
```

### How far it goes

`benchmarks/scale.py` measures a database as it grows, on whatever disk you run it on. Each participant adds a consent, a recording and a transcript, about eight log entries and four artifacts. A laptop with an SSD, `synchronous=FULL`:

| Participants | Log entries | File | Writes | Withdrawal | Open and verify | Another process's write seen after |
| --- | --- | --- | --- | --- | --- | --- |
| 2,000 | 8,000 | 5 MB | ~6,000 ops/s | 0.5 ms | 0.16 s | under 1 ms |
| 8,000 | 32,000 | 21 MB | ~5,600 ops/s | 0.8 ms | 0.7 s | 1 ms |
| 30,000 | 120,000 | 80 MB | ~4,000 ops/s | 4 ms | 3.4 s | 4 ms |

Reads and writes stay flat as it grows. Opening re-verifies everything, so it grows with the log. The whole state is held in memory while Comot runs. These are single-host numbers: SQLite is one file on one machine, and a laptop's `fsync` is gentler than a server disk's, so measure on yours. If you need several hosts writing to one database, that needs another backend, and there is none yet.

## Signing keys

Receipts and exports are signed so a participant, a board or an auditor can tell they are genuine. There are two kinds of key, and the difference matters for who can check them.

| | HMAC | Ed25519 (default) |
| --- | --- | --- |
| Verify with | the same secret that signs | a public key, safe to share |
| An auditor needs | your secret, so they could also forge | nothing secret |
| Needs | nothing | `pip install comot[vault]` |

```bash
uv run comot keygen signing.key                 # Ed25519 when available; prints the public key
uv run comot pubkey signing.key                 # print the public key again
uv run comot verify bundle.json --public-key ed25519:...    # an auditor, holding no secret
```

A signature names the key that made it, so a verifier picks the right one.

**Rotating.** Make a new key and open the database with a key ring that still holds the old one:

```bash
uv run comot keygen new.key
uv run comot rotate-key comot.db --key-file new.key --retired-key old.key
# from then on, pass the same two flags (or --retired-key with just the old public key)
```

The database records the change as a `signing_key_rotated` entry in the audit log. Receipts signed with the old key still verify. New ones use the new key. A rotated-out key cannot be made current again, an unrelated key is refused, and a key ring that has forgotten an earlier key is refused, because receipts signed with it could no longer be checked. For an Ed25519 key you only need to keep its public half. For an HMAC key you must keep the secret. An auditor checking a bundle that spans a rotation needs the public keys of every key that signed something in it.

**Losing a key.** A lost signing key means new receipts cannot be signed. Receipts already issued can still be checked with the public key (Ed25519), and the hash chains and anchors do not depend on it at all. Back the key up.

## Identity vault

The consent database never holds a name or phone number. Those go in a separate vault: its own SQLite file with its own key, so it can be backed up, locked down and erased on its own.

```python
from comot import Comot, IdentityVault, load_key_file, load_signer

vault = IdentityVault("vault.db", load_key_file("vault.key"))   # a different key from the signing key
comot = Comot.open("comot.db", signer=load_signer("signing.key"), vault=vault)

comot.store_identity(pid, actor="chw_17", name="...", phone="...")
comot.read_identity(pid, actor="dpo_1")         # every read is logged against who made it
comot.delete_identity(pid, actor="dpo_1")       # consent records and audit log are untouched
```

Records are encrypted with AES-256-GCM and bound to their participant id, so a ciphertext copied onto another row will not open. Only a fixed set of fields is accepted (name, phone, guardian name and phone), so the vault cannot become a place for health data. The audit log records that identity was stored, read or deleted, and by whom, never what it held.

**Rotating the vault key.** Every record is re-encrypted under the new key in one transaction, so a failure changes nothing, and the rotation is logged without any key material:

```bash
uv run comot keygen --kind vault new-vault.key
uv run comot vault-rotate comot.db vault.db --key-file signing.key --vault-key vault.key --new-vault-key new-vault.key
```

After it, the old key opens nothing. Old backups of the vault stay readable with the old key, so destroy them if they should stop being readable. **Losing the vault key loses the vault:** that is what encryption means, so keep it somewhere separate from the vault and back it up.

## Anchoring the audit log

A hash chain alone cannot stop someone with write access from rewriting the whole log from the first changed entry onward and recomputing every hash. Anchoring closes that gap: you publish the log's current head hash somewhere the database's writers cannot edit, and anything rewritten before that point no longer matches.

Anchoring can be automatic. Give Comot a sink and it publishes after each change, once `anchor_every` entries have gone unanchored:

```python
from comot import Comot, FileAnchorSink, load_signer

comot = Comot.open("comot.db", signer=load_signer("signing.key"),
                   anchor_sink=FileAnchorSink("/mnt/write-once/anchors.jsonl"), anchor_every=1)
```

With `anchor_every=1` every change is anchored as it commits, so nothing already committed can be rewritten without a mismatch. A larger number trades that for fewer anchors: a rewrite can then only reach back as far as the entries since the last one. If the sink is unreachable the change still succeeds, the failure is kept in `comot.anchor_errors`, and the next change retries and catches up, so watch that list. By hand, or from cron:

```bash
uv run comot anchor comot.db --key-file signing.key --out anchors.jsonl
uv run comot check comot.db --key-file signing.key --anchors anchors.jsonl
```

The sink only helps if the database's writers cannot edit it: another machine, a write-once volume, or a public repository the community board can see. Anchors are also kept in the database, and `comot check` compares both.

## Access control

As a library, Comot does not authenticate anyone: your code passes in an `Actor(id, roles)` and Comot checks that one of those roles allows the call. For network callers use the [HTTP server](#serving-it-over-http), which turns a bearer token into an `Actor`. Without an access policy, any named actor may do anything, which is fine for a notebook and wrong for a service.

```python
from comot import AccessPolicy, Actor, Comot

policy = AccessPolicy.load("policy.json")        # or AccessPolicy.default()
comot = Comot.open("comot.db", signer=signer, access=policy)
comot.withdraw(project, code=code, scope="all", channel="chw", actor=Actor("chw_17", {"health_worker"}))
```

**Default roles.**

| Role | May |
| --- | --- |
| `health_worker` | create participants, record consent, register recordings, take withdrawals, issue receipts, view actions, store identity |
| `data_team` | register recordings and derived copies, check use, check training runs, view and complete actions |
| `board` | view actions, escalate overdue ones, export the audit bundle |
| `auditor` | view actions, verify integrity, export the audit bundle. No identity access |
| `dpo` | take withdrawals, issue receipts, view actions, escalate, anchor, verify, export, read and delete identity |

**Writing your own.** The policy is a JSON file. Roles are only names, so you can add one that fits your deployment, such as a status line that may do nothing but take withdrawals:

```json
{
  "version": 1,
  "roles": {
    "withdrawal_line": ["withdraw"],
    "auditor": ["view_actions", "verify_integrity", "export_bundle"]
  }
}
```

An operation name that Comot does not know is an error, so a typo cannot quietly grant nothing. The full list is `comot.OPERATIONS`. A role that may `withdraw` also gets the actions and the first receipt that the withdrawal itself creates. Asking for a later receipt is a separate grant, `issue_receipt`.

**What is logged.**
- Every refusal is written to the audit log as `access_denied`, with who asked, which operation and which roles they held, never any content. An unauthenticated caller shows as their name if they gave one, otherwise `unauthenticated`.
- Whenever a Comot is opened with a policy that differs from the last one logged, an `access_policy_set` entry records the policy's hash and the table itself is not copied into the log. Keep the policy file under version control: the hash shows that it changed, and the file shows how.
- Every successful change is logged against the actor's id, as before.

**What it does not do.**
- In the library it takes the actor you give it at your word: code that can build `Actor("x", {"dpo"})` can claim any role. Build actors only from your own verified sign-in, or use the HTTP server, where the token decides.
- It guards Comot's methods. Code that holds the `Comot` object can still read `comot.log` or `comot.consents` directly, and anyone who owns the database file can read it. Run it behind the HTTP server and keep the file's permissions tight.
- Refusals are logged, so a caller who can reach Comot can add refusals to the log. They cost space, not integrity.
- The command line tools open the database directly and run without a policy, because whoever has the file and the key can do all of this anyway.

## Serving it over HTTP

Inside one process, code that holds the `Comot` object can read anything. Behind the HTTP server the object stays in the server's process, every request carries a bearer token, the token names an `Actor`, and the access policy decides what that actor may do. This is the boundary access control needs.

```bash
uv run comot token-new --tokens tokens.json --actor chw_17 --role health_worker   # prints the token once
uv run comot serve comot.db --key-file signing.key --tokens tokens.json \
    --anchor-file /mnt/write-once/anchors.jsonl --port 8080
uv run comot token-revoke --tokens tokens.json --actor chw_17                      # takes effect at once
```

- **Tokens.** 256 bits of randomness, shown once. The file holds only their SHA-256, is readable only by its owner, and is re-read whenever it changes, so a revoked or expired token stops working without a restart. A damaged file lets nobody in.
- **Roles.** The token's roles are the actor's roles. The request body cannot claim others. `--policy policy.json` replaces the built-in roles, and the server refuses to start with no policy.
- **Refusals** come back as `403` and are logged as `access_denied`. A refused registration or training run is `409` with the blockers. Unknown ids are `404`, bad input `400`, and nothing internal is ever shown (`500` says only "internal error").
- **Transport.** It listens on `127.0.0.1` by default. It will not listen on another address without `--tls-cert` and `--tls-key`, or `--behind-tls-proxy` if a proxy in front handles TLS, because tokens would otherwise cross the network in clear text.
- **No recordings.** Requests carry ids and hashes, never audio. Recordings are registered by `content_hash`.
- **Endpoints.** The list is at the top of `src/comot/server.py`: participants, consents, recordings, artifacts, use and training checks, withdrawals, actions, receipts, integrity, export, anchor and identity.

Requests are handled one at a time. That is plenty for consent traffic and is what keeps the single-writer rules simple.


## What this does and does not protect against

Comot makes tampering **detectable** and misuse **refusable**. It cannot make a file undeletable or a person trustworthy, and it says so:

- **Someone who owns the database file** can delete it, or rewrite it consistently. Opening a store checks every hash chain and every stored object against the log, so edits are caught. A complete rewrite is caught by anchors published before it (see above), so the strength of that is the strength of where you keep them. Deletion of the file is a backup question.
- **Code that holds the `Comot` object** can read `comot.log` or `comot.consents` directly, because it is in the same process. Run it behind the HTTP server, or give each pipeline only the narrow wrapper it needs.
- **Authentication** is the token file. Anyone who can read it cannot recover tokens, but anyone who can write to it can add one. Protect it like the signing key.
- **Keys.** A lost vault key means a lost vault. A lost signing key stops new signatures but does not affect the chains.
- **Schema.** There is no migration between schema versions yet: a database from an older version is refused rather than misread.
- **Scale.** One host, one file, state in memory. See the measurements above.
- **The law.** None of this is legal advice. See [legal-notes.md](legal-notes.md).
