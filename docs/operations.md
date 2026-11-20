# Running Comot

Notes for whoever operates a Comot database: how it is stored, how identity is kept apart, and how to make tampering with the audit log detectable. For what Comot is and how to use it from code, see the [README](../README.md).

## Persistence

Everything lives in one SQLite file. It is in the standard library, easy to back up, and enough for a small team. The store sits behind a small interface, so a PostgreSQL backend can replace it for a larger service.

- **Atomic.** Each Comot call is one transaction. A withdrawal that fails halfway leaves no new consent version, no half-made actions and no stray log entries, and the in-memory state is rebuilt to match.
- **Append-only in the database itself.** Triggers abort any `UPDATE` or `DELETE` on consent versions, the audit log, lineage edges, receipts, refusals, anchors and participants. They stop mistakes and casual edits. They do not stop someone who owns the file and can drop a trigger, which is what the hash chains and anchors are for.
- **Checked when opened.** Opening a database re-verifies the consent chain, the audit log and any stored anchors, and refuses a store that fails with `StoreIntegrityError`. `Comot.open(..., verify=False)` opens it anyway so an auditor can look.
- **More than one process.** Each write takes SQLite's write lock before it reads, and checks refresh from the database, so a second process sees a withdrawal the moment it is committed.
- **Private by default.** The database and key files are created readable only by their owner.

```bash
uv run comot demo --db demo.db --key-file demo.key   # the demo, kept in a database
uv run comot check demo.db --key-file demo.key       # verify chains and anchors
uv run comot export demo.db --key-file demo.key --out demo.bundle.json
```

## Identity vault

The consent database never holds a name or phone number. Those go in a separate vault: its own SQLite file with its own key, so it can be backed up, locked down and erased on its own.

```python
from comot import Comot, HmacSigner, IdentityVault, load_key_file

vault = IdentityVault("vault.db", load_key_file("vault.key"))   # a different key from the signing key
comot = Comot.open("comot.db", signer=HmacSigner.from_file("signing.key"), vault=vault)

comot.store_identity(pid, actor="chw_17", name="...", phone="...")
comot.read_identity(pid, actor="dpo_1")         # every read is logged against who made it
comot.delete_identity(pid, actor="dpo_1")       # consent records and audit log are untouched
```

Records are encrypted with AES-256-GCM and bound to their participant id, so a ciphertext copied onto another row will not open. Only a fixed set of fields is accepted (name, phone, guardian name and phone), so the vault cannot become a place for health data. The audit log records that identity was stored, read or deleted, and by whom, never what it held.

## Anchoring the audit log

A hash chain alone cannot stop someone with write access from rewriting the whole log from the first changed entry onward and recomputing every hash. Anchoring closes that gap: now and then you publish the log's current head hash somewhere the database's writers cannot edit, and anything rewritten before that point no longer matches.

```bash
uv run comot anchor comot.db --key-file signing.key --out anchors.jsonl   # run daily, for example from cron
uv run comot check comot.db --key-file signing.key --anchors anchors.jsonl
```

Keep `anchors.jsonl` somewhere else: another machine, a write-once volume, or a public repository the community board can see. An anchor protects everything before it, so anchor often. A quiet system does not anchor itself in circles; the command does nothing if nothing happened since the last anchor.

## Access control

Comot does not authenticate anyone. Your service or pipeline authenticates the caller and passes in an `Actor(id, roles)`; Comot checks that one of those roles allows the call. Without an access policy, any named actor may do anything, which is fine for a notebook and wrong for a service.

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
- It does not authenticate. A caller who can build an `Actor("x", {"dpo"})` can claim any role, so build actors only from your own verified sign-in.
- It guards Comot's methods. Code that holds the `Comot` object can still read `comot.log` or `comot.consents` directly, and anyone who owns the database file can read it. Keep the object behind your service and the file's permissions tight.
- Refusals are logged, so a caller who can reach Comot can add refusals to the log. They cost space, not integrity.
- The command line tools open the database directly and run without a policy, because whoever has the file and the key can do all of this anyway.

## Limits

These apply to everything above. They are also listed in the [README](../README.md#status).

- An anchor protects the log only up to the moment it was published. Something rewritten after the last anchor goes unnoticed until the next one.
- The database triggers stop mistakes and casual edits, not someone who owns the file and can drop a trigger.
- Losing the signing key loses the ability to verify receipts and exports. Losing the vault key loses the vault. There is no key rotation yet.
- SQLite suits one host and a small team. There is no schema migration yet: a database from an older schema version is refused.
- Access control is only as good as the authentication in front of it, and it guards methods, not the database file.
