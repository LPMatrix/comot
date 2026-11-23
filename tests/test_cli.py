import json

from comot.cli import main


def run(*args):
    return main([str(a) for a in args])


def test_full_database_workflow(tmp_path, capsys):
    key, db, anchors, bundle = tmp_path / "k", tmp_path / "d.db", tmp_path / "a.jsonl", tmp_path / "b.json"
    assert run("keygen", key) == 0
    assert run("demo", "--db", db, "--key-file", key) == 0
    assert run("check", db, "--key-file", key) == 0
    assert run("anchor", db, "--key-file", key, "--out", anchors) == 0
    assert run("anchor", db, "--key-file", key, "--out", anchors) == 0  # nothing new, still fine
    assert len(anchors.read_text().splitlines()) == 1
    assert run("check", db, "--key-file", key, "--anchors", anchors) == 0
    assert run("export", db, "--key-file", key, "--out", bundle) == 0
    assert run("verify", bundle, "--key-file", key, "--anchors", anchors) == 0
    assert "signature valid" in capsys.readouterr().out


def test_check_fails_when_the_anchor_file_disagrees(tmp_path, capsys):
    key, db, anchors = tmp_path / "k", tmp_path / "d.db", tmp_path / "a.jsonl"
    run("keygen", key)
    run("demo", "--db", db, "--key-file", key)
    run("anchor", db, "--key-file", key, "--out", anchors)
    line = json.loads(anchors.read_text())
    line["head"] = "0" * 63 + "1"
    anchors.write_text(json.dumps(line) + "\n")
    capsys.readouterr()
    assert run("check", db, "--key-file", key, "--anchors", anchors) == 1
    assert "rewritten" in capsys.readouterr().out


def test_a_different_key_is_refused(tmp_path, capsys):
    k1, k2, db = tmp_path / "k1", tmp_path / "k2", tmp_path / "d.db"
    run("keygen", k1)
    run("keygen", k2)
    run("demo", "--db", db, "--key-file", k1)
    capsys.readouterr()
    assert run("check", db, "--key-file", k2) == 2
    assert "different signing key" in capsys.readouterr().out


# ------------------------------------------------------- keys, rotation and tokens

import os
import stat

import pytest

from comot import Comot, IdentityVault, load_key_file, load_signer


def test_keygen_makes_an_ed25519_key_by_default_and_shows_only_the_public_half(tmp_path, capsys):
    key = tmp_path / "k"
    assert run("keygen", key) == 0
    out = capsys.readouterr().out
    assert "ed25519" in out and "public key" in out
    assert run("pubkey", key) == 0
    public = capsys.readouterr().out.strip()
    assert public.startswith("ed25519:") and public in out
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert run("keygen", key) == 2  # will not overwrite


def test_an_hmac_key_has_no_public_half(tmp_path, capsys):
    key = tmp_path / "h"
    assert run("keygen", key, "--algorithm", "hmac") == 0
    assert "shared secret" in capsys.readouterr().out
    assert run("pubkey", key) == 2


def test_an_auditor_verifies_a_bundle_with_only_the_public_key(tmp_path, capsys):
    key, db, bundle = tmp_path / "k", tmp_path / "d.db", tmp_path / "b.json"
    run("keygen", key)
    capsys.readouterr()
    run("pubkey", key)
    public = capsys.readouterr().out.strip()
    run("demo", "--db", db, "--key-file", key)
    run("export", db, "--key-file", key, "--out", bundle)
    capsys.readouterr()
    assert run("verify", bundle, "--public-key", public) == 0
    assert "signature valid" in capsys.readouterr().out
    other = tmp_path / "other"
    run("keygen", other)
    capsys.readouterr()
    assert run("verify", bundle, "--public-key", other) == 1  # a private key file also works as the source
    assert "does not hold" in capsys.readouterr().out


def test_demo_prints_a_way_to_verify_its_own_bundle(tmp_path, capsys):
    db, key, bundle = tmp_path / "d.db", tmp_path / "k", tmp_path / "b.json"
    run("demo", "--db", db, "--key-file", key, "--export", bundle)
    line = [l for l in capsys.readouterr().out.splitlines() if l.startswith("verify it with:")][0]
    assert "--public-key ed25519:" in line


def public_key_of(capsys, key):
    capsys.readouterr()
    run("pubkey", key)
    return capsys.readouterr().out.strip()


def test_rotating_the_signing_key_end_to_end(tmp_path, capsys):
    old, new, db, bundle = tmp_path / "old", tmp_path / "new", tmp_path / "d.db", tmp_path / "b.json"
    run("keygen", old)
    run("keygen", new)
    run("demo", "--db", db, "--key-file", old)
    capsys.readouterr()
    assert run("check", db, "--key-file", new) == 2  # not yet: the old key is unknown to it
    assert "different signing key" in capsys.readouterr().out
    assert run("rotate-key", db, "--key-file", new, "--retired-key", old) == 0
    assert "1 rotation(s) on record" in capsys.readouterr().out
    assert run("check", db, "--key-file", new) == 2  # the new key alone no longer holds the old one
    assert "lacks earlier signing keys" in capsys.readouterr().out
    assert run("check", db, "--key-file", new, "--retired-key", old) == 0
    assert run("export", db, "--key-file", new, "--retired-key", old, "--out", bundle) == 0
    public_new, public_old = public_key_of(capsys, new), public_key_of(capsys, old)
    capsys.readouterr()
    # The demo's receipts were signed with the old key and the bundle with the new one, so
    # an auditor needs both public keys, and holding only one is reported, not ignored.
    assert run("verify", bundle, "--public-key", public_new) == 1
    assert "receipt" in capsys.readouterr().out
    assert run("verify", bundle, "--public-key", public_old) == 1
    assert "does not hold" in capsys.readouterr().out


def test_a_public_half_is_enough_to_keep_a_retired_key(tmp_path, capsys):
    old, new, db, pub = tmp_path / "old", tmp_path / "new", tmp_path / "d.db", tmp_path / "old.pub"
    run("keygen", old)
    run("keygen", new)
    run("demo", "--db", db, "--key-file", old)
    pub.write_text(public_key_of(capsys, old) + "\n")  # all that is kept of the old key
    old.unlink()
    assert run("rotate-key", db, "--key-file", new, "--retired-key", pub) == 0
    assert run("check", db, "--key-file", new, "--retired-key", pub) == 0


def test_vault_rotation_through_the_cli(tmp_path, capsys):
    pytest.importorskip("cryptography")
    key, db, vault_path = tmp_path / "k", tmp_path / "d.db", tmp_path / "v.db"
    vkey, vnew = tmp_path / "vk", tmp_path / "vk2"
    run("keygen", key)
    run("keygen", vkey, "--kind", "vault")
    run("keygen", vnew, "--kind", "vault")
    v = IdentityVault(vault_path, load_key_file(vkey))
    v.put("p_1", name="Amina")
    v.close()
    run("demo", "--db", db, "--key-file", key)
    capsys.readouterr()
    assert run("vault-rotate", db, vault_path, "--key-file", key, "--vault-key", vkey, "--new-vault-key", vnew) == 0
    assert "re-encrypted" in capsys.readouterr().out
    assert IdentityVault(vault_path, load_key_file(vnew)).get("p_1") == {"name": "Amina"}
    c = Comot.open(db, signer=load_signer(key))
    assert [e.actor_id for e in c.log.entries if e.event_type == "vault_key_rotated"] == ["cli"]
    c.close()


def test_tokens_are_made_shown_once_and_revoked(tmp_path, capsys):
    tokens = tmp_path / "t.json"
    assert run("token-new", "--tokens", tokens, "--actor", "chw_1", "--role", "health_worker", "--days", "30") == 0
    captured = capsys.readouterr()
    token = captured.out.strip()
    assert token.startswith("cmt_") and "only time" in captured.err
    assert token not in tokens.read_text() and stat.S_IMODE(os.stat(tokens).st_mode) == 0o600
    with pytest.raises(SystemExit):  # a token with no role is not a thing
        run("token-new", "--tokens", tokens, "--actor", "chw_2")
    capsys.readouterr()
    assert run("token-revoke", "--tokens", tokens, "--actor", "chw_1") == 0
    assert "removed 1" in capsys.readouterr().out
    assert json.loads(tokens.read_text())["tokens"] == []


def test_serve_needs_an_access_policy_and_refuses_open_networks(tmp_path, capsys):
    key, db, tokens = tmp_path / "k", tmp_path / "d.db", tmp_path / "t.json"
    run("keygen", key)
    run("demo", "--db", db, "--key-file", key)
    run("token-new", "--tokens", tokens, "--actor", "a", "--role", "dpo")
    capsys.readouterr()
    assert run("serve", db, "--key-file", key, "--tokens", tokens, "--host", "0.0.0.0", "--port", "0") == 2
    assert "clear text" in capsys.readouterr().out
