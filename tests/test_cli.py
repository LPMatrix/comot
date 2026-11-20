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
