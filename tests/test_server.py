import copy
import datetime
import http.client
import json
import ssl
import threading
import urllib.error
import urllib.request

import pytest

from comot import AccessPolicy, Comot, HmacSigner, IdentityVault, TokenAuthenticator, issue_token, make_server, revoke_tokens, verify_bundle
from comot.auth import AuthError
from conftest import ALL

pytest.importorskip("cryptography")

ROLES = {"chw": ["health_worker"], "team": ["data_team"], "dpo": ["dpo"], "auditor": ["auditor"], "board": ["board"]}


@pytest.fixture
def stack(tmp_path, clock):
    tokens_path = tmp_path / "tokens.json"
    tokens = {name: issue_token(tokens_path, f"{name}_1", roles, clock=clock) for name, roles in ROLES.items()}
    vault = IdentityVault(tmp_path / "vault.db", b"k" * 32)
    comot = Comot.open(tmp_path / "comot.db", signer=HmacSigner(b"s" * 32), clock=clock, access=AccessPolicy.default(), vault=vault)
    auth = TokenAuthenticator.load(tokens_path, clock)
    server = make_server(comot, auth, port=0)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield type("Stack", (), dict(base=base, tokens=tokens, comot=comot, server=server, path=tokens_path, auth=auth, clock=clock))
    server.shutdown()
    server.server_close()
    comot.close()
    vault.close()


def call(stack, method, path, body=None, token="chw", raw_token=None, context=None, base=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request((base or stack.base) + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    t = raw_token if raw_token is not None else stack.tokens.get(token)
    if t is not None:
        req.add_header("Authorization", f"Bearer {t}")
    try:
        with urllib.request.urlopen(req, context=context) as r:
            text = r.read()
            return r.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as e:
        text = e.read()
        return e.code, (json.loads(text) if text else None)


CONSENT = dict(project_id="p1", answers=ALL, script_version="t", language="pcm", capture_method="spoken_yes_no", device_id="d")


# ------------------------------------------------------------------ authentication


def test_health_needs_no_token(stack):
    assert call(stack, "GET", "/v1/health", token=None) == (200, {"status": "ok"})


@pytest.mark.parametrize("raw", [None, "", "nope", "cmt_" + "a" * 43])
def test_a_missing_or_wrong_token_is_401(stack, raw):
    status, body = call(stack, "POST", "/v1/participants", {}, token=None, raw_token=raw)
    assert status == 401 and "token" in body["error"]


def test_a_token_in_the_wrong_scheme_is_401(stack):
    req = urllib.request.Request(stack.base + "/v1/participants", data=b"{}", method="POST")
    req.add_header("Authorization", "Token " + stack.tokens["chw"])
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 401 and e.value.headers["WWW-Authenticate"] == "Bearer"


def test_nothing_happens_before_authentication(stack):
    before = len(stack.comot.log.entries)
    call(stack, "POST", "/v1/participants", {}, token=None)
    assert len(stack.comot.log.entries) == before  # not even a denial entry: the caller is unknown


def test_the_token_file_holds_only_hashes_and_is_private(stack):
    import os, stat

    text = stack.path.read_text()
    assert all(t not in text for t in stack.tokens.values())
    assert stat.S_IMODE(os.stat(stack.path).st_mode) == 0o600


def test_a_revoked_token_stops_working_at_once_without_a_restart(stack):
    assert call(stack, "POST", "/v1/participants", {})[0] == 201
    assert revoke_tokens(stack.path, "chw_1") == 1
    assert call(stack, "POST", "/v1/participants", {})[0] == 401
    assert call(stack, "POST", "/v1/participants", {}, token="team")[0] == 403  # others are untouched


def test_a_token_added_while_running_works(stack):
    new = issue_token(stack.path, "chw_2", ["health_worker"], clock=stack.clock)
    assert call(stack, "POST", "/v1/participants", {}, token=None, raw_token=new)[0] == 201


def test_an_expired_token_is_refused(stack):
    short = issue_token(stack.path, "temp_1", ["health_worker"], days=1, clock=stack.clock)
    assert call(stack, "POST", "/v1/participants", {}, token=None, raw_token=short)[0] == 201
    stack.clock.advance(days=2)
    assert call(stack, "POST", "/v1/participants", {}, token=None, raw_token=short)[0] == 401


def test_a_damaged_token_file_lets_nobody_in(stack):
    stack.path.write_text("{ not json")
    assert call(stack, "POST", "/v1/participants", {})[0] == 401
    assert stack.auth.error


def test_a_malformed_token_entry_is_refused():
    with pytest.raises(AuthError):
        TokenAuthenticator([{"id": "x", "sha256": "short", "roles": []}])
    with pytest.raises(AuthError):
        issue_token("/dev/null/x", "", [])


# ------------------------------------------------------------ roles over the wire


def test_the_token_decides_the_actor_whatever_the_body_says(stack):
    status, body = call(stack, "POST", "/v1/participants", {"actor": "dpo_1", "roles": ["dpo"]})
    assert status == 201
    created = [e for e in stack.comot.log.entries if e.event_type == "participant_created"]
    assert [e.actor_id for e in created] == ["chw_1"]


def test_a_role_without_the_grant_is_403_and_logged(stack):
    status, body = call(stack, "POST", "/v1/withdrawals", {"project_id": "p", "code": "000000", "channel": "chw"}, token="team")
    assert status == 403 and body["operation"] == "withdraw"
    denied = [e for e in stack.comot.log.entries if e.event_type == "access_denied"]
    assert [(e.actor_id, e.object_id) for e in denied] == [("team_1", "withdraw")]


def test_the_whole_working_flow_over_http(stack):
    s, p = call(stack, "POST", "/v1/participants", {})
    assert s == 201
    pid, code = p["participant_id"], p["code"]
    assert call(stack, "POST", f"/v1/participants/{pid}/consents", CONSENT)[0] == 201
    s, rec = call(stack, "POST", "/v1/recordings", {"participant_id": pid, "project_id": "p1", "content_hash": "ab" * 32})
    assert s == 201 and rec["type"] == "recording"
    s, tr = call(stack, "POST", "/v1/artifacts", {"type": "transcript", "parents": [rec["artifact_id"]], "purpose": "research"}, token="team")
    assert s == 201
    assert call(stack, "POST", "/v1/use-checks", {"artifact_id": tr["artifact_id"], "purpose": "research"}, token="team")[1]["allowed"]
    s, w = call(stack, "POST", "/v1/withdrawals", {"project_id": "p1", "code": code, "scope": ["research"], "channel": "participant_code"})
    assert s == 201 and w["actions"]
    after = call(stack, "POST", "/v1/use-checks", {"artifact_id": tr["artifact_id"], "purpose": "research"}, token="team")[1]
    assert after["allowed"] is False and after["blockers"]
    action = call(stack, "GET", f"/v1/withdrawals/{w['withdrawal_id']}/actions", token="team")[1]["actions"][0]
    assert call(stack, "POST", f"/v1/actions/{action['action_id']}/complete", {"evidence": "ticket"}, token="team")[1]["done_by"] == "team_1"
    assert call(stack, "GET", f"/v1/withdrawals/{w['withdrawal_id']}/coverage", token="board")[1] == {"coverage": 1.0}
    s, r = call(stack, "POST", f"/v1/withdrawals/{w['withdrawal_id']}/receipts")
    assert s == 201 and "rendered" in r and r["signature"]
    assert call(stack, "GET", "/v1/integrity", token="auditor")[1] == {"intact": True, "problems": []}
    s, bundle = call(stack, "GET", "/v1/export", token="auditor")
    assert s == 200 and verify_bundle(bundle, stack.comot.signer.key) == []


def test_a_blocked_training_run_is_409_with_the_blockers(stack):
    pid = call(stack, "POST", "/v1/participants", {})[1]["participant_id"]
    call(stack, "POST", f"/v1/participants/{pid}/consents", {**CONSENT, "answers": {"record": True, "research": True}})
    rec = call(stack, "POST", "/v1/recordings", {"participant_id": pid, "project_id": "p1"})[1]
    s, body = call(stack, "POST", "/v1/training-runs", {"artifact_ids": [rec["artifact_id"]]}, token="team")
    assert s == 409 and body["blockers"]
    s, body = call(stack, "POST", "/v1/training-runs", {"artifact_ids": [rec["artifact_id"]], "strict": False}, token="team")
    assert s == 200 and body["ok"] is False


def test_a_refused_registration_is_409(stack):
    pid = call(stack, "POST", "/v1/participants", {})[1]["participant_id"]
    call(stack, "POST", f"/v1/participants/{pid}/consents", {**CONSENT, "answers": {"record": True}})
    rec = call(stack, "POST", "/v1/recordings", {"participant_id": pid, "project_id": "p1"})[1]
    s, body = call(stack, "POST", "/v1/artifacts", {"type": "transcript", "parents": [rec["artifact_id"]], "purpose": "research"}, token="team")
    assert s == 409 and body["blockers"]


def test_identity_is_only_for_the_roles_that_may_hold_it(stack):
    pid = call(stack, "POST", "/v1/participants", {})[1]["participant_id"]
    assert call(stack, "PUT", f"/v1/participants/{pid}/identity", {"name": "Amina", "phone": "0801"})[0] == 204
    assert call(stack, "GET", f"/v1/participants/{pid}/identity")[0] == 403  # the health worker who stored it cannot read it back
    assert call(stack, "GET", f"/v1/participants/{pid}/identity", token="team")[0] == 403
    s, body = call(stack, "GET", f"/v1/participants/{pid}/identity", token="dpo")
    assert s == 200 and body["name"] == "Amina"
    assert [e.actor_id for e in stack.comot.log.entries if e.event_type == "identity_read"] == ["dpo_1"]
    assert call(stack, "DELETE", f"/v1/participants/{pid}/identity", token="dpo")[1] == {"deleted": True}
    assert call(stack, "GET", f"/v1/participants/{pid}/identity", token="dpo")[0] == 404


# --------------------------------------------------------------- bad requests


def test_unknown_endpoint_and_wrong_method(stack):
    assert call(stack, "GET", "/v1/nothing")[0] == 404
    assert call(stack, "GET", "/v1/participants")[0] == 405
    assert call(stack, "GET", "/v1/withdrawals/w_nope/actions", token="team")[0] == 404


def test_a_missing_field_is_400_and_names_it(stack):
    s, body = call(stack, "POST", "/v1/recordings", {"project_id": "p1"})
    assert s == 400 and "participant_id" in body["error"]


def test_bad_json_and_non_object_bodies_are_400(stack):
    for raw in (b"{not json", b"[1, 2]", b'"text"'):
        c = http.client.HTTPConnection("127.0.0.1", stack.server.server_address[1])
        c.request("POST", "/v1/participants", raw, {"Authorization": f"Bearer {stack.tokens['chw']}", "Content-Length": str(len(raw))})
        assert c.getresponse().status == 400
        c.close()


def test_an_oversized_body_is_refused_without_reading_it(stack):
    c = http.client.HTTPConnection("127.0.0.1", stack.server.server_address[1])
    c.putrequest("POST", "/v1/participants")
    c.putheader("Authorization", f"Bearer {stack.tokens['chw']}")
    c.putheader("Content-Length", str(5 << 20))
    c.endheaders()
    assert c.getresponse().status == 413
    c.close()


def test_unexpected_errors_do_not_leak_internals(stack, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail /etc/passwd")

    monkeypatch.setattr(stack.comot, "create_participant", boom)
    s, body = call(stack, "POST", "/v1/participants", {})
    assert s == 500 and body == {"error": "internal error"}


def test_responses_are_never_cached(stack):
    req = urllib.request.Request(stack.base + "/v1/health")
    with urllib.request.urlopen(req) as r:
        assert r.headers["Cache-Control"] == "no-store"


def test_requests_in_parallel_do_not_corrupt_anything(stack):
    results = []

    def go():
        results.append(call(stack, "POST", "/v1/participants", {}))

    threads = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert [s for s, _ in results] == [201] * 12
    assert len({b["code"] for _, b in results}) == 12 and stack.comot.verify_integrity(actor=__import__("comot").Actor("a", {"auditor"})) == []


# -------------------------------------------------------------- how it is exposed


def test_a_server_without_an_access_policy_is_refused(clock, tmp_path):
    auth = TokenAuthenticator([])
    with pytest.raises(ValueError, match="access policy"):
        make_server(Comot(clock=clock), auth, port=0)


def test_it_will_not_listen_beyond_localhost_without_tls(clock):
    comot = Comot(clock=clock, access=AccessPolicy.default())
    with pytest.raises(ValueError, match="clear text"):
        make_server(comot, TokenAuthenticator([]), host="0.0.0.0", port=0)
    s = make_server(comot, TokenAuthenticator([]), host="0.0.0.0", port=0, behind_tls_proxy=True)
    s.server_close()


def test_the_api_works_over_tls(clock, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "c.pem", tmp_path / "k.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    tokens = tmp_path / "t.json"
    token = issue_token(tokens, "chw_1", ["health_worker"], clock=clock)
    server = make_server(Comot(clock=clock, access=AccessPolicy.default()), TokenAuthenticator.load(tokens, clock),
                         port=0, certfile=str(certfile), keyfile=str(keyfile))
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True).start()
    port = server.server_address[1]
    try:
        ctx = ssl.create_default_context(cafile=str(certfile))
        req = urllib.request.Request(f"https://localhost:{port}/v1/participants", data=b"{}", method="POST",
                                     headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ctx) as r:
            assert r.status == 201
        with pytest.raises(Exception):  # plain HTTP to a TLS port gets nothing usable
            urllib.request.urlopen(f"http://localhost:{port}/v1/health", timeout=3)
    finally:
        server.shutdown()
        server.server_close()
