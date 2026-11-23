"""A small HTTP API around Comot, so access control has a real boundary.

Inside one process, code that holds the ``Comot`` object can read anything. Behind
this server the object stays in the server's own process, every request must carry
a bearer token, the token names an ``Actor``, and the access policy decides what
that actor may do. Only the standard library is used.

Serve it on localhost, or put TLS in front of it: tokens travel in a header.

    POST /v1/participants
    POST /v1/participants/{id}/consents
    POST /v1/recordings
    POST /v1/artifacts
    POST /v1/use-checks
    POST /v1/training-runs
    POST /v1/withdrawals
    GET  /v1/withdrawals/{id}/actions
    GET  /v1/withdrawals/{id}/coverage
    POST /v1/withdrawals/{id}/receipts
    POST /v1/actions/{id}/complete
    GET  /v1/actions/overdue
    POST /v1/actions/escalate
    GET  /v1/integrity
    GET  /v1/export
    POST /v1/anchor
    PUT|GET|DELETE /v1/participants/{id}/identity
    GET  /v1/health                    (no token needed)
"""
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .access import AccessDenied, Actor
from .anchor import AnchorSink
from .auth import TokenAuthenticator
from .core import Comot
from .errors import ComotError, ConsentRefused, TrainingBlocked, UnknownObject
from .receipt import render_receipt
from .vault import VaultError

MAX_BODY = 1 << 20  # 1 MiB: requests carry ids and hashes, never recordings


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


def _need(body: dict[str, Any], *names: str) -> list[Any]:
    missing = [n for n in names if n not in body]
    if missing:
        raise ApiError(400, f"missing field(s): {', '.join(missing)}")
    return [body[n] for n in names]


Route = tuple[str, "re.Pattern[str]", Callable[..., Any]]


class _Api:
    """The operations, one method each. Each is called with the authenticated actor."""

    def __init__(self, comot: Comot, anchor_sink: AnchorSink | None):
        self.c = comot
        self.sink = anchor_sink

    def create_participant(self, actor: Actor, body: dict[str, Any]):
        pid, code = self.c.create_participant(actor=actor)
        return 201, {"participant_id": pid, "code": code}

    def record_consent(self, actor: Actor, body: dict[str, Any], pid: str):
        project_id, answers = _need(body, "project_id", "answers")
        optional = {
            k: body[k]
            for k in ("teach_back_score", "is_minor", "guardian_consent", "assent", "guardian_verification", "transfer_risk_explained")
            if k in body
        }
        script_version, language, capture_method, device_id = _need(body, "script_version", "language", "capture_method", "device_id")
        record = self.c.record_consent(
            pid, project_id, answers, script_version=script_version, language=language,
            capture_method=capture_method, device_id=device_id, actor=actor, **optional,
        )
        return 201, record.to_dict()

    def register_recording(self, actor: Actor, body: dict[str, Any]):
        participant_id, project_id = _need(body, "participant_id", "project_id")
        a = self.c.register_recording(
            participant_id, project_id, content_hash=body.get("content_hash"),
            storage_uri=body.get("storage_uri"), actor=actor,
        )
        return 201, a.to_dict()

    def register_artifact(self, actor: Actor, body: dict[str, Any]):
        type_, parents, purpose = _need(body, "type", "parents", "purpose")
        extra = {k: body[k] for k in ("content_hash", "storage_uri", "holder", "sharded", "destination_country", "transfer_basis") if k in body}
        return 201, self.c.register(type_, parents, purpose, actor=actor, **extra).to_dict()

    def check_use(self, actor: Actor, body: dict[str, Any]):
        artifact_id, purpose = _need(body, "artifact_id", "purpose")
        d = self.c.check_use(artifact_id, purpose, actor=actor)
        return 200, {"allowed": d.allowed, "blockers": [list(b) for b in d.blockers]}

    def training_run(self, actor: Actor, body: dict[str, Any]):
        (ids,) = _need(body, "artifact_ids")
        r = self.c.check_training_run(ids, actor=actor, strict=bool(body.get("strict", True)))
        return 200, {"run_id": r.run_id, "ok": r.ok, "allowed": r.allowed, "blocked": [list(b) for b in r.blocked]}

    def withdraw(self, actor: Actor, body: dict[str, Any]):
        project_id, channel = _need(body, "project_id", "channel")
        w = self.c.withdraw(
            project_id, participant_id=body.get("participant_id"), code=body.get("code"),
            scope=body.get("scope", "all"), channel=channel, actor=actor,
        )
        actions = [a.to_dict() for a in self.c.actions_for(w.withdrawal_id, actor=actor)]
        return 201, {**w.to_dict(), "actions": actions}

    def _known(self, wid: str) -> None:
        self.c.refresh()  # another process may have made it
        if wid not in self.c.withdrawals:
            raise UnknownObject(f"unknown withdrawal {wid!r}")

    def actions(self, actor: Actor, body: dict[str, Any], wid: str):
        self._known(wid)
        return 200, {"actions": [a.to_dict() for a in self.c.actions_for(wid, actor=actor)]}

    def coverage(self, actor: Actor, body: dict[str, Any], wid: str):
        self._known(wid)
        return 200, {"coverage": self.c.coverage(wid, actor=actor)}

    def issue_receipt(self, actor: Actor, body: dict[str, Any], wid: str):
        self._known(wid)
        r = self.c.issue_receipt(wid, actor=actor)
        return 201, {**r.to_dict(), "rendered": render_receipt(r)}

    def complete_action(self, actor: Actor, body: dict[str, Any], aid: str):
        (evidence,) = _need(body, "evidence")
        return 200, self.c.complete_action(aid, actor=actor, evidence=evidence).to_dict()

    def overdue(self, actor: Actor, body: dict[str, Any]):
        return 200, {"actions": [a.to_dict() for a in self.c.overdue_actions(actor=actor)]}

    def escalate(self, actor: Actor, body: dict[str, Any]):
        return 200, {"escalated": [a.to_dict() for a in self.c.escalate_overdue(actor=actor)]}

    def integrity(self, actor: Actor, body: dict[str, Any]):
        problems = self.c.verify_integrity(actor=actor)
        return 200, {"intact": not problems, "problems": problems}

    def export(self, actor: Actor, body: dict[str, Any]):
        return 200, self.c.export_bundle(actor=actor)

    def anchor(self, actor: Actor, body: dict[str, Any]):
        if self.sink is None:
            raise ApiError(501, "this server has no anchor file configured")
        a = self.c.anchor(self.sink, actor=actor)
        return 200, {"anchored": a is not None, "anchor": a.to_dict() if a else None}

    def put_identity(self, actor: Actor, body: dict[str, Any], pid: str):
        self.c.store_identity(pid, actor=actor, **body)
        return 204, None

    def get_identity(self, actor: Actor, body: dict[str, Any], pid: str):
        data = self.c.read_identity(pid, actor=actor)
        if data is None:
            raise UnknownObject("no identity is stored for this participant")
        return 200, data

    def delete_identity(self, actor: Actor, body: dict[str, Any], pid: str):
        return 200, {"deleted": self.c.delete_identity(pid, actor=actor)}


def _routes(api: _Api) -> list[Route]:
    seg = r"([A-Za-z0-9_\-]+)"
    table = [
        ("POST", r"/v1/participants", api.create_participant),
        ("POST", rf"/v1/participants/{seg}/consents", api.record_consent),
        ("POST", r"/v1/recordings", api.register_recording),
        ("POST", r"/v1/artifacts", api.register_artifact),
        ("POST", r"/v1/use-checks", api.check_use),
        ("POST", r"/v1/training-runs", api.training_run),
        ("POST", r"/v1/withdrawals", api.withdraw),
        ("GET", rf"/v1/withdrawals/{seg}/actions", api.actions),
        ("GET", rf"/v1/withdrawals/{seg}/coverage", api.coverage),
        ("POST", rf"/v1/withdrawals/{seg}/receipts", api.issue_receipt),
        ("POST", rf"/v1/actions/{seg}/complete", api.complete_action),
        ("GET", r"/v1/actions/overdue", api.overdue),
        ("POST", r"/v1/actions/escalate", api.escalate),
        ("GET", r"/v1/integrity", api.integrity),
        ("GET", r"/v1/export", api.export),
        ("POST", r"/v1/anchor", api.anchor),
        ("PUT", rf"/v1/participants/{seg}/identity", api.put_identity),
        ("GET", rf"/v1/participants/{seg}/identity", api.get_identity),
        ("DELETE", rf"/v1/participants/{seg}/identity", api.delete_identity),
    ]
    return [(m, re.compile(p + r"$"), fn) for m, p, fn in table]


class ComotServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128  # the default of 5 drops connections when a clinic's phones all sync at once

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A failed handshake or a dropped connection is routine; say so in one line."""
        exc = sys.exc_info()[1]
        sys.stderr.write(f"{client_address[0]}: connection ended ({type(exc).__name__})\n")

    def __init__(
        self,
        address: tuple[str, int],
        comot: Comot,
        auth: TokenAuthenticator,
        *,
        anchor_sink: AnchorSink | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
    ):
        if comot.access is None:
            raise ValueError("a server needs an access policy, or every token would be all-powerful")
        self.auth = auth
        self.lock = threading.Lock()  # Comot is not thread-safe, so requests take turns
        self.routes = _routes(_Api(comot, anchor_sink))
        super().__init__(address, _Handler)
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile, keyfile)
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


class _Handler(BaseHTTPRequestHandler):
    server: ComotServer
    protocol_version = "HTTP/1.1"
    server_version = "comot"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # one quiet line per request, never the token
        sys.stderr.write(f"{self.address_string()} {self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}\n")

    def _send(self, status: int, payload: Any) -> None:
        data = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "request body too large")
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            raise ApiError(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise ApiError(400, "body must be a JSON object")
        return body

    def _handle(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/"
        try:
            if self.command == "GET" and path == "/v1/health":
                return self._send(200, {"status": "ok"})
            actor = self.server.auth.authenticate(self.headers.get("Authorization"))
            if actor is None:
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                body = json.dumps({"error": "a valid bearer token is required"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")  # the request body was not read
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
                return
            body = self._body()
            for method, pattern, fn in self.server.routes:
                m = pattern.match(path)
                if m and method == self.command:
                    with self.server.lock:
                        status, payload = fn(actor, body, *m.groups())
                    return self._send(status, payload)
            if any(p.match(path) for _, p, _ in self.server.routes):
                raise ApiError(405, "method not allowed")
            raise ApiError(404, "no such endpoint")
        except ApiError as e:
            self._send(e.status, {"error": e.message, **e.extra})
        except AccessDenied as e:
            self._send(403, {"error": str(e), "operation": e.operation})
        except (ConsentRefused, TrainingBlocked) as e:
            self._send(409, {"error": str(e), "blockers": [list(b) for b in e.blockers]})
        except UnknownObject as e:
            self._send(404, {"error": str(e)})
        except (ComotError, ValueError, TypeError, VaultError) as e:
            self._send(400, {"error": str(e)})
        except Exception:  # never show internals to a caller
            traceback.print_exc()
            self._send(500, {"error": "internal error"})

    do_GET = do_POST = do_PUT = do_DELETE = _handle


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(
    comot: Comot,
    auth: TokenAuthenticator,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    anchor_sink: AnchorSink | None = None,
    certfile: str | None = None,
    keyfile: str | None = None,
    behind_tls_proxy: bool = False,
) -> ComotServer:
    """Build the server. Refuses to listen beyond localhost without TLS, since tokens would cross the network in clear."""
    if not is_loopback(host) and not certfile and not behind_tls_proxy:
        raise ValueError(
            "tokens would cross the network in clear text: give a TLS certificate and key, "
            "or pass behind_tls_proxy=True if a proxy in front terminates TLS"
        )
    return ComotServer((host, port), comot, auth, anchor_sink=anchor_sink, certfile=certfile, keyfile=keyfile)
