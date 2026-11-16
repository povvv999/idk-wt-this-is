"""Short-lived rendezvous. Device keys and approval protect the pairing payload."""
import base64
import collections
import math
import secrets
import time
import uuid

ALPHABET = "0123456789"
TTL = 300


def valid_key(value):
    return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32


def handle(handler):
    parts = handler.path.strip("/").split("/")
    public = parts[:2] == ["v1", "pairing"]
    host = len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3].startswith("pairing")
    if not public and not host:
        return False
    server = handler.server
    now = time.monotonic()
    room = None
    with server.lock:
        server.rooms = {key: item for key, item in server.rooms.items() if now - item.created < 7 * 86400}
        for item in server.rooms.values():
            if item.pairing and item.pairing["expires"] <= now:
                item.pairing = None
        if host:
            room = server.rooms.get(parts[2])
            if room is None or not handler.owns(room):
                handler.reply(404); return True
            if not handler.authorized(room.host_token):
                handler.reply(403); return True
        if public and handler.command == "POST":
            # Do not trust forwarded IP headers. A proxy shares this limit by default.
            server.pair_attempts = {ip: stamps for ip, stamps in server.pair_attempts.items() if stamps and now - stamps[-1] < 60}
            ip = handler.client_address[0]
            stamps = server.pair_attempts.get(ip, collections.deque())
            while stamps and now - stamps[0] >= 60:
                stamps.popleft()
            while server.pair_global and now - server.pair_global[0] >= 60:
                server.pair_global.popleft()
            if len(stamps) >= 12 or len(server.pair_global) >= 120:
                handler.reply(429); return True
            stamps.append(now); server.pair_attempts[ip] = stamps; server.pair_global.append(now)
    body = handler.read_body(16_384) if handler.command == "POST" else {}
    if not isinstance(body, dict):
        handler.reply(400); return True
    with server.lock:
        now = time.monotonic()
        if host:
            if server.rooms.get(room.id) is not room:
                handler.reply(410); return True
            operation = parts[3]
            if operation == "pairing" and handler.command == "POST":
                used = {item.pairing["code"] for item in server.rooms.values() if item.pairing}
                code = "".join(secrets.choice(ALPHABET) for _ in range(8))
                while code in used:
                    code = "".join(secrets.choice(ALPHABET) for _ in range(8))
                room.pairing = {"code": code, "expires": now + TTL, "request": None}
                handler.reply(201, {"code": code[:4] + " " + code[4:], "expiresIn": TTL}); return True
            invite = room.pairing
            if invite and invite["expires"] <= now:
                room.pairing = invite = None
            if operation == "pairing" and handler.command == "GET":
                request = invite and invite["request"]
                handler.reply(200, {
                    "invite": {"code": invite["code"][:4] + " " + invite["code"][4:], "expiresIn": math.ceil(invite["expires"] - now)} if invite and request is None else None,
                    "request": {"id": request["id"], "name": request["name"], "publicKey": request["publicKey"]} if request and request["status"] == "waiting" else None,
                }); return True
            request = invite and invite["request"]
            if handler.command != "POST" or not request or request["id"] != body.get("requestId"):
                handler.reply(410); return True
            if operation == "pairing-key" and request["status"] == "waiting":
                if not valid_key(body.get("publicKey")):
                    handler.reply(400); return True
                if request["hostPublicKey"] and request["hostPublicKey"] != body["publicKey"]:
                    handler.reply(409); return True
                request["hostPublicKey"] = body["publicKey"]
                handler.reply(204); return True
            if operation == "pairing-approve" and request["hostPublicKey"]:
                payload = body.get("payload")
                if not isinstance(payload, str) or not 28 <= len(base64.b64decode(payload, validate=True)) <= 8192:
                    handler.reply(400); return True
                if request["status"] == "approved" and request["payload"] == payload:
                    handler.reply(204); return True
                if request["status"] != "waiting":
                    handler.reply(409); return True
                request["payload"] = payload; request["status"] = "approved"
                handler.reply(204); return True
            if operation == "pairing-deny" and request["status"] == "waiting":
                request["status"] = "denied"
                handler.reply(204); return True
            handler.reply(409); return True

        if parts == ["v1", "pairing", "claim"] and handler.command == "POST":
            code, name, key = body.get("code"), body.get("name"), body.get("publicKey")
            if not isinstance(code, str) or not isinstance(name, str) or not 1 <= len(name) <= 64 or not valid_key(key):
                handler.reply(400); return True
            code = "".join(char for char in code if char != "-" and not char.isspace())
            if len(code) != 8 or any(char not in ALPHABET for char in code):
                handler.reply(400); return True
            room = next((item for item in server.rooms.values() if handler.owns(item) and item.pairing and item.pairing["expires"] > now and item.pairing["code"] == code and item.pairing["request"] is None), None)
            if room is None or not handler.owns(room):
                handler.reply(404); return True
            request = {"id": str(uuid.uuid4()), "token": secrets.token_urlsafe(32), "name": name,
                       "publicKey": key, "hostPublicKey": None, "payload": None, "status": "waiting"}
            room.pairing["request"] = request
            handler.reply(201, {"id": request["id"], "token": request["token"]}); return True
        if len(parts) == 4 and parts[:3] == ["v1", "pairing", "requests"]:
            request = next((item.pairing["request"] for item in server.rooms.values() if handler.owns(item) and item.pairing and item.pairing["expires"] > now and item.pairing["request"] and item.pairing["request"]["id"] == parts[3]), None)
            if request is None:
                handler.reply(410); return True
            if not handler.authorized(request["token"]):
                handler.reply(401); return True
            if handler.command == "GET":
                handler.reply(200, {"status": request["status"], "hostPublicKey": request["hostPublicKey"], "payload": request["payload"]}); return True
            if handler.command == "DELETE" and request["status"] == "waiting":
                request["status"] = "denied"
                handler.reply(204); return True
        handler.reply(404); return True


REMOTE_TTL = 180      # a remote-connect request must finish within three minutes
OTP_WINDOW = 600      # the emailed code must have been confirmed in the last ten minutes
ONLINE_WINDOW = 45    # a Mac counts as online for this long after it last checked in


def handle_remote(handler):
    """Pro: connect to an online Mac without anyone touching it.

    The Mac checks in regularly. The phone, after confirming a code emailed to the
    account, asks for that Mac. The Mac then starts a session and reports its pairing
    code, which the phone uses with the normal encrypted pairing handshake.
    """
    import hmac
    parts = handler.path.strip("/").split("/")
    if parts[:2] not in (["v1", "hosts"], ["v1", "remote"]) or (parts == ["v1", "hosts"] and handler.command == "POST"):
        return False
    server = handler.server
    bearer = handler.headers.get("Authorization", "").removeprefix("Bearer ")
    body = handler.read_body(4096) if handler.command == "POST" else {}
    if not isinstance(body, dict):
        handler.reply(400); return True
    profile = None
    if parts == ["v1", "remote", "requests"] and handler.command == "POST":
        try:
            profile = server.profile(handler.headers.get("X-Roamdesk-Account-Token", ""))
        except Exception:
            handler.reply(503); return True

    def mine(host):
        return server.allow_anonymous or host["account"] == handler.account_id

    with server.lock:
        now = time.monotonic()
        server.remote = {key: item for key, item in server.remote.items() if now - item["created"] < REMOTE_TTL}
        if parts == ["v1", "hosts"] and handler.command == "GET":
            hosts = [{"id": host["id"], "name": host["name"], "online": now - host.get("seen", -1e9) < ONLINE_WINDOW,
                      "remote": bool(host.get("remote"))} for host in server.hosts.values() if mine(host) and host.get("name")]
            handler.reply(200, {"hosts": hosts}); return True
        if parts == ["v1", "hosts", "presence"] and handler.command == "POST":
            host = server.hosts.get(bearer)
            name = body.get("name")
            if host is None or not mine(host):
                handler.reply(401); return True
            if not isinstance(name, str) or not 1 <= len(name) <= 100:
                handler.reply(400); return True
            host["name"] = name; host["seen"] = now; host["remote"] = body.get("remote") is True
            waiting = next((item for item in server.remote.values() if item["host"] == host["id"] and item["status"] == "verified"), None)
            handler.reply(200, {"request": {"id": waiting["id"]} if waiting and host["remote"] else None}); return True
        if parts == ["v1", "remote", "requests"] and handler.command == "POST":
            if profile["plan"] not in ("pro", "teams"):
                handler.reply(402, {"error": "Remote connect needs Pro"}); return True
            if time.time() - profile["otp_at"] > OTP_WINDOW:
                handler.reply(428, {"error": "Confirm the emailed code first"}); return True
            host = next((item for item in server.hosts.values() if item["id"] == body.get("hostId") and mine(item)), None)
            if host is None:
                handler.reply(404); return True
            if now - host.get("seen", -1e9) >= ONLINE_WINDOW or not host.get("remote"):
                handler.reply(409, {"error": "That Mac is offline"}); return True
            while server.remote_attempts and now - server.remote_attempts[0] >= 3600:
                server.remote_attempts.popleft()
            if len(server.remote_attempts) >= 60:
                handler.reply(429); return True
            server.remote_attempts.append(now)
            server.remote = {key: item for key, item in server.remote.items() if item["host"] != host["id"]}
            request = {"id": str(uuid.uuid4()), "token": secrets.token_urlsafe(32), "host": host["id"],
                       "status": "verified", "created": now, "code": None}
            server.remote[request["id"]] = request
            handler.reply(201, {"id": request["id"], "token": request["token"]}); return True
        if len(parts) == 4 and parts[:3] == ["v1", "remote", "requests"] and handler.command == "GET":
            request = server.remote.get(parts[3])
            if request is None or not hmac.compare_digest(bearer.encode(), request["token"].encode()):
                handler.reply(404); return True
            handler.reply(200, {"status": request["status"], "code": request["code"]}); return True
        if len(parts) == 5 and parts[:3] == ["v1", "remote", "requests"] and parts[4] == "ready" and handler.command == "POST":
            host = server.hosts.get(bearer)
            request = server.remote.get(parts[3])
            if host is None or not mine(host) or request is None or request["host"] != host["id"]:
                handler.reply(404); return True
            room = server.rooms.get(body.get("session")) if isinstance(body.get("session"), str) else None
            if room is None or room.owner != host["id"] or not room.pairing or room.pairing["expires"] <= now:
                handler.reply(409); return True
            code = room.pairing["code"]
            request["status"] = "ready"; request["code"] = code[:4] + " " + code[4:]
            handler.reply(204); return True
    handler.reply(405); return True
