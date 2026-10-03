"""Perimeter hardening: client identity, brute-force lockout, request-rate limiting, body-size cap, security headers.

All state is in memory and per process (a limiter in front of N replicas counts per replica); it is a speed bump for
guessing and floods, not a WAF. Put a real reverse proxy / WAF in front for internet exposure.

* client_ip(): the TCP peer, or, when the peer is a TRUSTED PROXY (LOGUNIFY_TRUSTED_PROXIES), the right-most X-Forwarded-For
  entry that is not itself a trusted proxy. X-Forwarded-For from untrusted peers is ignored, so it cannot be spoofed to evade limits.
* FailureLimiter: N failures inside a window lock the key for a while. Used for MACHINE credentials that can be guessed in bulk
  (alert API key, HTTP source tokens). Keyed by (client, target), so a legitimate device is not locked out by an attacker elsewhere.
  Human JWT logins are not hard-locked (a shared proxy address would lock everyone); their denials are audit-sampled instead.
* RequestRateLimiter: fixed-window requests/minute per client (optional, LOGUNIFY_RATE_LIMIT_PER_MIN, 0 = off).
* BodyLimitMiddleware: 413 for bodies over LOGUNIFY_MAX_BODY_BYTES, checked from Content-Length and while streaming.
* SecurityHeadersMiddleware: nosniff, frame denial, no referrer, no-store on API responses, optional HSTS behind TLS.
"""
import ipaddress
import json
import threading
import time
from collections import OrderedDict, deque


def _nets(csv: str):
    out = []
    for part in (csv or "").split(","):
        part = part.strip()
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return out


class Hardening:
    def __init__(self, settings):
        self.trusted = _nets(settings.trusted_proxies)
        self.keys = FailureLimiter(settings.auth_fail_max, settings.auth_fail_window_s, settings.auth_lock_s)
        self.rate = RequestRateLimiter(settings.rate_limit_per_min) if settings.rate_limit_per_min > 0 else None

    def _trusted(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.trusted)

    def client_ip(self, scope_or_request) -> str:
        """Works for a Starlette Request or a raw ASGI scope."""
        scope = getattr(scope_or_request, "scope", scope_or_request)
        peer = (scope.get("client") or ("-", 0))[0]
        if not self.trusted or not self._trusted(peer):
            return peer
        xff = [v for k, v in scope.get("headers", []) if k == b"x-forwarded-for"]
        if xff:
            for hop in reversed([h.strip() for h in xff[-1].decode("latin-1").split(",") if h.strip()]):
                if not self._trusted(hop):
                    return hop
        return peer


class FailureLimiter:
    def __init__(self, max_failures: int = 10, window_s: float = 60, lock_s: float = 300, max_keys: int = 10_000):
        self.max, self.window, self.lock_s, self.max_keys = max_failures, window_s, lock_s, max_keys
        self._d: OrderedDict[object, list] = OrderedDict()           # key -> [deque(failure times), locked_until]
        self._lk = threading.Lock()

    def locked(self, key, now: float | None = None) -> float:
        """Seconds of lockout remaining (0 = not locked)."""
        now = time.monotonic() if now is None else now
        with self._lk:
            e = self._d.get(key)
            return max(0.0, e[1] - now) if e else 0.0

    def fail(self, key, now: float | None = None) -> bool:
        """Record one failure; True if the key is (now) locked."""
        now = time.monotonic() if now is None else now
        with self._lk:
            e = self._d.pop(key, None) or [deque(), 0.0]
            fails = e[0]
            while fails and now - fails[0] > self.window:
                fails.popleft()
            fails.append(now)
            if len(fails) >= self.max:
                e[1] = now + self.lock_s
                fails.clear()
            self._d[key] = e
            while len(self._d) > self.max_keys:                      # bounded memory: forget the oldest keys
                self._d.popitem(last=False)
            return e[1] > now

    def success(self, key) -> None:
        with self._lk:
            self._d.pop(key, None)


class RequestRateLimiter:
    def __init__(self, per_minute: int, max_keys: int = 50_000):
        self.limit, self.max_keys = per_minute, max_keys
        self._d: OrderedDict[str, list] = OrderedDict()               # client -> [window_start, count]
        self._lk = threading.Lock()

    def allow(self, client: str, now: float | None = None) -> tuple[bool, int]:
        now = time.monotonic() if now is None else now
        with self._lk:
            e = self._d.pop(client, None)
            if e is None or now - e[0] >= 60:
                e = [now, 0]
            e[1] += 1
            self._d[client] = e
            while len(self._d) > self.max_keys:
                self._d.popitem(last=False)
            return e[1] <= self.limit, max(1, int(60 - (now - e[0])))


# ------------------------------------------------------------------------------------------------ ASGI middleware
async def _json(send, status: int, body: dict, extra: list | None = None) -> None:
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()), *(extra or [])]})
    await send({"type": "http.response.body", "body": data})


class _TooLarge(BaseException):          # BaseException on purpose: FastAPI turns body-read Exceptions into a 400
    pass


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app, self.max = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.max <= 0:
            return await self.app(scope, receive, send)
        for k, v in scope["headers"]:
            if k == b"content-length":
                try:
                    if int(v) > self.max:
                        return await _json(send, 413, {"detail": f"request body larger than {self.max} bytes"})
                except ValueError:
                    return await _json(send, 400, {"detail": "bad content-length"})
        seen = 0

        async def counted():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max:
                    raise _TooLarge()
            return msg

        started = False

        async def tracked(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)

        try:
            await self.app(scope, counted, tracked)
        except _TooLarge:
            if not started:
                await _json(send, 413, {"detail": f"request body larger than {self.max} bytes"})


class RateLimitMiddleware:
    _SKIP = ("/health", "/ready", "/api/v1/stream/")

    def __init__(self, app, hardening: Hardening):
        self.app, self.h = app, hardening

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.h.rate is not None and not scope["path"].startswith(self._SKIP):
            ok, retry = self.h.rate.allow(self.h.client_ip(scope))
            if not ok:
                return await _json(send, 429, {"detail": "rate limit exceeded"}, [(b"retry-after", str(retry).encode())])
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool = False):
        self.app, self.hsts = app, hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        api = scope["path"].startswith("/api/")

        async def wrapped(msg):
            if msg["type"] == "http.response.start":
                have = {k.lower() for k, _ in msg["headers"]}
                add = [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"), (b"referrer-policy", b"no-referrer"),
                       (b"cross-origin-resource-policy", b"same-origin"), (b"permissions-policy", b"geolocation=(), camera=(), microphone=()")]
                if api:
                    add.append((b"cache-control", b"no-store"))
                if self.hsts:
                    add.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                msg["headers"] = list(msg["headers"]) + [h for h in add if h[0] not in have]
            await send(msg)

        await self.app(scope, receive, wrapped)
