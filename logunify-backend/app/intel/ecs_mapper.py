"""Map Drain3-extracted template parameters to ECS field names using the word that precedes each slot."""
import ipaddress
import re

from .template_miner import Mined

_PLACEHOLDER = re.compile(r"<(IP|NUM|\*)>")
_SKIP = {"=", ":", "invalid", "illegal", "unknown", "the", "a", "of"}
_SRC_IP = {"from", "src", "source", "client", "remote", "srcip", "rhost"}
_DST_IP = {"to", "dst", "dest", "destination", "target", "server", "dstip"}
_USER = {"user", "for", "by", "account", "username", "login", "uid"}
_HOST = {"host", "hostname", "on", "at", "node"}
_FILE = {"file", "path", "opening", "reading", "writing"}
_PROC = {"process", "service", "daemon", "command", "cmd"}


def _prev_word(tokens: list[str], idx: int) -> str:
    for j in range(idx - 1, -1, -1):
        w = tokens[j].strip("[]():,").lower()
        if w and w not in _SKIP:
            return w
    return ""


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def map_to_ecs(m: Mined) -> dict:
    """Return a flat {ecs.field: value} dict. Only fields we can name with reasonable confidence.

    Drain3 returns one parameter per placeholder in template order, so every placeholder consumes a slot,
    including ones embedded in a larger token (e.g. 'db-<*>'); only standalone placeholders are mapped.
    """
    out: dict = {}
    last_dir = "source"                 # direction of the most recent IP, so 'port N' follows its IP
    slot = 0
    for i, tok in enumerate(m.tokens):
        for kind in _PLACEHOLDER.findall(tok):
            if slot >= len(m.params):
                return out
            value = m.params[slot][1]
            slot += 1
            if tok != f"<{kind}>":
                continue
            prev = _prev_word(m.tokens, i)

            if kind == "IP":
                if not _valid_ip(value):
                    continue
                last_dir = "destination" if prev in _DST_IP else "source" if prev in _SRC_IP else \
                    ("destination" if "source.ip" in out else "source")
                out.setdefault(f"{last_dir}.ip", value)
            elif value.isdigit():
                n = int(value)
                if prev == "port" and 0 < n < 65536:
                    out.setdefault(f"{last_dir}.port", n)
                elif prev.startswith("pid") or prev == "process":
                    out.setdefault("process.pid", n)
                elif prev in ("status", "code", "response") and 100 <= n < 600:
                    out.setdefault("http.response.status_code", n)
                elif prev in ("bytes", "size", "sent", "received"):
                    out.setdefault("network.bytes", n)
            elif kind == "*":
                for names, field in ((_USER, "user.name"), (_HOST, "host.name"),
                                     (_FILE, "file.path"), (_PROC, "process.name")):
                    if prev in names:
                        out.setdefault(field, value)
                        break
    return out
