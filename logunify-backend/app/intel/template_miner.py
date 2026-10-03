"""Online template mining with Drain3 (in memory; `export_state` / `import_state` let the state store persist it)."""
import re
from dataclasses import dataclass, field

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.persistence_handler import PersistenceHandler
from drain3.template_miner_config import TemplateMinerConfig

_IP = r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.){3}\d{1,3}((?=[^A-Za-z0-9])|$)"
_NUM = r"((?<=[^A-Za-z0-9.\-_/])|^)\d+((?=[^A-Za-z0-9.\-_/])|$)"     # standalone numbers only (not db-01, v2.3)
_KV = re.compile(r"(?<=\w)=(?=\S)")     # user=bob -> user = bob so the value becomes its own token


class _Slot(PersistenceHandler):
    """Hands Drain3's own snapshot bytes to / from the caller instead of a file or Kafka."""
    def __init__(self):
        self.state = None

    def save_state(self, state):
        self.state = state

    def load_state(self):
        return self.state


@dataclass
class Mined:
    cluster_id: int
    template: str
    is_new: bool
    cluster_size: int
    params: list[tuple[str, str]] = field(default_factory=list)   # (mask_name, value) in template order
    tokens: list[str] = field(default_factory=list)               # template tokens (for context lookup)


class TemplateMinerService:
    def __init__(self, sim_th: float = 0.4, depth: int = 4, max_clusters: int = 2000):
        cfg = TemplateMinerConfig()
        cfg.drain_sim_th = sim_th
        cfg.drain_depth = depth
        cfg.drain_max_clusters = max_clusters          # LRU-evicts old templates: bounded memory
        cfg.masking_instructions = [MaskingInstruction(_IP, "IP"), MaskingInstruction(_NUM, "NUM")]
        self._tm = TemplateMiner(persistence_handler=None, config=cfg)
        self.total = 0

    @staticmethod
    def preprocess(text: str) -> str:
        return " ".join(_KV.sub(" = ", text).split())

    def mine(self, text: str) -> Mined:
        content = self.preprocess(text)
        r = self._tm.add_log_message(content)
        self.total += 1
        template = r["template_mined"]
        try:
            extracted = self._tm.extract_parameters(template, content, exact_matching=True) or []
        except Exception:                # exotic tokens can defeat the template regex; degrade to no params
            extracted = []
        return Mined(
            cluster_id=r["cluster_id"], template=template, is_new=r["change_type"] == "cluster_created",
            cluster_size=r["cluster_size"], params=[(p.mask_name, p.value) for p in extracted],
            tokens=template.split(),
        )

    def export_state(self) -> bytes:
        """Drain3 snapshot (jsonpickle, zlib, base64). Not thread-safe against `mine`: call it from the thread that mines."""
        slot = _Slot()
        self._tm.persistence_handler = slot
        try:
            self._tm.save_state("logunify snapshot")
        finally:
            self._tm.persistence_handler = None
        return slot.state

    def import_state(self, state: bytes) -> int:
        """Restore a snapshot made by `export_state`. SECURITY: jsonpickle can instantiate arbitrary classes, so callers must
        authenticate `state` (the state store checks an HMAC) before calling this. Returns the restored template count."""
        slot = _Slot()
        slot.state = state
        self._tm.persistence_handler = slot
        try:
            self._tm.load_state()
        finally:
            self._tm.persistence_handler = None
        self.total = self._tm.drain.get_total_cluster_size()
        return self.cluster_count

    def top_templates(self, n: int = 20) -> list[dict]:
        cl = sorted(self._tm.drain.clusters, key=lambda c: c.size, reverse=True)[:n]
        return [{"id": c.cluster_id, "count": c.size, "template": c.get_template()} for c in cl]

    @property
    def cluster_count(self) -> int:
        return len(self._tm.drain.clusters)
