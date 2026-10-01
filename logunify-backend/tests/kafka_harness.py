"""Starts a real single-node Kafka (KRaft) from a local Kafka distribution so the no-loss tests run against a real broker.

Looks for the distribution in $LOGUNIFY_KAFKA_HOME or ../logunify-flink/tools/kafka_*; tests skip when Java or Kafka is missing.
Windows notes: bind to 127.0.0.1 (IPv6 loopback is broken here) and start with `java -cp libs/*` (the .bat scripts overflow).
"""
import base64
import glob
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

PORT, CTRL = 19092, 19093


def find_kafka() -> Path | None:
    cands = [os.environ.get("LOGUNIFY_KAFKA_HOME", "")] + glob.glob(str(Path(__file__).resolve().parents[2] / "logunify-flink" / "tools" / "kafka_*"))
    for c in cands:
        if c and (Path(c) / "libs").is_dir():
            return Path(c)
    return None


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


class Broker:
    def __init__(self, home: Path):
        self.home = home
        self.dir = Path(tempfile.mkdtemp(prefix="logunify-kafka-"))
        self.proc: subprocess.Popen | None = None
        self.cfg = self.dir / "server.properties"
        self.cfg.write_text("\n".join([
            "process.roles=broker,controller", "node.id=1", f"controller.quorum.voters=1@127.0.0.1:{CTRL}",
            f"listeners=PLAINTEXT://127.0.0.1:{PORT},CONTROLLER://127.0.0.1:{CTRL}",
            f"advertised.listeners=PLAINTEXT://127.0.0.1:{PORT}", "controller.listener.names=CONTROLLER",
            "listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT", "inter.broker.listener.name=PLAINTEXT",
            f"log.dirs={(self.dir / 'data').as_posix()}", "offsets.topic.replication.factor=1",
            "transaction.state.log.replication.factor=1", "transaction.state.log.min.isr=1", "num.partitions=3",
            "group.initial.rebalance.delay.ms=0", "auto.create.topics.enable=true", "log.flush.interval.messages=1"]) + "\n")
        self.cp = f"{(home / 'libs').as_posix()}/*"
        cid = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        subprocess.run(["java", "-cp", self.cp, "kafka.tools.StorageTool", "format", "-t", cid, "-c", str(self.cfg)],
                       check=True, capture_output=True, timeout=120)

    def start(self, timeout: float = 90) -> None:
        self.proc = subprocess.Popen(["java", "-Xmx512m", "-cp", self.cp, "kafka.Kafka", str(self.cfg)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + timeout
        while time.time() < end:
            if _port_open(PORT):
                time.sleep(2.0)                      # port open != controller ready
                return
            if self.proc.poll() is not None:
                raise RuntimeError("Kafka exited during startup")
            time.sleep(0.3)
        raise RuntimeError("Kafka did not start in time")

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(30)
        end = time.time() + 20
        while _port_open(PORT) and time.time() < end:
            time.sleep(0.2)

    def close(self) -> None:
        self.kill()
        shutil.rmtree(self.dir, ignore_errors=True)
