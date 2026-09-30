"""Periodic report files: `<dir>/compliance-<utc>.json` + `.pdf`, so a retention/control history exists without anyone asking."""
import asyncio
import json
import logging
import time
from pathlib import Path

from . import report

log = logging.getLogger("logunify.compliance")


def write_report(settings, pipeline, audit, rep: dict | None = None) -> Path:
    rep = rep or report.build(settings, pipeline, audit)
    d = Path(settings.compliance_report_dir)
    d.mkdir(parents=True, exist_ok=True)
    stem = "compliance-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    (d / f"{stem}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    (d / f"{stem}.pdf").write_bytes(report.render_pdf(rep))
    return d / f"{stem}.pdf"


async def run(settings, pipeline, audit) -> None:
    every = settings.compliance_report_interval_hours * 3600
    while True:
        try:
            path = await asyncio.to_thread(write_report, settings, pipeline, audit)
            audit.append("system", "system", "internal", "compliance.scheduled_report", str(path.name))
            log.info("compliance report written: %s", path)
        except Exception:
            log.exception("scheduled compliance report failed")
        await asyncio.sleep(every)
