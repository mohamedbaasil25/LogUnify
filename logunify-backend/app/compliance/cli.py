"""One-shot report for cron / CI:  python -m app.compliance.cli [--out DIR]   (exit 1 if any control is a GAP)"""
import argparse
import sys

from ..config import Settings
from ..main import create_app
from .scheduler import write_report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", help="output directory (default LOGUNIFY_COMPLIANCE_REPORT_DIR)")
    a = ap.parse_args(argv)
    s = Settings(**({"compliance_report_dir": a.out} if a.out else {}))
    app = create_app(s)
    from . import report
    rep = report.build(s, app.state.pipeline, app.state.audit)
    path = write_report(s, app.state.pipeline, app.state.audit, rep)
    print(f"wrote {path} (+ .json)  sha256={rep['report_sha256']}")
    for fw, c in rep["summary"].items():
        print(f"  {fw}: {c}")
    return 1 if any(c["gap"] for c in rep["summary"].values()) else 0


if __name__ == "__main__":
    sys.exit(main())
