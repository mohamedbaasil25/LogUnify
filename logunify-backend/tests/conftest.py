import os
import tempfile

# Set before `app` is imported anywhere: keep test runs from writing data/audit.db
os.environ.setdefault("LOGUNIFY_AUDIT_DB_PATH", ":memory:")
os.environ.setdefault("LOGUNIFY_STATE_DB_PATH", ":memory:")
os.environ.setdefault("LOGUNIFY_AUTH_DB_PATH", ":memory:")
os.environ.setdefault("LOGUNIFY_DLQ_PATH", os.path.join(tempfile.mkdtemp(prefix="logunify-test-"), "dlq.jsonl"))   # parse failures are dead-lettered, not dropped
