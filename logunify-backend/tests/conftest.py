import os

# Set before `app` is imported anywhere: keep test runs from writing data/audit.db
os.environ.setdefault("LOGUNIFY_AUDIT_DB_PATH", ":memory:")
os.environ.setdefault("LOGUNIFY_STATE_DB_PATH", ":memory:")
