"""Defaults shared by settings and the alerting package (kept import-light to avoid cycles with app.config)."""

# Techniques considered "critical" for automatic CERT-In-clock alerts: post-compromise or high-impact behaviour.
# Parent ids also cover their sub-techniques (T1070 matches T1070.001). T1110 (brute force) is intentionally absent:
# on internet-facing hosts it is constant background noise, and a high anomaly score on it alone is not an incident.
# Add it (LOGUNIFY_ALERT_CRITICAL_TECHNIQUES) if your threat model says otherwise.
DEFAULT_CRITICAL_TECHNIQUES = (
    "T1003,T1021,T1041,T1048,T1059,T1068,T1070,T1071,T1078,T1098,T1133,T1190,T1485,T1486,T1490,T1562,T1567")
