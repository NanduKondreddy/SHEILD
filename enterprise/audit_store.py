"""
ShieldIQ Enterprise — Audit Trail Store
────────────────────────────────────────
Records every scan verdict (metadata only — never message content).
Provides aggregate queries for the admin dashboard and reports.

Zero-Retention Compliance:
  - Message content is NEVER passed to or stored by this module
  - Only verdict metadata (score, band, language, latency, source)
  - GDPR/privacy safe by design
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Path for flat-file storage — swap for PostgreSQL in production
AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data_store", "audit")
os.makedirs(AUDIT_DIR, exist_ok=True)

AUDIT_FILE = os.path.join(AUDIT_DIR, "audit_log.jsonl")


def write_audit(
    request_id: str,
    risk_score: int,
    risk_band: str,
    detected_language: str = "en",
    provider_used: str = "gemini",
    latency_ms: int = 0,
    source: str = "web_app",
    was_overridden: bool = False,
    fraud_type: Optional[str] = None,
    api_key_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> None:
    """
    Write a single audit record. This NEVER receives message content.
    """
    record = {
        "request_id":       request_id,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "risk_score":       risk_score,
        "risk_band":        risk_band,
        "detected_language": detected_language,
        "provider_used":    provider_used,
        "latency_ms":       latency_ms,
        "source":           source,
        "was_overridden":   was_overridden,
        "fraud_type":       fraud_type,
        "api_key_id":       api_key_id,
        "org_id":           org_id,
    }

    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        logger.error("Audit write failed (non-fatal): %s", str(e))


def _read_records(days: int = 30, org_id: Optional[str] = None) -> list:
    """Read audit records from the JSONL file, filtered by time and optionally by org."""
    if not os.path.exists(AUDIT_FILE):
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    records = []

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    ts = datetime.fromisoformat(rec["timestamp"])
                    if ts >= cutoff:
                        if org_id and rec.get("org_id") != org_id:
                            continue
                        records.append(rec)
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception as e:
        logger.error("Audit read failed: %s", str(e))

    return records


def get_user_history(
    api_key_id: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    days: int = 30
) -> dict:
    """Get scan history filtered by API key (for partner access)."""
    all_records = _read_records(days=days)

    if api_key_id:
        all_records = [r for r in all_records if r.get("api_key_id") == api_key_id]

    total = len(all_records)
    # Sort newest first
    all_records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    page = all_records[offset:offset + limit]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "records": page
    }


def get_admin_summary(days: int = 30, org_id: Optional[str] = None) -> dict:
    """
    Returns aggregate dashboard metrics. Admin only.
    """
    records = _read_records(days=days, org_id=org_id)

    if not records:
        return {
            "total_scans": 0,
            "by_band": {"SAFE": 0, "CAUTION": 0, "HIGH_RISK": 0},
            "by_source": {},
            "by_language": {},
            "avg_latency_ms": 0,
            "confirmed_fraud_reports": 0,
        }

    by_band = {"SAFE": 0, "CAUTION": 0, "HIGH_RISK": 0}
    by_source = {}
    by_language = {}
    total_latency = 0
    overrides = 0

    for r in records:
        band = r.get("risk_band", "SAFE")
        by_band[band] = by_band.get(band, 0) + 1

        source = r.get("source", "unknown")
        by_source[source] = by_source.get(source, 0) + 1

        lang = r.get("detected_language", "en")
        by_language[lang] = by_language.get(lang, 0) + 1

        total_latency += r.get("latency_ms", 0)
        if r.get("was_overridden"):
            overrides += 1

    return {
        "total_scans": len(records),
        "by_band": by_band,
        "by_source": by_source,
        "by_language": by_language,
        "avg_latency_ms": total_latency // max(len(records), 1),
        "confirmed_fraud_reports": overrides,
        "override_rate_pct": round(overrides / max(len(records), 1) * 100, 1),
    }
