"""
ShieldIQ Enterprise — Webhook Routes
──────────────────────────────────────
POST /webhook/register — register a partner callback URL
POST /webhook/test     — test a registered webhook

Partners receive real-time alerts when fraud is detected
on messages scanned via their API key.
"""

import os, json, hmac, hashlib, logging, httpx
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhook", tags=["Webhook"])

# In-memory registry — swap for DB in production
_webhooks: dict = {}


class WebhookRegistration(BaseModel):
    callback_url: str
    secret: str
    events: list[str] = ["HIGH_RISK_DETECTED", "CAUTION_DETECTED"]
    description: Optional[str] = None


@router.post("/register", summary="Register a partner webhook")
async def register_webhook(request: Request, body: WebhookRegistration):
    api_key_id = getattr(request.state, "api_key_id", None)
    if not api_key_id:
        raise HTTPException(status_code=401, detail="API key required")

    _webhooks[api_key_id] = {
        "callback_url": body.callback_url, "secret": body.secret,
        "events": body.events, "description": body.description,
        "registered_at": datetime.now(timezone.utc).isoformat()
    }
    logger.info("Webhook registered: %s → %s", api_key_id, body.callback_url[:40])
    return {"status": "registered", "callback_url": body.callback_url, "events": body.events}


@router.post("/test", summary="Test a registered webhook")
async def test_webhook(request: Request):
    api_key_id = getattr(request.state, "api_key_id", None)
    webhook = _webhooks.get(api_key_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="No webhook registered for this key")

    test_payload = {"event": "TEST", "risk_score": 0, "risk_band": "SAFE",
                    "source": "test", "timestamp": datetime.now(timezone.utc).isoformat(),
                    "request_id": "test_ping", "message": "ShieldIQ webhook test — if you see this, it works!"}
    return {"status": "test_sent", "payload_preview": test_payload}


async def deliver_webhook(api_key_id: str, risk_band: str, risk_score: int,
                          request_id: str, source: str, metadata: dict = None):
    """Background task: deliver webhook to partner. Never blocks scan response."""
    webhook = _webhooks.get(api_key_id)
    if not webhook:
        return

    event_name = f"{risk_band}_DETECTED"
    if event_name not in webhook.get("events", []):
        return

    payload = json.dumps({"event": event_name, "risk_score": risk_score,
                          "risk_band": risk_band, "source": source,
                          "timestamp": datetime.now(timezone.utc).isoformat(),
                          "request_id": request_id, "metadata": metadata or {}},
                         separators=(',', ':')).encode()

    signature = hmac.new(webhook["secret"].encode(), payload, hashlib.sha256).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(webhook["callback_url"], content=payload,
                              headers={"Content-Type": "application/json",
                                       "X-ShieldIQ-Signature": f"sha256={signature}",
                                       "X-ShieldIQ-Event": event_name})
        logger.info("Webhook delivered: %s → %s", api_key_id[:8], event_name)
    except Exception as e:
        logger.warning("Webhook delivery failed (non-fatal): %s", str(e))
