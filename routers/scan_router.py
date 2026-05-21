# backend/routers/scan_router.py
import uuid
import logging
from enterprise.audit_store import write_audit
from enterprise.pattern_store import write_pattern
from enterprise.validation import scan_patterns

logger = logging.getLogger(__name__)
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from database import get_db
from auth import get_optional_user, get_current_user
import db_models
from models import ScanRequest, ScanResult, ScanHistoryItem, ScanHistoryResponse
from analyzer import analyze_message
from typing import Optional

router = APIRouter(tags=["Scans"])

MESSAGE_NOT_STORED = "[Message content not stored]"


@router.post("/scan", response_model=ScanResult)
async def scan(
    message: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: Optional[db_models.User] = Depends(get_optional_user),
):
    """Analyze a message or uploaded file for fraud signals."""

    image_bytes = None
    image_media_type = None
    request_id = uuid.uuid4().hex[:16]

    if file:
        image_bytes = await file.read()
        image_media_type = file.content_type

    if not message and not image_bytes:
        raise HTTPException(status_code=400, detail="Please provide a message or upload a file")

    try:
        result = await analyze_message(
            message=message,
            image_bytes=image_bytes,
            image_media_type=image_media_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    # Save scan to DB — user_id is None for anonymous scans
    if current_user:
        scan_record = db_models.Scan(
            user_id=current_user.id,
            message=MESSAGE_NOT_STORED,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            summary=result.summary,
            reasons=result.reasons,
            action=result.action,
            what_to_do=result.what_to_do,
            pass1_blocked=result.pass1_blocked,
        )
        db.add(scan_record)
        db.commit()

    # ── Enterprise: Write audit + pattern data (metadata only, non-blocking) ──
    try:
        _pattern_count, _fired = scan_patterns(message or "") if message else (0, [])

        write_audit(
            request_id=request_id,
            risk_score=result.risk_score,
            risk_band=_score_to_band(result.risk_score),
            detected_language="en",
            provider_used="gemini",
            source="web_app",
        )
        write_pattern(
            request_id=request_id,
            risk_band=_score_to_band(result.risk_score),
            fired_patterns=_fired,
            detected_language="en",
            source="web_app",
        )
    except Exception as e:
        logger.warning("Enterprise audit write failed (non-fatal): %s", str(e))

    return result


@router.post("/scan/json", response_model=ScanResult)
async def scan_json(
    body: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[db_models.User] = Depends(get_optional_user),
):
    """Analyze a text message (JSON body) for fraud signals."""
    request_id = uuid.uuid4().hex[:16]
    try:
        result = await analyze_message(body.message)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    if current_user:
        scan_record = db_models.Scan(
            user_id=current_user.id,
            message=MESSAGE_NOT_STORED,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            summary=result.summary,
            reasons=result.reasons,
            action=result.action,
            what_to_do=result.what_to_do,
            pass1_blocked=result.pass1_blocked,
        )
        db.add(scan_record)
        db.commit()

    # ── Enterprise audit ──
    try:
        _count, _fired = scan_patterns(body.message)
        write_audit(request_id=request_id, risk_score=result.risk_score,
                    risk_band=_score_to_band(result.risk_score), source="web_app")
        write_pattern(request_id=request_id, risk_band=_score_to_band(result.risk_score),
                      fired_patterns=_fired, source="web_app")
    except Exception:
        pass

    return result


@router.get("/scans/history", response_model=ScanHistoryResponse)
def get_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: db_models.User = Depends(get_current_user),  # must be logged in
):
    """Get scan history for the current authenticated user."""
    query = db.query(db_models.Scan).filter(db_models.Scan.user_id == current_user.id)

    total = query.count()
    scans = (
        query.order_by(db_models.Scan.scanned_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return ScanHistoryResponse(
        total=total,
        page=page,
        page_size=page_size,
        scans=[
            ScanHistoryItem(
                id=s.id,
                user_id=s.user_id,
                message=s.message,
                risk_score=s.risk_score,
                risk_level=s.risk_level,
                summary=s.summary,
                reasons=s.reasons,
                action=s.action,
                what_to_do=s.what_to_do,
                pass1_blocked=s.pass1_blocked,
                scanned_at=s.scanned_at,
            )
            for s in scans
        ],
    )


def _score_to_band(score: int) -> str:
    """Map ShieldIQ's existing score to enterprise risk bands."""
    if score <= 30:
        return "SAFE"
    elif score <= 69:
        return "CAUTION"
    else:
        return "HIGH_RISK"
