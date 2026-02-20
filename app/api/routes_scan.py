from datetime import datetime
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.models import Scan
from app.db.session import get_db

from urllib.parse import urlsplit


MAX_INPUT_LENGTH = 200

router = APIRouter()


class ScanRequest(BaseModel):
    domain: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str


class ScanDetailResponse(BaseModel):
    id: str
    domain: str
    status: str
    created_at: datetime
    score: int | None
    result_json: str | None
    warning: str | None

def sanitize_input(raw: str) -> str:
    if not raw:
        return ""

    # Trim and lowercase
    cleaned = raw.strip().lower()

    # Remove control characters (ASCII < 32 and DEL)
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", cleaned)

    # Normalize whitespace (multiple spaces -> single space)
    cleaned = re.sub(r"\s+", " ", cleaned)

    # Enforce max length
    if len(cleaned) > MAX_INPUT_LENGTH:
        cleaned = cleaned[:MAX_INPUT_LENGTH]

    return cleaned


def normalize_input(input: str) -> str:
    input_sanitized = sanitize_input(input)
    
    parsed_input = urlsplit(input_sanitized)

    if parsed_input.username or parsed_input.password:
        raise ValueError("Username or password in domain not allowed")

    domain = parsed_input.hostname
    if not domain:
        raise ValueError("Invalid domain")

    return [domain, input_sanitized]



@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    #Erstellt einen neuen Scan-Eintrag in der Datenbank.
    scan_id = str(uuid.uuid4())
    normalized_input = normalize_input(request.domain)
    normalized_domain = normalized_input[0]
    input_sanitized = normalized_input[1]

    #Warning eintragen falls Path/Query/Fragment im Input enthalten sind.
    sanitized_parts = urlsplit(input_sanitized)
    if sanitized_parts.path or sanitized_parts.query or sanitized_parts.fragment:
        warning_message = "Input contained path/query/fragment. Only the hostname was scanned."
    else:
        warning_message = None
    
    scan = Scan(
        id=scan_id,
        domain=normalized_domain,
        input_sanitized=input_sanitized,
        status="queued",
        created_at=datetime.utcnow(),
        warning=warning_message
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    return ScanResponse(scan_id=scan_id, status="queued")


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    #Ruft Scan-Details anhand der Scan-ID ab.
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan
