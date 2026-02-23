from datetime import datetime
from pydoc import importfile
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.models import Scan
from app.db.session import get_db

from app.scanner.security import validate_domain, sanitize_input

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


def normalize_input(input: str) -> str:
    input_sanitized = sanitize_input(input)
    domain = validate_domain(input_sanitized)
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

    #scan engine
    
    
    return ScanResponse(scan_id=scan_id, status="queued")


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    #Ruft Scan-Details anhand der Scan-ID ab.
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan
