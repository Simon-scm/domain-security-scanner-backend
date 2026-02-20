from fastapi import APIRouter
from pydantic import BaseModel
import uuid

router = APIRouter()

class ScanRequest(BaseModel):
    domain: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str

@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    return ScanResponse(scan_id=scan_id, status="queued")

