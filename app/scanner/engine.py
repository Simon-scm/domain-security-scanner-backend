from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Value
from this import d
import httpx
from app.scanner.security import resolve_validate_domain, validate_input
from urllib.parse import urljoin
from pydantic import BaseModel

# TODO: Add pydantic model for response data and error handling
class RedirectHop(BaseModel):
    from_url: str
    to_url: str
    status_code: int
    resolved_ips: set[str]
    blocked: bool
    block_reason: str | None      

class RequestResponse(BaseModel):
    success: bool
    error_type: str | None
    error_message: str | None

    requested_url: str
    last_attempted_url: str
    redirect_chain: list[RedirectHop] = []

    final_url: str | None
    status_code: int | None
    headers: list[tuple[str, str]] | None
    response_size: int | None
    final_ip_versions: set[str] | None
    connection_time_ms: int | None
    tls_used: bool
    tls_version: str | None
    certificate_valid: bool | None

def handle_redirect(r, redirect_count, current_url, redirect_status, client) -> list[RedirectHop]:
     # TODO: Track and save visited urls and their responses
    redirect_chain = []
    while r.status_code in redirect_status and redirect_count < client.max_redirects:
        location = r.headers.get("location")
        if not location:
            raise ValueError("redirect location not set")

        next_url = urljoin(current_url, location)
        new_domain = validate_input(next_url)
        ips = ips.union(resolve_validate_domain(new_domain))

        try:
            r = client.head(next_url)
            current_url = next_url
            redirect_count = redirect_count + 1
        except httpx.RequestError as e:
            raise ValueError(f"Request error: {str(e)}")

    return redirect_chain     


def make_request(domain):
    redirect_status = {301, 302, 303, 307, 308}
    redirect_count = 0
    current_url = f'https://{domain}/'

    requestResponse = RequestResponse(
        success=False,
        error_type=None,
        error_message=None,
        requested_url=current_url,
        last_attempted_url=current_url,
        redirect_chain=[],
        final_url=None,
        status_code=None,
        headers=None,
        response_size=None,
        final_ip_versions=None,
        connection_time_ms=None,
        tls_used=False,
        tls_version=None,
        certificate_valid=None
    )  
    
    with httpx.Client(
            max_redirects=5,
            timeout=5.0,
            follow_redirects=False
        ) as client:
            # Check if underlying ip is valid/safe
            ips = resolve_validate_domain(domain)
            r = client.head(current_url)

            # Follow and track redirects
            requestResponse.redirect_chain = handle_redirect(r, redirect_count, current_url, redirect_status, client)
                    

        


   