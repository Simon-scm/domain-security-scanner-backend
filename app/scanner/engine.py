from multiprocessing import Value
from this import d
import httpx
from app.scanner.security import resolve_validate_domain, validate_input
from urllib.parse import urljoin, urlsplit



def make_request(domain):
    redirect_status = {301, 302, 303, 307, 308}
    redirect_count = 0
    current_url = f'https://{domain}/'

    with httpx.Client(
            max_redirects=5,
            timeout=5.0,
            follow_redirects=False
        ) as client:
            # Check if underlying ip is valid/safe
            ips = resolve_validate_domain(domain)
            r = client.head(current_url)

            # Follow and track redirects
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
                    

        


   