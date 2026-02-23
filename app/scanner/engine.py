from multiprocessing import Value
from this import d
import httpx
from app.scanner.security import resolve_domain




def make_request(domain):
    valid_redirect_status = [301, 302, 303, 307, 308]
    ip = resolve_domain(domain)


   