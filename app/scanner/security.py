from urllib.parse import urlsplit
import ipaddress
import re


MAX_INPUT_LENGTH = 200

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

def validate_domain(input_sanitized: str) -> str:
    parsed_input = urlsplit(input_sanitized)

    if parsed_input.username or parsed_input.password:
        raise ValueError("Username or password in domain not allowed")

    domain = parsed_input.hostname
    if not domain:
        raise ValueError("Invalid domain")
    
    if domain == "localhost":
        raise ValueError("localhost is not allowed")

    try:
        ip = ipaddress.ip_address(domain)
        ValueError("IP Address not allowed")
    except:
        pass
        
    return domain


