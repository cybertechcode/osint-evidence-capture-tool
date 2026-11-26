"""netguard.py - shared URL safety check (blocks private/loopback/link-local targets)."""
import socket
import ipaddress
from urllib.parse import urlparse


def is_allowed_url(url, allow_private=False):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    if allow_private:
        return True
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True
