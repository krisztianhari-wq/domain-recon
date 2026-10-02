"""Könnyű szolgáltatás-ujjlenyomatozás a nyitott portokon.

  - banner : kis TCP-banner (ami magától szól, pl. SSH/FTP/SMTP), írás nélkül.
  - http   : HTTP(S) HEAD/GET – Server-fejléc + <title>.
  - tls    : a tanúsítvány CN / SAN / lejárat (kiegészítő host-felderítéshez is: SAN-ból új nevek).

Minden kíméletes: rövid időtúllépés, méretkorlát, csak olvasás.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time

from .ports import HTTP_PORTS, TLS_PORTS

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_SERVER = re.compile(r"^server:\s*(.+)$", re.I | re.M)
_BANNER_MAX = 512
_HTTP_MAX = 65536


async def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str | None:
    """Passzív banner: csatlakozás után rövid ideig olvasunk (sok szolgáltatás magától köszön)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        data = await asyncio.wait_for(reader.read(_BANNER_MAX), timeout=timeout)
        txt = data.decode("latin-1", "replace").strip()
        txt = "".join(c for c in txt if c.isprintable() or c in "\t")
        return txt[:200] or None
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def probe_http(host: str, ip: str, port: int, tls: bool, timeout: float = 6.0) -> dict | None:
    """HTTP(S) próba az IP-n, a hostnév Host-fejléccel (vhost). -> {status, server, title} vagy None."""
    scheme = "https" if tls else "http"

    def _sync():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = raw
        try:
            if tls:
                sock = ctx.wrap_socket(raw, server_hostname=host)
            req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: domain-recon/1.0 (+sadrobot)\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n").encode()
            sock.sendall(req)
            buf = b""
            while len(buf) < _HTTP_MAX:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
            return buf
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

    try:
        buf = await asyncio.wait_for(asyncio.to_thread(_sync), timeout=timeout + 2)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    if not buf:
        return None
    head, _, body = buf.partition(b"\r\n\r\n")
    head_txt = head.decode("latin-1", "replace")
    status = None
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head_txt)
    if m:
        status = int(m.group(1))
    headers: dict[str, str] = {}
    for line in head_txt.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if v:
            headers[k.strip().lower()] = v.strip()
    server = headers.get("server", "")[:120] or None
    body_txt = body[:_HTTP_MAX].decode("utf-8", "replace")
    title = None
    mt = _TITLE.search(body[:_HTTP_MAX])
    if mt:
        title = re.sub(r"\s+", " ", mt.group(1).decode("utf-8", "replace")).strip()[:160]
    from . import enrich                         # technológia-ujjlenyomat (fejléc + törzs)
    tech = enrich.detect_tech(headers, body_txt)
    return {"scheme": scheme, "status": status, "server": server, "title": title or None,
            "powered_by": headers.get("x-powered-by"), "tech": tech}


async def probe_tls(host: str, ip: str, port: int, timeout: float = 6.0) -> dict | None:
    """TLS-tanúsítvány: CN, SAN-nevek, lejárat. A SAN új aldomain-neveket is adhat."""
    def _sync():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        try:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                return ss.getpeercert(binary_form=False), ss.getpeercert(binary_form=True)
        finally:
            try:
                raw.close()
            except Exception:  # noqa: BLE001
                pass

    try:
        cert, der = await asyncio.wait_for(asyncio.to_thread(_sync), timeout=timeout + 2)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    # getpeercert verify_mode=CERT_NONE esetén {} → DER-ből olvassuk ki a mezőket
    if not cert and der:
        cert = _parse_der(der)
    if not cert:
        return None
    cn = None
    for rdn in cert.get("subject", []):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    sans = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"]
    not_after = cert.get("notAfter")
    exp = None
    if not_after:
        try:
            exp = int(ssl.cert_time_to_seconds(not_after))
        except Exception:  # noqa: BLE001
            exp = None
    return {"cn": cn, "sans": sans[:40], "expires": exp}


def _parse_der(der: bytes) -> dict:
    """Tartalék CERT_NONE-hoz: a DER-tanúsítványt az ssl modullal dekódoljuk ideiglenes PEM-en át."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            os.write(fd, pem.encode())
            os.close(fd)
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
    except Exception:  # noqa: BLE001
        return {}


async def fingerprint(host: str, ip: str, port: int, timeout: float = 6.0) -> dict:
    """Portszintű ujjlenyomat: web-portnál HTTP(+TLS SAN), egyébként banner. -> mezők a result rekordhoz."""
    out: dict = {"port": port}
    t0 = time.perf_counter()
    if port in TLS_PORTS:
        tlsinfo = await probe_tls(host, ip, port, timeout)
        if tlsinfo:
            out["tls"] = tlsinfo
        if port in (443, 8443) or port in HTTP_PORTS:
            http = await probe_http(host, ip, port, tls=True, timeout=timeout)
            if http:
                out["http"] = http
    elif port in HTTP_PORTS:
        http = await probe_http(host, ip, port, tls=False, timeout=timeout)
        if http:
            out["http"] = http
    else:
        banner = await grab_banner(ip, port, timeout=min(timeout, 3.0))
        if banner:
            out["banner"] = banner
    out["rtt_ms"] = round((time.perf_counter() - t0) * 1000)
    return out
