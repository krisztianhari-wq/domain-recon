"""Hálózati ellenőrzések a HTTP-n túl: TCP-port, DNS-rekord, ICMP-ping, DNSBL/feketelista, domain-lejárat.
Stdlib-alapú DNS-kliens (UDP) a dns-check / dns-változás / DNSBL kiszolgálásához; domain-lejárat RDAP-on (HTTP), WHOIS:43 tartalékkal.
"""
import asyncio
import ipaddress
import os
import random
import socket
import struct
import time

import httpx

RESOLVERS = [r.strip() for r in os.getenv("DNS_RESOLVERS", "1.1.1.1,8.8.8.8").split(",") if r.strip()]
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


# ---------------- DNS-kliens (UDP) ----------------
def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def _read_name(buf: bytes, off: int, depth=0):
    labels = []
    while off < len(buf) and depth < 12:
        n = buf[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            name, _ = _read_name(buf, ptr, depth + 1)
            labels.append(name)
            return ".".join(labels), off + 2
        labels.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), off


def _dns_query_sync(name: str, qtype: str, resolver: str, timeout: float):
    qt = QTYPES[qtype]
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_qname(name) + struct.pack(">HH", qt, 1)
    fam = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (resolver, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    rcode = data[3] & 0x0F
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _read_name(data, off)
        typ, _cls, _ttl, rdl = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdl]
        if typ == 1 and rdl == 4:
            out.append(socket.inet_ntoa(rd))
        elif typ == 28 and rdl == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, rd))
        elif typ in (2, 5):
            out.append(_read_name(data, off)[0])
        elif typ == 15:
            pref = struct.unpack(">H", rd[:2])[0]
            out.append(f"{pref} {_read_name(data, off + 2)[0]}")
        elif typ == 16:
            parts, i = [], 0
            while i < len(rd):
                ln = rd[i]
                parts.append(rd[i + 1:i + 1 + ln].decode("ascii", "replace"))
                i += 1 + ln
            out.append("".join(parts))
        off += rdl
    return rcode, out


async def dns_query(name: str, qtype: str = "A", timeout: float = 5.0):
    """(rcode, records) – a válaszoló rekordok listája szövegként. Több resolvert próbál."""
    last = (None, [])
    for r in RESOLVERS:
        try:
            return await asyncio.to_thread(_dns_query_sync, name, qtype, r, timeout)
        except Exception:  # noqa: BLE001
            continue
    return last


# ---------------- TCP-port ----------------
async def tcp_check(host: str, port: int, timeout: float):
    try:
        fut = asyncio.open_connection(host, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True, None
    except (asyncio.TimeoutError, OSError) as e:
        return False, e


# ---------------- ICMP-ping (unprivileged datagram, tartalék raw) ----------------
def _icmp_ping_sync(host: str, timeout: float):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except socket.gaierror:
        return None, "dns"
    fam = infos[0][0]
    addr = infos[0][4][0]
    is6 = fam == socket.AF_INET6
    proto = socket.IPPROTO_ICMPV6 if is6 else socket.IPPROTO_ICMP
    icmp_type = 128 if is6 else 8
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM, proto)            # unprivileged ICMP
    except PermissionError:
        try:
            s = socket.socket(fam, socket.SOCK_RAW, proto)          # tartalék: raw (NET_RAW kell)
        except PermissionError:
            return None, "perm"
    s.settimeout(timeout)
    ident = random.randint(0, 0xFFFF)
    header = struct.pack(">BBHHH", icmp_type, 0, 0, ident, 1)
    payload = b"yhuptime"
    chk = 0 if is6 else _checksum(header + payload)
    header = struct.pack(">BBHHH", icmp_type, 0, chk, ident, 1)
    pkt = header + payload
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (addr, 0))
        s.recvfrom(1024)
        return round((time.perf_counter() - t0) * 1000), None
    except socket.timeout:
        return None, "timeout"
    except OSError as e:
        return None, str(e)[:60]
    finally:
        s.close()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


async def icmp_ping(host: str, timeout: float = 5.0):
    """(latency_ms|None, error_code|None). error_code: 'perm' (nincs jogosultság), 'timeout', 'dns', egyéb."""
    return await asyncio.to_thread(_icmp_ping_sync, host, timeout)


# ---------------- DNSBL / feketelista ----------------
DEFAULT_DNSBL = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net"]


async def dnsbl_lookup(ip: str, zones=None, timeout: float = 5.0):
    """Egy IP ellenőrzése DNSBL-zónákban. -> listázó zónák listája (üres = tiszta)."""
    zones = zones or DEFAULT_DNSBL
    try:
        rev = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if rev.version != 4:
        return []                                   # a legtöbb DNSBL csak IPv4
    prefix = ".".join(reversed(ip.split(".")))
    err_net = ipaddress.ip_network("127.255.255.0/24")   # publikus-resolver hiba/blokk kód – NEM listázás
    listed = []
    for z in zones:
        rcode, recs = await dns_query(f"{prefix}.{z}", "A", timeout)
        hit = any(r.startswith("127.") and ipaddress.ip_address(r) not in err_net for r in recs)
        if hit:
            listed.append(z)
    return listed


# ---------------- Domain-lejárat (RDAP → WHOIS:43) ----------------
def _registrable(host: str) -> str:
    """Egyszerű bejegyezhető-domain levezetés (host → domain.tld, kétszintű TLD-kkel)."""
    parts = host.rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two = {"co.uk", "org.uk", "com.hu", "co.hu"}
    if ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _parse_rdap_expiry(data: dict):
    for ev in data.get("events", []):
        if ev.get("eventAction") in ("expiration", "registration expiration"):
            return ev.get("eventDate")
    return None


def _parse_date(s: str):
    from datetime import datetime
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y.%m.%d.", "%Y.%m.%d"):
        try:
            dt = datetime.strptime(s.replace("Z", "+0000") if fmt.endswith("%z") else s, fmt)
            return int(dt.timestamp())
        except ValueError:
            continue
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _whois_sync(domain: str, timeout: float):
    """IANA-referrált WHOIS:43; a tld whois-szerverét az IANA-tól kérdezi le, majd a domaint. (epoch|None, error)."""
    tld = domain.rsplit(".", 1)[-1]
    def ask(server, query):
        s = socket.create_connection((server, 43), timeout=timeout)
        try:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 200000:
                    break
            return data.decode("utf-8", "replace")
        finally:
            s.close()
    try:
        ref = ask("whois.iana.org", tld)
        server = None
        for line in ref.splitlines():
            if line.lower().startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                break
        if not server:
            return None, "nincs WHOIS-szerver a TLD-hez"
        txt = ask(server, domain)
        for line in txt.splitlines():
            low = line.lower()
            for key in ("registry expiry date", "expiry date", "expiration date", "expire", "paid-till", "renewal date"):
                if low.strip().startswith(key):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    ep = _parse_date(val)
                    if ep:
                        return ep, None
        return None, "a WHOIS nem közöl lejárati dátumot"
    except Exception as e:  # noqa: BLE001
        return None, f"WHOIS hiba: {e.__class__.__name__}"


async def domain_expiry(domain: str, client: httpx.AsyncClient, timeout: float = 15.0):
    """(not_after_epoch|None, registrar|None, error|None) RDAP-ból (rdap.org), majd WHOIS:43 tartalékkal."""
    dom = _registrable(domain)
    registrar = None
    try:
        r = await client.get(f"https://rdap.org/domain/{dom}", timeout=timeout,
                             headers={"Accept": "application/rdap+json"}, follow_redirects=True)
        if r.status_code == 200:
            data = r.json()
            iso = _parse_rdap_expiry(data)
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    for v in ent.get("vcardArray", [[], []])[1]:
                        if v[0] == "fn":
                            registrar = v[3]
            if iso:
                ep = _parse_date(iso)
                if ep:
                    return ep, registrar, None
    except Exception:  # noqa: BLE001
        pass
    # tartalék: WHOIS:43 (ccTLD-knél, pl. .hu, ahol nincs RDAP)
    ep, werr = await asyncio.to_thread(_whois_sync, dom, timeout)
    if ep:
        return ep, registrar, None
    return None, registrar, werr or "lejárat nem elérhető"
