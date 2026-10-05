"""Kvantum-reziliencia felmérés a host TLS-kriptográfiájára (kíméletes, kulcs nélküli).

Két jel:
  1) Kulcscsere (titkosság): egy nyers TLS 1.3 ClientHello-t küldünk ÜRES key_share-rel, de a
     supported_groups listában PQ (ML-KEM hibrid) csoportokkal. Ha a szerver HelloRetryRequest-tel
     az egyik PQ csoportot választja, akkor támogatja a poszt-kvantum kulcscserét → a lehallgatott
     forgalom „harvest-now, decrypt-later” ellen védett. (A pqcheck-ből átvett technika; nem kell
     helyi PQC-könyvtár, bármilyen OpenSSL-lel működik.)
  2) Tanúsítvány (hitelesítés): a szerver cert nyilvános kulcsa és aláírása (RSA/ECDSA/EdDSA ma
     klasszikus → Shor ellen sebezhető; ML-DSA/SPHINCS+ → PQ). Ez csak a kapcsolat idején számít.

Visszaad egy kompakt értékelést; a célponton 1–3 rövid TLS-kapcsolatot nyit hostonként.
"""
from __future__ import annotations

import asyncio
import os
import socket
import ssl
import struct

# PQ (hibrid ML-KEM / Kyber) csoport-kódpontok → név
PQ_GROUPS = {4588: "X25519MLKEM768", 4587: "SecP256r1MLKEM768", 4589: "SecP384r1MLKEM1024",
             512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024",
             25497: "X25519Kyber768Draft00", 25498: "SecP256r1Kyber768Draft00"}
CLASSICAL_GROUPS = {29: "x25519", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 256: "ffdhe2048"}
ALL_NAMES = {**PQ_GROUPS, **CLASSICAL_GROUPS}

_SUITES = (0x1301, 0x1302, 0x1303, 0xC02C, 0xC030, 0xC02B, 0xC02F, 0x009D)
_SIGALGS = (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0808)
_HRR = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def _ext(t, body):
    return struct.pack(">HH", t, len(body)) + body


def _client_hello(sni: str, groups) -> bytes:
    suites = b"".join(struct.pack(">H", s) for s in _SUITES)
    sig = b"".join(struct.pack(">H", s) for s in _SIGALGS)
    grp = b"".join(struct.pack(">H", g) for g in groups)
    host = sni.encode("idna")
    exts = _ext(0, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host)
    exts += _ext(10, struct.pack(">H", len(grp)) + grp)
    exts += _ext(11, b"\x01\x00")
    exts += _ext(13, struct.pack(">H", len(sig)) + sig)
    exts += _ext(43, b"\x02\x03\x04")
    exts += _ext(45, b"\x01\x01")
    exts += _ext(51, b"\x00\x00")               # üres key_share → HRR
    body = struct.pack(">H", 0x0303) + os.urandom(32) + b"\x20" + os.urandom(32)
    body += struct.pack(">H", len(suites)) + suites + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf += c
    return buf


def _probe_groups_sync(host, port, groups, timeout):
    """(status, selected_group). status: hrr|serverhello|tls12|alert|error."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(_client_hello(host, groups))
            hdr = _recv(s, 5)
            typ, ln = hdr[0], struct.unpack(">H", hdr[3:5])[0]
            rec = _recv(s, ln)
        if typ == 0x15:
            return "alert", None
        if typ != 0x16 or rec[0] != 0x02:
            return "error", None
        p = 4 + 2
        rnd = rec[p:p + 32]; p += 32
        p += 1 + rec[p]
        p += 3
        extl = struct.unpack(">H", rec[p:p + 2])[0]; p += 2
        exts = rec[p:p + extl]
        e, selected, tls13 = 0, None, False
        while e + 4 <= len(exts):
            et, el = struct.unpack(">HH", exts[e:e + 4])
            ev = exts[e + 4:e + 4 + el]
            if et == 43:
                tls13 = ev == b"\x03\x04"
            if et == 51 and len(ev) >= 2:
                selected = struct.unpack(">H", ev[:2])[0]
            e += 4 + el
        if not tls13:
            return "tls12", None
        return ("hrr" if rnd == _HRR else "serverhello"), selected
    except (OSError, ConnectionError, struct.error, IndexError):
        return "error", None


# ---------------- tanúsítvány kulcs/aláírás ----------------
def _tlv(b, off):
    tag = b[off]; off += 1
    ln = b[off]; off += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[off:off + n], "big"); off += n
    return tag, off, ln


def _children(b):
    out, off = [], 0
    while off < len(b):
        tag, o, ln = _tlv(b, off)
        out.append((tag, b[o:o + ln]))
        off = o + ln
    return out


def _oid(b):
    if not b:
        return ""
    vals = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            vals.append(v); v = 0
    return ".".join(str(x) for x in vals)


_KEY_OID = {
    "1.2.840.113549.1.1.1": ("RSA", "classical"),
    "1.2.840.10045.2.1": ("ECDSA", "classical"),
    "1.3.101.112": ("Ed25519", "classical"), "1.3.101.113": ("Ed448", "classical"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pq"), "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pq"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pq"),
}
_CURVE = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}
_SIG_OID = {
    "1.2.840.113549.1.1.11": ("RSA-SHA256", "classical"), "1.2.840.113549.1.1.12": ("RSA-SHA384", "classical"),
    "1.2.840.113549.1.1.13": ("RSA-SHA512", "classical"), "1.2.840.113549.1.1.10": ("RSA-PSS", "classical"),
    "1.2.840.10045.4.3.2": ("ECDSA-SHA256", "classical"), "1.2.840.10045.4.3.3": ("ECDSA-SHA384", "classical"),
    "1.2.840.10045.4.3.4": ("ECDSA-SHA512", "classical"),
    "1.3.101.112": ("Ed25519", "classical"), "1.3.101.113": ("Ed448", "classical"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pq"), "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pq"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pq"),
}


def classify_cert(der: bytes) -> dict:
    """{key_alg, key_bits, key_status, sig_alg, sig_status} a cert DER-ből (best-effort, stdlib)."""
    out = {}
    try:
        _, o, ln = _tlv(der, 0)
        cert = der[o:o + ln]
        top = _children(cert)                       # [tbs, sigAlg, sigValue]
        tbs = top[0][1]
        sigalg_oid = _oid(_children(top[1][1])[0][1])
        name, st = _SIG_OID.get(sigalg_oid, (sigalg_oid, "classical"))
        out["sig_alg"], out["sig_status"] = name, st
        elems = _children(tbs)
        i = 1 if elems and elems[0][0] == 0xA0 else 0   # optional [0] version
        spki = elems[i + 5][1]                        # serial,sigalg,issuer,validity,subject,SPKI
        sp = _children(spki)
        algid = _children(sp[0][1])
        key_oid = _oid(algid[0][1])
        kname, kst = _KEY_OID.get(key_oid, (key_oid, "classical"))
        if kname == "ECDSA" and len(algid) > 1:
            kname = "ECDSA " + _CURVE.get(_oid(algid[1][1]), "?")
        out["key_alg"], out["key_status"] = kname, kst
        if key_oid == "1.2.840.113549.1.1.1":        # RSA → modulus bit length
            bitstr = sp[1][1]
            inner = bitstr[1:] if bitstr and bitstr[0] == 0 else bitstr
            rsa = _children(inner)
            if rsa and rsa[0][0] == 0x02:
                m = rsa[0][1].lstrip(b"\x00")
                out["key_bits"] = len(m) * 8
    except Exception:  # noqa: BLE001
        pass
    return out


def _fetch_cert_sync(host, ip, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:   # IP-re csatlakozunk
            with ctx.wrap_socket(raw, server_hostname=host) as ss:            # de a hostnév a SNI
                return ss.getpeercert(binary_form=True), ss.version()
    except (OSError, ssl.SSLError):
        return None, None


async def assess(host: str, ip: str, port: int, timeout: float = 6.0) -> dict:
    """Kompakt kvantum-reziliencia értékelés a host adott TLS-portjára."""
    # 1) kulcscsere PQ-próba (az IP-re csatlakozunk, SNI = host)
    status, grp = await asyncio.to_thread(_probe_groups_sync, ip, port, list(PQ_GROUPS), timeout)
    if status in ("hrr", "serverhello") and grp in PQ_GROUPS:
        kex = {"group": PQ_GROUPS[grp], "status": "pq", "tls": "1.3"}
    else:
        cstatus, cgrp = await asyncio.to_thread(_probe_groups_sync, ip, port, list(CLASSICAL_GROUPS), timeout)
        if cstatus in ("hrr", "serverhello"):
            kex = {"group": ALL_NAMES.get(cgrp, "classical"), "status": "classical", "tls": "1.3"}
        elif cstatus == "tls12" or status == "tls12":
            kex = {"group": "ECDHE/RSA", "status": "classical", "tls": "1.2"}
        else:
            kex = {"group": None, "status": "unknown", "tls": None}
    # 2) tanúsítvány
    der, ver = await asyncio.to_thread(_fetch_cert_sync, host, ip, port, timeout)
    cert = classify_cert(der) if der else {}
    if ver and not kex.get("tls"):
        kex["tls"] = ver.replace("TLSv", "")
    # összegző verdikt
    if kex["status"] == "pq":
        verdict = "hybrid"           # PQ/hibrid kulcscsere → titkosság kvantum-biztos
    elif kex["status"] == "classical":
        verdict = "classical"        # klasszikus → harvest-now, decrypt-later kockázat
    else:
        verdict = "unknown"
    return {"kex": kex, "cert": cert, "verdict": verdict, "port": port}
