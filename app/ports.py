"""Portprofilok és szolgáltatásnevek a feltérképezéshez.

Profilok:
  - service : szűk, „érdekes” szolgáltatási portok (gyors, kíméletes) – ALAP
  - common  : a rendszerportok (1–1024) + a gyakori magasabb szolgáltatási portok (~1100 port)
  - full    : 1–65535 (lassú, zajos – csak saját/engedélyezett célponton)
  - custom  : felhasználói lista, pl. "22,80,443,8000-8100"
"""
from __future__ import annotations

# A legfontosabb szolgáltatási portok – a 80/443 a „várt” webes pár, a többi figyelemre méltó.
SERVICE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1025, 1433, 1521, 2049, 2082, 2083, 2375, 2376,
    3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5985, 6379, 7001,
    8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 11211,
    15672, 27017, 27018,
]

# Jól ismert szolgáltatásnevek (IANA + elterjedt használat).
PORT_NAME = {
    7: "echo", 20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 53: "DNS", 67: "DHCP", 69: "TFTP", 79: "finger", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPCbind", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS-ns", 139: "NetBIOS-ssn", 143: "IMAP", 161: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
    514: "syslog", 515: "LPD", 548: "AFP", 554: "RTSP", 587: "submission",
    631: "IPP", 636: "LDAPS", 873: "rsync", 989: "FTPS-data", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1025: "MS-RPC", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-TLS", 2379: "etcd", 3000: "dev/Grafana", 3128: "Squid",
    3306: "MySQL", 3389: "RDP", 4444: "metasploit?", 5000: "dev/UPnP",
    5060: "SIP", 5222: "XMPP", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "AMQP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
    6443: "Kubernetes", 7001: "WebLogic", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8080: "HTTP-proxy", 8081: "HTTP-alt", 8088: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt/Prom", 9200: "Elasticsearch",
    9300: "ES-transport", 10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ-UI",
    27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop",
}

# A web-jellegű portok, ahol HTTP-címet/TLS-t próbálunk ujjlenyomatozni.
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 2082, 3000, 5000, 8888, 9000, 9090}
TLS_PORTS = {443, 8443, 465, 993, 995, 636, 990, 2083, 2376, 5986, 6443, 8443}

EXPECTED_WEB = {80, 443}


def _common_ports() -> list[int]:
    hi = {
        1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376,
        2379, 3000, 3128, 3306, 3389, 4444, 5000, 5060, 5222, 5432, 5601, 5672,
        5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8086, 8088,
        8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 15672, 27017, 27018,
        32768, 49152, 50000, 50070,
    }
    return sorted(set(range(1, 1025)) | hi)


COMMON_PORTS = _common_ports()


def parse_ports(spec: str, cap: int = 65535) -> list[int]:
    """"22,80,443,8000-8100" → rendezett egyedi portlista (1..65535), felső korláttal a darabszámra."""
    out: set[int] = set()
    for chunk in (spec or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            for p in range(max(1, lo), min(65535, hi) + 1):
                out.add(p)
        else:
            try:
                p = int(chunk)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                out.add(p)
    return sorted(out)[:cap]


def resolve_profile(profile: str, custom: str = "") -> tuple[list[int], str]:
    """(portlista, normalizált-profilnév). Ismeretlen → service."""
    p = (profile or "service").lower()
    if p == "full":
        return list(range(1, 65536)), "full"
    if p == "common":
        return COMMON_PORTS, "common"
    if p == "custom":
        ports = parse_ports(custom)
        return (ports, "custom") if ports else (SERVICE_PORTS, "service")
    return SERVICE_PORTS, "service"


def svc(port: int) -> str:
    return PORT_NAME.get(port, "?")
