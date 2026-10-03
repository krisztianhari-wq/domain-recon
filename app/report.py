"""Exportformátumok: olvasható Markdown-jelentés és tiszta, hosztonként csoportosított JSON.

Cél: az egy hoszthoz tartozó adatok (DNS, hálózat/ASN, portok, technológia, kitettség, sebezhetőség,
takeover) jól elkülönítve, átlátható szekciókban jelenjenek meg — ne egy lapos, ismétlődő táblában.
"""
from __future__ import annotations

import time


def _status(h: dict) -> str:
    if h.get("takeover") and h["takeover"].get("service"):
        return "takeover"
    if (h.get("exposed_flags") or h.get("vuln")):
        return "exposed"
    return "live" if h.get("alive") else "dead"


def _fmt_dt(epoch) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))
    except Exception:  # noqa: BLE001
        return "-"


def _host_clean(h: dict) -> dict:
    """Egy host adatai tiszta, csoportosított szerkezetben (JSON-exporthoz)."""
    net = []
    for i in h.get("ips_info", []) or [{"ip": ip} for ip in h.get("ips", [])]:
        net.append({k: i.get(k) for k in ("ip", "ptr", "asn", "org", "cc", "prefix") if i.get(k) is not None})
    ports = []
    for p in h.get("ports", []):
        rec = {"port": p["port"], "service": p.get("name"), "expected": p.get("expected", False)}
        if p.get("rtt_ms") is not None:
            rec["rtt_ms"] = p["rtt_ms"]
        if p.get("http"):
            http = p["http"]
            rec["http"] = {k: http[k] for k in ("status", "server", "powered_by", "title") if http.get(k)}
        if p.get("tls"):
            tls = p["tls"]
            rec["tls"] = {k: tls[k] for k in ("cn", "sans", "expires") if tls.get(k)}
        if p.get("banner"):
            rec["banner"] = p["banner"]
        if p.get("tech"):
            rec["tech"] = p["tech"]
        ports.append(rec)
    out = {
        "host": h["host"],
        "status": _status(h),
        "dns": {
            "a": h.get("v4", []), "aaaa": h.get("v6", []),
            "cname": h.get("cname"), "wildcard": bool(h.get("wildcard")),
            "source": "brute" if h.get("source_brute") else "passive",
        },
        "network": net,
        "ports": ports,
    }
    if h.get("tech"):
        out["technologies"] = h["tech"]
    if h.get("exposed_flags"):
        out["exposure"] = h["exposed_flags"]
    if h.get("vuln"):
        out["vulnerabilities"] = h["vuln"]
    if h.get("takeover") and h["takeover"].get("service"):
        out["takeover"] = h["takeover"]
    if h.get("tls_sans"):
        out["tls_sans"] = h["tls_sans"]
    return out


def build_json(scan: dict, hosts: list[dict]) -> dict:
    """Tiszta, csoportosított JSON: scan-meta + posture + hostonkénti blokkok."""
    return {
        "scan": {
            "domain": scan.get("domain"),
            "id": scan.get("id"),
            "created": _fmt_dt(scan.get("created")),
            "finished": _fmt_dt(scan.get("finished")) if scan.get("finished") else None,
            "version": scan.get("version"),
            "build": scan.get("build"),
            "passive_status": scan.get("status"),
            "active_status": scan.get("active_status"),
            "counts": {"hosts": scan.get("n_hosts", 0), "live": scan.get("n_live", 0),
                       "open_ports": scan.get("n_ports", 0)},
        },
        "dns_posture": scan.get("posture"),
        "wildcard_ips": scan.get("wildcard") or [],
        "hosts": [_host_clean(h) for h in hosts],
    }


# ---------------- Markdown-jelentés ----------------
def _net_line(i: dict) -> str:
    parts = [i.get("ip", "")]
    if i.get("ptr"):
        parts.append(f"PTR {i['ptr']}")
    if i.get("asn"):
        parts.append(f"AS{i['asn']}" + (f" {i['org']}" if i.get("org") else "") + (f" ({i['cc']})" if i.get("cc") else ""))
    return " · ".join(p for p in parts if p)


def _host_md(h: dict) -> str:
    st = _status(h)
    badge = {"takeover": "🔴 TAKEOVER", "exposed": "🟠 KITETT", "live": "🟢 élő", "dead": "⚪ nem él"}[st]
    lines = [f"### {h['host']}  —  {badge}", ""]
    # DNS
    dns = []
    if h.get("ips"):
        dns.append(f"**IP:** {', '.join(h['ips'])}")
    if h.get("cname"):
        dns.append(f"**CNAME:** {h['cname']}")
    dns.append("**Forrás:** " + ("brute" if h.get("source_brute") else "passzív") + (" · wildcard" if h.get("wildcard") else ""))
    lines.append(" · ".join(dns))
    # hálózat/ASN
    info = h.get("ips_info") or []
    if any(i.get("asn") or i.get("ptr") for i in info):
        lines.append("")
        lines.append("**Hálózat:**")
        for i in info:
            line = _net_line(i)
            if line:
                lines.append(f"- {line}")
    # technológia
    if h.get("tech"):
        lines.append("")
        lines.append("**Technológia:** " + ", ".join(h["tech"]))
    # takeover
    if h.get("takeover") and h["takeover"].get("service"):
        t = h["takeover"]
        lines.append("")
        lines.append(f"**Lehetséges takeover:** {t['service']} → {t.get('cname','')} "
                     f"({'megerősítve' if t.get('confirmed') else 'gyanús'})")
    # kitettség
    if h.get("exposed_flags"):
        lines.append("")
        lines.append("**Kitett szolgáltatás:** " + ", ".join(h["exposed_flags"]))
    # sebezhetőség
    if h.get("vuln"):
        lines.append("")
        lines.append("**Sebezhetőség / kitettség:**")
        for v in h["vuln"]:
            ev = f" — {v['evidence']}" if v.get("evidence") else ""
            lines.append(f"- [{v.get('severity','?')}] {v.get('title','')}{ev}")
    # portok
    if h.get("ports"):
        lines.append("")
        lines.append("**Nyitott portok:**")
        lines.append("")
        lines.append("| Port | Szolgáltatás | Részlet | RTT |")
        lines.append("|---|---|---|---|")
        for p in h["ports"]:
            http = p.get("http") or {}
            tls = p.get("tls") or {}
            det = []
            if http.get("status"):
                det.append(f"HTTP {http['status']}")
            if http.get("server"):
                det.append(http["server"])
            if http.get("powered_by"):
                det.append(http["powered_by"])
            if http.get("title"):
                det.append(f"„{http['title']}”")
            if p.get("tech"):
                det.append(", ".join(p["tech"]))
            if tls.get("cn"):
                det.append(f"CN={tls['cn']}")
            if p.get("banner"):
                det.append(p["banner"])
            seen, ded = set(), []
            for d in det:
                d = str(d)
                if d.lower() not in seen:
                    seen.add(d.lower())
                    ded.append(d)
            detail = "; ".join(ded).replace("|", "\\|") or "—"
            rtt = f"{p['rtt_ms']} ms" if p.get("rtt_ms") is not None else "—"
            lines.append(f"| {p['port']} | {p.get('name','?')} | {detail} | {rtt} |")
    if h.get("tls_sans"):
        lines.append("")
        lines.append("**TLS SAN (új nevek):** " + ", ".join(h["tls_sans"]))
    lines.append("")
    return "\n".join(lines)


def build_markdown(scan: dict, hosts: list[dict]) -> str:
    domain = scan.get("domain", "")
    p = scan.get("posture") or {}
    wc = scan.get("wildcard") or []
    n_live = sum(1 for h in hosts if h.get("alive"))
    n_exp = sum(1 for h in hosts if _status(h) == "exposed")
    n_tk = sum(1 for h in hosts if _status(h) == "takeover")
    n_ports = sum(len(h.get("ports", [])) for h in hosts)

    L = [f"# domain-recon — {domain}", ""]
    ver = f" · v{scan['version']}" + (f" ({scan['build']})" if scan.get("build") else "") if scan.get("version") else ""
    L.append(f"*Vizsgálat: {_fmt_dt(scan.get('created'))}{ver} · "
             f"passzív: {scan.get('status','?')} · aktív: {scan.get('active_status','none')}*")
    L.append("")
    L.append(f"**Összegzés:** {len(hosts)} host · {n_live} élő · {n_tk} takeover · {n_exp} kitett · {n_ports} nyitott port")
    L.append("")
    # posture
    L.append("## DNS / e-mail posture (apex)")
    def ok(v): return "✓ van" if v else "✗ hiányzik"
    L.append("")
    L.append(f"- **SPF:** {ok(p.get('spf_ok'))}" + (f" — `{p['spf']}`" if p.get("spf") else ""))
    L.append(f"- **DMARC:** {ok(p.get('dmarc_ok'))}" + (f" — `{p['dmarc']}`" if p.get("dmarc") else ""))
    L.append(f"- **DKIM:** " + (", ".join(p["dkim"]) if p.get("dkim") else "✗ nincs ismert selector"))
    L.append(f"- **CAA:** " + (", ".join(p["caa"]) if p.get("caa") else "✗ nincs"))
    L.append(f"- **MX:** " + (", ".join(p["mx"]) if p.get("mx") else "✗ nincs"))
    L.append(f"- **NS:** " + (", ".join(p["ns"]) if p.get("ns") else "—"))
    if wc:
        L.append(f"- **Wildcard DNS:** ⚠ aktív — {', '.join(wc)}")
    L.append("")

    # hostok három csoportban: figyelmet igénylő / élő / nem élő
    order = {"takeover": 0, "exposed": 1, "live": 2, "dead": 3}
    attn = sorted([h for h in hosts if _status(h) in ("takeover", "exposed")],
                  key=lambda h: (order[_status(h)], h["host"]))
    live = sorted([h for h in hosts if _status(h) == "live"], key=lambda h: h["host"])
    dead = sorted([h for h in hosts if _status(h) == "dead"], key=lambda h: h["host"])

    if attn:
        L.append("## ⚠ Figyelmet igénylő hostok")
        L.append("")
        for h in attn:
            L.append(_host_md(h))
            L.append("---")
            L.append("")
    if live:
        L.append("## Élő hostok")
        L.append("")
        for h in live:
            L.append(_host_md(h))
            L.append("---")
            L.append("")
    if dead:
        L.append("## Nem élő / fel nem oldott hostok")
        L.append("")
        for h in dead:
            cn = f" (CNAME {h['cname']})" if h.get("cname") else ""
            L.append(f"- {h['host']}{cn}")
        L.append("")
    L.append("---")
    L.append("*sadrobot · domain-recon · csak engedélyezett célpontra*")
    return "\n".join(L)
