# For educational and authorized penetration testing use only.
# Do not use this tool on systems you do not own or have explicit permission to test.
# ctxzero - PortHunt - A simple port scanner with vulnerability lookup capabilities.


import socket
import ipaddress
import time as _time
import requests
import concurrent.futures
import re
import ssl
import json
import csv
import os
import subprocess
import html
import sys
from urllib.parse import quote
from datetime import datetime
from colorama import Fore, Style, init
from functools import lru_cache


init(autoreset=True)

VERBOSE = False

if os.environ.get("PORTHUNT_VERBOSE", "").lower() in ("1", "true", "yes"):
    VERBOSE = True

THEME = {
    "header": Fore.MAGENTA,
    "menu": Fore.WHITE,
    "highlight": Fore.CYAN,
    "ok": Fore.GREEN,
    "warn": Fore.YELLOW,
    "error": Fore.RED
}

def enable_verbose(v=True):
    global VERBOSE
    VERBOSE = bool(v)
    print(THEME["ok"] + f"Verbose {'enabled' if VERBOSE else 'disabled'}")

def log(msg, level="info"):
    if not VERBOSE:
        return
    prefix = {
        "info": THEME["menu"],
        "ok": THEME["ok"],
        "warn": THEME["warn"],
        "error": THEME["error"]
    }.get(level, THEME["menu"])
    print(prefix + str(msg) + Style.RESET_ALL)

COMMON_SERVICES = {
    1: "tcpmux",
    7: "echo",
    9: "discard",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "time",
    42: "nameserver",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP (server)",
    68: "DHCP (client)",
    69: "TFTP",
    79: "Finger",
    80: "HTTP",
    81: "HTTP (alt)",
    88: "Kerberos",
    95: "SUPDUP",
    99: "Metagram Relay",
    110: "POP3",
    111: "rpcbind",
    113: "Ident",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    199: "SMUX",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    519: "RIPng",
    520: "route",
    521: "RIPng",
    523: "IBM-DB2",
    540: "UUCP",
    543: "KLogin",
    544: "KShell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    548: "AFP",
    554: "RTSP",
    587: "SMTP (submission)",
    591: "FileMaker",
    593: "HTTP-RPC-EPMAP",
    631: "IPP",
    636: "LDAPS",
    646: "LDP",
    666: "DPNSS",
    873: "rsync",
    888: "cddbp-alt",
    898: "sun-manageconsole",
    900: "Doom ID",
    901: "Samba SWAT",
    902: "VMware Server",
    989: "FTPS (data)",
    990: "FTPS (control)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle TNS",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2086: "WHM",
    2095: "Webmail (cPanel)",
    2096: "Webmail (cPanel SSL)",
    2121: "FTP (alt)",
    2222: "DirectAdmin",
    2302: "Game Server",
    2483: "Oracle TNS (deprecated)",
    25565: "Minecraft",
    27015: "Source Engine",
    27017: "MongoDB",
    28017: "MongoDB Web",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    3632: "distcc",
    3690: "Subversion (svn)",
    3986: "mapper-ws_ethd",
    4000: "Workstation",
    4444: "Oracle Web",
    4662: "eDonkey",
    4899: "RAdmin",
    5000: "UPnP / Flask",
    5001: "iperf",
    5060: "SIP",
    5061: "SIPS/TLS",
    5432: "PostgreSQL",
    5631: "pcAnywhere",
    5900: "VNC",
    5984: "CouchDB",
    6000: "X11",
    6379: "Redis",
    6667: "IRC",
    6881: "BitTorrent (DHT)",
    7001: "WebLogic",
    7002: "AJP13",
    7199: "Cassandra JMX",
    8000: "HTTP (alt)",
    8008: "HTTP (alt)",
    8080: "HTTP-Proxy",
    8081: "HTTP (alt)",
    8443: "HTTPS-Alt / Tomcat",
    8888: "Alternate HTTP",
    9001: "Tor ORPort",
    9090: "Openfire / Web UI",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
    11211: "Memcached",
    28017: "MongoDB Web",
    32768: "RPC Ephemeral (Linux)",
    33060: "MySQL X Protocol",
    3478: "TURN/STUN",
    37017: "MongoDB (alt)",
    50070: "HDFS NameNode (web)",
    50075: "HDFS DataNode (web)",
    49152: "Windows Ephemeral Start",
    49153: "Windows Ephemeral",
    49154: "Windows Ephemeral",
    49155: "Windows Ephemeral",
    49156: "Windows Ephemeral",
    49157: "Windows Ephemeral",
    50090: "Hadoop Web",
    11212: "Memcached (alt)",
    12345: "NetBus/Backdoor (common historic)",
    12346: "NetBus (alt)",
    25575: "Minecraft RCON",
    27019: "MongoDB Config",
    28080: "HTTP (alt)",
    50030: "HDFS UI",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    9999: "Monitoring / Admin"
}


EXPLOITDB_RAW_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
_EXPLOITDB_INDEX = None

def _load_exploitdb_index():
    global _EXPLOITDB_INDEX
    if _EXPLOITDB_INDEX is not None:
        return _EXPLOITDB_INDEX
    try:
        r = requests.get(EXPLOITDB_RAW_URL, timeout=12)
        r.raise_for_status()
        text = r.text.splitlines()
        reader = csv.reader(text)
        index = []
        for row in reader:
            if len(row) < 3:
                continue
            try:
                eid = row[0].strip()
                file_path = row[1].strip()
                desc = row[2].strip()
                date = row[3].strip() if len(row) > 3 else ""
                platform = row[5].strip() if len(row) > 5 else ""
                index.append({"id": eid, "file": file_path, "desc": desc, "date": date, "platform": platform})
            except Exception:
                continue
        _EXPLOITDB_INDEX = index
        return _EXPLOITDB_INDEX
    except Exception:
        _EXPLOITDB_INDEX = []
        return _EXPLOITDB_INDEX

@lru_cache(maxsize=256)
def _query_exploitdb(keyword, max_results=5):
    if not keyword:
        return []
    idx = _load_exploitdb_index()
    if not idx:
        return []
    kw = keyword.lower()
    matches = []
    cve_match = None
    m = re.search(r"(CVE[-:]?\s*\d{4}[-/]\d{4,7})", keyword, re.IGNORECASE)
    if m:
        cve_match = m.group(1).upper().replace(":", "-").replace(" ", "")
    for item in idx:
        desc = item.get("desc", "").lower()
        if cve_match and cve_match.lower() in desc:
            matches.append(item)
        elif kw in desc:
            matches.append(item)
        if len(matches) >= max_results:
            break
    log(f"_query_exploitdb('{keyword}') -> {len(matches)} matches", "info")
    return matches

@lru_cache(maxsize=256)
def _query_circl(keyword, max_results=5):
    if not keyword:
        return []
    try:
        q = quote(keyword)
        url = f"https://cve.circl.lu/api/search/{q}"
        r = requests.get(url, timeout=8, headers={"User-Agent": "ctxzero-portscanner/1.0"})
        if r.status_code != 200:
            return []
        data = r.json()
        results = []
        if isinstance(data, list):
            for it in data[:max_results]:
                cid = it.get("id") or it.get("CVE")
                summary = it.get("summary") or ""
                pub = it.get("Published") or it.get("PublishedDate") or ""
                results.append({"cve": cid, "desc": summary, "published": pub})
        elif isinstance(data, dict):
            items = data.get("results") or data.get("data") or []
            for it in items[:max_results]:
                cid = it.get("id") or it.get("CVE")
                summary = it.get("summary") or ""
                pub = it.get("Published") or it.get("PublishedDate") or ""
                results.append({"cve": cid, "desc": summary, "published": pub})
        log(f"_query_circl('{keyword}') -> {len(results)} matches", "info")
        return results
    except Exception as e:
        log(f"_query_circl('{keyword}') failed: {e}", "error")
        return []
    
@lru_cache(maxsize=256)
def _query_nvd(keyword, max_results=5):
    if not keyword:
        return []
    headers = {"User-Agent": "PortHunt/1.0"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        r = requests.get(url, params=params, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", []) or []
            out = []
            for v in vulns[:max_results]:
                cve = (v.get("cve") or {}).get("id")
                desc = ""
                for d in ((v.get("cve") or {}).get("descriptions") or []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "") or desc
                pub = (v.get("cve") or {}).get("published")
                out.append({"cve": cve, "desc": desc, "published": pub})
            log(f"_query_nvd(v2 '{keyword}') -> {len(out)}", "info")
            return out
    except Exception as e:
        log(f"_query_nvd v2 failed: {e}", "warn")

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {"keyword": keyword, "resultsPerPage": max_results}
        r = requests.get(url, params=params, headers=headers, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        items = data.get("result", {}).get("CVE_Items", [])
        out = []
        for it in items[:max_results]:
            cve_id = it.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            descs = it.get("cve", {}).get("description", {}).get("description_data", [])
            desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "") if descs else ""
            published = it.get("publishedDate", "")
            out.append({"cve": cve_id, "desc": desc, "published": published})
        log(f"_query_nvd(v1 '{keyword}') -> {len(out)}", "info")
        return out
    except Exception as e:
        log(f"_query_nvd v1 failed: {e}", "error")
        return []

def _recv_until(sock, timeout, max_bytes=8192):
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < max_bytes:
            data = sock.recv(2048)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except Exception:
        pass
    return b"".join(chunks)

def _probe_banner(target, port, timeout=1.0):
    try:
        if port in (3306, 33060):
            try:
                s = socket.create_connection((target, port), timeout=timeout)
                s.settimeout(timeout)
                hdr = s.recv(4)
                if len(hdr) == 4:
                    plen = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
                    payload = b""
                    while len(payload) < min(plen, 4096):
                        chunk = s.recv(min(2048, plen - len(payload)))
                        if not chunk:
                            break
                        payload += chunk
                    if len(payload) > 2:
                        ver = payload[1:].split(b'\x00', 1)[0].decode(errors="ignore")
                        s.close()
                        return f"MySQL version: {ver}"
                s.close()
            except Exception:
                pass

        tls_ports = {443, 465, 636, 993, 995}
        http_like = {80, 8080, 8000, 3000, 5000}

        if port in tls_ports:
            s = socket.create_connection((target, port), timeout=timeout)
            try:
                ctx = ssl.create_default_context()
                ss = ctx.wrap_socket(s, server_hostname=target)
                try:
                    ss.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
                except Exception:
                    pass
                raw = _recv_until(ss, timeout, max_bytes=8192)
                txt = raw.decode(errors="ignore")
                server = ""
                m = re.search(r"^Server:\s*(.+)$", txt, re.IGNORECASE | re.MULTILINE)
                if m:
                    server = m.group(1).strip()
                cert = ss.getpeercert()
                subj = cert.get('subject', ())
                subj_str = " ".join("=".join(item[0]) for part in subj for item in part) if subj else ""
                ss.close()
                if server:
                    return f"HTTPS | Server: {server} | cert:{subj_str}"
                first = txt.splitlines()[0] if txt else ""
                return f"HTTPS | {first} | cert:{subj_str}"
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                return None

        if port in http_like:
            s = socket.create_connection((target, port), timeout=timeout)
            try:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
            raw = _recv_until(s, timeout, max_bytes=8192)
            s.close()
            txt = raw.decode(errors="ignore")
            server = ""
            m = re.search(r"^Server:\s*(.+)$", txt, re.IGNORECASE | re.MULTILINE)
            if m:
                server = m.group(1).strip()
            if server:
                return f"HTTP | Server: {server}"
            first = txt.splitlines()[0] if txt else ""
            return first.strip()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        try:
            data = s.recv(2048)
            if not data:
                s.close()
                return ""
            raw = data.decode(errors="ignore").strip()
            s.close()
            return raw.splitlines()[0] if raw else ""
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return ""
    except Exception:
        return None

def _normalize_version(v):
    v = (v or "").strip().lower()
    v = re.sub(r'[^0-9a-z\.]', '', v)
    parts = [p for p in v.split('.') if p != ""]
    out = []
    for p in parts:
        m = re.match(r'(\d+)', p)
        if not m:
            break
        out.append(int(m.group(1)))
    return out

def _cmp_ver(a, b):
    la, lb = len(a), len(b)
    for i in range(max(la, lb)):
        va = a[i] if i < la else 0
        vb = b[i] if i < lb else 0
        if va < vb: return -1
        if va > vb: return 1
    return 0

def _cve_affects_version(product, version, desc):
    d = (desc or "").lower()
    if product.lower() not in d:
        return False

    inst = _normalize_version(version)
    if not inst:
        return False

    for m in re.finditer(r'(?:before|prior to)\s+([0-9][0-9a-z\.\-_]*)', d):
        x = _normalize_version(m.group(1))
        if x and _cmp_ver(inst, x) >= 0:
            return False

    for m in re.finditer(r'(<|<=)\s*([0-9][0-9a-z\.\-_]*)', d):
        op = m.group(1); x = _normalize_version(m.group(2))
        if not x:
            continue
        cmp = _cmp_ver(inst, x)
        if op == '<' and not (cmp < 0): return False
        if op == '<=' and not (cmp <= 0): return False

    for m in re.finditer(r'through\s+([0-9][0-9a-z\.\-_]*)', d):
        x = _normalize_version(m.group(1))
        if x and _cmp_ver(inst, x) <= 0:
            return True

    for m in re.finditer(r'([0-9]+\.[0-9][0-9a-z\.\-_]*)\s*(?:to|-|through)\s*([0-9]+\.[0-9][0-9a-z\.\-_]*)', d):
        a = _normalize_version(m.group(1))
        b = _normalize_version(m.group(2))
        if a and b and _cmp_ver(inst, a) >= 0 and _cmp_ver(inst, b) <= 0:
            return True

    if version.lower() in d:
        return True
    vmj = ".".join(version.split(".")[:2])
    if vmj and vmj in d and "not affected" not in d:
        return True

    return False

def _is_cve_relevant(cve_data, product, version):
    pub = cve_data.get("published") or ""
    try:
        if pub and int(pub[:4]) < 2010:
            return False
    except Exception:
        pass
    desc = cve_data.get("desc") or cve_data.get("summary") or ""
    return _cve_affects_version(product, version, desc)

def _extract_versions(banner: str):
    if not banner:
        return []
    versions = set()
    for m in re.finditer(r'\b(\d+\.\d+(?:\.\d+){0,2}(?:[a-z]\d*)?(?:[-_][0-9A-Za-z\.]+)?)\b', banner):
        v = m.group(1)
        if re.match(r'^\d+\.\d+', v):
            versions.add(v)
    return list(versions)

def _normalize_service_for_product(service_name: str):
    if not service_name:
        return ""
    s = service_name.lower()
    mapping = {
        "ssh": "openssh",
        "ftp": "ftp",
        "ftp control": "ftp",
        "ftp data": "ftp",
        "smtp": "postfix",
        "smtp (submission)": "postfix",
        "pop3": "dovecot",
        "pop3s": "dovecot",
        "imap": "dovecot",
        "imaps": "dovecot",
        "http": "apache",
        "https": "apache",
        "https-alt / tomcat": "tomcat",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "rdp": "rdp",
        "redis": "redis",
        "mongodb": "mongodb",
    }
    return mapping.get(s, s.split()[0])

def _extract_product_version_pairs(banner: str):
    if not banner:
        return []
    pairs = set()

    for m in re.finditer(r'\b([A-Za-z][A-Za-z0-9\-_]{1,40})[\/_](\d+\.\d+(?:\.\d+){0,2}[a-z0-9\-\.]*)', banner):
        prod = m.group(1).lower()
        ver = m.group(2)
        if prod not in ("http", "https", "ssl", "tls", "server"):
            pairs.add(f"{prod} {ver}")

    for m in re.finditer(r'\b([A-Za-z][A-Za-z0-9\-_]{1,40})\s+v?(\d+\.\d+(?:\.\d+){0,2}[a-z0-9\-\.]*)', banner):
        prod = m.group(1).lower()
        ver = m.group(2)
        if prod not in ("version", "server", "port", "host", "protocol"):
            pairs.add(f"{prod} {ver}")

    m_srv = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
    if m_srv:
        for token in m_srv.group(1).split():
            mm = re.match(r'([A-Za-z][A-Za-z0-9\-_]+)/(\d+\.\d+(?:\.\d+)*)', token)
            if mm:
                pairs.add(f"{mm.group(1).lower()} {mm.group(2)}")

    m_ossh = re.search(r'OpenSSH[_ ](\d[\w\.p-]+)', banner, re.IGNORECASE)
    if m_ossh:
        pairs.add(f"openssh {m_ossh.group(1)}")

    m_mysql = re.search(r'mysql version:\s*([\d\.]+)', banner, re.IGNORECASE)
    if m_mysql:
        pairs.add(f"mysql {m_mysql.group(1)}")

    out = []
    for pv in pairs:
        prod, ver = pv.split()[:2]
        if re.match(r'^\d+\.\d+', ver):
            out.append(pv)
    return out

def check_vulnerabilities_multi(detected,
                                max_candidates_per_service=5,
                                max_cves_per_candidate=4,
                                pause_between_queries=0.6):
    results = []
    global_seen = set()

    for port, svc, info in detected:
        entry = {"port": port, "service": svc, "info": info, "matches": []}
        banner = info or ""
        product_pairs = _extract_product_version_pairs(banner)
        versions = _extract_versions(banner)

        candidates = []

        for pp in product_pairs:
            candidates.append(pp)

        if versions:
            if not product_pairs:
                base = _normalize_service_for_product(svc)
                for v in versions:
                    candidates.append(f"{base} {v}")

        seen_local = set()
        final_candidates = []
        for c in candidates:
            c_norm = c.lower()
            if c_norm not in seen_local:
                seen_local.add(c_norm)
                final_candidates.append(c)
            if len(final_candidates) >= max_candidates_per_service:
                break

        if not final_candidates:
            results.append(entry)
            continue

        for cand in final_candidates:
            cand_norm = cand.lower()
            if cand_norm in global_seen:
                continue
            global_seen.add(cand_norm)

            parts = cand.split()
            if len(parts) < 2:
                continue
            product = parts[0]
            version = parts[1]

            match_block = {"candidate": cand, "sources": {}}

            nvd_all = _query_nvd(cand, max_results=15)
            _time.sleep(pause_between_queries)
            nvd_rel = [c for c in nvd_all if _is_cve_relevant(c, product, version)][:max_cves_per_candidate]
            if nvd_rel:
                match_block["sources"]["NVD"] = nvd_rel

            circl_all = _query_circl(cand, max_results=15)
            _time.sleep(pause_between_queries)
            circl_rel = [c for c in circl_all if _is_cve_relevant(c, product, version)][:max_cves_per_candidate]
            if circl_rel:
                match_block["sources"]["circl"] = circl_rel

            edb_all = _query_exploitdb(cand, max_results=25)
            _time.sleep(pause_between_queries)
            ver_minor = ".".join(version.split(".")[:2])
            edb_rel = []
            for e in edb_all:
                d = e.get("desc", "").lower()
                if product in d and (version in d or ver_minor in d):
                    edb_rel.append(e)
                if len(edb_rel) >= max_cves_per_candidate:
                    break
            if edb_rel:
                match_block["sources"]["exploit-db"] = edb_rel

            if match_block["sources"]:
                entry["matches"].append(match_block)

        results.append(entry)

    return results

check_vulnerabilities = check_vulnerabilities_multi


def pretty_print_vuln_results(vuln_results):
    if not vuln_results:
        print(Fore.YELLOW + "No vulnerability data found / nothing to check.")
        return

    print()
    print(Style.BRIGHT + Fore.WHITE + "Vulnerability lookup results (aggregated sources)")
    print(Style.BRIGHT + Fore.WHITE + "-" * 80)
    for ent in vuln_results:
        port = ent.get("port")
        svc = ent.get("service")
        info = ent.get("info") or ""
        matches = ent.get("matches", [])
        print(Fore.MAGENTA + f"Port {port}/tcp  Service: {svc}  Info: {info}")
        if not matches:
            print(Fore.YELLOW + "  No matches found across sources.")
            continue
        for m in matches:
            cand = m.get("candidate")
            sources = m.get("sources", {})
            print(Fore.CYAN + f"  Candidate: {cand}")
            for src, items in sources.items():
                print(Fore.WHITE + f"    Source: {src}  Results: {len(items)}")
                for it in items:
                    cve = it.get("cve") or it.get("id") or it.get("CVE") or it.get("id")
                    desc = (it.get("desc") or it.get("summary") or it.get("descText") or "")[:300]
                    pub = it.get("published") or it.get("date") or it.get("Published") or ""
                    print(Fore.RED + f"      {cve}  ({pub})")
                    if desc:
                        print(Fore.WHITE + f"        {desc}{'...' if len(desc) > 300 else ''}")
            print("    " + "-" * 60)
        print("-" * 80)
    print()

def print_current_time():
    current_time = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime())
    print(Fore.RED + current_time)

def _service_name_from_port(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "Unknown Service")
    
def scan_all_ports(target_ip, preset="normal"):
    PRESETS = {
        "slow":       {"fast_timeout": 0.6,  "discovery_workers": 40,  "chunksize": 1},
        "normal":     {"fast_timeout": 0.20, "discovery_workers": 200, "chunksize": 200},
        "fast":       {"fast_timeout": 0.12, "discovery_workers": 320, "chunksize": 400},
        "aggressive": {"fast_timeout": 0.06, "discovery_workers": 450, "chunksize": 600},
    }

    preset = (preset or "normal").lower()
    if preset not in PRESETS:
        print(Fore.YELLOW + f"Unknown Preset '{preset}', use 'normal'.")
        preset = "normal"

    params = PRESETS[preset]
    fast_timeout = params["fast_timeout"]
    discovery_workers = params["discovery_workers"]
    chunksize = params["chunksize"]

    try:
        target = socket.gethostbyname(target_ip)
    except Exception as e:
        print(Fore.RED + f"Hostname resolution failed: {e}")
        return []

    print(Fore.RED + f"Starting full port scan on {target} ({target_ip}) using preset '{preset}' "
                     f"(timeout={fast_timeout:.2f}s workers={discovery_workers} chunksize={chunksize})...")
    open_ports = []

    ports = range(1, 65536)

    def _fast_check(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(fast_timeout)
                if s.connect_ex((target, p)) == 0:
                    return p
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=discovery_workers) as ex:
        for res in ex.map(_fast_check, ports, chunksize=chunksize):
            if res:
                open_ports.append(res)

    open_ports.sort()
    print(Fore.RED + f"Discovery complete. {len(open_ports)} open ports found.")

    if not open_ports:
        return []

    detected = []
    probe_timeout = max(0.6, fast_timeout * 3)
    probe_workers = min(100, max(10, len(open_ports)))

    def _probe(p):
        svc = _service_name_from_port(p)
        banner = _probe_banner(target, p, timeout=probe_timeout)
        if banner is None:
            return (p, svc, "no response")
        banner = banner or ""
        m = re.search(r"(version[:\s]*\d+(\.\d+){0,3})|(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
        ver = m.group(0) if m else ""
        info = banner if banner else (ver if ver else "unknown")
        return (p, svc, info)

    with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as ex:
        for res in ex.map(_probe, open_ports, chunksize=10):
            detected.append(res)

    print(Fore.RED + f"Scan completed. {len(detected)} open ports detailed.")
    return detected

def pretty_print_scan_results(detected):
    if not detected:
        print(Fore.YELLOW + "No open Ports found.")
        return

    detected_sorted = sorted(detected, key=lambda x: x[0])

    hdr_port = "PORT"
    hdr_proto = "PROTO"
    hdr_svc = "SERVICE"
    hdr_info = "INFO"
    print()
    print(Style.BRIGHT + Fore.WHITE + f"{hdr_port:>6}  {hdr_proto:6}  {hdr_svc:20}  {hdr_info}")
    print(Style.BRIGHT + Fore.WHITE + "-" * 80)

    for port, svc, info in detected_sorted:
        proto = "tcp"
        port_str = f"{port:>6}"
        svc_str = (svc[:20]) if svc else "unknown"
        if any(k.lower() in (svc_str.lower()) for k in ("ssh", "rdp", "mysql", "vnc", "ftp", "smtp", "http", "https")):
            svc_col = Fore.CYAN + svc_str
        else:
            svc_col = Fore.WHITE + svc_str

        if info and ("no response" in info.lower() or "unknown" in info.lower()):
            info_col = Fore.YELLOW + info
        else:
            info_col = Fore.GREEN + (info if info else "-")

        print(f"{Fore.GREEN}{port_str}  {Fore.MAGENTA}{proto:6}  {svc_col:20}  {info_col}{Style.RESET_ALL}")

    print()
    print(Style.BRIGHT + Fore.WHITE + f"Total open ports: {len(detected_sorted)}")
    print()

DEFAULT_TOP_PORTS = [
    21,22,23,25,53,67,68,69,80,81,88,110,111,119,123,135,139,143,161,162,179,194,199,389,443,445,465,
    514,515,587,631,636,873,902,993,995,1080,1194,1433,1521,1723,1883,1900,2049,2082,2083,2086,2095,2096,
    2121,2222,2302,25565,27015,27017,3306,3389,3478,3632,3690,4000,4444,4899,5000,5001,5060,5061,5432,5900,
    5984,6000,6379,6667,6881,7001,7002,7199,8000,8008,8080,8081,8443,8888,9001,9090,9200,9300,9999,11211,
    27019,28017,32768,33060,50070,50075,5985,5986,12345,25575
]

def top_1000_port_scan(target_ip, preset="normal"):
    ports = DEFAULT_TOP_PORTS

    PRESETS = {
        "slow":       {"fast_timeout": 0.6,  "discovery_workers": 40,  "chunksize": 1},
        "normal":     {"fast_timeout": 0.20, "discovery_workers": 200, "chunksize": 200},
        "fast":       {"fast_timeout": 0.12, "discovery_workers": 320, "chunksize": 400},
        "aggressive": {"fast_timeout": 0.06, "discovery_workers": 450, "chunksize": 600},
    }

    preset = (preset or "normal").lower()
    if preset not in PRESETS:
        print(Fore.YELLOW + f"Unknown Preset '{preset}', use 'normal'.")
        preset = "normal"

    params = PRESETS[preset]
    fast_timeout = params["fast_timeout"]
    discovery_workers = params["discovery_workers"]
    chunksize = params["chunksize"]

    try:
        target = socket.gethostbyname(target_ip)
    except Exception as e:
        print(Fore.RED + f"Hostname resolution failed: {e}")
        return []

    ports = sorted(set(p for p in ports if 1 <= p <= 65535))
    print(Fore.RED + f"Starting Top port scan on {target} ({target_ip}) using preset '{preset}' "
                     f"(ports={len(ports)} timeout={fast_timeout:.2f}s workers={discovery_workers})...")

    open_ports = []

    def _fast_check(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(fast_timeout)
                if s.connect_ex((target, p)) == 0:
                    return p
        except Exception:
            return None

    use_workers = min(discovery_workers, max(4, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=use_workers) as ex:
        for res in ex.map(_fast_check, ports, chunksize=max(1, chunksize)):
            if res:
                open_ports.append(res)

    open_ports.sort()
    print(Fore.RED + f"Discovery complete. {len(open_ports)} open ports found: {open_ports}")

    if not open_ports:
        return []

    detected = []
    probe_timeout = max(0.6, fast_timeout * 3)
    probe_workers = min(100, max(4, len(open_ports)))

    def _probe(p):
        svc = _service_name_from_port(p)
        banner = _probe_banner(target, p, timeout=probe_timeout)
        if banner is None:
            return (p, svc, "no response")
        banner = banner or ""
        m = re.search(r"(version[:\s]*\d+(\.\d+){0,3})|(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
        ver = m.group(0) if m else ""
        info = banner if banner else (ver if ver else "unknown")
        return (p, svc, info)

    with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as ex:
        for res in ex.map(_probe, open_ports, chunksize=10):
            detected.append(res)

    print(Fore.RED + f"Top scan completed. {len(detected)} open ports detailed.")
    return detected


def _build_report_structure(detected, vuln_results):
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "open_ports": len(detected),
            "vuln_candidates": sum(len(x.get("matches", [])) for x in (vuln_results or []))
        },
        "ports": [
            {"port": p, "service": s, "info": i}
            for p, s, i in detected
        ],
        "vulnerabilities": vuln_results or []
    }

def _save_json_report(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(Fore.GREEN + f"JSON report saved to {os.path.abspath(path)}")
    except Exception as e:
        print(Fore.RED + f"Failed to save JSON report: {e}")

def _save_html_report(path, data):
    try:
        html = []
        html.append("<!doctype html><html><head><meta charset='utf-8'><title>Scan Report</title>")
        html.append("<style>body{font-family:Segoe UI,Arial;background:#111;color:#eee;padding:20px}h1,h2{color:#ffa}</style></head><body>")
        html.append(f"<h1>Scan Report</h1><p>Generated: {data['generated_at']}</p>")
        html.append(f"<h2>Summary</h2><p>Open ports: {data['summary']['open_ports']} &nbsp; Vulnerable candidates: {data['summary']['vuln_candidates']}</p>")
        html.append("<h2>Open Ports</h2><table border='1' cellpadding='6' cellspacing='0'><tr><th>Port</th><th>Service</th><th>Info</th></tr>")
        for p in data["ports"]:
            html.append(f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['info']}</td></tr>")
        html.append("</table>")

        html.append("<h2>Vulnerability Matches</h2>")
        if not data["vulnerabilities"]:
            html.append("<p>No vulnerability matches found.</p>")
        else:
            for ent in data["vulnerabilities"]:
                html.append(f"<h3>Port {ent.get('port')} — {ent.get('service')}</h3>")
                html.append(f"<p>{ent.get('info') or ''}</p>")
                for m in ent.get("matches", []):
                    html.append(f"<h4>Candidate: {m.get('candidate')}</h4>")
                    sources = m.get("sources", {}) if isinstance(m.get("sources", {}), dict) else {}
                    for src, items in sources.items():
                        html.append(f"<b>Source: {src} ({len(items)})</b><ul>")
                        for it in items:
                            cve = it.get("cve") or it.get("id") or it.get("CVE") or ""
                            desc = (it.get("desc") or it.get("summary") or "")[:800]
                            html.append("<li>")
                            if cve:
                                html.append(f"<a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank'>{cve}</a>: ")
                            html.append(f"{desc}")
                            html.append("</li>")
                        html.append("</ul>")
        html.append("<footer><p>Generated by PortHunt -"
                    "<a href='https://ctxzero.dev/PortHunt' target='_blank'>Website</a> • "
                    "<a href='https://discord.gg/KqVkdYN6yr' target='_blank'>Discord</a></p></footer></body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(Fore.GREEN + f"HTML report saved to {os.path.abspath(path)}")
    except Exception as e:
        print(Fore.RED + f"Failed to save HTML report: {e}")

def _handle_scan_and_vulns(result):
    pretty_print_scan_results(result)
    if not result:
        return
    do_v = input("Search public vulnerability databases for discovered services? (y/N): ").strip().lower()
    vuln_results = None
    if do_v == "y":
        print(Fore.YELLOW + "Querying multiple vulnerability sources (may be rate-limited) — this may take a few seconds...")
        vuln_results = check_vulnerabilities(result)
        pretty_print_vuln_results(vuln_results)

    save_choice = input("Save scan + vuln report? (y/N): ").strip().lower()
    if save_choice != "y":
        return

    struct = _build_report_structure(result, vuln_results)
    default_name = "scan_report_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = input(f"Filename (without extension) [{default_name}]: ").strip() or default_name
    fmt = input("Format (json/html/both) [both]: ").strip().lower() or "both"

    if fmt in ("json", "both"):
        _save_json_report(fname + ".json", struct)
    if fmt in ("html", "both"):
        _save_html_report(fname + ".html", struct)

def _parse_ports_input(s):
    ports = set()
    if not s:
        return []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a = int(a); b = int(b)
                if a > b:
                    a, b = b, a
                for p in range(max(1, a), min(65535, b) + 1):
                    ports.add(p)
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)

def scan_ports_list(target_ip, ports, preset="normal"):
    PRESETS = {
        "slow":       {"fast_timeout": 0.6,  "discovery_workers": 40,  "chunksize": 1},
        "normal":     {"fast_timeout": 0.20, "discovery_workers": 200, "chunksize": 50},
        "fast":       {"fast_timeout": 0.12, "discovery_workers": 320, "chunksize": 100},
        "aggressive": {"fast_timeout": 0.06, "discovery_workers": 450, "chunksize": 200},
    }

    preset = (preset or "normal").lower()
    if preset not in PRESETS:
        print(Fore.YELLOW + f"Unknown Preset '{preset}', use 'normal'.")
        preset = "normal"
    params = PRESETS[preset]
    fast_timeout = params["fast_timeout"]
    discovery_workers = params["discovery_workers"]
    chunksize = params["chunksize"]

    try:
        target = socket.gethostbyname(target_ip)
    except Exception as e:
        print(Fore.RED + f"Hostname resolution failed: {e}")
        return []

    ports = list(sorted(set(int(p) for p in ports if 1 <= int(p) <= 65535)))
    if not ports:
        print(Fore.YELLOW + "No valid ports to scan.")
        return []

    print(Fore.RED + f"Scanning {len(ports)} ports on {target} using preset '{preset}' (timeout={fast_timeout}s workers={discovery_workers})...")

    open_ports = []

    def _fast_check(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(fast_timeout)
                if s.connect_ex((target, p)) == 0:
                    return p
        except Exception:
            return None

    use_workers = min(discovery_workers, max(4, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=use_workers) as ex:
        for res in ex.map(_fast_check, ports, chunksize=max(1, chunksize)):
            if res:
                open_ports.append(res)

    open_ports.sort()
    print(Fore.RED + f"Discovery complete. {len(open_ports)} open ports found: {open_ports}")
    if not open_ports:
        return []

    detected = []
    probe_timeout = max(0.6, fast_timeout * 3)
    probe_workers = min(100, max(4, len(open_ports)))

    def _probe(p):
        svc = _service_name_from_port(p)
        banner = _probe_banner(target, p, timeout=probe_timeout)
        if banner is None:
            return (p, svc, "no response")
        banner = banner or ""
        m = re.search(r"(version[:\s]*\d+(\.\d+){0,3})|(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
        ver = m.group(0) if m else ""
        info = banner if banner else (ver if ver else "unknown")
        return (p, svc, info)

    with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as ex:
        for res in ex.map(_probe, open_ports, chunksize=10):
            detected.append(res)

    print(Fore.RED + f"Scan completed. {len(detected)} open ports detailed.")
    return detected

def _parse_ip_range_input(s):
    if not s:
        return []
    s = s.strip()
    ips = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    ips.add(str(ip))
            except Exception:
                continue
        elif "-" in part:
            try:
                a, b = part.split("-", 1)
                a = a.strip(); b = b.strip()
                if a.count(".") == 3 and b.count(".") == 0:
                    base = ".".join(a.split(".")[:3])
                    start = int(a.split(".")[3])
                    end = int(b)
                    for o in range(start, end + 1):
                        ips.add(f"{base}.{o}")
                else:
                    start_ip = int(ipaddress.IPv4Address(a))
                    end_ip = int(ipaddress.IPv4Address(b))
                    if start_ip > end_ip:
                        start_ip, end_ip = end_ip, start_ip
                    for n in range(start_ip, end_ip + 1):
                        ips.add(str(ipaddress.IPv4Address(n)))
            except Exception:
                continue
        else:
            try:
                ipaddress.IPv4Address(part)
                ips.add(part)
            except Exception:
                continue
    return sorted(ips)

def _ping_host(host, timeout_ms=500):
    try:
        proc = subprocess.run(["ping", "-n", "1", "-w", str(int(timeout_ms)), host],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except Exception:
        return False

def discover_hosts(ips, timeout_ms=400, workers=200):
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(4, len(ips)))) as ex:
        futs = {ex.submit(_ping_host, ip, timeout_ms): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass
    return sorted(alive)

def scan_ip_range_cli():
    rng = input("Enter IP range (CIDR, range or comma list): ").strip()
    if not rng:
        log("No range provided", "error")
        return
    
    ips = _parse_ip_range_input(rng)
    if not ips:
        log("No valid IPs parsed", "error")
        return
    
    print(Fore.WHITE + f"Parsed {len(ips)} addresses. Running host discovery (ping)...")
    ping_timeout = input("Ping timeout ms [400]: ").strip()
    try:
        ping_timeout = int(ping_timeout) if ping_timeout else 400
    except Exception:
        ping_timeout = 400
    
    workers = input("Discovery workers [200]: ").strip()
    try:
        workers = int(workers) if workers else 200
    except Exception:
        workers = 200

    alive = discover_hosts(ips, timeout_ms=ping_timeout, workers=workers)
    print(Fore.GREEN + f"{len(alive)} hosts alive: {alive}")
    
    if not alive:
        log("No alive hosts found", "warn")
        return
    
    preset = input("Scan preset (slow/normal/fast/aggressive) [normal]: ").strip().lower() or "normal"
    
    all_results = {}
    for host in alive:
        print(Fore.CYAN + f"\n{'='*80}")
        print(Fore.CYAN + f">>> Scanning {host}...")
        print(Fore.CYAN + f"{'='*80}")
        detected = top_1000_port_scan(host, preset=preset)
        all_results[host] = detected
        pretty_print_scan_results(detected)
    
    print(Fore.WHITE + "\n" + "="*80)
    print(Fore.WHITE + f"Scan complete for {len(alive)} hosts")
    print("="*80)
    
    do_vuln = input("\nSearch CVEs for discovered services? (y/N): ").strip().lower()
    
    all_vuln_results = {}
    if do_vuln == "y":
        for host in alive:
            if all_results[host]:
                print(Fore.CYAN + f"\nChecking vulnerabilities for {host}...")
                vuln_res = check_vulnerabilities_multi(all_results[host])
                all_vuln_results[host] = vuln_res
                pretty_print_vuln_results(vuln_res)
    
    save_choice = input("\nSave scan + vuln report for all hosts? (y/N): ").strip().lower()
    if save_choice == "y":
        default_name = "range_scan_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        fname = input(f"Filename (without extension) [{default_name}]: ").strip() or default_name
        fmt = input("Format (json/html/both) [both]: ").strip().lower() or "both"
        
        struct = _build_range_report_structure(all_results, all_vuln_results)
        
        if fmt in ("json", "both"):
            _save_json_report(f"{fname}.json", struct)
            print(Fore.GREEN + f"✓ Saved {fname}.json")
        if fmt in ("html", "both"):
            _save_html_report_range(f"{fname}.html", struct)
            print(Fore.GREEN + f"✓ Saved {fname}.html")
    
    print(Fore.GREEN + "\n" + "="*80)
    print(Fore.YELLOW + "SUMMARY")
    print("="*80)
    for host in alive:
        ports_count = len(all_results[host])
        vuln_count = len(all_vuln_results.get(host, []))
        print(Fore.WHITE + f"{host:20} | {ports_count:3} open ports | {vuln_count:3} CVEs found")
    print("="*80)

def _build_range_report_structure(all_results, all_vuln_results):
    report = {
        "scan_date": datetime.utcnow().isoformat(),
        "hosts": {}
    }
    
    for host in all_results.keys():
        report["hosts"][host] = {
            "detected_ports": all_results[host],
            "vulnerabilities": all_vuln_results.get(host, [])
        }
    
    return report

def _save_html_report_range(path, data):
    try:
        html = []
        html.append("<!doctype html><html><head><meta charset='utf-8'><title>Range Scan Report</title>")
        html.append("<style>body{font-family:Segoe UI,Arial;background:#111;color:#eee;padding:25px}"
                    ".host{border:2px solid #5a15ff;padding:15px;margin:18px 0}"
                    "h1{color:#ffa}h2{color:#ccc}table{border-collapse:collapse;margin:10px 0}"
                    "th,td{border:1px solid #444;padding:6px 10px}"
                    ".cve{background:#2a1a1a;margin:6px 0;padding:6px;border-left:4px solid #cc5500}"
                    ".candidate{color:#5ad;font-weight:600;margin-top:8px}"
                    ".src{color:#ffa;font-weight:600;margin-top:4px}"
                    ".port{color:#0af;font-weight:600}</style></head><body>")
        html.append(f"<h1>Range Scan Report</h1><p>Generated: {data.get('scan_date')}</p>")

        for host, host_data in data.get("hosts", {}).items():
            ports = host_data.get("detected_ports", [])
            vulns = host_data.get("vulnerabilities", [])
            html.append(f"<div class='host'><h2>Host: {host}</h2>")
            html.append(f"<p><b>Open Ports:</b> {len(ports)} &nbsp; "
                        f"<b>Vuln Candidates:</b> {sum(len(e.get('matches', [])) for e in vulns)}</p>")

            html.append("<table><tr><th>Port</th><th>Service</th><th>Info</th></tr>")
            for p, svc, info in ports:
                html.append(f"<tr><td class='port'>{p}</td><td>{svc}</td><td>{info}</td></tr>")
            html.append("</table>")

            html.append("<h3>Vulnerability Matches</h3>")
            if not vulns:
                html.append("<p>No vulnerability matches found.</p>")
            else:
                for entry in vulns:
                    port = entry.get("port"); svc = entry.get("service"); info = entry.get("info") or ""
                    matches = entry.get("matches", [])
                    html.append(f"<div class='cve'><div><b>Port {port} / {svc}</b> - {info}</div>")
                    if not matches:
                        html.append("<div>No matches.</div>")
                    else:
                        for m in matches:
                            cand = m.get("candidate")
                            html.append(f"<div class='candidate'>Candidate: {cand}</div>")
                            for src, items in (m.get('sources') or {}).items():
                                html.append(f"<div class='src'>Source: {src} ({len(items)})</div><ul>")
                                for it in items:
                                    cve = it.get("cve") or it.get("id") or it.get("CVE") or ""
                                    desc = (it.get("desc") or it.get("summary") or "")[:400]
                                    if cve:
                                        html.append(f"<li><a style='color:#ff6' target='_blank' "
                                                    f"href='https://nvd.nist.gov/vuln/detail/{cve}'>{cve}</a>: {desc}</li>")
                                    else:
                                        html.append(f"<li>{desc}</li>")
                                html.append("</ul>")
                    html.append("</div>")
            html.append("</div>") 

        html.append("<footer><p>Generated by PortHunt (ctxzero) — authorized testing only.</p></footer></body></html>")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(Fore.GREEN + f"Range HTML report saved to {os.path.abspath(path)}")
    except Exception as e:
        print(Fore.RED + f"Failed to save range HTML report: {e}")

def main_menu():
  print(THEME["header"] + "                          ██▓███   ▒█████   ██▀███  ▄▄▄█████" + Fore.WHITE + "▓ ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓")
  print(THEME["header"] + "                         ▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓" + Fore.WHITE + "▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒")
  print(THEME["header"] + "                         ▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒" + Fore.WHITE + "░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░")
  print(THEME["header"] + "                         ▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░" + Fore.WHITE + " ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ")
  print(THEME["header"] + "                         ▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░" + Fore.WHITE + " ░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ")
  print(THEME["header"] + "                         ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░  " + Fore.WHITE + "  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ")
  print(THEME["header"] + "                         ░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░    " + Fore.WHITE + " ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    ")
  print(THEME["header"] + "                         ░░       ░ ░ ░ ▒    ░░   ░   ░      " + Fore.WHITE + " ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      ")
  print(THEME["header"] + "                                      ░ ░     ░              " + Fore.WHITE + " ░  ░  ░   ░              ░          ")
  print("")  
  print(THEME["header"] + "                                    [*] Author: ctxzero | GitHub: github.com/ctxzero")
  print(THEME["header"] + "                        [*] Disclaimer: For educational and authorized penetration testing use only.")
  print()
  print(Fore.RED + "[1]" +  Fore.WHITE + " Scan All Ports")
  print(Fore.RED + "[2]" +  Fore.WHITE + " Scan Top Ports")
  print(Fore.RED + "[3]" +  Fore.WHITE + " Scan Custom Port Range")
  print(Fore.RED + "[4]" + Fore.WHITE + " Scan IP Range")
  print(Fore.RED + "[5]" + Fore.WHITE + " Toggle Verbose Mode")
  print(Fore.RED + "[6]" + Fore.WHITE + " Exit")
  choice = input(Fore.RED + "Select an option: " + Fore.WHITE)  
  if choice == "1":
   target = input("Enter target IP address or hostname: ").strip()
   preset_input = input("Choose Preset (slow, normal, fast, aggressive) [default: normal]: ").strip().lower()
   if preset_input == "":
       preset_input = "normal"
   if preset_input not in ("slow", "normal", "fast", "aggressive"):
       print(Fore.YELLOW + f"Unknown Preset '{preset_input}', use 'slow', 'normal', 'fast' or 'aggressive'.")
       preset_input = "normal"
   result = scan_all_ports(target, preset=preset_input)
   _handle_scan_and_vulns(result)
  elif choice == "2":
   target = input("Enter target IP address or hostname: ").strip()
   preset_input = input("Choose Preset (slow, normal, fast, aggressive) [default: normal]: ").strip().lower()
   if preset_input == "":
       preset_input = "normal"
   if preset_input not in ("slow", "normal", "fast", "aggressive"):
       print(Fore.YELLOW + f"Unknown Preset '{preset_input}', use 'slow', 'normal', 'fast' or 'aggressive'.")
       preset_input = "normal"
   result = top_1000_port_scan(target, preset=preset_input)
   _handle_scan_and_vulns(result)
  elif choice == "3":
   target = input("Enter target IP address or hostname: ").strip()
   ports_input = input("Enter ports (e.g. 80,443,8000-8100): ").strip()
   ports = _parse_ports_input(ports_input)
   if not ports:
       print(Fore.YELLOW + "No valid ports parsed. Aborting.")
   else:
       preset_input = input("Choose Preset (slow, normal, fast, aggressive) [default: normal]: ").strip().lower()
       if preset_input == "":
           preset_input = "normal"
       if preset_input not in ("slow", "normal", "fast", "aggressive"):
           print(Fore.YELLOW + f"Unknown Preset '{preset_input}', use 'slow', 'normal', 'fast' or 'aggressive'.")
           preset_input = "normal"
       result = scan_ports_list(target, ports, preset=preset_input)
       _handle_scan_and_vulns(result)
  elif choice == "4":
      scan_ip_range_cli()
  elif choice == "5":
      current = VERBOSE
      enable_verbose(not current)
  elif choice == "6":
        print(THEME["warn"] + "Exiting. Goodbye.")
        sys.exit(0)
  else:
   print(Fore.YELLOW + "Invalid option. Please select a valid menu number.")

try:
    while True:
        main_menu()
except (KeyboardInterrupt, EOFError):
    print(THEME["warn"] + "\nExiting (user interrupt). Goodbye.")
    sys.exit(0)
