"""
OSINT 侦察引擎 v1.0 — Open Source Intelligence
───────────────────────────────────────────
覆盖:
  • DNS 枚举: A/AAAA/MX/NS/TXT/CNAME/SOA/PTR
  • Whois 查询: 注册信息/联系人/到期时间
  • 子域名枚举: 证书透明度(crt.sh)/字典爆破
  • 端口 banner 抓取: socket 原始连接
  • HTTP 指纹: Server/Header/技术栈
  • 邮件地址收集: 从网页提取

纯 Python 实现, 无外部 API 依赖(证书透明度用 crt.sh)。
"""

import socket
import ssl
import re
import subprocess
import json
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class DnsRecord:
    type: str
    value: str
    ttl: int = 0


@dataclass
class Subdomain:
    name: str
    ip: str = ""
    source: str = ""


@dataclass
class HttpFingerprint:
    url: str
    status: int
    server: str = ""
    tech: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    title: str = ""


class OsintEngine:
    """OSINT 侦察引擎"""

    def __init__(self):
        self._common_subdomains = [
            "www", "mail", "ftp", "api", "admin", "test", "dev", "staging",
            "blog", "shop", "cdn", "img", "static", "vpn", "remote", "owa",
            "exchange", "autodiscover", "portal", "dashboard", "git", "gitlab",
            "jenkins", "ci", "build", "ns1", "ns2", "dns", "smtp", "pop", "imap",
            "webmail", "m", "mobile", "app", "api2", "gateway", "proxy", "db",
            "mysql", "redis", "mongo", "backup", "old", "new", "demo", "beta",
            "alpha", "prod", "stage", "uat", "qa", "support", "help", "docs",
            "wiki", "forum", "community", "status", "monitor", "grafana",
            "prometheus", "kibana", "elasticsearch", "docker", "k8s", "console",
        ]

    # ============ DNS 枚举 ============

    def dns_lookup(self, domain: str, record_type: str = "A") -> List[DnsRecord]:
        """DNS 查询(调用系统 dig/nslookup 或 socket)"""
        records = []
        # 优先用 dig
        try:
            r = subprocess.run(["dig", "+short", record_type, domain],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                for line in r.stdout.strip().split("\n"):
                    if line.strip():
                        records.append(DnsRecord(type=record_type, value=line.strip()))
                return records
        except Exception:
            pass
        # 回退: socket(仅 A 记录)
        if record_type.upper() == "A":
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    records.append(DnsRecord(type="A", value=ip))
            except Exception:
                pass
        return records

    def dns_all(self, domain: str) -> Dict[str, List[DnsRecord]]:
        """查询所有常见 DNS 记录"""
        result = {}
        for rt in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            recs = self.dns_lookup(domain, rt)
            if recs:
                result[rt] = recs
        return result

    def dns_zone_transfer(self, domain: str) -> List[str]:
        """尝试 DNS 区域传送"""
        results = []
        ns_records = self.dns_lookup(domain, "NS")
        for ns in ns_records:
            ns_server = ns.value.rstrip(".")
            try:
                r = subprocess.run(["dig", f"@{ns_server}", "AXFR", domain],
                                   capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and "transfer failed" not in r.stdout.lower():
                    for line in r.stdout.split("\n"):
                        if line.strip() and not line.startswith(";"):
                            results.append(line.strip())
            except Exception:
                pass
        return results

    # ============ Whois ============

    def whois(self, domain: str) -> Dict:
        """Whois 查询"""
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            raw = r.stdout
        except Exception:
            return {"error": "whois command not available"}

        info = {"raw": raw[:2000]}
        # 解析关键字段
        patterns = {
            "registrar": r"(?:Registrar:|Registry Registrar ID:)\s*(.+)",
            "created": r"(?:Creation Date:|created:)\s*(.+)",
            "expires": r"(?:Registry Expiry Date:|Expiration Date:|expires:)\s*(.+)",
            "updated": r"(?:Updated Date:|changed:)\s*(.+)",
            "status": r"(?:Domain Status:|status:)\s*(.+)",
            "nameservers": r"(?:Name Server:|nserver:)\s*(.+)",
            "registrant": r"(?:Registrant Organization:|Registrant:)\s*(.+)",
            "registrant_email": r"(?:Registrant Email:|e-mail:)\s*(.+)",
        }
        for key, pat in patterns.items():
            m = re.findall(pat, raw, re.I)
            if m:
                info[key] = list(set(x.strip() for x in m))[:5]
        return info

    # ============ 子域名枚举 ============

    def subdomain_crtsh(self, domain: str) -> List[Subdomain]:
        """通过 crt.sh 证书透明度枚举子域名"""
        results = []
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lstrip("*.")
                        if n and domain in n and n not in seen:
                            seen.add(n)
                            results.append(Subdomain(name=n, source="crt.sh"))
        except Exception as e:
            pass
        return results

    def subdomain_brute(self, domain: str, wordlist: Optional[List[str]] = None) -> List[Subdomain]:
        """字典爆破子域名"""
        if wordlist is None:
            wordlist = self._common_subdomains
        results = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                results.append(Subdomain(name=fqdn, ip=ip, source="brute"))
            except Exception:
                pass
        return results

    def subdomain_all(self, domain: str, wordlist: Optional[List[str]] = None) -> List[Subdomain]:
        """合并 crt.sh + 爆破结果"""
        seen = set()
        results = []
        for sd in self.subdomain_crtsh(domain) + self.subdomain_brute(domain, wordlist):
            if sd.name not in seen:
                seen.add(sd.name)
                # 补充 IP
                if not sd.ip:
                    try:
                        sd.ip = socket.gethostbyname(sd.name)
                    except Exception:
                        pass
                results.append(sd)
        return results

    # ============ HTTP 指纹 ============

    def http_fingerprint(self, url: str) -> Optional[HttpFingerprint]:
        """HTTP 指纹识别"""
        if not url.startswith("http"):
            url = "https://" + url
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                status = resp.status
                headers = dict(resp.headers)
                body = resp.read(50000).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status = e.code
            headers = dict(e.headers) if e.headers else {}
            body = e.read(50000).decode("utf-8", errors="ignore") if e.fp else ""
        except Exception:
            return None

        # 提取 title
        title = ""
        tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if tm:
            title = tm.group(1).strip()[:100]

        # 技术栈识别
        tech = []
        tech_patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"Drupal|drupal-settings",
            "Joomla": r"joomla|/media/system/js",
            "Laravel": r"laravel|csrf-token.*csrf",
            "Django": r"csrftoken|django",
            "Flask": r"flask|werkzeug",
            "Spring": r"springframework|X-Application-Context",
            "ASP.NET": r"asp.net|__VIEWSTATE",
            "Node.js": r"express|x-powered-by.*express",
            "Nginx": r"Server:.*nginx",
            "Apache": r"Server:.*apache",
            "IIS": r"Server:.*microsoft-iis",
            "Cloudflare": r"CF-RAY|cloudflare",
            "jQuery": r"jquery",
            "Bootstrap": r"bootstrap",
            "Vue.js": r"vue",
            "React": r"react",
        }
        header_str = str(headers).lower()
        for name, pat in tech_patterns.items():
            if re.search(pat, body, re.I) or re.search(pat, header_str, re.I):
                tech.append(name)

        server = headers.get("Server", "") or headers.get("server", "")
        return HttpFingerprint(url=url, status=status, server=server,
                               tech=tech, headers=headers, title=title)

    # ============ 端口 banner 抓取 ============

    def port_banner(self, host: str, port: int, timeout: int = 5) -> str:
        """抓取端口 banner"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            # 发送换行触发 banner
            try:
                s.send(b"\r\n")
            except Exception:
                pass
            data = s.recv(1024).decode("utf-8", errors="ignore")
            s.close()
            return data.strip()[:500]
        except Exception as e:
            return f"error: {e}"

    def scan_common_ports(self, host: str) -> Dict[int, str]:
        """扫描常见端口并抓取 banner"""
        common = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
                  5432, 5900, 6379, 8080, 8443, 9200, 27017]
        results = {}
        for port in common:
            banner = self.port_banner(host, port, timeout=3)
            if banner and not banner.startswith("error"):
                results[port] = banner
        return results

    # ============ 邮件收集 ============

    def collect_emails(self, url: str) -> List[str]:
        """从网页收集邮件地址"""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return []
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
        return list(set(emails))

    # ============ 一键全量侦察 ============

    def full_recon(self, domain: str) -> Dict:
        """一键全量侦察"""
        result = {"domain": domain}
        result["dns"] = self.dns_all(domain)
        result["whois"] = self.whois(domain)
        result["zone_transfer"] = self.dns_zone_transfer(domain)
        result["subdomains"] = [{"name": s.name, "ip": s.ip, "source": s.source}
                                for s in self.subdomain_all(domain)]
        fp = self.http_fingerprint(domain)
        if fp:
            result["http_fingerprint"] = {
                "status": fp.status, "server": fp.server, "tech": fp.tech,
                "title": fp.title,
            }
        result["emails"] = self.collect_emails(f"https://{domain}")
        return result


# ==================== 便捷函数 ====================

def osint_dns(domain: str) -> Dict:
    """DNS 全记录查询"""
    return {k: [r.__dict__ for r in v] for k, v in OsintEngine().dns_all(domain).items()}


def osint_whois(domain: str) -> Dict:
    """Whois 查询"""
    return OsintEngine().whois(domain)


def osint_subdomains(domain: str) -> List[Dict]:
    """子域名枚举"""
    return [{"name": s.name, "ip": s.ip, "source": s.source}
            for s in OsintEngine().subdomain_all(domain)]


def osint_http_fingerprint(url: str) -> Optional[Dict]:
    """HTTP 指纹识别"""
    fp = OsintEngine().http_fingerprint(url)
    if not fp:
        return None
    return {"url": fp.url, "status": fp.status, "server": fp.server,
            "tech": fp.tech, "title": fp.title}


def osint_port_banner(host: str, port: int) -> str:
    """端口 banner 抓取"""
    return OsintEngine().port_banner(host, port)


def osint_full(domain: str) -> Dict:
    """一键全量侦察"""
    return OsintEngine().full_recon(domain)
