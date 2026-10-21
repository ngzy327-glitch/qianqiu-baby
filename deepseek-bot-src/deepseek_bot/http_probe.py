"""
批量 HTTP 探测模块 (http_probe)
基于 VulnClaw 项目功能实现:
- 批量 URL 存活探测 (状态码/标题/长度/指纹)
- 敏感文件/目录扫描 (常见后台、备份、配置文件)
- 响应头安全审计 (HSTS/CSP/X-Frame-Options 等)
- 技术栈指纹识别
- 批量资产探活
"""

import re
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from typing import List, Dict, Optional, Any

# 常见敏感路径 (后台/备份/配置/版本控制/敏感文件)
SENSITIVE_PATHS = [
    # 后台登录
    "/admin", "/admin/login", "/admin.php", "/administrator", "/wp-login.php",
    "/wp-admin", "/manager", "/manage", "/backend", "/console", "/dashboard",
    "/login", "/signin", "/system", "/cms", "/user/login", "/member/login",
    "/admin/index.php", "/admin/login.php", "/adm", "/admin1",
    # 备份文件
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/www.zip",
    "/web.zip", "/site.zip", "/wwwroot.zip", "/1.zip", "/db.sql", "/dump.sql",
    "/database.sql", "/backup.bak", "/data.zip", "/www.tar.gz",
    # 配置文件
    "/.env", "/.env.local", "/.env.production", "/config.php", "/config.inc.php",
    "/config.json", "/config.yaml", "/config.yml", "/db.php", "/database.yml",
    "/settings.py", "/appsettings.json", "/web.config", "/.htaccess",
    "/.git/config", "/.svn/entries", "/.DS_Store", "/.git/HEAD",
    # 编辑器/IDE 临时文件
    "/index.php.bak", "/index.php~", "/index.php.swp", "/index.php.save",
    "/.index.php.swp", "/index.php.old",
    # 信息泄露
    "/phpinfo.php", "/info.php", "/test.php", "/pi.php", "/server-status",
    "/server-info", "/.bash_history", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/.well-known/security.txt",
    # API/接口
    "/api", "/api/v1", "/swagger-ui.html", "/swagger.json", "/v2/api-docs",
    "/graphql", "/graphiql", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/druid/index.html", "/monitoring", "/jolokia",
    # 上传
    "/upload", "/uploads", "/files", "/media", "/static",
]

# 响应头安全检查规则
HEADER_SECURITY_CHECKS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "severity": "high",
        "desc": "未启用 HSTS，可能遭受 SSL 剥离攻击",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "severity": "medium",
        "desc": "未设置 CSP，存在 XSS 风险",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "desc": "未设置 X-Frame-Options，存在点击劫持风险",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "desc": "未设置 nosniff，可能存在 MIME 嗅探风险",
    },
    "X-XSS-Protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "desc": "未启用 XSS 过滤",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "desc": "未设置 Referrer-Policy",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "desc": "未设置 Permissions-Policy (原 Feature-Policy)",
    },
}

# 危险响应头 (信息泄露)
DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def _make_ssl_context() -> ssl.SSLContext:
    """创建不验证证书的 SSL 上下文"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(url: str, timeout: int = 8, method: str = "GET",
                  headers: Optional[Dict] = None) -> Optional[Dict]:
    """发起 HTTP 请求并返回响应信息"""
    if not url.startswith("http"):
        url = "http://" + url

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=default_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ssl_context()) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            body = resp.read(200000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}
        body = e.read(200000).decode("utf-8", errors="ignore") if e.fp else ""
    except Exception as e:
        return {"url": url, "error": str(e)[:200]}

    # 提取 title
    title = ""
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1).strip())[:120]

    # Content-Length
    content_length = len(body)
    cl_header = resp_headers.get("Content-Length") or resp_headers.get("content-length")
    if cl_header and cl_header.isdigit():
        content_length = int(cl_header)

    return {
        "url": url,
        "status": status,
        "title": title,
        "length": content_length,
        "headers": resp_headers,
        "body_snippet": body[:500],
    }


def _detect_tech(headers: Dict, body: str) -> List[str]:
    """识别技术栈"""
    tech = []
    header_str = str(headers).lower()
    patterns = {
        "WordPress": r"wp-content|wp-includes",
        "Drupal": r"drupal-settings|Drupal",
        "Joomla": r"joomla",
        "Laravel": r"laravel|csrf-token",
        "Django": r"csrftoken|django",
        "Flask": r"werkzeug|flask",
        "Spring": r"springframework|X-Application-Context",
        "ASP.NET": r"asp.net|__VIEWSTATE",
        "Node.js/Express": r"x-powered-by.*express",
        "Nginx": r"server.*nginx",
        "Apache": r"server.*apache",
        "IIS": r"server.*microsoft-iis",
        "Cloudflare": r"cf-ray|cloudflare",
        "Tomcat": r"tomcat|coyote",
        "Jetty": r"jetty",
        "JBoss": r"jboss",
        "Weblogic": r"weblogic",
        "Shiro": r"rememberme=deleteme|shiro",
        "Struts2": r"struts",
        "ThinkPHP": r"thinkphp",
        "jQuery": r"jquery",
        "Vue.js": r"vue",
        "React": r"react",
        "Bootstrap": r"bootstrap",
        "Swagger": r"swagger",
    }
    for name, pat in patterns.items():
        if re.search(pat, body, re.I) or re.search(pat, header_str, re.I):
            tech.append(name)
    return tech


def probe_url(url: str, timeout: int = 8) -> Dict:
    """探测单个 URL"""
    result = _http_request(url, timeout=timeout)
    if result.get("error"):
        return result

    result["tech"] = _detect_tech(result["headers"], result.get("body_snippet", ""))
    result["server"] = (result["headers"].get("Server") or
                        result["headers"].get("server") or "")
    result["powered_by"] = (result["headers"].get("X-Powered-By") or
                            result["headers"].get("x-powered-by") or "")
    return result


def probe_batch(urls: List[str], timeout: int = 8, max_workers: int = 20) -> Dict:
    """批量 URL 探测"""
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.replace(",", "\n").split("\n") if u.strip()]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(probe_url, url, timeout): url for url in urls}
        for future in concurrent.futures.as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"url": future_map[future], "error": str(e)[:200]})

    # 按状态码排序
    alive = [r for r in results if not r.get("error") and r.get("status")]
    dead = [r for r in results if r.get("error")]

    return {
        "total": len(urls),
        "alive": len(alive),
        "dead": len(dead),
        "alive_hosts": [
            {
                "url": r["url"],
                "status": r["status"],
                "title": r.get("title", ""),
                "length": r.get("length", 0),
                "server": r.get("server", ""),
                "tech": r.get("tech", []),
            }
            for r in alive
        ],
        "dead_hosts": [r["url"] for r in dead],
    }


def probe_asset(host: str, ports: Optional[List[int]] = None,
                timeout: int = 5) -> Dict:
    """资产探活: 检测主机在常见端口上的 HTTP/HTTPS 服务"""
    if ports is None:
        ports = [80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 7002, 81, 82, 8081, 8082, 9000]

    # 去除协议前缀
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]

    results = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}"
        r = _http_request(url, timeout=timeout)
        if not r.get("error"):
            results.append({
                "port": port,
                "scheme": scheme,
                "status": r["status"],
                "title": r.get("title", ""),
                "server": r.get("headers", {}).get("Server", ""),
                "length": r.get("length", 0),
            })

    return {
        "host": host,
        "open_http_ports": len(results),
        "services": results,
    }


def scan_sensitive(target: str, paths: Optional[List[str]] = None,
                   timeout: int = 6, max_workers: int = 15) -> Dict:
    """扫描敏感文件/目录"""
    target = re.sub(r"/$", "", target)
    if not target.startswith("http"):
        target = "http://" + target

    if paths is None:
        paths = SENSITIVE_PATHS

    found = []

    def _check(path):
        url = target + path
        r = _http_request(url, timeout=timeout, method="GET")
        if not r.get("error"):
            status = r["status"]
            # 200/301/302/403 都算存在 (排除 404)
            if status in (200, 301, 302, 403, 500):
                # 过滤掉通用 404 页面 (通过长度判断)
                length = r.get("length", 0)
                return {
                    "path": path,
                    "status": status,
                    "length": length,
                    "title": r.get("title", "")[:80],
                }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_check, p) for p in paths]
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
                if r:
                    found.append(r)
            except Exception:
                pass

    # 按状态码排序
    found.sort(key=lambda x: (x["status"] != 200, x["path"]))

    return {
        "target": target,
        "scanned": len(paths),
        "found": len(found),
        "results": found,
    }


def audit_headers(target: str, timeout: int = 8) -> Dict:
    """响应头安全审计"""
    if not target.startswith("http"):
        target = "http://" + target

    r = _http_request(target, timeout=timeout)
    if r.get("error"):
        return {"target": target, "error": r["error"]}

    headers = r["headers"]
    # 统一 key 为小写以便匹配
    header_keys_lower = {k.lower(): v for k, v in headers.items()}

    missing = []
    present = []
    for hdr, info in HEADER_SECURITY_CHECKS.items():
        if hdr.lower() in header_keys_lower:
            present.append({
                "header": hdr,
                "value": header_keys_lower[hdr.lower()][:100],
            })
        else:
            missing.append(info)

    # 信息泄露头
    info_leak = []
    for hdr in DANGEROUS_HEADERS:
        val = header_keys_lower.get(hdr.lower())
        if val:
            info_leak.append({"header": hdr, "value": val[:100]})

    # 风险评分
    severity_score = {"high": 10, "medium": 5, "low": 2}
    risk_score = sum(severity_score.get(m["severity"], 0) for m in missing)
    risk_level = "high" if risk_score >= 15 else "medium" if risk_score >= 8 else "low"

    return {
        "target": target,
        "status": r["status"],
        "server": header_keys_lower.get("server", ""),
        "missing_headers": missing,
        "present_security_headers": present,
        "info_leak_headers": info_leak,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def http_probe_list() -> Dict:
    """列出所有 HTTP 探测功能"""
    return {
        "probe": "单URL探测(状态码/标题/长度/指纹/技术栈)",
        "batch": "批量URL探活",
        "asset": "资产探活(多端口HTTP服务检测)",
        "sensitive": "敏感文件/目录扫描",
        "audit": "响应头安全审计",
    }
