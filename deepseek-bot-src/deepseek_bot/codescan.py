#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""源码安全扫描 - 支持 PHP/Python/Java/JS 多语言漏洞检测"""

import os
import re
import json
from pathlib import Path
from typing import Optional


# 漏洞规则库
RULES = {
    "php": {
        "rce": {
            "name": "远程代码执行 (RCE)",
            "severity": "critical",
            "patterns": [
                r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'preg_replace\s*\([^)]*/e[^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'create_function\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
        "sqli": {
            "name": "SQL 注入",
            "severity": "critical",
            "patterns": [
                r'mysql_query\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'->query\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'->exec\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                r'select.*from.*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
        "xss": {
            "name": "跨站脚本 (XSS)",
            "severity": "high",
            "patterns": [
                r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
                r'print\s+\$_(GET|POST|REQUEST|COOKIE)',
                r'<\?=\s*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
        "file_inclusion": {
            "name": "文件包含",
            "severity": "critical",
            "patterns": [
                r'include\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'require\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'include_once\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'require_once\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
        "lfi": {
            "name": "本地文件包含",
            "severity": "high",
            "patterns": [
                r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'file_put_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'fopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'readfile\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'highlight_file\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'show_source\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
        "deserialization": {
            "name": "反序列化漏洞",
            "severity": "critical",
            "patterns": [
                r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'unserialize\s*\(\s*\$_COOKIE',
            ],
        },
        "xxe": {
            "name": "XXE 注入",
            "severity": "high",
            "patterns": [
                r'simplexml_load_string\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                r'DOMDocument.*loadXML\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            ],
        },
    },
    "python": {
        "rce": {
            "name": "远程代码执行 (RCE)",
            "severity": "critical",
            "patterns": [
                r'eval\s*\(\s*request\.(args|form|values|json|cookies)',
                r'exec\s*\(\s*request\.(args|form|values|json|cookies)',
                r'os\.system\s*\(\s*request\.(args|form|values|json|cookies)',
                r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*request\.(args|form|values|json|cookies)',
            ],
        },
        "sqli": {
            "name": "SQL 注入",
            "severity": "critical",
            "patterns": [
                r'execute\s*\(\s*f["\'].*\{.*request\.(args|form|values)',
                r'execute\s*\(\s*["\'].*%s.*%\s*request\.(args|form|values)',
                r'SELECT.*FROM.*\+.*request\.(args|form|values)',
            ],
        },
        "deserialization": {
            "name": "反序列化漏洞",
            "severity": "critical",
            "patterns": [
                r'pickle\.loads\s*\(\s*request\.(args|form|values|data|cookies)',
                r'yaml\.load\s*\([^)]*request\.(args|form|values|data)',
            ],
        },
        "ssti": {
            "name": "模板注入 (SSTI)",
            "severity": "high",
            "patterns": [
                r'render_template_string\s*\(\s*request\.(args|form|values)',
                r'Template\s*\(\s*request\.(args|form|values)',
            ],
        },
        "ssrf": {
            "name": "服务端请求伪造 (SSRF)",
            "severity": "high",
            "patterns": [
                r'requests\.(get|post|put|delete|head)\s*\(\s*request\.(args|form|values)',
                r'urllib\.request\.urlopen\s*\(\s*request\.(args|form|values)',
            ],
        },
    },
    "java": {
        "rce": {
            "name": "远程代码执行 (RCE)",
            "severity": "critical",
            "patterns": [
                r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*request\.get',
                r'ProcessBuilder\s*\([^)]*request\.get',
                r'eval\s*\([^)]*request\.get',
            ],
        },
        "sqli": {
            "name": "SQL 注入",
            "severity": "critical",
            "patterns": [
                r'createStatement\(\)\.executeQuery\s*\([^)]*request\.get',
                r'String.*sql.*\+.*request\.get',
            ],
        },
        "deserialization": {
            "name": "反序列化漏洞",
            "severity": "critical",
            "patterns": [
                r'ObjectInputStream.*readObject\s*\(\s*\)',
                r'readObject\s*\(\s*\)',
                r'XMLDecoder.*readObject',
            ],
        },
        "xxe": {
            "name": "XXE 注入",
            "severity": "high",
            "patterns": [
                r'DocumentBuilderFactory.*newInstance.*setFeature.*false',
                r'SAXReader.*read\s*\([^)]*request',
            ],
        },
    },
    "javascript": {
        "rce": {
            "name": "远程代码执行 (RCE)",
            "severity": "critical",
            "patterns": [
                r'eval\s*\(\s*req\.(query|body|params)',
                r'Function\s*\(\s*req\.(query|body|params)',
                r'child_process\.(exec|execSync|spawn)\s*\([^)]*req\.(query|body|params)',
            ],
        },
        "sqli": {
            "name": "SQL 注入",
            "severity": "critical",
            "patterns": [
                r'query\s*\(\s*`[^`]*\$\{req\.(query|body|params)',
                r'query\s*\(\s*["\'][^"\']*["\']\s*\+\s*req\.(query|body|params)',
            ],
        },
        "xss": {
            "name": "跨站脚本 (XSS)",
            "severity": "high",
            "patterns": [
                r'res\.send\s*\(\s*req\.(query|body|params)',
                r'res\.write\s*\(\s*req\.(query|body|params)',
            ],
        },
        "path_traversal": {
            "name": "路径穿越",
            "severity": "high",
            "patterns": [
                r'fs\.readFile\s*\([^)]*req\.(query|body|params)',
                r'fs\.sendFile\s*\([^)]*req\.(query|body|params)',
                r'res\.sendFile\s*\(\s*req\.(query|body|params)',
            ],
        },
    },
}

# 文件扩展名映射
EXT_MAP = {
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php5": "php",
    ".py": "python",
    ".java": "java",
    ".jsp": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
}


def scan_file(filepath: str) -> dict:
    """扫描单个文件"""
    path = Path(filepath)
    if not path.exists():
        return {"error": f"文件不存在: {filepath}"}

    ext = path.suffix.lower()
    lang = EXT_MAP.get(ext)
    if not lang or lang not in RULES:
        return {"file": filepath, "language": None, "findings": [], "skipped": "不支持的文件类型"}

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"error": f"读取失败: {e}"}

    findings = []
    rules = RULES[lang]

    for vuln_type, rule in rules.items():
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line_content = content.split("\n")[line_num - 1].strip()
                findings.append({
                    "type": vuln_type,
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "line": line_num,
                    "code": line_content[:120],
                    "match": match.group()[:80],
                })

    # 统计
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1

    return {
        "file": filepath,
        "language": lang,
        "total_findings": len(findings),
        "severity_count": severity_count,
        "findings": findings,
    }


def scan_directory(dirpath: str, extensions: Optional[list] = None) -> dict:
    """扫描目录"""
    path = Path(dirpath)
    if not path.exists() or not path.is_dir():
        return {"error": f"目录不存在: {dirpath}"}

    if extensions is None:
        extensions = list(EXT_MAP.keys())

    results = []
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in extensions:
                result = scan_file(fp)
                if "error" not in result:
                    results.append(result)

    # 汇总
    total = sum(r["total_findings"] for r in results)
    sev_total = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for k, v in r["severity_count"].items():
            sev_total[k] = sev_total.get(k, 0) + v

    return {
        "directory": dirpath,
        "files_scanned": len(results),
        "total_findings": total,
        "severity_summary": sev_total,
        "files": results,
    }


def scan_code(code: str, language: str = "auto") -> dict:
    """扫描代码字符串"""
    # 自动检测语言
    if language == "auto":
        if "<?php" in code or "$_" in code:
            language = "php"
        elif "import " in code and ("def " in code or "class " in code):
            language = "python"
        elif "public class" in code or "System.out" in code:
            language = "java"
        elif "require(" in code or "module.exports" in code or "const " in code:
            language = "javascript"
        else:
            language = "php"

    if language not in RULES:
        return {"error": f"不支持的语言: {language}", "supported": list(RULES.keys())}

    findings = []
    rules = RULES[language]
    for vuln_type, rule in rules.items():
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count("\n") + 1
                line_content = code.split("\n")[line_num - 1].strip()
                findings.append({
                    "type": vuln_type,
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "line": line_num,
                    "code": line_content[:120],
                    "match": match.group()[:80],
                })

    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1

    return {
        "language": language,
        "total_findings": len(findings),
        "severity_count": severity_count,
        "findings": findings,
    }


def codescan_list_rules() -> dict:
    """列出所有检测规则"""
    result = {}
    for lang, rules in RULES.items():
        result[lang] = {}
        for vuln_type, rule in rules.items():
            result[lang][vuln_type] = {
                "name": rule["name"],
                "severity": rule["severity"],
                "patterns": len(rule["patterns"]),
            }
    return result
