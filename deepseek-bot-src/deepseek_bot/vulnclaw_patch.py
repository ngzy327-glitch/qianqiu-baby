"""VulnClaw 工具挂载补丁 (2026-10-21)

用途: 不改动 bot.py 主体, 运行期把 5 个新工具注入 TOOLS / HEAVY_KW / HEAVY_NAMES,
并接管 rt() 分派。用法: 在 bot.py 末尾追加一行 install(globals())。

这样做的原因: 线上 bot.py 与仓库版本存在本地差异, 直接覆盖风险高;
纯运行期注入只依赖三个公开全局(TOOLS / HEAVY_KW / rt), 不碰其它逻辑。
"""

import json

_INSTALLED = False
_MODS = None


# ============ 工具定义(OpenAI function calling schema) ============
TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "codec",
        "description": "编解码/加解密工具箱:list列操作/b64e/b64d(base64)/b32e/b32d(base32)/b85e/b85d(base85)/hexe/hexd(十六进制)/urle/urld(URL编码)/htmle/htmld(HTML实体)/rot13/caesar(凯撒)/xor/xord(异或加解密,需key)/md5/sha1/sha256/sha512/hashall/morsec/morsed(摩斯)/jwt(解码JWT)/unie/unid(Unicode)/aese/aesd(AES加解密,需key)/auto(自动尝试多编码解码)。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": [
                    "list", "b64e", "b64d", "b32e", "b32d", "b85e", "b85d", "hexe", "hexd",
                    "urle", "urld", "htmle", "htmld", "rot13", "caesar", "xor", "xord",
                    "md5", "sha1", "sha256", "sha512", "hashall", "morsec", "morsed",
                    "jwt", "unie", "unid", "aese", "aesd", "auto"]},
                "data": {"type": "string"},
                "key": {"type": "string"},
                "shift": {"type": "integer"},
            },
            "required": ["act"],
        },
    }},
    {"type": "function", "function": {
        "name": "codescan",
        "description": "源码安全扫描:list列规则/file扫描本地文件/dir扫描目录/code扫描代码字符串(自动检测语言,支持php/python/java/javascript)。检测RCE/SQLI/XSS/LFI/XXE/反序列化/SSTI/SSRF等漏洞。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": ["list", "file", "dir", "code"]},
                "path": {"type": "string"},
                "code": {"type": "string"},
                "language": {"type": "string"},
                "extensions": {"type": "string"},
            },
            "required": ["act"],
        },
    }},
    {"type": "function", "function": {
        "name": "pocgen",
        "description": "渗透测试报告 & PoC 生成:gen生成Markdown报告(需target和findings列表)/poc生成漏洞PoC脚本(sqli/xss/ssrf/lfi/rce/ssti/xxe/deserialization/path_traversal/open_redirect)/list列PoC类型/save保存报告文件/savepoc保存PoC文件。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": ["gen", "poc", "list", "save", "savepoc"]},
                "target": {"type": "string"},
                "findings": {"type": "string", "description": "JSON格式发现列表"},
                "vuln_type": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["act"],
        },
    }},
    {"type": "function", "function": {
        "name": "httpprobe",
        "description": "批量HTTP探测:probe单URL探测/batch批量URL探活/asset资产多端口探活/sensitive敏感文件目录扫描/audit响应头安全审计/list列功能。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": [
                    "probe", "batch", "asset", "sensitive", "audit", "list"]},
                "url": {"type": "string"},
                "urls": {"type": "string", "description": "逗号或换行分隔的多个URL"},
                "host": {"type": "string"},
                "ports": {"type": "string"},
                "paths": {"type": "string"},
            },
            "required": ["act"],
        },
    }},
    {"type": "function", "function": {
        "name": "evidence",
        "description": "证据层(证据记忆+流量存储+反幻觉闸门)。用户说『记住这条证据/存证据/记到证据库/把原文存下来』时, 必须用本工具 act=add 存原文, 不要用 memory(长期记忆)工具, 否则后续 verify 查不到。下结论/报flag/写报告前必须先用 act=verify 校验 claim 是否逐字出现在真实证据里, verified=false 的结论不得写入报告。act:list列证据/add存证据/search检索/view按id回查原文/stats统计/traffic_list列流量/traffic_view看原始报文(request|response|full)/traffic_repeat重放请求/traffic_sitemap按host聚合访问路径/verify反幻觉校验。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": [
                    "list", "add", "search", "view", "stats",
                    "traffic_list", "traffic_view", "traffic_repeat", "traffic_sitemap", "verify"]},
                "content": {"type": "string", "description": "act=add 时的证据原文"},
                "kind": {"type": "string", "description": "证据类型: note/scan/response/poc/flag"},
                "source": {"type": "string", "description": "证据来源(工具名/URL)"},
                "tags": {"type": "string", "description": "逗号分隔标签"},
                "scope": {"type": "string", "description": "作用域, 默认 default"},
                "query": {"type": "string", "description": "act=search 检索串"},
                "id": {"type": "string", "description": "证据/流量 id"},
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
                "claim": {"type": "string", "description": "act=verify 待校验的 flag/结论串"},
                "part": {"type": "string", "enum": ["request", "response", "full"]},
                "host": {"type": "string", "description": "act=traffic_list 过滤主机"},
                "status": {"type": "integer", "description": "act=traffic_list 过滤状态码"},
            },
            "required": ["act"],
        },
    }},
    {"type": "function", "function": {
        "name": "rundiff",
        "description": "运行时差分探测:sqli SQL注入差分检测(布尔/报错/时间盲注)/xss反射XSS检测/lfi本地文件包含检测/waf WAF行为拦截检测/response两URL响应差异分析/hpp参数污染测试/list列功能。url需含?或参数,param为测试参数名。",
        "parameters": {
            "type": "object",
            "properties": {
                "act": {"type": "string", "enum": [
                    "sqli", "xss", "lfi", "waf", "response", "hpp", "list"]},
                "url": {"type": "string"},
                "url2": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["act", "url"],
        },
    }},
]

# 关键词挂载: 命中任一关键词就自动把该工具挂给模型
HK_EXTRA = {
    "codec": ("编码", "解码", "加密", "解密", "base64", "编解码", "hash", "哈希", "xor", "aes", "jwt", "摩斯", "morse", "rot13", "凯撒"),
    "codescan": ("代码审计", "源码扫描", "代码扫描", "白盒", "源码审计", "代码漏洞", "静态扫描", "代码安全"),
    "pocgen": ("poc", "生成poc", "漏洞报告", "生成报告", "渗透报告", "poc脚本", "报告生成"),
    "httpprobe": ("http探测", "批量探测", "资产探活", "目录扫描", "敏感文件", "指纹识别", "批量url", "存活探测", "响应头"),
    "rundiff": ("差分", "注入检测", "盲注", "waf检测", "参数污染", "xss检测", "sql注入检测", "运行时差分"),
    "evidence": ("证据", "证据链", "存证据", "记住证据", "记证据", "证据库", "写进证据", "流量记录", "重放", "原始报文", "反幻觉", "flag校验", "核实", "sitemap"),
}


def _mods():
    """延迟导入(避免启动阶段因单个模块语法问题拖垮整个 bot)"""
    global _MODS
    if _MODS is None:
        try:
            from . import codec, codescan, report_gen, http_probe, runtime_diff, evidence
        except ImportError:
            import codec, codescan, report_gen, http_probe, runtime_diff, evidence
        _MODS = {
            "codec": codec, "codescan": codescan, "report_gen": report_gen,
            "http_probe": http_probe, "runtime_diff": runtime_diff,
            "evidence": evidence,
        }
    return _MODS


def _out(r):
    """统一输出: dict/list 转 JSON 字符串, 并限制长度防撑爆上下文"""
    if isinstance(r, (dict, list)):
        try:
            s = json.dumps(r, ensure_ascii=False, indent=2, default=str)
        except Exception:
            s = str(r)
    else:
        s = str(r)
    return s if len(s) <= 9000 else s[:9000] + "\n...(已截断)"


def _handle(n, a):
    """处理 5 个新工具; 不是这些名字就返回 None 交回原 rt()"""
    a = a or {}
    try:
        m = _mods()
    except Exception as e:
        return f"[vulnclaw] 模块加载失败: {e}"

    if n == "codec":
        cm = m["codec"]
        act = a.get("act", "list")
        data = a.get("data", "")
        key = a.get("key", "")
        if act == "list":
            return _out(cm.codec_list())
        table = {
            "b64e": cm.b64_encode, "b64d": cm.b64_decode,
            "b32e": cm.b32_encode, "b32d": cm.b32_decode,
            "b85e": cm.b85_encode, "b85d": cm.b85_decode,
            "hexe": cm.hex_encode, "hexd": cm.hex_decode,
            "urle": cm.url_encode, "urld": cm.url_decode,
            "htmle": cm.html_encode, "htmld": cm.html_decode,
            "rot13": cm.rot13, "md5": cm.md5, "sha1": cm.sha1,
            "sha256": cm.sha256, "sha512": cm.sha512, "hashall": cm.hash_all,
            "morsec": cm.morse_encode, "morsed": cm.morse_decode,
            "jwt": cm.jwt_decode, "unie": cm.unicode_encode,
            "unid": cm.unicode_decode, "auto": cm.auto_decode,
        }
        if act in table:
            return _out(table[act](data))
        if act == "caesar":
            return _out(cm.caesar(data, int(a.get("shift", 3))))
        if act == "xor":
            return _out(cm.xor_encrypt(data, key))
        if act == "xord":
            return _out(cm.xor_decrypt_hex(data, key))
        if act == "aese":
            return _out(cm.aes_encrypt(data, key))
        if act == "aesd":
            return _out(cm.aes_decrypt(data, key))
        return f"codec: unknown act={act}"

    if n == "codescan":
        cs = m["codescan"]
        act = a.get("act", "list")
        if act == "list":
            return _out(cs.codescan_list_rules())
        if act == "file":
            return _out(cs.scan_file(a.get("path", "")))
        if act == "dir":
            exts = a.get("extensions", "") or ""
            ext_list = [e.strip() for e in exts.split(",") if e.strip()] or None
            return _out(cs.scan_directory(a.get("path", ""), ext_list))
        if act == "code":
            return _out(cs.scan_code(a.get("code", ""), a.get("language", "auto")))
        return f"codescan: unknown act={act}"

    if n == "pocgen":
        rg = m["report_gen"]
        act = a.get("act", "list")
        if act == "list":
            return _out(rg.poc_list())
        if act == "poc":
            return _out(rg.generate_poc(a.get("vuln_type", "sqli"), a.get("target", ""),
                                       param=a.get("param", "id")))
        if act == "gen":
            try:
                findings = json.loads(a.get("findings") or "[]")
            except Exception:
                findings = []
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
            return _out(rg.generate_report(a.get("target", ""), findings))
        if act == "save":
            try:
                report = json.loads(a.get("findings") or "{}")
            except Exception:
                report = {}
            if not isinstance(report, dict):
                report = {}
            return _out(rg.save_report(report))
        if act == "savepoc":
            try:
                poc = json.loads(a.get("findings") or "{}")
            except Exception:
                poc = {}
            if not isinstance(poc, dict):
                poc = {}
            return _out(rg.save_poc(poc))
        return f"report: unknown act={act}"

    if n == "httpprobe":
        hp = m["http_probe"]
        act = a.get("act", "probe")
        if act == "list":
            return _out(hp.http_probe_list())
        if act == "probe":
            return _out(hp.probe_url(a.get("url", "")))
        if act == "batch":
            urls = a.get("urls", "") or a.get("url", "")
            url_list = [u.strip() for u in str(urls).replace(",", "\n").split("\n") if u.strip()]
            return _out(hp.probe_batch(url_list))
        if act == "asset":
            ports = a.get("ports", "") or ""
            port_list = [int(p.strip()) for p in str(ports).split(",") if p.strip().isdigit()] or None
            return _out(hp.probe_asset(a.get("host", "") or a.get("url", ""), port_list))
        if act == "sensitive":
            paths = a.get("paths", "") or ""
            path_list = [p.strip() for p in str(paths).split(",") if p.strip()] or None
            return _out(hp.scan_sensitive(a.get("url", ""), path_list))
        if act == "audit":
            return _out(hp.audit_headers(a.get("url", "")))
        return f"httpprobe: unknown act={act}"

    if n == "evidence":
        ev = m["evidence"]
        act = a.get("act", "list")
        scope = a.get("scope", "") or ""
        if act == "list":
            return _out(ev.ev_list(scope, a.get("kind", ""), a.get("limit", 30)))
        if act == "add":
            _tags = [t.strip() for t in str(a.get("tags", "") or "").split(",") if t.strip()]
            return _out(ev.ev_add(a.get("content", ""), a.get("kind", "note"),
                                  a.get("source", ""), _tags, scope or "default"))
        if act == "search":
            return _out(ev.ev_search(a.get("query", ""), scope, a.get("limit", 10)))
        if act == "view":
            return _out(ev.ev_view(a.get("id", ""), a.get("offset", 0), a.get("limit", 4000)))
        if act == "stats":
            return _out(ev.ev_stats())
        if act == "traffic_list":
            return _out(ev.traffic_list(scope, a.get("host", ""), a.get("status", 0), a.get("limit", 50)))
        if act == "traffic_view":
            return _out(ev.traffic_view(a.get("id", ""), a.get("part", "response"),
                                        a.get("offset", 0), a.get("limit", 6000)))
        if act == "traffic_repeat":
            return _out(ev.traffic_repeat(a.get("id", ""), scope or "default"))
        if act == "traffic_sitemap":
            return _out(ev.traffic_sitemap(scope, a.get("limit", 300)))
        if act == "verify":
            return _out(ev.verify(a.get("claim", ""), scope, a.get("limit", 5)))
        return f"evidence: unknown act={act}"

    if n == "rundiff":
        rd = m["runtime_diff"]
        act = a.get("act", "list")
        if act == "list":
            return _out(rd.runtime_diff_list())
        if act == "sqli":
            return _out(rd.diff_sqli(a.get("url", ""), a.get("param", "id")))
        if act == "xss":
            return _out(rd.diff_xss(a.get("url", ""), a.get("param", "q")))
        if act == "lfi":
            return _out(rd.diff_lfi(a.get("url", ""), a.get("param", "file")))
        if act == "waf":
            return _out(rd.diff_waf(a.get("url", "")))
        if act == "response":
            return _out(rd.diff_response(a.get("url", ""), a.get("url2", "")))
        if act == "hpp":
            return _out(rd.diff_param_pollution(a.get("url", ""), a.get("param", "id")))
        return f"rundiff: unknown act={act}"

    return None


def install(g):
    """把新工具注入 bot 模块的全局命名空间

    g: bot.py 的 globals()
    只做三件事: 补 TOOLS 定义 / 补关键词表 / 包一层 rt 分派。
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True

    names = {"codec", "codescan", "pocgen", "httpprobe", "rundiff", "evidence"}

    # 1) 工具定义
    tools = g.get("TOOLS")
    if isinstance(tools, list):
        have = set()
        for x in tools:
            try:
                have.add(x["function"]["name"])
            except Exception:
                pass
        for d in TOOL_DEFS:
            if d["function"]["name"] not in have:
                tools.append(d)
    else:
        print("[vulnclaw] 警告: 没找到 TOOLS 列表, 工具定义未注入", flush=True)

    # 2) 关键词挂载 + 重型名单
    hk = g.get("HEAVY_KW")
    if isinstance(hk, dict):
        for k, v in HK_EXTRA.items():
            hk.setdefault(k, v)
    hn = g.get("HEAVY_NAMES")
    if isinstance(hn, set):
        hn |= names

    # 3) 分派接管
    orig = g.get("rt")
    if not callable(orig):
        print("[vulnclaw] 警告: 没找到 rt(), 分派未接管", flush=True)
        return

    def rt(n, a, *args, **kwargs):
        r = _handle(n, a)
        if r is not None:
            return r
        return orig(n, a, *args, **kwargs)

    # 保留调用层挂在 rt 上的属性(rt._uid / rt._is_admin / rt._on_line 等)
    try:
        rt.__dict__.update(getattr(orig, "__dict__", {}))
    except Exception:
        pass
    g["rt"] = rt
