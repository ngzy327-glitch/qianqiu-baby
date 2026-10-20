"""
Strix AI 渗透测试集成模块 v1.0
─────────────────────────────
功能:
  • Strix 启动/停止管理
  • AI驱动自动化渗透
  • 结果解析与集成
  • 自适应攻击链对接

依赖: /opt/strix/ (Python 3.12 venv)

用法:
  from .strix_ai import StrixAgent
  sa = StrixAgent(project_id=5)
  result = sa.run(target="https://target.com", mode="full")
"""

import subprocess, json, time, os, re
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field

from . import db

STRIX_PATH = Path("/opt/strix")
STRIX_VENV = STRIX_PATH / "venv"
TMP = Path("/tmp/strix_runs")
TMP.mkdir(exist_ok=True)

ProgressCallback = Callable[[str, str, str, str], None]


@dataclass
class StrixResult:
    """Strix 运行结果"""
    target: str
    mode: str
    vulnerabilities: List[Dict] = field(default_factory=list)
    requests_count: int = 0
    duration: float = 0.0
    raw_output: str = ""
    success: bool = False
    error: str = ""


class StrixAgent:
    """Strix AI 渗透代理"""

    def __init__(self, project_id: int,
                 callback: Optional[ProgressCallback] = None):
        self.project_id = project_id
        self.cb = callback or (lambda *a: None)

    def _step(self, tool: str, target: str, status: str, msg: str):
        self.cb(tool, target, status, msg)

    def is_available(self) -> bool:
        """检查 Strix 是否可用"""
        if not STRIX_PATH.exists():
            return False
        # 检查 venv 或直接可执行
        if (STRIX_VENV / "bin" / "python").exists():
            return True
        if (STRIX_PATH / "strix.py").exists() or (STRIX_PATH / "main.py").exists():
            return True
        # 尝试找入口
        for f in STRIX_PATH.glob("*.py"):
            return True
        return False

    def run(self, target: str, mode: str = "scan",
            timeout: int = 600, extra_args: str = "") -> StrixResult:
        """运行 Strix AI 渗透

        Args:
            target: 目标URL或IP
            mode: scan(扫描)/full(全流程)/recon(侦察)/exploit(利用)
            timeout: 超时秒数
            extra_args: 额外参数

        Returns:
            StrixResult
        """
        if not self.is_available():
            return StrixResult(
                target=target, mode=mode,
                success=False, error="Strix 不可用: /opt/strix 未找到"
            )

        self._step("strix", target, "running", f"AI渗透模式:{mode}")

        start = time.time()
        result = StrixResult(target=target, mode=mode)

        # 构建命令
        python_bin = "python3"
        strix_entry = ""

        # 检测入口点
        if (STRIX_VENV / "bin" / "python").exists():
            python_bin = str(STRIX_VENV / "bin" / "python")

        for candidate in ["strix.py", "main.py", "run.py", "core.py", "cli.py"]:
            if (STRIX_PATH / candidate).exists():
                strix_entry = str(STRIX_PATH / candidate)
                break

        if not strix_entry:
            # 直接尝试 `strix` 命令
            strix_entry = "strix"

        cmd = f"timeout {timeout} {python_bin} {strix_entry} "
        cmd += f"--target {target} --mode {mode} "
        if extra_args:
            cmd += extra_args
        cmd += " 2>/dev/null"

        self._step("strix", target, "running", f"执行: {cmd[:150]}")

        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout + 30, cwd=str(STRIX_PATH)
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            result.raw_output = output
            result.success = proc.returncode == 0
            result.duration = time.time() - start

            # 解析输出
            result.vulnerabilities = self._parse_output(output)
            result.requests_count = self._count_requests(output)

            self._step("strix", target, "done",
                       f"发现{len(result.vulnerabilities)}个漏洞, {result.requests_count}次请求")

        except subprocess.TimeoutExpired:
            result.error = f"超时 ({timeout}s)"
            result.duration = timeout
            self._step("strix", target, "error", result.error)
        except Exception as e:
            result.error = str(e)
            self._step("strix", target, "error", result.error)

        # 保存结果到数据库
        self._save_result(result)

        return result

    def _parse_output(self, text: str) -> List[Dict]:
        """解析 Strix 输出中的漏洞"""
        vulns = []

        # JSON格式
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                vulns.append({
                                    "name": item.get("name", item.get("title", "")),
                                    "severity": item.get("severity", "medium"),
                                    "detail": item.get("description", item.get("detail", "")),
                                    "url": item.get("url", ""),
                                })
                return vulns
        except (json.JSONDecodeError, TypeError):
            pass

        # 文本格式: [CRITICAL] / [HIGH] / [MEDIUM] 标记
        for line in text.split('\n'):
            m = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+)', line, re.IGNORECASE)
            if m:
                vulns.append({
                    "severity": m.group(1).lower(),
                    "detail": m.group(2).strip(),
                })
                continue

            # 常见漏洞关键词
            for kw, sev in [("SQL injection", "high"), ("XSS", "medium"),
                           ("RCE", "critical"), ("Remote Code Execution", "critical"),
                           ("Path Traversal", "high"), ("SSRF", "high"),
                           ("IDOR", "medium"), ("File Upload", "high"),
                           ("XXE", "high"), ("Open Redirect", "low"),
                           ("Information Disclosure", "info")]:
                if kw.lower() in line.lower():
                    vulns.append({"detail": line.strip(), "severity": sev})
                    break

        return vulns

    def _count_requests(self, text: str) -> int:
        """统计请求数量"""
        m = re.search(r'(?:Requests|requests|总请求)[:\s]*(\d+)', text)
        if m:
            return int(m.group(1))
        # 数HTTP请求行
        return len(re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+', text))

    def _save_result(self, result: StrixResult):
        """保存结果到数据库"""
        try:
            sid = db.scan_start(self.project_id, 0, "strix", result.target)
            db.scan_finish(sid, result.raw_output[:10000],
                          {"vulnerabilities": result.vulnerabilities,
                           "requests_count": result.requests_count,
                           "duration": result.duration})

            for v in result.vulnerabilities[:20]:
                db.finding_add(
                    scan_id=sid,
                    project_id=self.project_id,
                    uid=0,
                    severity=v.get("severity", "info"),
                    title=v.get("name", v.get("detail", "Strix Finding")),
                    description=v.get("detail", ""),
                    target=result.target,
                    evidence=json.dumps(v, ensure_ascii=False)[:2000]
                )
        except Exception:
            pass

    def recon_only(self, target: str) -> StrixResult:
        """仅侦察模式"""
        return self.run(target, mode="recon", timeout=300)

    def full_auto(self, target: str) -> StrixResult:
        """全自动渗透"""
        return self.run(target, mode="full", timeout=900)

    def quick_scan(self, target: str) -> StrixResult:
        """快速扫描"""
        return self.run(target, mode="scan", timeout=300)


def strix_available() -> bool:
    """全局检查"""
    return StrixAgent(0).is_available()
