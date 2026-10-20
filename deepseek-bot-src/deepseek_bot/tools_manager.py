"""
外部工具统一管理器 v1.0 — Tools Manager
───────────────────────────────────────────
功能:
  • 统一检测所有渗透工具的安装状态
  • 支持环境变量覆盖工具路径
  • 提供安装命令提示
  • 所有模块通过本模块调用外部工具

环境变量命名: TOOL_<NAME>_PATH (如 TOOL_YSOSERIAL_PATH)
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    name: str
    description: str
    installed: bool
    path: str = ""
    version: str = ""
    install_hint: str = ""
    category: str = ""


# 工具注册表: name -> (检测命令, 版本提取正则, 安装提示, 分类)
TOOLS_REGISTRY = {
    # ===== 反序列化 =====
    "ysoserial": {
        "check": ["java", "-jar", "{path}", "--help"],
        "path_env": "TOOL_YSOSERIAL_PATH",
        "default_path": "/opt/deepseek-bot/tools/ysoserial.jar",
        "version_re": r"ysoserial\s+(\S+)",
        "install": "git clone https://github.com/frohoff/ysoserial.git && cd ysoserial && mvn package -DskipTests",
        "category": "deserialization",
        "is_jar": True,
    },
    "phpggc": {
        "check": ["{path}", "--list"],
        "path_env": "TOOL_PHPGGC_PATH",
        "default_path": "/opt/deepseek-bot/tools/phpggc/phpggc",
        "version_re": r"phpggc\s+(\S+)",
        "install": "git clone https://github.com/ambionics/phpggc.git /opt/deepseek-bot/tools/phpggc",
        "category": "deserialization",
    },
    "ysoserial_net": {
        "check": ["{path}", "--help"],
        "path_env": "TOOL_YSOSERIAL_NET_PATH",
        "default_path": "/opt/deepseek-bot/tools/ysoserial.net/ysoserial.exe",
        "version_re": r"ysoserial\.net\s+(\S+)",
        "install": "需 Windows 环境: git clone https://github.com/pwntester/ysoserial.net.git",
        "category": "deserialization",
    },
    # ===== 哈希破解 =====
    "hashcat": {
        "check": ["hashcat", "--version"],
        "version_re": r"v?(\S+)",
        "install": "apt install hashcat 或 pacman -S hashcat",
        "category": "cracking",
    },
    "john": {
        "check": ["john", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install john 或 pacman -S john",
        "category": "cracking",
    },
    # ===== Windows 远程执行 =====
    "evil-winrm": {
        "check": ["evil-winrm", "-h"],
        "version_re": r"Evil-WinRM\s+(\S+)",
        "install": "gem install evil-winrm",
        "category": "lateral",
    },
    "impacket": {
        "check": ["psexec.py", "-h"],
        "version_re": r"impacket\s+(\S+)",
        "install": "pip install impacket",
        "category": "lateral",
    },
    "netexec": {
        "check": ["netexec", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install netexec 或 pip install netexec",
        "category": "lateral",
    },
    "crackmapexec": {
        "check": ["crackmapexec", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install crackmapexec (已被 netexec 取代)",
        "category": "lateral",
    },
    # ===== AD 侦察 =====
    "bloodhound": {
        "check": ["bloodhound", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install bloodhound",
        "category": "recon",
    },
    "sharphound": {
        "check": ["{path}", "--help"],
        "path_env": "TOOL_SHARPHOUND_PATH",
        "default_path": "/opt/deepseek-bot/tools/SharpHound.exe",
        "version_re": r"(\S+)",
        "install": "从 https://github.com/BloodHoundAD/SharpHound 下载",
        "category": "recon",
    },
    # ===== 代理隧道 =====
    "chisel": {
        "check": ["{path}", "version"],
        "path_env": "TOOL_CHISEL_PATH",
        "default_path": "/opt/deepseek-bot/tools/chisel",
        "version_re": r"(\S+)",
        "install": "从 https://github.com/jpillora/chisel/releases 下载",
        "category": "tunnel",
    },
    "ligolo": {
        "check": ["{path}", "-version"],
        "path_env": "TOOL_LIGOLO_PATH",
        "default_path": "/opt/deepseek-bot/tools/ligolo-ng",
        "version_re": r"(\S+)",
        "install": "从 https://github.com/nicocha30/ligolo-ng/releases 下载",
        "category": "tunnel",
    },
    "proxychains": {
        "check": ["proxychains", "-h"],
        "version_re": r"(\S+)",
        "install": "apt install proxychains4",
        "category": "tunnel",
    },
    # ===== 移动安全 =====
    "mobsf": {
        "check": ["docker", "ps", "--filter", "name=mobsf"],
        "version_re": r"(\S+)",
        "install": "docker pull opensecurity/mobile-security-framework-mobsf",
        "category": "mobile",
    },
    "apktool": {
        "check": ["apktool", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install apktool",
        "category": "mobile",
    },
    "jadx": {
        "check": ["jadx", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install jadx 或从 github 下载",
        "category": "mobile",
    },
    # ===== 扫描器 =====
    "nmap": {
        "check": ["nmap", "--version"],
        "version_re": r"Nmap\s+version\s+(\S+)",
        "install": "apt install nmap",
        "category": "scanner",
    },
    "nuclei": {
        "check": ["nuclei", "-version"],
        "version_re": r"(\S+)",
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "category": "scanner",
    },
    "ffuf": {
        "check": ["ffuf", "-V"],
        "version_re": r"(\S+)",
        "install": "apt install ffuf 或 go install github.com/ffuf/ffuf/v2@latest",
        "category": "scanner",
    },
    "sqlmap": {
        "check": ["sqlmap", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install sqlmap 或 git clone https://github.com/sqlmapproject/sqlmap.git",
        "category": "scanner",
    },
    "arjun": {
        "check": ["arjun", "--help"],
        "version_re": r"(\S+)",
        "install": "pip install arjun",
        "category": "scanner",
    },
    "subfinder": {
        "check": ["subfinder", "-version"],
        "version_re": r"(\S+)",
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "category": "scanner",
    },
    "httpx": {
        "check": ["httpx", "-version"],
        "version_re": r"(\S+)",
        "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "category": "scanner",
    },
    "whatweb": {
        "check": ["whatweb", "--version"],
        "version_re": r"(\S+)",
        "install": "apt install whatweb",
        "category": "scanner",
    },
    "wafw00f": {
        "check": ["wafw00f", "--help"],
        "version_re": r"(\S+)",
        "install": "pip install wafw00f",
        "category": "scanner",
    },
    # ===== 云 CLI =====
    "aws": {
        "check": ["aws", "--version"],
        "version_re": r"aws-cli/(\S+)",
        "install": "pip install awscli",
        "category": "cloud",
    },
    "kubectl": {
        "check": ["kubectl", "version", "--client"],
        "version_re": r"GitVersion:\"v(\S+)\"",
        "install": "curl -LO https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl",
        "category": "cloud",
    },
    "gcloud": {
        "check": ["gcloud", "--version"],
        "version_re": r"Google Cloud SDK (\S+)",
        "install": "从 https://cloud.google.com/sdk/docs/install 下载",
        "category": "cloud",
    },
    "az": {
        "check": ["az", "--version"],
        "version_re": r"(\S+)",
        "install": "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
        "category": "cloud",
    },
    # ===== 系统工具 =====
    "shred": {
        "check": ["shred", "--version"],
        "version_re": r"(\S+)",
        "install": "系统自带(coreutils)",
        "category": "system",
    },
    "wevtutil": {
        "check": ["wevtutil", "/?"],
        "version_re": r"(\S+)",
        "install": "Windows 自带",
        "category": "system",
    },
    "dig": {
        "check": ["dig", "-v"],
        "version_re": r"Dig (\S+)",
        "install": "apt install dnsutils",
        "category": "system",
    },
    "whois": {
        "check": ["whois", "--version"],
        "version_re": r"Version (\S+)",
        "install": "apt install whois",
        "category": "system",
    },
    "ssh": {
        "check": ["ssh", "-V"],
        "version_re": r"OpenSSH_(\S+)",
        "install": "apt install openssh-client",
        "category": "system",
    },
    "socat": {
        "check": ["socat", "-V"],
        "version_re": r"(\S+)",
        "install": "apt install socat",
        "category": "system",
    },
    "nc": {
        "check": ["nc", "-h"],
        "version_re": r"(\S+)",
        "install": "apt install netcat-openbsd",
        "category": "system",
    },
    "ncat": {
        "check": ["ncat", "--version"],
        "version_re": r"Ncat: Version (\S+)",
        "install": "apt install ncat",
        "category": "system",
    },
}


class ToolsManager:
    """外部工具统一管理器"""

    def __init__(self):
        self._cache: Dict[str, ToolInfo] = {}

    def detect(self, name: str) -> ToolInfo:
        """检测单个工具"""
        if name in self._cache:
            return self._cache[name]
        reg = TOOLS_REGISTRY.get(name)
        if not reg:
            info = ToolInfo(name=name, description="未知工具", installed=False,
                            install_hint="工具不在注册表中")
            self._cache[name] = info
            return info

        # 确定路径
        path = ""
        path_env = reg.get("path_env", "")
        if path_env and os.getenv(path_env):
            path = os.getenv(path_env, "")
        else:
            default_path = reg.get("default_path", "")
            if default_path and Path(default_path).exists():
                path = default_path
            else:
                # 在 PATH 中查找
                found = shutil.which(reg["check"][0])
                if found:
                    path = found

        if not path:
            info = ToolInfo(name=name, description=reg.get("install", ""),
                            installed=False, install_hint=reg["install"],
                            category=reg.get("category", ""))
            self._cache[name] = info
            return info

        # 执行检测命令
        check_cmd = [c.replace("{path}", path) for c in reg["check"]]
        try:
            r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            output = (r.stdout + r.stderr).strip()
            version = ""
            import re
            vm = re.search(reg.get("version_re", r"(\S+)"), output)
            if vm:
                version = vm.group(1)
            info = ToolInfo(name=name, description=reg.get("install", ""),
                            installed=(r.returncode == 0), path=path,
                            version=version, install_hint=reg["install"],
                            category=reg.get("category", ""))
        except Exception as e:
            info = ToolInfo(name=name, description=reg.get("install", ""),
                            installed=False, path=path,
                            install_hint=reg["install"],
                            category=reg.get("category", ""))
        self._cache[name] = info
        return info

    def detect_all(self) -> List[ToolInfo]:
        """检测所有工具"""
        return [self.detect(name) for name in TOOLS_REGISTRY.keys()]

    def is_installed(self, name: str) -> bool:
        """工具是否安装"""
        return self.detect(name).installed

    def get_path(self, name: str) -> str:
        """获取工具路径"""
        return self.detect(name).path

    def list_installed(self) -> List[ToolInfo]:
        """列出已安装的工具"""
        return [t for t in self.detect_all() if t.installed]

    def list_missing(self) -> List[ToolInfo]:
        """列出未安装的工具"""
        return [t for t in self.detect_all() if not t.installed]

    def list_by_category(self, category: str) -> List[ToolInfo]:
        """按分类列出工具"""
        return [t for t in self.detect_all() if t.category == category]

    def run(self, name: str, args: List[str], timeout: int = 60,
            cwd: Optional[str] = None) -> Tuple[int, str, str]:
        """运行工具, 返回 (returncode, stdout, stderr)"""
        info = self.detect(name)
        if not info.installed:
            return -1, "", f"工具 {name} 未安装: {info.install_hint}"
        reg = TOOLS_REGISTRY[name]
        if reg.get("is_jar"):
            cmd = ["java", "-jar", info.path] + args
        else:
            cmd = [info.path] + args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -2, "", f"工具 {name} 超时({timeout}s)"
        except Exception as e:
            return -1, "", str(e)

    def run_shell(self, name: str, args_str: str, timeout: int = 60) -> Tuple[int, str, str]:
        """以 shell 方式运行工具(用于复杂管道)"""
        info = self.detect(name)
        if not info.installed:
            return -1, "", f"工具 {name} 未安装: {info.install_hint}"
        reg = TOOLS_REGISTRY[name]
        if reg.get("is_jar"):
            cmd = f"java -jar {info.path} {args_str}"
        else:
            cmd = f"{info.path} {args_str}"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -2, "", f"工具 {name} 超时({timeout}s)"
        except Exception as e:
            return -1, "", str(e)


# ==================== 全局单例 ====================

_tools_mgr = ToolsManager()


# ==================== 便捷函数 ====================

def tool_detect(name: str) -> Dict:
    """检测单个工具"""
    t = _tools_mgr.detect(name)
    return {"name": t.name, "installed": t.installed, "path": t.path,
            "version": t.version, "install_hint": t.install_hint,
            "category": t.category}


def tool_detect_all() -> List[Dict]:
    """检测所有工具"""
    return [{"name": t.name, "installed": t.installed, "path": t.path,
             "version": t.version, "install_hint": t.install_hint,
             "category": t.category} for t in _tools_mgr.detect_all()]


def tool_installed(name: str) -> bool:
    """工具是否安装"""
    return _tools_mgr.is_installed(name)


def tool_path(name: str) -> str:
    """获取工具路径"""
    return _tools_mgr.get_path(name)


def tool_list_installed() -> List[Dict]:
    """列出已安装工具"""
    return [{"name": t.name, "path": t.path, "version": t.version, "category": t.category}
            for t in _tools_mgr.list_installed()]


def tool_list_missing() -> List[Dict]:
    """列出未安装工具及安装方法"""
    return [{"name": t.name, "install_hint": t.install_hint, "category": t.category}
            for t in _tools_mgr.list_missing()]


def tool_run(name: str, args: List[str], timeout: int = 60) -> Dict:
    """运行工具"""
    rc, out, err = _tools_mgr.run(name, args, timeout)
    return {"returncode": rc, "stdout": out, "stderr": err}


def tool_run_shell(name: str, args_str: str, timeout: int = 60) -> Dict:
    """以 shell 方式运行工具"""
    rc, out, err = _tools_mgr.run_shell(name, args_str, timeout)
    return {"returncode": rc, "stdout": out, "stderr": err}
