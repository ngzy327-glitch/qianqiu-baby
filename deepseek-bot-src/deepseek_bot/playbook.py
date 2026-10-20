"""自动化渗透 Playbook v2: 工具链串联 — 上游结果自动喂入下游"""
import subprocess, json, time, os, threading
from pathlib import Path
from typing import Callable, Optional, List

from . import db
from .parser import auto_parse

OUT = Path("/opt/deepseek-bot/playbook_output")
OUT.mkdir(exist_ok=True)

ProgressCallback = Callable[[str, str, str, str], None]


def _run(cmd: str, timeout: int = 300) -> str:
    """执行命令，返回输出"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return "[超时]"
    except Exception as e:
        return f"[错误: {e}]"


class Playbook:
    """自动化渗透 Playbook v2 — 工具链串联"""

    def __init__(self, uid: int, project_id: int, target: str,
                 callback: Optional[ProgressCallback] = None):
        self.uid = uid
        self.project_id = project_id
        self.target = target
        self.cb = callback or (lambda *a: None)
        self.results = {}
        self.scan_ids = []

    def _step(self, tool: str, cmd: str, target: str = "", timeout: int = 300):
        """执行一个步骤，记录到数据库。返回输出文本。"""
        tgt = target or self.target
        self.cb(tool, tgt, "running", cmd[:200])

        sid = db.scan_start(self.project_id, self.uid, tool, tgt)
        self.scan_ids.append(sid)

        output = _run(cmd, timeout)
        parsed = auto_parse(tool, output)

        db.scan_finish(sid, output, parsed)
        self.results[tool] = {"raw": output, "parsed": parsed}

        self.cb(tool, tgt, "done", output[:500])
        return output

    # ==================== 数据提取器（链式调用核心） ====================

    def _extract_subdomains(self) -> List[str]:
        """从 subfinder 结果中提取子域名列表"""
        sd = self.results.get("subfinder", {}).get("parsed", {})
        return sd.get("subdomains", [])

    def _extract_live_urls(self) -> List[str]:
        """从 httpx 结果中提取存活 URL"""
        hd = self.results.get("httpx", {}).get("parsed", {})
        return [u["url"] for u in hd.get("urls", []) if u.get("status", 0) > 0]

    def _extract_frameworks(self) -> List[str]:
        """从 whatweb/httpx 结果中提取框架/CMS"""
        fw = []
        # whatweb parsed
        ww = self.results.get("whatweb", {}).get("parsed", {})
        fw.extend(ww.get("frameworks", []))
        # httpx tech-detect
        hd = self.results.get("httpx", {}).get("parsed", {})
        fw.extend(hd.get("technologies", []))
        return list(set(fw))

    def _extract_web_urls_from_nmap(self) -> List[str]:
        """从 nmap 结果中提取 Web 端口 → URL 列表"""
        nd = self.results.get("nmap", {}).get("parsed", {})
        ip = nd.get("ip", self.target)
        urls = []
        web_ports = {80, 443, 8080, 8443, 3000, 4443, 5000, 8000, 8081, 8443, 8888, 9090, 9443}
        for p in nd.get("ports", []):
            if p.get("state") == "open" and p.get("port") in web_ports:
                scheme = "https" if p["port"] in (443, 8443, 4443, 9443) else "http"
                urls.append(f"{scheme}://{ip}:{p['port']}")
        # 也检查服务名
        for s in nd.get("services", []):
            svc = s.get("details", "").lower()
            if any(w in svc for w in ("http", "nginx", "apache", "iis", "tomcat", "jetty", "node", "flask")):
                port = s.get("port", 0)
                if port and port not in (80, 443):
                    scheme = "https" if "ssl" in svc or "tls" in svc else "http"
                    url = f"{scheme}://{ip}:{port}"
                    if url not in urls:
                        urls.append(url)
        return urls

    def _extract_paths(self) -> List[str]:
        """从 ffuf/dirsearch 结果中提取发现的路径"""
        fd = self.results.get("ffuf", {}).get("parsed", {})
        paths = []
        for r in fd.get("results", []):
            path = r.get("path", r.get("url", ""))
            if path:
                # 提取相对路径部分
                if "://" in path:
                    path = "/" + path.split("/", 3)[-1] if len(path.split("/")) > 3 else "/"
                paths.append(path)
        return list(set(paths))[:20]  # 最多20个

    def _extract_nuclei_vulns(self) -> List[dict]:
        """汇总所有 nuclei 扫描漏洞"""
        vulns = []
        for tool, data in self.results.items():
            if "nuclei" in tool:
                parsed = data.get("parsed", {})
                vulns.extend(parsed.get("vulnerabilities", []))
        return vulns

    # ==================== Playbook v2（串联版） ====================

    def recon(self) -> dict:
        """① 信息收集: 子域名 → 存活检测 → 指纹 (串联)"""
        self.cb("playbook", self.target, "running", "🔍 信息收集阶段(串联)...")

        # Step 1: 子域名发现
        self._step("subfinder",
                   f"timeout 120 subfinder -d {self.target} -silent 2>/dev/null",
                   self.target, 180)

        subdomains = self._extract_subdomains()

        # Step 1.5: theHarvester 补充发现 (crtsh 源, 无需API key)
        harv_out = _run(f"timeout 90 /opt/theHarvester-venv/bin/theHarvester "
                        f"-d {self.target} -b crtsh 2>/dev/null", 120)
        if harv_out.strip():
            sid = db.scan_start(self.project_id, self.uid, "theharvester", self.target)
            self.scan_ids.append(sid)
            harv_parsed = auto_parse("theharvester", harv_out)
            db.scan_finish(sid, harv_out, harv_parsed)
            self.results["theharvester"] = {"raw": harv_out, "parsed": harv_parsed}
            self.cb("theharvester", self.target, "done", harv_out[:500])
            # 合并去重
            for sd in harv_parsed.get("subdomains", []):
                if sd not in subdomains:
                    subdomains.append(sd)

        all_targets = [self.target] + subdomains

        # Step 2: 存活检测 ← 喂入子域名
        targets_file = OUT / f"targets_{self.project_id}.txt"
        targets_file.write_text("\n".join(all_targets))
        self._step("httpx",
                   f"timeout 120 httpx -l {targets_file} -silent -title -status-code "
                   f"-tech-detect -no-color 2>/dev/null",
                   self.target, 180)

        live_urls = self._extract_live_urls()

        # Step 3: 指纹识别 ← 只对存活URL
        if live_urls:
            all_whatweb = ""
            for url in live_urls[:5]:  # 最多5个
                ww_out = _run(f"timeout 30 whatweb {url} --no-errors 2>/dev/null", 60)
                all_whatweb += f"\n--- {url} ---\n{ww_out}"

            sid = db.scan_start(self.project_id, self.uid, "whatweb", self.target)
            self.scan_ids.append(sid)
            parsed = auto_parse("whatweb", all_whatweb)
            db.scan_finish(sid, all_whatweb, parsed)
            self.results["whatweb"] = {"raw": all_whatweb, "parsed": parsed}
            self.cb("whatweb", self.target, "done", all_whatweb[:500])

        # 链式摘要
        fw = self._extract_frameworks()
        self.cb("playbook", self.target, "done",
                f"✅ 子域:{len(subdomains)} 存活:{len(live_urls)} 框架:{fw}")

        return self.results

    def scan_ports(self) -> dict:
        """② 端口扫描: nmap → 提取Web端口 → nuclei 逐端口扫描 (串联)"""
        self.cb("playbook", self.target, "running", "🔌 端口扫描(串联)...")

        # Step 1: nmap 全端口
        self._step("nmap",
                   f"timeout 300 nmap -sV -sC -T4 --top-ports 1000 {self.target} 2>/dev/null",
                   self.target, 360)

        web_urls = self._extract_web_urls_from_nmap()

        # Step 2: nuclei ← 每个Web端口独立扫描
        if web_urls:
            all_nuclei = ""
            for i, url in enumerate(web_urls[:5]):
                self.cb("nuclei", url, "running", f"扫描 {url}")
                nout = _run(
                    f"timeout 120 nuclei -u {url} -silent -severity critical,high,medium "
                    f"-no-color 2>/dev/null", 180)
                all_nuclei += f"\n--- {url} ---\n{nout}"

            key = "nuclei_ports"
            sid = db.scan_start(self.project_id, self.uid, key, self.target)
            self.scan_ids.append(sid)
            parsed = auto_parse("nuclei", all_nuclei)
            db.scan_finish(sid, all_nuclei, parsed)
            self.results[key] = {"raw": all_nuclei, "parsed": parsed}

        self.cb("playbook", self.target, "done",
                f"✅ Web端口:{len(web_urls)} → {web_urls}")

        return self.results

    def scan_web(self) -> dict:
        """③ Web扫描: 基线采集 → 目录爆破 → 参数发现 → SQL注入检测 (串联)"""
        self.cb("playbook", self.target, "running", "🌐 Web扫描(串联)...")

        # Step 0: 基线采集（为 auto-verify 提供对比参照）
        self.cb("auto-verify", self.target, "running", "采集端点基线...")
        base_urls = "/,/robots.txt,/sitemap.xml,/.well-known/security.txt"
        _run(
            f"timeout 30 auto-verify baseline --pid {self.project_id} "
            f"--target https://{self.target} --urls '{base_urls}' "
            f"--output {OUT}/baseline_{self.project_id}.json 2>/dev/null", 60)
        if os.path.exists(f"{OUT}/baseline_{self.project_id}.json"):
            with open(f"{OUT}/baseline_{self.project_id}.json") as f:
                self.results["baseline"] = {"raw": f.read(), "parsed": {}}
            self.cb("auto-verify", self.target, "done", "基线采集完成")

        # Step 1: 目录爆破
        self._step("ffuf",
                   f"timeout 120 ffuf -u https://{self.target}/FUZZ "
                   f"-w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 "
                   f"-s -o {OUT}/ffuf_{self.project_id}.json 2>/dev/null || "
                   f"timeout 120 dirsearch -u https://{self.target} -e php,asp,aspx,jsp,html --quiet 2>/dev/null",
                   f"https://{self.target}", 180)

        paths = self._extract_paths()
        interesting = [p for p in paths if any(k in p.lower() for k in
                       ("api", "admin", "dev", "test", "debug", "backup", ".git", "config",
                        "login", "upload", "graphql", "swagger", "v1", "v2"))]

        # Step 2: WAF 检测
        self._step("wafw00f",
                   f"timeout 30 wafw00f {self.target} 2>/dev/null",
                   self.target, 60)

        # Step 3: 参数发现 ← 对有趣路径跑 arjun
        if interesting:
            all_arjun = ""
            for path in interesting[:5]:
                url = f"https://{self.target}{path}"
                self.cb("arjun", url, "running", f"参数发现 {path}")
                aj_out = _run(
                    f"timeout 60 arjun -u {url} -oT {OUT}/arjun_{self.project_id}.txt "
                    f"--stable 2>/dev/null", 90)
                all_arjun += f"\n--- {url} ---\n{aj_out}"

            if all_arjun.strip():
                sid = db.scan_start(self.project_id, self.uid, "arjun", self.target)
                self.scan_ids.append(sid)
                parsed = auto_parse("arjun", all_arjun)
                db.scan_finish(sid, all_arjun, parsed)
                self.results["arjun"] = {"raw": all_arjun, "parsed": parsed}

            # Step 4: SQL注入检测 ← 对发现的参数跑 sqlmap
            arjun_data = self.results.get("arjun", {}).get("parsed", {})
            injectable_params = arjun_data.get("params", [])

            if injectable_params:
                for p_info in injectable_params[:3]:
                    p_url = p_info.get("url", "")
                    p_name = p_info.get("name", "")
                    if p_url and p_name:
                        self.cb("sqlmap", p_url, "running", f"SQL注入测试 {p_name}")
                        self._step(f"sqlmap_{p_name}",
                                   f"timeout 180 sqlmap -u '{p_url}' --batch --level=3 --risk=2 "
                                   f"--random-agent --no-color 2>/dev/null",
                                   p_url, 240)

        self.cb("playbook", self.target, "done",
                f"✅ 目录:{len(paths)} 有趣:{len(interesting)} → {interesting[:5]}")

        return self.results

    def scan_vuln(self) -> dict:
        """④ 漏洞扫描: 利用所有上游数据 → 针对性 nuclei 扫描"""
        self.cb("playbook", self.target, "running", "💣 漏洞扫描(串联)...")

        # 收集所有需要扫描的URL
        scan_targets = [f"https://{self.target}"]

        # 从 nmap 加端口URL
        web_urls = self._extract_web_urls_from_nmap()
        scan_targets.extend(web_urls)

        # 从 httpx 加存活URL
        live_urls = self._extract_live_urls()
        scan_targets.extend(live_urls)

        # 从 ffuf 加路径
        paths = self._extract_paths()
        for p in paths[:10]:
            scan_targets.append(f"https://{self.target}{p}")

        # 去重
        scan_targets = list(set(scan_targets))[:10]

        # 框架匹配 → 选择 nuclei 模板标签
        frameworks = self._extract_frameworks()
        tags = []
        fw_tag_map = {
            "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal",
            "laravel": "laravel", "django": "django", "flask": "flask",
            "spring": "spring", "tomcat": "tomcat", "nginx": "nginx",
            "apache": "apache", "iis": "iis", "php": "php", "rails": "rails",
            "node": "nodejs", "react": "react", "angular": "angular",
            "jquery": "jquery", "bootstrap": "bootstrap",
        }
        for fw in frameworks:
            fw_lower = fw.lower()
            for k, v in fw_tag_map.items():
                if k in fw_lower and v not in tags:
                    tags.append(v)

        tag_str = ",".join(tags[:5]) if tags else ""
        tag_arg = f"-tags {tag_str}" if tag_str else ""

        # 对所有目标跑 nuclei（JSONL格式 → auto-verify可解析）
        nuclei_jsonl = OUT / f"nuclei_{self.project_id}.jsonl"
        all_nuclei_text = ""
        for i, url in enumerate(scan_targets):
            self.cb("nuclei", url, "running", f"扫描 [{i+1}/{len(scan_targets)}] tags:{tag_str}")
            # -jsonl 输出结构化JSON，同时保留 -silent 文本用于展示
            nout = _run(
                f"timeout 120 nuclei -u {url} -silent -jsonl "
                f"-severity critical,high,medium "
                f"{tag_arg} -no-color 2>/dev/null", 180)
            if nout.strip():
                all_nuclei_text += f"\n--- {url} ---\n{nout}"
                # 追加到 JSONL 文件
                with open(nuclei_jsonl, "a") as jf:
                    jf.write(nout.rstrip() + "\n")

        if all_nuclei_text.strip():
            key = "nuclei_targeted"
            sid = db.scan_start(self.project_id, self.uid, key, self.target)
            self.scan_ids.append(sid)
            parsed = auto_parse("nuclei", all_nuclei_text)
            db.scan_finish(sid, all_nuclei_text, parsed)
            self.results[key] = {"raw": all_nuclei_text, "parsed": parsed}

            # 🔥 auto-verify: 自动验证 nuclei 发现的漏洞（JSONL → 精准解析）
            if nuclei_jsonl.exists():
                self.cb("auto-verify", self.target, "running",
                        f"自动验证漏洞({nuclei_jsonl.stat().st_size}字节)...")
                avout = _run(
                    f"timeout 120 auto-verify batch --pid {self.project_id} "
                    f"--input {nuclei_jsonl} --mode normal "
                    f"--output {OUT}/av_{self.project_id}.json 2>/dev/null", 150)
                av_file = OUT / f"av_{self.project_id}.json"
                if av_file.exists():
                    with open(av_file) as f:
                        av_raw = f.read()
                    try:
                        av_data = json.loads(av_raw)
                        av_parsed = auto_parse("auto-verify", av_raw)
                        self.results["auto_verify"] = {"raw": av_raw, "parsed": av_parsed}
                        self.cb("auto-verify", self.target, "done",
                                f"✅ 验证: {av_data.get('verified',0)}/{av_data.get('total',0)} 确认为真漏洞")
                    except json.JSONDecodeError:
                        self.cb("auto-verify", self.target, "error", "JSON解析失败")

        vulns = self._extract_nuclei_vulns()
        self.cb("playbook", self.target, "done",
                f"✅ 扫描{len(scan_targets)}目标 标签:{tags} 漏洞:{len(vulns)}")

        return self.results

    def full(self, phases: str = "all") -> dict:
        """
        ⑤ 全流程自动化（串联版）
        阶段间数据自动流转: recon → ports → web → vuln
        """
        phase_list = ["recon", "ports", "web", "vuln"] if phases == "all" else \
                     [p.strip() for p in phases.split(",")]

        phase_methods = {
            "recon": self.recon,
            "ports": self.scan_ports,
            "web": self.scan_web,
            "vuln": self.scan_vuln,
        }

        chain_summary = []
        for i, phase in enumerate(phase_list):
            method = phase_methods.get(phase)
            if not method:
                continue
            try:
                self.cb("chain", self.target, "running",
                        f"🔗 阶段 [{i+1}/{len(phase_list)}]: {phase}")
                method()
                # 阶段间数据桥接
                fw = self._extract_frameworks()
                subdomains = self._extract_subdomains()
                live_urls = self._extract_live_urls()
                web_urls = self._extract_web_urls_from_nmap()
                chain_summary.append(
                    f"{phase}: 子域={len(subdomains)} 存活={len(live_urls)} "
                    f"Web端口={len(web_urls)} 框架={fw[:5] if fw else '无'}"
                )
            except Exception as e:
                self.cb(phase, self.target, "error", str(e))
                chain_summary.append(f"{phase}: ❌ {e}")

        self._extract_findings()

        self.cb("chain", self.target, "done",
                " | ".join(chain_summary))

        return self.results

    def _extract_findings(self):
        """从解析结果中提取漏洞"""
        for tool, data in self.results.items():
            parsed = data.get("parsed", {})
            if not parsed:
                continue

            vulns = parsed.get("vulnerabilities", [])
            for v in vulns:
                db.finding_add(
                    scan_id=self.scan_ids[-1] if self.scan_ids else 0,
                    project_id=self.project_id,
                    uid=self.uid,
                    severity=v.get("severity", "info"),
                    title=v.get("name", v.get("template", "")),
                    description=v.get("matched", ""),
                    target=v.get("host", self.target),
                    evidence=json.dumps(v, ensure_ascii=False)[:2000]
                )

            # nmap 开放端口也算发现
            ports = parsed.get("ports", [])
            for p in ports:
                if p.get("state") == "open":
                    svc = p.get("service", "")
                    db.finding_add(
                        scan_id=self.scan_ids[-1] if self.scan_ids else 0,
                        project_id=self.project_id,
                        uid=self.uid,
                        severity="info",
                        title=f"开放端口: {p['port']}/{p.get('proto','tcp')} ({svc})",
                        description=f"服务: {svc}",
                        target=self.target,
                    )


# ==================== Playbook 快捷调用 ====================

def run_recon(uid: int, project_id: int, target: str,
              cb: Optional[ProgressCallback] = None) -> dict:
    play = Playbook(uid, project_id, target, cb)
    return play.recon()


def run_full(uid: int, project_id: int, target: str,
             phases: str = "all",
             cb: Optional[ProgressCallback] = None) -> dict:
    play = Playbook(uid, project_id, target, cb)
    return play.full(phases)


def run_port_scan(uid: int, project_id: int, target: str,
                  cb: Optional[ProgressCallback] = None) -> dict:
    play = Playbook(uid, project_id, target, cb)
    return play.scan_ports()


def run_web_scan(uid: int, project_id: int, target: str,
                 cb: Optional[ProgressCallback] = None) -> dict:
    play = Playbook(uid, project_id, target, cb)
    return play.scan_web()


def run_vuln_scan(uid: int, project_id: int, target: str,
                  cb: Optional[ProgressCallback] = None) -> dict:
    play = Playbook(uid, project_id, target, cb)
    return play.scan_vuln()
