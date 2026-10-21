#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编解码/加解密工具库 - 支持 30+ 种编解码操作"""

import base64
import hashlib
import urllib.parse
import json
import codecs
import struct
from typing import Optional


# ============ Base64 系列 ============

def b64_encode(data: str) -> dict:
    """Base64 编码"""
    try:
        encoded = base64.b64encode(data.encode()).decode()
        return {"type": "base64_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def b64_decode(data: str) -> dict:
    """Base64 解码"""
    try:
        decoded = base64.b64decode(data).decode()
        return {"type": "base64_decode", "input": data, "output": decoded}
    except Exception as e:
        try:
            decoded = base64.b64decode(data + "==").decode()
            return {"type": "base64_decode", "input": data, "output": decoded}
        except Exception as e2:
            return {"error": f"解码失败: {e2}"}


def b32_encode(data: str) -> dict:
    """Base32 编码"""
    try:
        encoded = base64.b32encode(data.encode()).decode()
        return {"type": "base32_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def b32_decode(data: str) -> dict:
    """Base32 解码"""
    try:
        decoded = base64.b32decode(data).decode()
        return {"type": "base32_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


def b85_encode(data: str) -> dict:
    """Base85 编码"""
    try:
        encoded = base64.b85encode(data.encode()).decode()
        return {"type": "base85_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def b85_decode(data: str) -> dict:
    """Base85 解码"""
    try:
        decoded = base64.b85decode(data).decode()
        return {"type": "base85_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


# ============ Hex ============

def hex_encode(data: str) -> dict:
    """Hex 编码"""
    try:
        encoded = data.encode().hex()
        return {"type": "hex_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def hex_decode(data: str) -> dict:
    """Hex 解码"""
    try:
        decoded = bytes.fromhex(data).decode()
        return {"type": "hex_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


# ============ URL 编码 ============

def url_encode(data: str) -> dict:
    """URL 编码"""
    try:
        encoded = urllib.parse.quote(data)
        return {"type": "url_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def url_decode(data: str) -> dict:
    """URL 解码"""
    try:
        decoded = urllib.parse.unquote(data)
        return {"type": "url_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


def url_encode_all(data: str) -> dict:
    """URL 全编码（每个字符都编码）"""
    try:
        encoded = "".join(f"%{ord(c):02X}" for c in data)
        return {"type": "url_encode_all", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


# ============ HTML 实体 ============

def html_encode(data: str) -> dict:
    """HTML 实体编码"""
    import html
    try:
        encoded = html.escape(data)
        return {"type": "html_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def html_decode(data: str) -> dict:
    """HTML 实体解码"""
    import html
    try:
        decoded = html.unescape(data)
        return {"type": "html_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


# ============ ROT13 / Caesar ============

def rot13(data: str) -> dict:
    """ROT13 编码/解码"""
    try:
        result = codecs.decode(data, "rot_13")
        return {"type": "rot13", "input": data, "output": result}
    except Exception as e:
        return {"error": str(e)}


def caesar(data: str, shift: int = 3) -> dict:
    """凯撒密码（可自定义位移）"""
    try:
        result = []
        for c in data:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return {"type": "caesar", "shift": shift, "input": data, "output": "".join(result)}
    except Exception as e:
        return {"error": str(e)}


# ============ XOR ============

def xor_encrypt(data: str, key: str) -> dict:
    """XOR 加密"""
    try:
        key_bytes = key.encode()
        data_bytes = data.encode()
        encrypted = bytes([data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes))])
        return {"type": "xor", "key": key, "input": data, "output_hex": encrypted.hex(), "output_b64": base64.b64encode(encrypted).decode()}
    except Exception as e:
        return {"error": str(e)}


def xor_decrypt_hex(data_hex: str, key: str) -> dict:
    """XOR 解密（hex 输入）"""
    try:
        encrypted = bytes.fromhex(data_hex)
        key_bytes = key.encode()
        decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))]).decode()
        return {"type": "xor_decrypt", "key": key, "input_hex": data_hex, "output": decrypted}
    except Exception as e:
        return {"error": str(e)}


# ============ 哈希 ============

def md5(data: str) -> dict:
    """MD5 哈希"""
    try:
        return {"type": "md5", "input": data, "output": hashlib.md5(data.encode()).hexdigest()}
    except Exception as e:
        return {"error": str(e)}


def sha1(data: str) -> dict:
    """SHA1 哈希"""
    try:
        return {"type": "sha1", "input": data, "output": hashlib.sha1(data.encode()).hexdigest()}
    except Exception as e:
        return {"error": str(e)}


def sha256(data: str) -> dict:
    """SHA256 哈希"""
    try:
        return {"type": "sha256", "input": data, "output": hashlib.sha256(data.encode()).hexdigest()}
    except Exception as e:
        return {"error": str(e)}


def sha512(data: str) -> dict:
    """SHA512 哈希"""
    try:
        return {"type": "sha512", "input": data, "output": hashlib.sha512(data.encode()).hexdigest()}
    except Exception as e:
        return {"error": str(e)}


def hash_all(data: str) -> dict:
    """一次性计算所有哈希"""
    try:
        return {
            "type": "hash_all",
            "input": data,
            "md5": hashlib.md5(data.encode()).hexdigest(),
            "sha1": hashlib.sha1(data.encode()).hexdigest(),
            "sha256": hashlib.sha256(data.encode()).hexdigest(),
            "sha512": hashlib.sha512(data.encode()).hexdigest(),
        }
    except Exception as e:
        return {"error": str(e)}


# ============ Morse 电码 ============

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
    "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.',
    '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
}

MORSE_REVERSE = {v: k for k, v in MORSE_CODE.items()}


def morse_encode(data: str) -> dict:
    """Morse 编码"""
    try:
        result = []
        for c in data.upper():
            if c == ' ':
                result.append('/')
            elif c in MORSE_CODE:
                result.append(MORSE_CODE[c])
            else:
                result.append('?')
        return {"type": "morse_encode", "input": data, "output": ' '.join(result)}
    except Exception as e:
        return {"error": str(e)}


def morse_decode(data: str) -> dict:
    """Morse 解码"""
    try:
        result = []
        for word in data.split('/'):
            for code in word.strip().split():
                if code in MORSE_REVERSE:
                    result.append(MORSE_REVERSE[code])
                else:
                    result.append('?')
            result.append(' ')
        return {"type": "morse_decode", "input": data, "output": ''.join(result).strip()}
    except Exception as e:
        return {"error": str(e)}


# ============ JWT ============

def jwt_decode(token: str) -> dict:
    """JWT 解码（不验证签名）"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "无效的 JWT 格式，应有 3 段"}
        # Header
        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))
        # Payload
        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        return {"type": "jwt_decode", "header": header, "payload": payload, "signature": parts[2][:50] + "..."}
    except Exception as e:
        return {"error": str(e)}


# ============ Unicode ============

def unicode_encode(data: str) -> dict:
    """Unicode 编码（\\uXXXX 格式）"""
    try:
        encoded = ''.join(f'\\u{ord(c):04x}' for c in data)
        return {"type": "unicode_encode", "input": data, "output": encoded}
    except Exception as e:
        return {"error": str(e)}


def unicode_decode(data: str) -> dict:
    """Unicode 解码"""
    try:
        decoded = data.encode().decode('unicode_escape')
        return {"type": "unicode_decode", "input": data, "output": decoded}
    except Exception as e:
        return {"error": str(e)}


# ============ AES (简化版，使用 cryptography 库) ============

def aes_encrypt(data: str, key: str) -> dict:
    """AES-CBC 加密（key 自动填充到 16/24/32 字节）"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        import os
        key_bytes = key.encode()[:32].ljust(32, b'\x00')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data.encode()) + padder.finalize()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        result = base64.b64encode(iv + encrypted).decode()
        return {"type": "aes_cbc_encrypt", "key": key, "input": data, "output": result, "iv_hex": iv.hex()}
    except ImportError:
        return {"error": "需要安装 cryptography 库: pip install cryptography"}
    except Exception as e:
        return {"error": str(e)}


def aes_decrypt(data_b64: str, key: str) -> dict:
    """AES-CBC 解密"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        key_bytes = key.encode()[:32].ljust(32, b'\x00')
        raw = base64.b64decode(data_b64)
        iv = raw[:16]
        encrypted = raw[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(padded) + unpadder.finalize()
        return {"type": "aes_cbc_decrypt", "key": key, "input": data_b64, "output": decrypted.decode()}
    except ImportError:
        return {"error": "需要安装 cryptography 库: pip install cryptography"}
    except Exception as e:
        return {"error": str(e)}


# ============ 自动识别编码 ============

def auto_decode(data: str) -> dict:
    """自动尝试多种编码方式解码"""
    results = {}
    # Base64
    try:
        decoded = base64.b64decode(data).decode()
        if decoded.isprintable():
            results["base64"] = decoded
    except:
        pass
    # Hex
    try:
        decoded = bytes.fromhex(data).decode()
        if decoded.isprintable():
            results["hex"] = decoded
    except:
        pass
    # URL
    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data:
            results["url"] = decoded
    except:
        pass
    # ROT13
    try:
        decoded = codecs.decode(data, "rot_13")
        if decoded.isprintable():
            results["rot13"] = decoded
    except:
        pass
    # HTML
    try:
        import html
        decoded = html.unescape(data)
        if decoded != data:
            results["html"] = decoded
    except:
        pass
    return {"type": "auto_decode", "input": data, "results": results}


# ============ 工具列表 ============

def codec_list() -> dict:
    """列出所有编解码操作"""
    return {
        "encoding": [
            "base64_encode", "base32_encode", "base85_encode",
            "hex_encode", "url_encode", "url_encode_all",
            "html_encode", "rot13", "caesar", "xor",
            "morse_encode", "unicode_encode",
        ],
        "decoding": [
            "base64_decode", "base32_decode", "base85_decode",
            "hex_decode", "url_decode", "html_decode",
            "morse_decode", "unicode_decode", "jwt_decode",
            "xor_decrypt", "auto_decode",
        ],
        "hash": ["md5", "sha1", "sha256", "sha512", "hash_all"],
        "crypto": ["aes_encrypt", "aes_decrypt"],
    }
