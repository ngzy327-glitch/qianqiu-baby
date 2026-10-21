#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给 wudie.work 的 nginx 配置补一条 index.html 不缓存规则。

背景: 前端更新后, Telegram WebView / iOS Safari 会继续用缓存的旧 index.html,
     导致页面还停在旧版(例如仍显示「请从 Telegram 里打开」)。
做法: 在 443 server 块里加 `location = /index.html` 精确匹配, 只对入口 HTML 关缓存,
     带 hash 的 assets 仍然正常缓存, 不影响加载速度。
幂等: 已有 no-store 则直接跳过; 改写前自动备份; 不重启, 由调用方决定 reload。
"""
import re
import sys
import time
from pathlib import Path

CONF = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/nginx/conf.d/wudie.work.conf")

if not CONF.exists():
    print(f"CONF_MISSING {CONF}")
    sys.exit(1)

s = CONF.read_text(encoding="utf-8")
if "no-store" in s:
    print("ALREADY")
    sys.exit(0)

block = (
    '\n    # 2026-10-21 入口 HTML 不缓存, 避免 WebView 吃旧包\n'
    '    location = /index.html {\n'
    '        add_header Cache-Control "no-store, must-revalidate" always;\n'
    '    }\n'
)

# 插到最后一个 server 块的收尾大括号前(配置文件最后一个 })
i = s.rstrip().rfind("}")
if i < 0:
    print("BAD_CONF")
    sys.exit(1)

bak = CONF.with_suffix(CONF.suffix + ".bak." + time.strftime("%Y%m%d%H%M%S"))
bak.write_text(s, encoding="utf-8")

new = s[:i].rstrip("\n") + "\n" + block + "}\n"
# 粗校验: 大括号必须配平, 否则不落盘
if new.count("{") != new.count("}"):
    print("UNBALANCED_SKIP")
    sys.exit(1)

CONF.write_text(new, encoding="utf-8")
print(f"DONE backup={bak}")
