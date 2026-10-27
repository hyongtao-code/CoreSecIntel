#!/usr/bin/env bash
# ============================================================================
# 发送测试邮件：验证 SMTP 配置是否可用（不跑采集）
#
#   ./scripts/send_test_mail.sh
#
# 用途：配置完 .env 后先跑这个，确认凭证正确、投递通路正常。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

PYTHON="${PYTHON:-python3}"

"$PYTHON" - <<'PYCODE'
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from signalintel.config import load_config
from signalintel.notifications.email_sender import EmailSender

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

config = load_config()
smtp = config.smtp

print("=== SMTP 配置检查 ===")
print(f"  主机端口 : {smtp.host}:{smtp.port}")
print(f"  SSL/TLS  : use_ssl={smtp.use_ssl} use_tls={smtp.use_tls}")
print(f"  账号     : {smtp.user or '(未配置)'}")
print(f"  密码     : {'已设置' if smtp.password else '未设置'}"
      + ("  ← 仍是占位符 REPLACE_ME" if smtp.password == "REPLACE_ME" else ""))
print(f"  发件人   : {smtp.sender}")
print(f"  收件人   : {smtp.recipients}")

if smtp.password == "REPLACE_ME":
    print("\n✗ SMTP_PASSWORD 仍是占位符。请先设置网易邮箱客户端授权密码：")
    print("  1) 登录 163 邮箱 → 设置 → POP3/SMTP/IMAP")
    print("  2) 开启 SMTP 服务 → 生成客户端授权密码")
    print("  3) 执行：python3 scripts/setup_env.py --email <163地址> --to <收件人> --force")
    sys.exit(2)

if not smtp.is_configured:
    print("\n✗ SMTP 配置不完整")
    sys.exit(2)

html = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>核心网信令安全周报 · 测试</title></head>
<body style="margin:0;padding:24px;background:#f2f4f7;font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
 style="width:600px;max-width:100%;margin:0 auto;background:#fff;border-radius:8px;">
<tr><td style="background:#0b3d6b;padding:20px 24px;color:#fff;font-size:19px;font-weight:700;">
核心网信令安全周报 · 测试邮件</td></tr>
<tr><td style="padding:22px 24px;font-size:14px;color:#344054;line-height:1.85;">
这是一封 <strong>SMTP 连通性测试邮件</strong>。<br><br>
如果你收到了它，说明：<br>
• Gmail 应用专用密码配置正确<br>
• smtp.gmail.com:465 (SSL) 投递通路正常<br>
• 中文 UTF-8 正文渲染正常<br><br>
正式的报告邮件将使用同一套配置自动发送。
</td></tr>
<tr><td style="padding:14px 24px;background:#f9fafb;font-size:12px;color:#98a2b3;">
由「核心网信令安全情报自动订阅系统」发送</td></tr>
</table></body></html>"""

print("\n=== 正在发送测试邮件 ===")
result = EmailSender(smtp).send(
    "【核心网信令安全周报】SMTP 测试", html
)

if result.success:
    print(f"✓ 发送成功 → {', '.join(result.recipients)}")
    print(f"  尝试次数: {result.attempts}")
    sys.exit(0)

print(f"✗ 发送失败: {result.error}")
print(f"  尝试次数: {result.attempts}")
print("\n排查建议：")
print("  1) 确认用的是「客户端授权密码」而非 163 账号登录密码")
print("  2) 确认该账号已在设置中开启 SMTP 服务")
print("  3) 确认网络能出站 smtp.163.com:465")
sys.exit(1)
PYCODE
