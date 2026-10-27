#!/usr/bin/env python3
"""生成 .env：LLM 密钥从环境变量读取，SMTP 密码由用户填入。

用法：
    # 从环境变量 MINIMAX_CN_API_KEY 读取 LLM 密钥
    MINIMAX_CN_API_KEY=xxx python3 scripts/setup_env.py --email <邮箱> --to <收件人>

    # 或显式传入
    python3 scripts/setup_env.py --email <邮箱> --to <收件人> --llm-key <LLM_KEY>

不依赖任何特定工具链，纯标准库实现。
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"


TEMPLATE = """# ============================================================================
# 核心网信令安全情报自动订阅系统 —— 环境变量
# 由 scripts/setup_env.py 生成。含密钥，**不要提交到版本库**。
# ============================================================================

# ----------------------------------------------------------------------------
# 大模型 API（OpenAI 兼容 Chat Completions）
# ----------------------------------------------------------------------------
LLM_API_BASE=https://api.minimaxi.com/v1
LLM_API_KEY={llm_key}
LLM_MODEL=MiniMax-Text-01
LLM_TIMEOUT=90
LLM_MAX_RETRIES=6
LLM_TEMPERATURE=0.2
LLM_MAX_BATCH_SIZE=3
LLM_MAX_ITEMS=40

# ----------------------------------------------------------------------------
# SMTP 邮件发送（网易 163）
# ----------------------------------------------------------------------------
# 163 必须用「客户端授权密码」，不能用账号登录密码：
#   登录 163 邮箱 → 设置 → POP3/SMTP/IMAP → 开启 SMTP → 生成授权密码
# 该授权密码是独立的一串密码，仅供第三方客户端使用。
SMTP_HOST=smtp.163.com
SMTP_PORT=465
SMTP_USER={email}
SMTP_PASSWORD={app_password}
SMTP_USE_TLS=true
SMTP_USE_SSL=true

# 发件人与收件人
EMAIL_FROM={email}
EMAIL_TO={email_to}

# ----------------------------------------------------------------------------
# 采集与调度
# ----------------------------------------------------------------------------
TIMEZONE=Asia/Shanghai
WINDOW_DAYS=7
DATA_DIR=./data
LOG_DIR=./logs
DB_PATH=./data/signalintel.db

# ----------------------------------------------------------------------------
# 可选：需要 API Key 的数据源（启用对应来源时生效）
# ----------------------------------------------------------------------------
# IEEE Xplore API Key，免费注册：https://ieeexploreapi.ieee.org/
# 注意：只用官方 API 取题录元数据，不登录、不抓全文。
IEEE_API_KEY={ieee_key}
# ----------------------------------------------------------------------------
# HTTP 采集行为
# ----------------------------------------------------------------------------
HTTP_MIN_INTERVAL=1.0
HTTP_TIMEOUT=30
HTTP_MAX_RETRIES=3
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True, help="Gmail 地址（发件人）")
    parser.add_argument("--to", default="", help="收件人，逗号分隔；缺省与 --email 相同")
    parser.add_argument("--app-password", default="", help="Gmail 应用专用密码")
    parser.add_argument(
        "--llm-key",
        default="",
        help="LLM Key，缺省从环境变量 MINIMAX_CN_API_KEY 读取",
    )
    parser.add_argument("--ieee-key", default="", help="IEEE Xplore API Key（可选）")
    parser.add_argument("--force", action="store_true", help="覆盖已存在的 .env")
    args = parser.parse_args()

    if ENV_PATH.exists() and not args.force:
        print(f"{ENV_PATH} 已存在。加 --force 覆盖。")
        return 1

    llm_key = args.llm_key or os.environ.get("MINIMAX_CN_API_KEY", "").strip()
    if not llm_key:
        print(
            "错误：找不到 LLM API Key。请设置环境变量 MINIMAX_CN_API_KEY，"
            "或用 --llm-key 指定。",
            file=sys.stderr,
        )
        return 2

    app_password = args.app_password
    if not app_password:
        print("\n请到 https://myaccount.google.com/apppasswords 生成应用专用密码。")
        app_password = getpass.getpass("应用专用密码（输入不回显）: ").strip()
    if not app_password:
        app_password = "REPLACE_ME"
        print("未填入应用专用密码，已写入占位符 REPLACE_ME。")

    recipients = args.to or args.email
    ENV_PATH.write_text(
        TEMPLATE.format(
            llm_key=llm_key,
            email=args.email,
            email_to=recipients,
            app_password=app_password,
            ieee_key=args.ieee_key,
        ),
        encoding="utf-8",
    )
    ENV_PATH.chmod(0o600)
    print(f"已生成 {ENV_PATH}（权限 600）")
    print(f"  发件人: {args.email}")
    print(f"  收件人: {recipients}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
