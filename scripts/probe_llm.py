#!/usr/bin/env python3
"""探测可用的 LLM 端点与模型（不打印密钥明文）。

密钥从环境变量 ``MINIMAX_CN_API_KEY`` 读取（可用 ``--api-key`` 覆盖）。
不依赖任何特定工具链，纯标准库实现。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def probe(base: str, key: str, model: str) -> None:
    url = base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "reply with exactly: OK"}],
        "max_tokens": 20,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = json.loads(response.read())
            content = data["choices"][0]["message"]["content"]
            print(f"  {model:22s} HTTP {response.status} -> {content!r}"[:110])
    except urllib.error.HTTPError as exc:
        body = exc.read()[:160].decode("utf-8", "replace")
        print(f"  {model:22s} HTTP {exc.code}: {body}"[:150])
    except Exception as exc:  # noqa: BLE001
        print(f"  {model:22s} {type(exc).__name__}: {str(exc)[:100]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="探测 LLM 端点可用性")
    parser.add_argument(
        "--api-key",
        default="",
        help="API Key，缺省从环境变量 MINIMAX_CN_API_KEY 读取",
    )
    args = parser.parse_args()

    key = (args.api_key or os.environ.get("MINIMAX_CN_API_KEY", "")).strip()
    print(f"MINIMAX_CN_API_KEY: found={bool(key)} len={len(key)}")
    if not key:
        print(
            "提示：设置环境变量 MINIMAX_CN_API_KEY，或用 --api-key 指定。",
            file=sys.stderr,
        )
        return 1

    print("\n=== https://api.minimaxi.com/v1 ===")
    for model in ("MiniMax-Text-01", "MiniMax-M2", "abab6.5s-chat"):
        probe("https://api.minimaxi.com/v1", key, model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
