#!/usr/bin/env python3
"""探测可用的 LLM 端点与模型（不打印密钥明文）。"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def read_env_value(path: str, name: str) -> str:
    """从 env 文件读取某个变量（兼容 export 前缀与引号）。"""
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip('"').strip("'")
    return ""


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
    key = read_env_value(os.path.expanduser("~/.hermes/.env"), "MINIMAX_CN_API_KEY")
    print(f"MINIMAX_CN_API_KEY: found={bool(key)} len={len(key)}")
    if not key:
        return 1

    print("\n=== https://api.minimaxi.com/v1 ===")
    for model in ("MiniMax-Text-01", "MiniMax-M2", "abab6.5s-chat"):
        probe("https://api.minimaxi.com/v1", key, model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
