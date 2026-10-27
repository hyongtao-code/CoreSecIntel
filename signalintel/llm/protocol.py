"""大模型调用接口（Protocol）。

处理器只依赖这个协议，而不是具体的 :class:`LLMClient`，
便于测试时注入假实现，也便于后续接入非 OpenAI 格式的独立客户端。
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["LLMBackend"]


@runtime_checkable
class LLMBackend(Protocol):
    """大模型后端的最小接口。"""

    def complete_one(
        self, system_prompt: str, user_prompt: str, json_mode: bool = True
    ) -> Any:
        """执行一次对话，返回解析后的 JSON 对象（``json_mode=True``）或文本。"""
        ...

    def complete_batch(
        self,
        system_prompt: str,
        user_prompt: str,
        items: list[Any],
        max_batch_size: int | None = None,
    ) -> list[Any]:
        """批量执行，返回与输入等长的结果列表。"""
        ...
