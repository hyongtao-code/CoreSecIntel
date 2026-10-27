"""共享正则模式。

集中定义协议 / 网元 / 攻击面的匹配规则，避免各处理器出现不一致的判定。

关键设计：短缩写（MAP、SIP、IMS、NAS 等）要求**全大写**才视为协议名，
避免 "roadmap"、"relationship"、"nasal" 之类的普通英文单词误命中。
"""

from __future__ import annotations

import re

__all__ = [
    "ATTACK_STEM",
    "NETWORK_ELEMENT_RE",
    "PROTOCOL_RE",
    "SIGNALING_PROTOCOLS",
    "CORE_NETWORK_RE",
]

#: 需要全大写才匹配的短缩写（避免与普通英文单词冲突）
_UPPER_ONLY = r"SS7|MAP|TCAP|SCCP|SIGTRAN|GTP-C|GTP-U|PFCP|SIP|IMS|NAS|NGAP|S1AP|SBA|SBC|MME|HSS|PCRF|AMF|SMF|UPF|AUSF|UDM|UDR|PCF|NRF"

#: 不区分大小写的长协议名（本身就有明显特征）
_ANY_CASE = r"Diameter|PFCP|GTP|GTP-C|GTP-U|SIGTRAN|SCCP|TCAP|5G Core|5G SBA|NAS"

#: 协议名匹配（大小写敏感）
PROTOCOL_RE = re.compile(
    rf"\b(?:{_UPPER_ONLY}|{_ANY_CASE})\b",
)

#: 核心网网元匹配（同样要求全大写）
NETWORK_ELEMENT_RE = re.compile(
    r"\b(?:MME|HSS|PCRF|AMF|SMF|UPF|AUSF|UDM|UDR|PCF|NRF|SGW|PGW|MMSC|MSC|HLR|VLR|"
    r"BSC|RNC|SCP|SMF-AUSF|SCEF)\b"
)

#: 攻击类词干（允许复数与派生形式）
ATTACK_STEM = (
    r"vulnerabilit|exploit|attack|abus|bypass|inject|fuzz|overflow|spoof|"
    r"replay|hijack|compromis|backdoor|malicious|adversar|threat|"
    r"impersonat|spoofing|intercept"
)

#: 已知信令协议名（用于报告展示与提示词构造）
SIGNALING_PROTOCOLS: tuple[str, ...] = (
    "SS7",
    "MAP",
    "TCAP",
    "SCCP",
    "SIGTRAN",
    "Diameter",
    "GTP-C",
    "GTP-U",
    "PFCP",
    "SIP",
    "IMS",
    "NAS",
    "NGAP",
    "S1AP",
    "5G SBA",
    "HTTP/2",
)
