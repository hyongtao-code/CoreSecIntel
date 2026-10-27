"""电信领域相关性闸门。

与 :mod:`signalintel.processors.filter` 的关键词召回不同，本模块解决的是
另一个问题：**即便命中了安全类关键词，内容是否真的属于电信核心网 / 信令领域**。

典型误判场景（这些内容属于通用互联网安全，应当剔除）：

- Linux 内核 CVE（即使描述里提到 pfcp / net / socket）
- 蓝牙协议栈漏洞
- Web 应用 / CMS / WordPress 插件漏洞
- 通用 XSS / SQL 注入 / 反序列化漏洞
- 材料科学论文里的 "Diameter"、生物学论文里的 "MAP"
- 通用 DDoS / 僵尸网络 / 挖矿木马

判定方式：内容中必须出现**电信领域实体**（协议、网元、接口、业务场景），
才认为属于电信安全范畴。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

__all__ = ["TelecomGate", "TelecomSignals"]


#: 电信领域实体 —— 协议名
#: 注意大小写：SS7/TCAP/PFCP 等小写形式无歧义，可忽略大小写；
#: MAP / IMS / NAS / SIP 等有歧义，要求全大写。
_PROTOCOL_PATTERN = (
    r"\b(?:"
    r"SS7|TCAP|SCCP|SIGTRAN|GTP-C|GTP-U|PFCP|GTP|NGAP|S1AP|"
    r"Diameter|SIP-?based|HTTP/2"
    r")\b"
    r"|\b(?:SIP|IMS|NAS|MAP)\b"
)

#: 电信领域实体 —— 网元名（要求全大写，避免误命中普通词）
_NETWORK_ELEMENT_PATTERN = (
    r"\b(?:"
    r"MME|HSS|PCRF|AMF|SMF|UPF|AUSF|UDM|UDR|PCF|NRF|NSSF|"
    r"SGW|PGW|MSC|HLR|VLR|MMSC|SCEF|SCP"
    r")\b"
)

#: 电信领域实体 —— 接口 / 架构 / 业务场景
_SERVICE_PATTERN = (
    r"\b(?:"
    r"mobile core network|core network|5G\s*core|4G\s*core|EPC|"
    r"evolved packet core|service[- ]based architecture|SBA|"
    r"subscriber|IMSI|IMEI|MSISDN|HLR|VLR|MAP operations|"
    r"roaming|interworking|interconnect|"
    r"telecom|telecommunication|mobile network|cellular network|"
    r"operator|carrier network|MNO|MVNO|"
    r"base station|RAN|vRAN|Open RAN|eNodeB|gNodeB|"
    r"VoLTE|VoNR|IMS|PSTN|ISDN|SIP trunk|media gateway|softswitch|"
    r"lawful intercept|SMS|SS7|Diameter|PFCP|"
    r"telecom fraud|toll fraud|"
    r"3GPP|GSMA|ITU-T|"
    r"private 5G|network slicing|MEC|edge computing"
    r")\b"
    r"|\b(?:SIP|IMS|NAS|MAP)\b"
)

#: 明确属于通用互联网 / 软件工程领域的内容（命中即剔除）
#: 这些领域即使出现电信词汇也不构成信令安全情报。
_NON_TELECOM_PATTERN = re.compile(
    r"\b(?:"
    r"linux kernel|kernel module|use-after-free|double[- ]free|"
    r"bluetooth|ble stack|usb gadget|nvme|ext4|xfs|btrfs|"
    r"wordpress|joomla|drupal|magento|typo3|prestashop|"
    r"php symfony|laravel|django|flask|express\.js|rails|"
    r"cross-site scripting|xss|csrf|sql injection|"
    r"deserialization|prototype pollution|path traversal|"
    r"log4shell|openssl|gnutls|curl|wget|busybox|"
    r"ransomware|botnet|miner|coinminer|trojan|"
    r"ransom note|cryptojacking"
    r")\b",
    re.IGNORECASE,
)

#: 协议上下文提示词：出现这些词说明内容确实在谈电信协议
_PROTOCOL_CONTEXT = re.compile(
    r"\b(?:"
    r"message|messages|parsing|parser|parse|state machine|opcode|"
    r"message type|protocol|procedure|dialog|transaction|operation|"
    r"attack|abuse|exploit|fuzzing|vulnerability|bypass|injection|spoofing|"
    r"replay|hijack|impersonat|redirect|tamper|modify|manipulat|"
    r"firewall|filter|validation|encoding|decode|header|payload|"
    r"interface|signaling|signalling|routing|routed|route|"
    r"tunnel|session|subscription|registration|authentication|"
    r"field|value|length|type|flag|command|request|response"
    r")\b",
    re.IGNORECASE,
)


@dataclass
class TelecomSignals:
    """一次电信相关性判定的信号明细。"""

    matched: bool = False
    protocols: list[str] = field(default_factory=list)
    network_elements: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    reason: str = ""
    rejected_by: Optional[str] = None


class TelecomGate:
    """电信领域相关性闸门。"""

    def __init__(
        self,
        require_protocol_context: bool = True,
        exclude_non_telecom: bool = True,
    ) -> None:
        self.require_protocol_context = require_protocol_context
        self.exclude_non_telecom = exclude_non_telecom
        self._protocol_re = re.compile(_PROTOCOL_PATTERN)
        self._element_re = re.compile(_NETWORK_ELEMENT_PATTERN)
        self._service_re = re.compile(_SERVICE_PATTERN)

    # ------------------------------------------------------------------

    def evaluate(self, title: str, abstract: str) -> TelecomSignals:
        """判定内容是否属于电信核心网 / 信令安全领域。"""
        text = f"{title}\n{abstract}".strip()
        signals = TelecomSignals()

        # 1) 收集电信领域实体
        signals.protocols = [m.group(0) for m in self._protocol_re.finditer(text)]
        signals.network_elements = [
            m.group(0) for m in self._element_re.finditer(text)
        ]
        signals.services = [m.group(0) for m in self._service_re.finditer(text)]

        # 去重
        signals.protocols = list(dict.fromkeys(signals.protocols))
        signals.network_elements = list(dict.fromkeys(signals.network_elements))
        signals.services = list(dict.fromkeys(signals.services))

        has_entity = bool(
            signals.protocols or signals.network_elements or signals.services
        )
        if not has_entity:
            signals.reason = "未出现任何电信领域实体（协议 / 网元 / 接口 / 业务场景）"
            return signals

        # 2) 明确属于通用互联网 / 软件工程领域的，剔除。
        #    但**信令协议专属漏洞除外**：例如 Linux 内核里的 PFCP / GTP-C
        #    解析漏洞，宿主平台虽是 Linux，缺陷本身却在核心网信令协议上，
        #    属于本系统应当收录的内容。
        if self.exclude_non_telecom:
            hit = _NON_TELECOM_PATTERN.search(text)
            if hit and not self._is_signaling_specific(signals, text):
                signals.rejected_by = hit.group(0)
                signals.reason = f"属于通用互联网/软件工程领域（命中「{hit.group(0)}」）"
                return signals

        # 3) 协议上下文校验：谈协议必须谈协议行为
        if self.require_protocol_context:
            context_hit = bool(_PROTOCOL_CONTEXT.search(text))
            if not context_hit:
                signals.reason = "出现电信词汇但缺少协议行为上下文"
                return signals

        signals.matched = True
        signals.reason = "命中电信领域实体：" + ", ".join(
            (signals.protocols + signals.network_elements + signals.services)[:6]
        )
        return signals

    # ------------------------------------------------------------------

    #: 核心网信令协议（命中即视为信令专属内容，豁免通用领域排除规则）
    _SIGNALING_SPECIFIC = frozenset(
        {"SS7", "TCAP", "SCCP", "SIGTRAN", "GTP-C", "GTP-U", "PFCP", "GTP",
         "NGAP", "S1AP", "Diameter", "SIP", "IMS"}
    )

    def _is_signaling_specific(
        self, signals: TelecomSignals, text: str
    ) -> bool:
        """判断内容是否聚焦于核心网信令协议本身。

        命中信令协议名（SS7 / GTP-C / PFCP / Diameter / SIP / IMS ...）
        且伴随协议行为语义时，视为信令专属内容 —— 即使宿主平台是
        Linux 内核或某个通用软件栈。
        """
        protocol_hits = {
            p.upper() for p in signals.protocols if p.upper() in self._SIGNALING_SPECIFIC
        }
        if not protocol_hits:
            return False
        return bool(_PROTOCOL_CONTEXT.search(text))

    # ------------------------------------------------------------------

    def filter(
        self, items: Iterable[Any]
    ) -> tuple[list[Any], list[Any]]:
        """批量过滤，返回 ``(保留项, 剔除项)``。

        被剔除的条目会记录 ``relevance_keywords`` 之外的说明，便于排查。
        """
        kept: list[Any] = []
        dropped: list[Any] = []
        for item in items:
            signals = self.evaluate(
                getattr(item, "title", "") or "", getattr(item, "abstract", "") or ""
            )
            if signals.matched:
                item.telecom_signals = signals  # type: ignore[attr-defined]
                kept.append(item)
            else:
                item.telecom_reject_reason = signals.reason  # type: ignore[attr-defined]
                dropped.append(item)
        return kept, dropped
