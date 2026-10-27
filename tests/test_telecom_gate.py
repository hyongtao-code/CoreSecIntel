"""电信领域相关性闸门测试。

核心目的：把「通用互联网安全」内容（Linux 内核、蓝牙、Web 应用等）
与「核心网信令安全」内容区分开。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from signalintel.models import IntelItem
from signalintel.processors.telecom_gate import TelecomGate

CST = timezone(timedelta(hours=8))


def _item(**kwargs) -> IntelItem:
    base: dict = dict(
        source="NVD / CVE",
        source_type="vulnerability",
        title="",
        url="https://example.com/x",
        abstract="",
        content_type="vulnerability",
        published_at=datetime(2026, 10, 22, 8, 0, tzinfo=CST),
    )
    base.update(kwargs)
    return IntelItem(**base)


# ---------------------------------------------------------------------------
# 应当保留的内容
# ---------------------------------------------------------------------------


def test_gate_keeps_pfcp_kernel_cve():
    """Linux 内核里真正的 PFCP 协议漏洞属于信令安全，应保留。"""
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-98952: pfcp: make sure the SEID is linear before reading it",
        "In the Linux kernel, the following vulnerability has been resolved: "
        "pfcp: make sure the SEID is linear before reading it. "
        "pfcp_encap_recv() only makes sure that the UDP header and the 4 byte "
        "PFCP header are in the linear area. A remote attacker sending a crafted "
        "PFCP message could trigger an out-of-bounds read.",
    )
    assert signals.matched


def test_gate_keeps_ss7_attack_paper():
    gate = TelecomGate()
    signals = gate.evaluate(
        "SS7 Attacks Against Mobile Core Networks",
        "We analyze SS7 message injection attacks against the HLR and MSC in the "
        "mobile core network, and propose a signaling firewall for anomaly detection.",
    )
    assert signals.matched
    assert "SS7" in signals.protocols


def test_gate_keeps_diameter_attack():
    gate = TelecomGate()
    signals = gate.evaluate(
        "Diameter Routing Attacks in 5G Core",
        "We study Diameter message abuse against the AMF, showing how a rogue "
        "subscriber can trigger routing table manipulation in the 5G core network.",
    )
    assert signals.matched


def test_gate_keeps_sip_vulnerability():
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-57193: Asterisk SIP LDAP injection",
        "Asterisk is an open source private branch exchange and telephony toolkit. "
        "The LDAP realtime driver may permit LDAP filter injection through a SIP "
        "username, allowing an unauthenticated attacker to read configuration.",
    )
    assert signals.matched


def test_gate_keeps_ims_signaling_security():
    gate = TelecomGate()
    signals = gate.evaluate(
        "IMS Signaling Security in 5G",
        "This paper analyzes IMS registration attacks against the P-CSCF and "
        "proposes mutual authentication improvements for VoLTE subscribers.",
    )
    assert signals.matched


def test_gate_keeps_gtpc_tunnel_attack():
    gate = TelecomGate()
    signals = gate.evaluate(
        "GTP-C Tunnel Manipulation in Mobile Networks",
        "We demonstrate how an attacker positioned in the roaming path can modify "
        "GTP-C messages to redirect subscriber traffic through a rogue serving node.",
    )
    assert signals.matched


# ---------------------------------------------------------------------------
# 应当剔除的内容
# ---------------------------------------------------------------------------


def test_gate_rejects_linux_kernel_cve():
    """Linux 内核通用漏洞与信令安全无关。"""
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-98942: Linux kernel sched_ext cid tables",
        "In the Linux kernel, the following vulnerability has been resolved: "
        "sched_ext: Build the cid tables privately and publish them with RCU. "
        "A local attacker could trigger a use-after-free.",
    )
    assert not signals.matched
    # 未出现任何电信领域实体，或被通用领域排除规则命中
    assert signals.rejected_by or "电信领域实体" in signals.reason


def test_gate_rejects_bluetooth_vulnerability():
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-81039: Bluetooth host bt_conn out-of-bounds",
        "The Bluetooth host pre-allocates a bt_conn object from a fixed pool for "
        "every connectable advertising set. An attacker can trigger an "
        "out-of-bounds write.",
    )
    assert not signals.matched


def test_gate_rejects_wordpress_plugin():
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-113493: GeoDirectory WordPress plugin XSS",
        "A stored cross-site scripting vulnerability exists in the contact detail "
        "view of a WordPress plugin before 2.x. The map field is rendered without "
        "escaping.",
    )
    assert not signals.matched


def test_gate_rejects_generic_xss():
    gate = TelecomGate()
    signals = gate.evaluate(
        "CVE-2026-114703: Improper Neutralization of Input During Web Page Generation",
        "A stored cross-site scripting vulnerability allows an attacker to inject "
        "arbitrary JavaScript into a web application.",
    )
    assert not signals.matched


def test_gate_rejects_material_science_diameter():
    """化学论文里的 Diameter 与信令无关。"""
    gate = TelecomGate()
    signals = gate.evaluate(
        "Diameter Control of Core/Shell Nanorods for Tunable Band Gaps",
        "We synthesize nanorods and control their diameter to tune optical band "
        "gaps. The core-shell structure is characterized by electron microscopy.",
    )
    assert not signals.matched


def test_gate_rejects_biology_map():
    gate = TelecomGate()
    signals = gate.evaluate(
        "The core interaction network of transcription elongation factors",
        "We map protein interactions using yeast two-hybrid. The MAP pathway is "
        "central to the observed regulatory network.",
    )
    assert not signals.matched


def test_gate_rejects_generic_intrusion_detection():
    gate = TelecomGate()
    signals = gate.evaluate(
        "Intrusion Detection Methods for Enterprise Networks",
        "A survey of machine learning based intrusion detection systems for "
        "general enterprise networks, with experiments on the NSL-KDD dataset.",
    )
    assert not signals.matched


def test_gate_rejects_quantum_paper():
    gate = TelecomGate()
    signals = gate.evaluate(
        "Quantum Error Correction on Superconducting Qubits",
        "We study logical qubit lifetimes and error correction codes in a "
        "superconducting processor.",
    )
    assert not signals.matched


# ---------------------------------------------------------------------------
# 批量过滤
# ---------------------------------------------------------------------------


def test_gate_filter_splits_kept_and_dropped():
    gate = TelecomGate()
    keep = _item(
        title="SS7 Attack Analysis",
        abstract="We analyze SS7 message injection against the HLR in the mobile core network.",
    )
    drop = _item(
        title="CVE-2026-98942: Linux kernel sched_ext",
        abstract="In the Linux kernel, the following vulnerability has been resolved.",
    )
    kept, dropped = gate.filter([keep, drop])
    assert len(kept) == 1
    assert len(dropped) == 1
    assert kept[0] is keep
    assert dropped[0] is drop


def test_gate_records_reject_reason():
    gate = TelecomGate()
    item = _item(
        title="Generic Web Vulnerability",
        abstract="A cross-site scripting vulnerability in a PHP application.",
    )
    _, dropped = gate.filter([item])
    assert dropped[0].telecom_reject_reason


def test_gate_can_disable_non_telecom_exclusion():
    gate = TelecomGate(exclude_non_telecom=False)
    signals = gate.evaluate(
        "CVE-2026-98942: Linux kernel sched_ext",
        "In the Linux kernel, a use-after-free was fixed in the CID table code.",
    )
    # 关闭排除后，仍因缺少电信实体而被拒
    assert not signals.matched
    assert signals.rejected_by is None


def test_gate_context_requirement():
    """只出现电信名词但完全没有协议行为语义的，应被拒。"""
    gate = TelecomGate()
    signals = gate.evaluate(
        "A Survey of 5G Core Deployments",
        "We survey the current state of 5G core deployments across operators and "
        "report on the number of base stations per country.",
    )
    assert not signals.matched
