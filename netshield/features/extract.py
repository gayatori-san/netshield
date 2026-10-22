"""Flow aggregation primitives."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from netshield.models import PacketRecord


@dataclass(frozen=True, slots=True)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str


def flow_key_from(pkt: PacketRecord) -> FlowKey:
    return FlowKey(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)


@dataclass
class FlowState:
    key: FlowKey
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    syn: int = 0
    syn_ack: int = 0
    rst: int = 0
    fin: int = 0

    def to_dict(self) -> dict:
        return {
            "src_ip": self.key.src_ip,
            "dst_ip": self.key.dst_ip,
            "src_port": self.key.src_port,
            "dst_port": self.key.dst_port,
            "protocol": self.key.protocol,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class FlowExtractor:
    """Bounded LRU flow table.

    Bounded on purpose: an attacker sending spoofed source addresses can
    otherwise grow the table without limit (a memory-exhaustion vector on the
    monitoring host itself).
    """

    STATE_FIELDS = {
        "SYN": "syn",
        "SYN_ACK": "syn_ack",
        "RST": "rst",
        "FIN": "fin",
    }

    def __init__(self, max_flows: int = 20000, idle_seconds: int = 300):
        self.max_flows = max_flows
        self.idle_seconds = idle_seconds
        self._flows: OrderedDict[FlowKey, FlowState] = OrderedDict()

    def observe(self, pkt: PacketRecord) -> FlowState:
        key = flow_key_from(pkt)
        state = self._flows.get(key)
        if state is None:
            state = FlowState(key=key, first_seen=pkt.timestamp, last_seen=pkt.timestamp)
            self._flows[key] = state
            if len(self._flows) > self.max_flows:
                self._flows.popitem(last=False)
        else:
            self._flows.move_to_end(key)

        state.packets += 1
        state.bytes += pkt.size
        state.last_seen = pkt.timestamp
        attr = self.STATE_FIELDS.get(pkt.tcp_state or "")
        if attr:
            setattr(state, attr, getattr(state, attr) + 1)

        return state

    def evict_idle(self, now: float) -> int:
        cutoff = now - self.idle_seconds
        removed = 0
        for key in [k for k, s in self._flows.items() if s.last_seen < cutoff]:
            self._flows.pop(key, None)
            removed += 1
        return removed

    def active_count(self) -> int:
        return len(self._flows)

    def recent(self, limit: int = 100) -> list[dict]:
        items = list(self._flows.values())[-limit:]
        return [state.to_dict() for state in reversed(items)]
