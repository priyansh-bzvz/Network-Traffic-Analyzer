"""Thread-safe protocol counters and a bounded buffer of packet summaries."""

from collections import Counter, deque
from dataclasses import dataclass
from threading import Lock

from analyzer.parser import PacketSummary


@dataclass(frozen=True)
class StatisticsSnapshot:
    """A consistent copy of current counts and recent packet metadata."""

    total_packets: int
    protocol_counts: dict[str, int]
    recent_packets: list[dict[str, object]]
    report_packets: list[dict[str, object]]
    report_packets_omitted: int


class PacketStatistics:
    """Keep counts and only the most recent summaries, protected by a lock."""

    PROTOCOLS = ("TCP", "UDP", "ICMP", "Other")

    def __init__(self, recent_limit: int = 100, report_limit: int = 10_000) -> None:
        if recent_limit < 1 or report_limit < 1:
            raise ValueError("recent_limit and report_limit must be at least 1")

        self._lock = Lock()
        self._counts: Counter[str] = Counter({name: 0 for name in self.PROTOCOLS})
        self._recent_packets: deque[PacketSummary] = deque(maxlen=recent_limit)
        self._report_packets: deque[PacketSummary] = deque(maxlen=report_limit)
        self._total_packets = 0

    def record(self, summary: PacketSummary) -> None:
        """Count one packet and add its metadata to the bounded recent buffer."""
        protocol = summary.protocol if summary.protocol in self.PROTOCOLS else "Other"
        with self._lock:
            self._total_packets += 1
            self._counts[protocol] += 1
            self._recent_packets.append(summary)
            self._report_packets.append(summary)

    def reset(self) -> None:
        """Clear all counters and bounded packet-summary buffers."""
        with self._lock:
            self._total_packets = 0
            self._counts = Counter({name: 0 for name in self.PROTOCOLS})
            self._recent_packets.clear()
            self._report_packets.clear()

    def snapshot(self) -> StatisticsSnapshot:
        """Return copies of the counts and recent summaries under one lock."""
        with self._lock:
            return StatisticsSnapshot(
                total_packets=self._total_packets,
                protocol_counts={name: self._counts[name] for name in self.PROTOCOLS},
                recent_packets=[item.to_dict() for item in self._recent_packets],
                report_packets=[item.to_dict() for item in self._report_packets],
                report_packets_omitted=max(0, self._total_packets - len(self._report_packets)),
            )

