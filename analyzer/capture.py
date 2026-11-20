"""Start and stop passive Scapy packet capture in a background thread."""

from threading import Lock

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from analyzer.parser import parse_packet
from analyzer.statistics import PacketStatistics


class CaptureController:
    """Manage a passive capture on an optional Scapy interface name."""

    def __init__(
        self,
        statistics: PacketStatistics,
        interface: str | None = None,
    ) -> None:
        self.statistics = statistics
        self.interface = interface
        self._lock = Lock()
        self._sniffer: AsyncSniffer | None = None

    def _handle_packet(self, packet: Packet) -> None:
        """Parse each captured packet and retain only its metadata summary."""
        self.statistics.record(parse_packet(packet))

    @property
    def is_running(self) -> bool:
        """Whether the Scapy capture thread is currently running."""
        with self._lock:
            return self._sniffer is not None and self._sniffer.running

    def start(self) -> None:
        """Begin passive capture; Scapy chooses its default interface if unset."""
        with self._lock:
            if self._sniffer is not None and self._sniffer.running:
                raise RuntimeError("Packet capture is already running")

            sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
            )
            sniffer.start()
            self._sniffer = sniffer

    def stop(self) -> None:
        """Stop capture and wait for Scapy's background thread to finish."""
        with self._lock:
            if self._sniffer is None or not self._sniffer.running:
                return
            self._sniffer.stop()

