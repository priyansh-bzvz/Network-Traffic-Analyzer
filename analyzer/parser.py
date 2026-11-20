"""Convert Scapy packets into small summaries without storing payload data."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


@dataclass(frozen=True)
class PacketSummary:
    """Metadata kept for one packet; payload contents are deliberately omitted."""

    timestamp: str
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    source_port: int | None
    destination_port: int | None
    packet_length: int

    def to_dict(self) -> dict[str, object]:
        """Return a plain dictionary that is easy to display or send as JSON."""
        return asdict(self)


def parse_packet(packet: Packet) -> PacketSummary:
    """Extract timestamp, addresses, protocol, ports, and length from a packet."""
    source_ip = None
    destination_ip = None

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

    source_port = None
    destination_port = None
    if packet.haslayer(TCP):
        transport_layer = packet[TCP]
        protocol = "TCP"
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)
    elif packet.haslayer(UDP):
        transport_layer = packet[UDP]
        protocol = "UDP"
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)
    elif packet.haslayer(ICMP) or any(
        layer.__name__.startswith("ICMPv6")
        and not layer.__name__.startswith("ICMPv6NDOpt")
        for layer in packet.layers()
    ):
        protocol = "ICMP"
    else:
        protocol = "Other"

    packet_time = getattr(packet, "time", None)
    if packet_time is None:
        timestamp = datetime.now(timezone.utc)
    else:
        timestamp = datetime.fromtimestamp(float(packet_time), timezone.utc)

    return PacketSummary(
        timestamp=timestamp.isoformat(timespec="milliseconds"),
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_length=len(packet),
    )

