"""Terminal demo for packet parsing, statistics, and optional live capture."""

import argparse
import time

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether

from analyzer.capture import CaptureController
from analyzer.parser import parse_packet
from analyzer.statistics import PacketStatistics


def show_snapshot(statistics: PacketStatistics) -> None:
    """Print packet counts and recent metadata in a readable form."""
    snapshot = statistics.snapshot()
    print(f"\nTotal packets: {snapshot.total_packets}")
    print("Protocol counts:")
    for protocol, count in snapshot.protocol_counts.items():
        print(f"  {protocol}: {count}")
    print("Recent packet summaries:")
    for packet in snapshot.recent_packets:
        print(f"  {packet}")


def demo_parsing() -> None:
    """Parse a few locally constructed example packets (no network capture)."""
    statistics = PacketStatistics(recent_limit=3)
    examples = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=51515, dport=80),
        Ether() / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(sport=53000, dport=53),
        Ether() / IP(src="192.0.2.10", dst="198.51.100.30") / ICMP(),
        Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20")
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / ICMPv6EchoRequest(),
        Ether() / ARP(psrc="192.0.2.10", pdst="192.0.2.1"),
    ]

    for packet in examples:
        summary = parse_packet(packet)
        statistics.record(summary)
        print(summary.to_dict())

    show_snapshot(statistics)


def demo_live_capture(interface: str | None, seconds: int) -> None:
    """Capture passively for a short period, then display the resulting counts."""
    statistics = PacketStatistics(recent_limit=20)
    capture = CaptureController(statistics, interface=interface)
    try:
        capture.start()
        print(f"Capturing passively for {seconds} seconds. Press Ctrl+C to stop early.")
        time.sleep(seconds)
    except KeyboardInterrupt:
        print("Stopping capture...")
    finally:
        capture.stop()
    show_snapshot(statistics)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="capture live traffic instead of using example packets",
    )
    parser.add_argument(
        "--interface",
        help="Scapy interface name for live capture; omit to use Scapy's default",
    )
    parser.add_argument(
        "--seconds",
        type=int,
        default=5,
        help="live capture duration in seconds (default: 5)",
    )
    args = parser.parse_args()

    if args.seconds < 1:
        parser.error("--seconds must be at least 1")
    if args.live:
        demo_live_capture(args.interface, args.seconds)
    else:
        demo_parsing()


if __name__ == "__main__":
    main()
