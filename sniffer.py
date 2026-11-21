
from scapy.all import (
    sniff, IP, IPv6, TCP, UDP, ICMP,
    ICMPv6EchoRequest, ICMPv6EchoReply, Raw
)

from datetime import datetime
import argparse
import csv


# Default network interface
DEFAULT_INTERFACE = "Intel(R) Wi-Fi 6 AX201 160MHz"

# CSV output file
CSV_FILE = "captured_packets.csv"

# Protocol statistics
statistics = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

# Store captured packet information
packet_records = []


def analyze_packet(packet):

    # Check for IPv4 or IPv6
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    else:
        return

    # Identify protocol
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif (
        ICMP in packet
        or ICMPv6EchoRequest in packet
        or ICMPv6EchoReply in packet
    ):
        protocol = "ICMP"
        source_port = "N/A"
        destination_port = "N/A"

    else:
        protocol = "OTHER"
        source_port = "N/A"
        destination_port = "N/A"

    # Update statistics for every captured IP packet
    statistics[protocol] += 1

    # Apply protocol filter
    if args.protocol != "ALL" and protocol != args.protocol:
        return

    # Get timestamp
    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).strftime("%Y-%m-%d %H:%M:%S")

    # Calculate payload size
    payload_size = (
        len(bytes(packet[Raw].load))
        if Raw in packet else 0
    )

    # Store packet information for CSV export
    packet_records.append({
        "Time": timestamp,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Payload Size": payload_size
    })

    # Display packet information
    print("\n" + "=" * 55)
    print("             NETWORK PACKET ANALYSIS")
    print("=" * 55)

    print("Time:              ", timestamp)
    print("Source IP:         ", source_ip)
    print("Destination IP:    ", destination_ip)
    print("Protocol:          ", protocol)
    print("Source Port:       ", source_port)
    print("Destination Port:  ", destination_port)
    print("Payload Size:      ", payload_size, "bytes")

    # Show limited payload preview if requested
    if args.show_payload and Raw in packet:
        preview = bytes(packet[Raw].load)[:32]
        print("Payload Preview:   ", preview.hex(" "))

    print("=" * 55)


def export_to_csv():

    if not packet_records:
        print("\nNo packets available to export.")
        return

    fieldnames = [
        "Time",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Payload Size"
    ]

    try:
        with open(
            CSV_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()
            writer.writerows(packet_records)

        print(f"\nPackets successfully exported to {CSV_FILE}")

    except OSError as error:
        print("\nCSV export error:", error)


def show_statistics():

    print("\n\n========== CAPTURE STATISTICS ==========")

    total = sum(statistics.values())

    for protocol, count in statistics.items():
        print(f"{protocol}: {count}")

    print("----------------------------------------")
    print("Total IP packets:", total)
    print("========================================")


def main():

    print("\n========================================")
    print("          BASIC NETWORK SNIFFER")
    print("========================================")

    print("Interface:", args.interface)
    print("Packet limit:", args.count if args.count else "Unlimited")
    print("Protocol filter:", args.protocol)

    print("Starting packet capture...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            count=args.count,
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

    except (OSError, ValueError) as error:
        print("\nCapture error:", error)

    finally:
        show_statistics()

        if args.export:
            export_to_csv()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Python Basic Network Sniffer"
    )

    parser.add_argument(
        "--interface",
        default=DEFAULT_INTERFACE,
        help="Network interface to monitor"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture. Use 0 for unlimited."
    )

    parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Show up to 32 payload bytes in hexadecimal"
    )

    parser.add_argument(
        "--protocol",
        choices=["ALL", "TCP", "UDP", "ICMP"],
        default="ALL",
        help="Filter packets by protocol"
    )

    parser.add_argument(
        "--export",
        action="store_true",
        help="Export captured packets to CSV"
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count cannot be negative")

    main()
