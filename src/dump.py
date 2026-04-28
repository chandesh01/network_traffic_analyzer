import argparse
from scapy.all import sniff
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="source IP")
    parser.add_argument("--dst", required=True, help="destination IP")
    return parser.parse_args()


def hexdump(data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{i:04x}  {hex_part:<48}  {ascii_part}")


def packet_callback(packet, src_filter, dst_filter):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    # Match both directions
    if not (
        (ip.src == src_filter and ip.dst == dst_filter) or
        (ip.src == dst_filter and ip.dst == src_filter)
    ):
        return

    if not packet.haslayer(Raw):
        return

    data = packet[Raw].load

    # Skip tiny/noise packets
    if len(data) < 20:
        return

    #  Direction
    direction = "OUT" if ip.src == src_filter else "IN"

    # Protocol detection
    protocol = "TCP/Other"
    if packet.haslayer(UDP):
        if packet[UDP].sport == 443 or packet[UDP].dport == 443:
            protocol = "QUIC"
        else:
            protocol = "UDP"
    else:
        protocol = "TCP"

    print("\n====== PAYLOAD DUMP ======")
    print(f"Flow: {src_filter} ↔ {dst_filter}")
    print(f"[{direction}] {ip.src} → {ip.dst}")
    print(f"Protocol: {protocol}")
    print(f"Size: {len(data)} bytes\n")

    hexdump(data[:128])


def start_dump(src, dst):
    sniff(
        prn=lambda pkt: packet_callback(pkt, src, dst),
        store=False
    )


if __name__ == "__main__":
    args = get_args()
    print(f"Starting dump for {args.src} ↔ {args.dst}...\n")
    start_dump(args.src, args.dst)