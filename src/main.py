import time
import argparse
import threading

from analyzer import Analyzer
from sniffer import start_sniffing
from logger import Logger
from hostinfo import get_local_ip, get_mac

logger = Logger()
local_ip = get_local_ip()
mac = get_mac()
seen = set()

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=str, help="tcp/udp/icmp")
    parser.add_argument("--port", type=int, help="port number")
    return parser.parse_args()

def format_packet(p):
    sport = p["sport"] if p["sport"] else "-"
    dport = p["dport"] if p["dport"] else "-"

    # Only real HTTP requests
    if p["service"] == "HTTP" and p["method"]:
        host = p["host"] if p["host"] else p["dst"]
        return f"[HTTP ] {p['src']} → {host} ({p['method']})"

    # fallback (non-HTTP payload)
    return f"[{p['protocol']:<5}] {p['src']}:{sport} → {p['dst']}:{dport}"

def display(analyzer):
    while True:
        stats = analyzer.get_stats()

        print("\033c", end="")  # clear screen

        print("====== NetScope ======\n")



        print(f"Packets/sec: {stats['rate']}\n")
        print(f"TCP: {stats['tcp']}   UDP: {stats['udp']}   ICMP: {stats['icmp']}")
        print(f"HTTP: {stats['http']}   HTTPS: {stats['https']}   QUIC: {stats['quic']}   DNS: {stats['dns']}\n")

        print("====== HOST INFO ======\n")

        print(f"Local IP: {local_ip}")
        print(f"MAC: {mac}")
        print(f"Active Connections: {stats['connections']}")
        print(f"Unique Peers: {stats['peers']}\n")

        print("Top Destinations:")
        for ip, count in stats["top_dest"]:
            print(f"{ip} → {count} packets")

        print("\nTop Sources:")
        for ip, count in stats["top"]:
            print(f"{ip} → {count} packets\n")

        print("Recent Packets:")
        for p in stats["recent"]:
            line = format_packet(p)
            print(line)
            if line not in seen:
                logger.log(line)
                seen.add(line)

        time.sleep(1)

if __name__ == "__main__":
    args = get_args()

    analyzer = Analyzer(
        protocol_filter=args.protocol,
        port_filter=args.port,
        local_ip=local_ip
    )

    # pass analyzer into sniffer
    t = threading.Thread(
        target=start_sniffing,
        args=(analyzer,),
        daemon=True
    )
    t.start()

    display(analyzer)