from collections import deque, defaultdict
import time
import heapq


class Analyzer:
    def __init__(self, protocol_filter=None, port_filter=None, local_ip=None):
        self.protocol_filter = protocol_filter
        self.port_filter = port_filter
        self.local_ip = local_ip

        self.ip_count = defaultdict(int)
        self.dest_count = defaultdict(int)

        self.packet_count = 0
        self.start_time = time.time()

        self.connections = set()
        self.peers = set()

        # protocol counters
        self.tcp = 0
        self.udp = 0
        self.icmp = 0

        # service counters
        self.http = 0
        self.https = 0
        self.dns = 0
        self.quic = 0

        self.recent = deque(maxlen=10)

        # cached top results (optimization)
        self.top_sources = []
        self.top_destinations = []

    # ------------------------------

    def match_filter(self, packet):
        proto = packet.get("protocol")
        sport = packet.get("sport")
        dport = packet.get("dport")

        if self.protocol_filter:
            if not proto or proto.lower() != self.protocol_filter.lower():
                return False

        if self.port_filter:
            if sport != self.port_filter and dport != self.port_filter:
                return False

        return True

    # ------------------------------

    def process(self, packet):
        if not self.match_filter(packet):
            return

        src = packet.get("src")
        dst = packet.get("dst")
        sport = packet.get("sport")
        dport = packet.get("dport")
        proto = packet.get("protocol")
        service = packet.get("service")

        if not src or not dst:
            return

        # counts
        self.ip_count[src] += 1
        self.packet_count += 1

        if self.local_ip and dst != self.local_ip:
            self.dest_count[dst] += 1

        # peers
        self.peers.add(src)
        self.peers.add(dst)

        # connections (flow-based)
        conn = tuple(sorted([
            f"{src}:{sport}",
            f"{dst}:{dport}"
        ]))
        self.connections.add(conn)

        # protocol counters
        if proto == "TCP":
            self.tcp += 1
        elif proto == "UDP":
            self.udp += 1
        elif proto == "ICMP":
            self.icmp += 1

        # service counters
        if service == "HTTP":
            self.http += 1
        elif service == "HTTPS":
            self.https += 1
        elif service == "DNS":
            self.dns += 1
        elif service == "QUIC":
            self.quic += 1

        # recent packets
        self.recent.append(packet)

        # update top (efficient for small k)
        self.top_sources = heapq.nlargest(3, self.ip_count.items(), key=lambda x: x[1])
        self.top_destinations = heapq.nlargest(3, self.dest_count.items(), key=lambda x: x[1])

    # ------------------------------

    def get_stats(self):
        elapsed = time.time() - self.start_time
        rate = self.packet_count / elapsed if elapsed > 0 else 0

        return {
            "tcp": self.tcp,
            "udp": self.udp,
            "icmp": self.icmp,
            "http": self.http,
            "https": self.https,
            "dns": self.dns,
            "quic": self.quic,

            "recent": list(self.recent),

            # use cached values (no sorting here)
            "top": self.top_sources,
            "top_dest": self.top_destinations,

            "rate": round(rate, 2),
            "connections": len(self.connections),
            "peers": len(self.peers),
        }