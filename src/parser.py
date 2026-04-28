from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


def detect_service(protocol, sport, dport):
    ports = {sport, dport}

    if 80 in ports:
        return "HTTP"
    elif 443 in ports:
        if protocol == "UDP":
            return "QUIC"
        return "HTTPS"
    elif 53 in ports:
        return "DNS"
    else:
        return protocol


def extract_http_info(packet):
    if not packet.haslayer(Raw):
        return None, None

    try:
        payload = packet[Raw].load.decode(errors="ignore")

        lines = payload.split("\r\n")

        if len(lines) > 0:
            first_line = lines[0]

            # Detect GET / POST
            if first_line.startswith("GET") or first_line.startswith("POST"):
                method = first_line.split()[0]

                host = None
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break

                return method, host

    except:
        pass

    return None, None


def parse_packet(packet):
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    src = ip_layer.src
    dst = ip_layer.dst

    protocol = None
    sport = None
    dport = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    service = detect_service(protocol, sport, dport)

    method, host = None, None

    if service == "HTTP":
        method, host = extract_http_info(packet)

    return {
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "sport": sport,
        "dport": dport,
        "service": service,
        "method": method,
        "host": host
    }