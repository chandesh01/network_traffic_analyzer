from scapy.all import sniff
from parser import parse_packet

def start_sniffing(analyzer):
    def packet_callback(packet):
        parsed = parse_packet(packet)
        if parsed:
            analyzer.process(parsed)

    sniff(prn=packet_callback, store=False)