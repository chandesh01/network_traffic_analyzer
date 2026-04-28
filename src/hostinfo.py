import socket
import uuid


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unknown"


def get_mac():
    mac = uuid.getnode()
    return ':'.join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))