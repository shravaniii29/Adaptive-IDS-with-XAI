from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP

flows = defaultdict(list)

def get_flow_key(packet):
    """
    Create a unique key for every network flow.
    """

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )
    
def add_packet_to_flow(packet):

    key = get_flow_key(packet)

    if key is None:
        return

    flows[key].append(packet)

    print(f"Flow Packets : {len(flows[key])}")