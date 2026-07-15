from scapy.layers.inet import IP, TCP, UDP


def get_flow_key(packet):
    """
    Create a bidirectional unique key for every network flow.

    Forward and backward packets of the same connection
    generate the same flow key.
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

    endpoint_1 = (src_ip, src_port)
    endpoint_2 = (dst_ip, dst_port)

    if endpoint_1 <= endpoint_2:
        return (
            endpoint_1,
            endpoint_2,
            protocol,
        )

    return (
        endpoint_2,
        endpoint_1,
        protocol,
    )