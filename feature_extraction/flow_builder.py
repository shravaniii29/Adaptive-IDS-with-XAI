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


def get_packet_ports(packet):
    """
    Return the (src_port, dst_port) of THIS packet, in its own
    original (non-canonicalized) direction.

    Unlike get_flow_key(), this does NOT reorder endpoints, so it
    is safe to use to capture the flow-initiating packet's
    destination port (CIC-IDS2018 "Dst Port"), without affecting
    flow-key identity/matching behavior in any way.

    Returns (0, 0) for non-TCP/UDP IP traffic, matching the
    existing zero-port convention used in get_flow_key().
    """

    if IP not in packet:
        return (0, 0)

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return (src_port, dst_port)
