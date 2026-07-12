from feature_extraction.flow import Flow
from scapy.layers.inet import IP, TCP, UDP

flows = {}

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

    # Create a new flow if it doesn't exist
    if key not in flows:
        flows[key] = Flow()

    # Update the flow
    flows[key].add_packet(packet)

    # Display current statistics
    flow = flows[key]

    print("=" * 50)
    print("Flow Statistics")
    print(f"Packets      : {flow.packet_count}")
    print(f"Bytes        : {flow.total_bytes}")
    print(f"Duration     : {flow.duration:.6f} sec")
    print(f"Packets/sec  : {flow.packets_per_second:.2f}")
    print(f"Bytes/sec    : {flow.bytes_per_second:.2f}")