from capture import start_capture
from scapy.layers.inet import IP
from feature_extraction.flow_builder import add_packet_to_flow

protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def process(packet):

    if IP in packet:
        add_packet_to_flow(packet)
        protocol = protocol_map.get(packet[IP].proto, str(packet[IP].proto))

        print("=" * 60)

        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {len(packet)} bytes")
        print(f"Timestamp      : {packet.time}")

print("Listening for packets...\n")

start_capture(process, packet_count=20)