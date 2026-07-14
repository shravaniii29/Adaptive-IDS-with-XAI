from scapy.layers.inet import IP, TCP

from feature_extraction.flow_builder import (
    get_flow_key,
    add_packet_to_flow,
    flows
)


packet_1 = (
    IP(src="192.168.1.10", dst="8.8.8.8")
    / TCP(sport=50000, dport=443)
)


packet_2 = (
    IP(src="8.8.8.8", dst="192.168.1.10")
    / TCP(sport=443, dport=50000)
)


key_1 = get_flow_key(packet_1)
key_2 = get_flow_key(packet_2)


print("Forward Key:")
print(key_1)

print()

print("Backward Key:")
print(key_2)

print()

print("Same Flow:", key_1 == key_2)


add_packet_to_flow(packet_1)
add_packet_to_flow(packet_2)


flow = flows[key_1]


print()
print("FINAL FLOW STATISTICS")
print("---------------------")

print("Total Packets:", flow.packet_count)
print("Forward Packets:", len(flow.forward_packet_lengths))
print("Backward Packets:", len(flow.backward_packet_lengths))