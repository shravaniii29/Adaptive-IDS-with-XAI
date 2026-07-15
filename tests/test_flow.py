from scapy.layers.inet import IP, TCP


from feature_extraction.flow import Flow


flow = Flow(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
)


packet_1 = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / TCP(
        sport=50000,
        dport=443,
    )
)


packet_2 = (
    IP(
        src="8.8.8.8",
        dst="192.168.1.10",
    )
    / TCP(
        sport=443,
        dport=50000,
    )
)


packet_3 = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / TCP(
        sport=50000,
        dport=443,
    )
)


packet_1.time = 1.0
packet_2.time = 2.5
packet_3.time = 4.0


flow.add_packet(packet_1)
flow.add_packet(packet_2)
flow.add_packet(packet_3)


print("Packets:", flow.packet_count)
print("Bytes:", flow.total_bytes)
print("Duration:", flow.duration)
print("Packets/sec:", flow.packets_per_second)
print("Bytes/sec:", flow.bytes_per_second)


assert flow.packet_count == 3
assert flow.duration == 3.0

assert len(
    flow.forward_packet_lengths
) == 2

assert len(
    flow.backward_packet_lengths
) == 1


print("\nFLOW TEST PASSED")