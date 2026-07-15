import time

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from feature_extraction.flow_manager import FlowManager


manager = FlowManager(
    flow_timeout=2
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
    / Raw(
        load="Hello"
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
    / Raw(
        load="Response"
    )
)


print("\nAdding first packet...")

key_1 = manager.process_packet(
    packet_1
)


print(
    "Active flows:",
    len(manager.active_flows),
)


print("\nAdding backward packet...")

key_2 = manager.process_packet(
    packet_2
)


print(
    "Active flows:",
    len(manager.active_flows),
)


assert key_1 == key_2

assert len(
    manager.active_flows
) == 1


flow = manager.active_flows[key_1]


assert flow.packet_count == 2

assert len(
    flow.forward_packet_lengths
) == 1

assert len(
    flow.backward_packet_lengths
) == 1


print("\nBidirectional flow test passed.")


print("\nWaiting for flow timeout...")

time.sleep(3)


expired_flows = (
    manager.get_expired_flows()
)


assert len(
    expired_flows
) == 1


assert len(
    manager.active_flows
) == 0


expired_key, expired_flow = (
    expired_flows[0]
)


assert expired_key == key_1

assert expired_flow.packet_count == 2


print(
    "Expired flow packets:",
    expired_flow.packet_count,
)


print("\nChecking duplicate expiration...")

expired_again = (
    manager.get_expired_flows()
)


assert len(
    expired_again
) == 0


print(
    "Flow returned exactly once."
)


print(
    "\nFLOW MANAGER TEST PASSED"
)