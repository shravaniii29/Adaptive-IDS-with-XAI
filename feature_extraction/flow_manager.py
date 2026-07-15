import time

from scapy.layers.inet import IP

from feature_extraction.flow import Flow
from feature_extraction.flow_builder import get_flow_key


class FlowManager:

    def __init__(self, flow_timeout=5):

        self.active_flows = {}

        self.flow_timeout = flow_timeout

    def process_packet(self, packet):

        key = get_flow_key(packet)

        if key is None:
            return None

        if key not in self.active_flows:

            self.active_flows[key] = Flow(
                src_ip=packet[IP].src,
                dst_ip=packet[IP].dst,
            )

        self.active_flows[key].add_packet(packet)

        return key

    def get_expired_flows(self):

        current_time = time.time()

        expired_flows = []

        for key, flow in list(
            self.active_flows.items()
        ):

            if flow.end_time is None:
                continue

            inactive_time = (
                current_time - flow.end_time
            )

            if inactive_time >= self.flow_timeout:

                expired_flows.append(
                    (key, flow)
                )

                del self.active_flows[key]

        return expired_flows

    def flush_all_flows(self):

        completed_flows = list(
            self.active_flows.items()
        )

        self.active_flows.clear()

        return completed_flows