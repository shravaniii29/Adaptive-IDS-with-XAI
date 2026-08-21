import threading
import time

from scapy.layers.inet import IP, TCP, UDP

from feature_extraction.flow import Flow
from feature_extraction.flow_builder import get_flow_key


def _first_packet_dst_port(packet):
    """dst_port of the packet that started this flow (0 for non-TCP/UDP),
    matching how src_ip already defines "forward" for the flow. Not part
    of get_flow_key's own return value since that key sorts endpoints and
    so doesn't preserve which side is actually the destination."""

    if TCP in packet:
        return packet[TCP].dport

    if UDP in packet:
        return packet[UDP].dport

    return 0


class FlowManager:

    def __init__(self, flow_timeout=5, active_timeout=20):

        self.active_flows = {}

        # active_flows is written by the capture thread (process_packet)
        # and read/mutated by the expiry-worker thread (get_expired_flows)
        # concurrently - guard every access with this lock.
        self._lock = threading.Lock()

        # Idle timeout: flush a flow once no new packets
        # have arrived for this many seconds.
        self.flow_timeout = flow_timeout

        # Active timeout: flush a flow after it has been
        # running for this long even if it is still receiving
        # packets. Without this, a continuous flood (e.g. a
        # sustained ping flood) never goes idle and would
        # never be handed to the detector.
        self.active_timeout = active_timeout

    def process_packet(self, packet):

        key = get_flow_key(packet)

        if key is None:
            return None

        with self._lock:

            if key not in self.active_flows:

                self.active_flows[key] = Flow(
                    src_ip=packet[IP].src,
                    dst_ip=packet[IP].dst,
                    protocol=packet[IP].proto,
                    dst_port=_first_packet_dst_port(packet),
                )

            self.active_flows[key].add_packet(packet)

        return key

    def get_expired_flows(self):

        current_time = time.time()

        expired_flows = []

        with self._lock:

            for key, flow in list(
                self.active_flows.items()
            ):

                if flow.end_time is None:
                    continue

                inactive_time = (
                    current_time - flow.end_time
                )

                active_time = (
                    current_time - flow.start_time
                )

                if (
                    inactive_time >= self.flow_timeout
                    or active_time >= self.active_timeout
                ):

                    expired_flows.append(
                        (key, flow)
                    )

                    del self.active_flows[key]

        return expired_flows

    def flush_all_flows(self):

        with self._lock:

            completed_flows = list(
                self.active_flows.items()
            )

            self.active_flows.clear()

        return completed_flows