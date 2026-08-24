from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, Loopback


class Flow:

    def __init__(self, src_ip=None, dst_ip=None, protocol=None, dst_port=None):

        # Flow identity
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        # IP protocol number (6=TCP, 17=UDP, 1=ICMP, ...) and destination
        # port of the flow, taken from the first packet. Used by the
        # experimental-models rolling history, which groups by
        # (Dst Port, Protocol) - not used by the deployed 25-feature model.
        self.protocol = protocol
        self.dst_port = dst_port

        # Basic statistics
        self.packet_count = 0
        self.total_bytes = 0

        # Time information
        self.start_time = None
        self.end_time = None

        # All packet information
        self.packet_lengths = []
        self.packet_timestamps = []

        # Forward direction
        self.forward_packet_lengths = []
        self.forward_timestamps = []
        self.forward_header_lengths = []

        # Forward PAYLOAD lengths (frame length minus IP/TCP/UDP headers).
        # This is what CICFlowMeter's "Fwd Pkt Len Min" etc. actually
        # measure - distinct from forward_packet_lengths above, which is
        # full frame length and was previously (incorrectly) reused for
        # the experimental models' "Min Pkt Size" feature.
        self.forward_payload_lengths = []

        # Backward direction
        self.backward_packet_lengths = []
        self.backward_timestamps = []

        # Initial backward TCP window
        self.init_bwd_window_bytes = None

    def add_packet(self, packet):

        packet_length = len(packet)
        timestamp = float(packet.time)

        # Basic statistics
        self.packet_count += 1
        self.total_bytes += packet_length

        # Flow timing
        if self.start_time is None:
            self.start_time = timestamp

        self.end_time = timestamp

        # Store overall packet data
        self.packet_lengths.append(packet_length)
        self.packet_timestamps.append(timestamp)

        # Direction detection
        if IP in packet:

            if packet[IP].src == self.src_ip:

                # Forward packet
                self.forward_packet_lengths.append(packet_length)
                self.forward_timestamps.append(timestamp)

                ip_header_length = packet[IP].ihl

                if ip_header_length is None:
                    ip_header_length = 5

                # L2 framing varies by capture medium and was previously
                # never subtracted at all: Loopback-captured packets carry
                # a 4-byte DLT_NULL header instead of Ethernet's 14 bytes
                # (no Ether layer present), so the two capture paths leaked
                # a different number of framing bytes into "payload length"
                # - a capture-medium-dependent skew in Min Pkt Size, the
                # single highest-importance feature in variant 1.
                if Loopback in packet:
                    l2_header_length = 4
                elif Ether in packet:
                    l2_header_length = 14
                else:
                    l2_header_length = 0

                header_length = l2_header_length + ip_header_length * 4

                if TCP in packet:

                    tcp_header_length = packet[TCP].dataofs

                    if tcp_header_length is None:
                        tcp_header_length = 5

                    header_length += tcp_header_length * 4

                elif UDP in packet:

                    header_length += 8

                self.forward_header_lengths.append(header_length)

                payload_length = max(0, packet_length - header_length)

                self.forward_payload_lengths.append(payload_length)

            else:

                # Backward packet
                self.backward_packet_lengths.append(packet_length)
                self.backward_timestamps.append(timestamp)

                # Save first backward TCP window
                if (
                    self.init_bwd_window_bytes is None
                    and TCP in packet
                ):
                    self.init_bwd_window_bytes = packet[TCP].window

    @property
    def duration(self):
        if self.start_time is None or self.end_time is None:
         return 0.0

        return max(0.0, self.end_time - self.start_time)

    @property
    def bytes_per_second(self):

        if self.duration == 0:
            return 0

        return self.total_bytes / self.duration

    @property
    def packets_per_second(self):

        if self.duration == 0:
            return 0

        return self.packet_count / self.duration