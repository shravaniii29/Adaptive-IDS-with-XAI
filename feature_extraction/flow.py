from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether, Loopback


class Flow:

    # ICMP types that are REPLIES (vs. requests). No port field exists to
    # disambiguate ICMP direction the way TCP/UDP src_port does below, so
    # direction is inferred from type instead.
    _ICMP_REPLY_TYPES = {0, 14, 16, 18}

    def __init__(self, src_ip=None, dst_ip=None, protocol=None, dst_port=None, src_port=None):

        # Flow identity
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        # Source port of the packet that opened this flow. Needed (see
        # _is_forward_packet) to tell direction apart for self-targeted
        # traffic, where src_ip == dst_ip on every packet in both
        # directions - None (the default for callers that construct a
        # Flow directly, e.g. tests, rather than via FlowManager) falls
        # back to the old IP-only comparison.
        self.src_port = src_port

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

    def _is_forward_packet(self, packet):
        """True if `packet` travels in the same direction as the packet
        that opened this flow.

        IP address alone can't tell direction apart for self-targeted
        traffic (this project's live testing always targets 127.0.0.1 -
        see RUNNING.md) - src_ip == dst_ip on EVERY packet in both
        directions there, so `packet[IP].src == self.src_ip` used to be
        true unconditionally, misclassifying 100% of packets (including
        every real backward reply) as forward. Confirmed by diffing this
        project's extractor against the real cicflowmeter library on an
        identical captured pcap: 7,520 fwd / 0 bwd here vs. the correct
        3,761 fwd / 3,760 bwd there, for the same SYN-flood flow. Fixed
        by keying TCP/UDP direction on (src_ip, src_port) of the
        initiating packet, not IP alone - src_port disambiguates even
        when both endpoints share an IP, and is a no-op improvement when
        they don't. Falls back to the old IP-only check when this Flow
        was constructed without src_port (e.g. tests that build one
        directly rather than via FlowManager).

        ICMP has no port to key on, so direction is inferred from type
        instead: request types (echo/timestamp/info/mask request) are
        forward, their reply counterparts are backward.
        """

        if ICMP in packet:
            return packet[ICMP].type not in self._ICMP_REPLY_TYPES

        if self.src_port is not None:

            if TCP in packet:
                return (
                    packet[IP].src == self.src_ip
                    and packet[TCP].sport == self.src_port
                )

            if UDP in packet:
                return (
                    packet[IP].src == self.src_ip
                    and packet[UDP].sport == self.src_port
                )

        return packet[IP].src == self.src_ip

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

            if self._is_forward_packet(packet):

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

                # L4 (TCP/UDP/ICMP) header size alone - this is what
                # CICFlowMeter's own "Fwd Header Len" feature measures
                # (confirmed against the real cicflowmeter library on
                # captured HTTP-flood-shaped traffic: it reports a flat
                # 20 bytes/fwd-packet - TCP header only, no IP/L2 - while
                # this project's own extractor was summing L2+IP+L4 and
                # landing at ~44-56 bytes/packet, a ~2-2.5x inflation on
                # every single flow this project has ever scored, for a
                # feature the deployed model's TOP_FEATURES actually
                # uses). Tracked separately from the L2+IP+L4 total below,
                # which payload_length still needs for Min Pkt Size.
                l4_header_length = 0

                if TCP in packet:

                    tcp_header_length = packet[TCP].dataofs

                    if tcp_header_length is None:
                        tcp_header_length = 5

                    l4_header_length = tcp_header_length * 4

                elif UDP in packet:

                    l4_header_length = 8

                elif ICMP in packet:

                    # Fixed 8-byte header (type, code, checksum, id, seq) -
                    # without this, the ICMP header itself was being counted
                    # as forward payload, inflating Min Pkt Size (the
                    # single highest-importance experimental-model feature)
                    # by a constant 8 bytes for every ICMP flow.
                    l4_header_length = 8

                self.forward_header_lengths.append(l4_header_length)

                header_length = l2_header_length + ip_header_length * 4 + l4_header_length

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