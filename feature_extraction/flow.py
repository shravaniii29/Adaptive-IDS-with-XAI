from scapy.layers.inet import IP, TCP


class Flow:

    def __init__(self, src_ip=None, dst_ip=None):

        # Flow identity
        self.src_ip = src_ip
        self.dst_ip = dst_ip

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

                header_length = ip_header_length * 4

                if TCP in packet:

                    tcp_header_length = packet[TCP].dataofs

                    if tcp_header_length is None:
                        tcp_header_length = 5

                    header_length += tcp_header_length * 4

                self.forward_header_lengths.append(header_length)

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

        if self.start_time is None:
            return 0

        return self.end_time - self.start_time

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