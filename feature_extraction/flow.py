class Flow:

    def __init__(self):

        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None

    def add_packet(self, packet):

        self.packet_count += 1
        self.total_bytes += len(packet)

        if self.start_time is None:
            self.start_time = packet.time

        self.end_time = packet.time

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

        return self.total_bytes / self.duration if self.duration else 0