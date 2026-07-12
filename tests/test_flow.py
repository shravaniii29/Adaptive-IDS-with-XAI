from feature_extraction.flow import Flow

class DummyPacket:
    def __init__(self, size, timestamp):
        self._size = size
        self.time = timestamp

    def __len__(self):
        return self._size


flow = Flow()

flow.add_packet(DummyPacket(100, 1.0))
flow.add_packet(DummyPacket(200, 2.5))
flow.add_packet(DummyPacket(150, 4.0))

print("Packets:", flow.packet_count)
print("Bytes:", flow.total_bytes)
print("Duration:", flow.duration)
print("Packets/sec:", flow.packets_per_second)
print("Bytes/sec:", flow.bytes_per_second)