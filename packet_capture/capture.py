from scapy.all import sniff

def start_capture(callback, packet_count=0):
    """
    Starts packet capture.

    callback      : Function to process each packet
    packet_count  : Number of packets to capture
                    0 = infinite capture
    """

    sniff(
        prn=callback,
        count=packet_count,
        store=False
    )