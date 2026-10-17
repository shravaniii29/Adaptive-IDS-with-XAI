import socket
import threading

from scapy.all import sniff


def _local_lan_ip():
    """This machine's real LAN IP - the UDP-connect trick doesn't send
    any packets, it just asks the OS routing table which local address
    would be used to reach an external host."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def has_npcap_loopback():
    """True if scapy can sniff on Npcap's loopback capture path.

    Npcap has supported loopback capture without any installer option
    since 0.9983 (years before any version in current use) - it exposes
    a fixed device, `\\Device\\NPF_Loopback`, that Windows' own loopback
    pseudo-interface gets remapped to inside scapy (see
    scapy.arch.windows.NPCAP_LOOPBACK_NAME). There is no "Npcap Loopback
    Adapter" checkbox to look for on a modern install - that name only
    ever applied to the pre-0.9983 legacy KM-TEST-style adapter, which
    a fresh 1.x install has no reason to create. Confirmed working here
    by an actual sniff+send round-trip on `\\Device\\NPF_Loopback`.

    Plain Windows loopback (127.0.0.1, self-addressed traffic) is NOT
    reliably captured on any *physical* adapter - Windows short-circuits
    it before it reaches a NIC driver. This loopback device is the
    actual fix for that, already available by default."""
    try:
        from scapy.all import conf
    except ImportError:
        return False
    return bool(conf.use_npcap) and conf.loopback_name in conf.ifaces


def _lan_interface():
    """The adapter that carries this machine's real LAN IP (None if it
    cannot be resolved, or off Windows where scapy's own pick is fine)."""
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return None

    try:
        target_ip = _local_lan_ip()
    except OSError:
        return None

    for iface in get_windows_if_list():
        if target_ip in iface.get("ips", []):
            return iface.get("name")
    return None


def _select_interfaces():
    """Interfaces to sniff on - always the real LAN adapter, plus Npcap's
    loopback device when present.

    Both are needed and neither can stand in for the other. Self-targeted
    test traffic (the attack simulation) only exists on the loopback device
    - Windows short-circuits it before any NIC driver (see
    has_npcap_loopback()). Real traffic - browsing, a video, a LAN
    attacker - only exists on the physical adapter. An earlier version
    returned loopback *instead of* the LAN adapter, which left the live
    dashboard blind to every real flow (only loopback flows were ever
    built, and nearly all of those are ignored as desktop noise).

    Resolving the adapter by IP, instead of letting scapy pick its default,
    matters on a machine with many adapters (seen here: 50+, including
    VirtualBox virtual adapters, hidden "Local Area Connection*" APIPA
    adapters, and a Npcap/WFP sub-driver entry per real adapter) - scapy's
    default-route heuristic can silently pick the wrong one after a reboot,
    VPN connect or adapter state change, with no exception raised.
    """
    ifaces = []

    lan = _lan_interface()
    if lan is not None:
        ifaces.append(lan)

    if has_npcap_loopback():
        from scapy.all import conf
        ifaces.append(conf.loopback_name)

    return ifaces


def _select_interface():
    """Single-interface pick for the offline live-test scripts, which only
    drive self-targeted traffic: loopback if available, else the LAN
    adapter. The live backend uses _select_interfaces() instead."""
    if has_npcap_loopback():
        from scapy.all import conf
        return conf.loopback_name
    return _lan_interface()


def start_capture(callback, packet_count=0):
    """
    Starts packet capture on every interface from _select_interfaces().

    callback      : Function to process each packet (must be thread-safe -
                    FlowManager.process_packet is, it holds a lock)
    packet_count  : Number of packets to capture per interface
                    0 = infinite capture
    """

    ifaces = _select_interfaces()
    if not ifaces:
        print("WARNING: could not resolve this machine's LAN interface by IP - "
              "falling back to scapy's default interface selection, which may "
              "be wrong on a multi-adapter machine.")
        ifaces = [None]

    def _prn(packet):
        # scapy's sniff() print()s whatever prn returns, if it isn't None -
        # callback (FlowManager.process_packet) returns the flow key for its
        # own callers' benefit (tests key on it), which under this wiring
        # meant every captured packet got auto-printed. Under flood-level
        # packet rates with stdout redirected to a log file, that print
        # storm can back up and stall this capture loop, dropping real
        # packets - confirmed by a 3-trial back-to-back ICMP flood: trial 1
        # (empty stdout buffer) captured the full ~11.5k-packet flood as one
        # flow, trials 2-3 (queued print backlog from trial 1) captured only
        # 2-4 packets total each. Discard the return value here so sniff()
        # never has anything to print.
        callback(packet)

    def _sniff(iface):
        sniff(iface=iface, prn=_prn, count=packet_count, store=False)

    # One sniff() per interface, each on its own thread; the first runs on
    # the calling thread so start_capture still blocks like it always did.
    threads = [
        threading.Thread(target=_sniff, args=(iface,), daemon=True)
        for iface in ifaces[1:]
    ]
    for t in threads:
        t.start()

    _sniff(ifaces[0])

    for t in threads:
        t.join()
