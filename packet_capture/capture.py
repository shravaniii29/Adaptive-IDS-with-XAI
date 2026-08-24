import socket

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


def _select_interface():
    """Finds the scapy/Npcap interface to sniff() on, instead of letting
    scapy fall back to its own automatic default-interface pick.

    Without this, sniff() with no `iface` uses scapy's default-route
    heuristic, which is unreliable on a machine with many adapters (seen
    here: 50+, including VirtualBox virtual adapters, several hidden
    "Local Area Connection*" APIPA adapters, and a Npcap/WFP sub-driver
    entry per real adapter) - it can silently pick the wrong one,
    especially after a reboot, VPN connect, or adapter state change,
    with no exception raised.

    Prefers the loopback device when present (see has_npcap_loopback())
    - that's the only reliable way to capture self-targeted test traffic
    (127.0.0.1) on Windows; self-addressing a real adapter's own IP is
    not reliably captured at all. Otherwise falls back to whichever
    adapter carries this machine's real LAN IP.
    """
    if has_npcap_loopback():
        from scapy.all import conf
        return conf.loopback_name

    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return None  # non-Windows: let scapy pick its own default

    target_ip = _local_lan_ip()
    for iface in get_windows_if_list():
        if target_ip in iface.get("ips", []):
            return iface.get("name")
    return None


def start_capture(callback, packet_count=0):
    """
    Starts packet capture.

    callback      : Function to process each packet
    packet_count  : Number of packets to capture
                    0 = infinite capture
    """

    iface = _select_interface()
    if iface is None:
        print("WARNING: could not resolve this machine's LAN interface by IP - "
              "falling back to scapy's default interface selection, which may "
              "be wrong on a multi-adapter machine.")

    sniff(
        iface=iface,
        prn=callback,
        count=packet_count,
        store=False
    )