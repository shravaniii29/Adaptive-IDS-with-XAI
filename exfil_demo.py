"""Data-exfiltration demo driven by REAL network data flow, not a dashboard button.

This sends a genuine, sustained, one-directional OUTBOUND data stream from this
machine to a target - the classic shape of data exfiltration (a lot of bytes
leaving, almost nothing coming back). The live IDS captures that flow on the
wire, extracts its CICFlowMeter features, scores it with the real XGBoost +
Isolation Forest models, and flags it. Nothing here touches the dashboard or the
model; the detection happens entirely because the packets are on the wire.

Run it from a terminal while the backend is capturing:

    python exfil_demo.py                      # self-targeted (lab address 127.0.0.77)
    python exfil_demo.py --mb 20 --seconds 12 # heavier / longer
    python exfil_demo.py --target 192.168.1.42 --i-am-authorized   # to a second PC you own

Then watch the dashboard: open Live Logs, filter the feed by the target IP, and
the exfiltration flow appears flagged "NEEDS REVIEW" - and the alert fires.

Only run this against a machine you own or are explicitly authorised to test. A
non-loopback target is refused unless you pass --i-am-authorized.
"""

import argparse
import ipaddress
import os
import socket
import sys
import time


def _lab_target() -> str:
    """The self-targeted address the backend scores on the loopback device
    (same default the attack simulation uses). Windows short-circuits traffic
    to this machine's own LAN IP before any NIC, so 127.0.0.77 is what is
    reliably captured for self-targeted tests."""
    explicit = os.environ.get("SIM_TARGET_IP", "").strip()
    if explicit:
        return explicit
    return os.environ.get("IDS_LAB_ADDRESS", "127.0.0.77").strip()


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default=_lab_target(),
                    help="destination IP (default: the lab address 127.0.0.77, captured on the loopback device)")
    ap.add_argument("--port", type=int, default=4444, help="destination port (default 4444)")
    ap.add_argument("--mb", type=float, default=12.0, help="megabytes to exfiltrate (default 12)")
    ap.add_argument("--seconds", type=float, default=10.0, help="spread the transfer over about this long (default 10)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required to target any non-loopback host; asserts you own or may test it")
    args = ap.parse_args()

    target = args.target.strip()
    if not _is_loopback(target) and not args.i_am_authorized:
        print(f"REFUSED: {target} is not a loopback address. Re-run with --i-am-authorized "
              f"only if you own or are authorised to test it (e.g. your own second PC).")
        return 2

    # Craft the exfil stream with scapy so it is one real flow on the wire:
    # a fixed source port -> target:port of UDP datagrams, each carrying a full
    # ~1400-byte payload, sent at high volume. That gives the flow a high
    # forward byte count, a packet-rate ratio near 1 (one-directional) and a
    # large mean packet size - the one-directional high-volume outbound data
    # pattern the deployed model scores as malicious. (A quiet, slow TCP copy
    # is NOT reliably flagged: the Isolation Forest finds it anomalous but the
    # fused score stays under the alert threshold - the detector is tuned for
    # attack-shaped outbound traffic, not every large transfer.)
    try:
        from scapy.all import IP, UDP, Raw, send
    except ImportError:
        print("scapy is required (pip install scapy) and Npcap must be installed.")
        return 1

    payload_size = 1400
    total_bytes = int(args.mb * 1024 * 1024)
    n_packets = max(1, total_bytes // payload_size)
    batch = 50
    src_port = 55555
    payload = b"EXFIL" + os.urandom(payload_size - 5)

    # Pace the send so it spans ~args.seconds rather than firing instantly,
    # which makes it read as a sustained transfer and lets the flow build up.
    inter = max(0.0, args.seconds / (n_packets / batch)) if n_packets > batch else 0.0

    print(f"Exfiltrating ~{args.mb:.0f} MB ({n_packets} packets x {payload_size} B) "
          f"from this machine to {target}:{args.port} over ~{args.seconds:.0f}s ...")
    print(f"  flow 5-tuple:  <this host>:{src_port}  ->  {target}:{args.port}  (UDP)")

    pkt = IP(dst=target) / UDP(sport=src_port, dport=args.port) / Raw(load=payload)
    sent = 0
    start = time.time()
    try:
        while sent < n_packets:
            count = min(batch, n_packets - sent)
            send(pkt, count=count, inter=0, verbose=0)
            sent += count
            if inter:
                time.sleep(inter)
            if sent % (batch * 10) == 0:
                mb = sent * payload_size / (1024 * 1024)
                print(f"    sent {sent}/{n_packets} packets ({mb:.1f} MB) ...", flush=True)
    except PermissionError:
        print("Sending raw packets needs admin/Npcap privileges - run this terminal as Administrator.")
        return 1
    except OSError as exc:
        print(f"send failed: {exc}")
        return 1

    elapsed = time.time() - start
    mb = sent * payload_size / (1024 * 1024)
    print(f"Done: {sent} packets, {mb:.1f} MB outbound in {elapsed:.1f}s.")
    print()
    print("Now, in the dashboard:")
    print(f"  - Open Live Logs and search / filter by  {target}")
    print(f"  - The exfiltration flow to port {args.port} should appear flagged NEEDS REVIEW")
    print("  - Open it to see the SHAP reason (large one-directional outbound transfer).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
