"""Run one bounded IDS test scenario against another PC on your own LAN, but
ONLY after that PC's operator approves it on their dashboard.

This is the requesting ("source") side of the consent handshake in
app/main.py (/remote_attack/*). It does not contain any traffic-generation
code of its own: once, and only once, the target's operator has clicked
Approve, it calls the existing, already-reviewed scenario functions from
simulate_attacks.py against the target. With no approval it sends nothing.

    SOURCE PC   (this script - needs no backend of its own)
        python lan_consent_test.py http://192.168.1.20:8000 icmp_flood \
            --duration 10 --i-am-authorized

    TARGET PC   (runs the IDS backend + dashboard as usual; its operator
                 sees an "Approve / Deny" card and must click Approve)

The target's backend captures and scores the resulting flows like any other
LAN traffic, so the test shows up on the target's own dashboard.

Only use this between machines you own or are explicitly authorised to test.
The handshake is cooperative consent, not an enforcement boundary: its point
is that the receiving operator is always the one who authorises the test.
"""

import argparse
import os
import sys
import time

import requests

SCENARIOS = ("icmp_flood", "syn_flood", "udp_flood", "http_flood", "port_scan")
POLL_INTERVAL = 2.0


def request_consent(base, scenario, duration):
    """Raise a pending request on the target and return its id."""
    resp = requests.post(
        f"{base}/remote_attack/requests",
        json={"scenario": scenario, "duration": duration},
        timeout=10,
    )
    if not resp.ok:
        detail = resp.json().get("detail") if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        sys.exit(f"target refused the request: {detail}")
    data = resp.json()
    print(f"request {data['id']} raised on {base} - waiting for the operator there to approve "
          f"(expires in {int(data['expires_at'] - data['created_at'])}s) ...")
    return data["id"]


def wait_for_decision(base, request_id):
    """Poll until the operator approves (returns the token), or denies/expires
    (exits). Returns the one-time token."""
    while True:
        resp = requests.get(f"{base}/remote_attack/requests/{request_id}", timeout=10)
        if not resp.ok:
            sys.exit(f"could not read the request status: {resp.status_code}")
        data = resp.json()
        status = data["status"]
        if status == "approved" and data.get("token"):
            print("approved by the target operator.")
            return data["token"]
        if status in ("denied", "expired", "consumed"):
            sys.exit(f"not approved (status: {status}) - nothing was sent.")
        time.sleep(POLL_INTERVAL)


def spend_token(base, request_id, token):
    """Consume the single-use token right before running, so an approval can
    never authorise more than one run."""
    resp = requests.post(
        f"{base}/remote_attack/requests/{request_id}/consume",
        json={"token": token},
        timeout=10,
    )
    if not resp.ok:
        detail = resp.json().get("detail") if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        sys.exit(f"could not spend the approval: {detail}")
    print("approval spent (single use). running the approved scenario ...")


def run_scenario(target_ip, scenario, duration):
    """Delegate entirely to simulate_attacks.py's existing scenario function.
    SIM_TARGET_IP (set before import) points its TARGET_IP at the approved
    target; no packet-building happens in this file."""
    os.environ["SIM_TARGET_IP"] = target_ip
    import simulate_attacks as sim  # imported here so TARGET_IP resolves to the target

    if scenario in ("http_flood", "port_scan"):
        print("note: HTTP flood / port scan expect a responder on the target "
              "(run `python simulate_attacks.py` prerequisites there) or flows will be one-sided.")

    fn = getattr(sim, f"scenario_{scenario}")
    result = fn(duration=duration)
    print(f"done: {result.name} ran {result.end_time - result.start_time:.1f}s against {target_ip}. "
          f"Check the target's dashboard (Live Logs) for the scored flows.")


def _target_ip_from_base(base):
    host = base.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_backend", help="the target PC's backend URL, e.g. http://192.168.1.20:8000")
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--duration", type=int, default=10, help="seconds (the target caps this, default 10)")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="confirm you own or are authorised to test the target machine")
    args = parser.parse_args()

    if not args.i_am_authorized:
        sys.exit("refusing to proceed without --i-am-authorized: only test machines you are allowed to.")

    base = args.target_backend.rstrip("/")
    target_ip = _target_ip_from_base(base)

    request_id = request_consent(base, args.scenario, args.duration)
    token = wait_for_decision(base, request_id)
    spend_token(base, request_id, token)
    run_scenario(target_ip, args.scenario, args.duration)


if __name__ == "__main__":
    main()
