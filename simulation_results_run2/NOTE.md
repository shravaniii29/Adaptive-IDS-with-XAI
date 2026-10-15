# Reliability note for this run

**These results should not be used for model comparison.** Flow
attribution mostly failed: only 3 of 629 observed flows were matched to
a scenario (1 benign, 2 SYN flood; ICMP flood, UDP flood, HTTP flood,
and port scan all got zero attributed flows).

This is the third consecutive run on this machine with degrading
attribution, tracking rising background network load over the session
(`/status` `total_flows`: 1880 -> 1941 -> 2428 across the three runs).
Suspected cause: `attribute_flows()` matches by destination IP + timing
window, and/or scenario flows are being evicted from the backend's
capped 500-entry history buffer (`AppState.max_history`) by background
traffic before the poller's next `/history` read - not yet confirmed.

See [`../simulation_results/`](../simulation_results/) for the first run
(32 of 169 flows attributed - the only one with enough coverage to be
meaningful) and its analysis in
[`../VOTING_SYSTEM_ANALYSIS.md`](../VOTING_SYSTEM_ANALYSIS.md).

Kept here anyway per instruction, for the record and as a diagnostic
data point (worth investigating: the attribution/history-buffer
degradation itself is now a more urgent open item than any single
model's live accuracy).
