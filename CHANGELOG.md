# Changelog

Running log of investigation findings and changes, newest first. One entry per
meaningful change - appended to and committed alongside the code/model files
it describes, so the history in this file always matches what's in git.

Each entry: **What** changed, **Why** (the finding that drove it), **Result**
(what testing showed), **Files** touched.

---

## 2026-09-06 — RL verdict classifier (contextual bandit) on combined 2018+2019 data; live-tested

**What:** Added `rl_cicids_combined_classifier.py`, a one-step contextual
bandit (numpy MLP Q-network, no torch dependency) trained as a general
benign/attack classifier on the FULL pooled CIC-IDS2018 (28 offset windows +
3 full days) + CIC-DDoS2019 (18 attack-type files) dataset -
`train_attack_family_models.py`'s own loaders and 25-feature
`TOP_FEATURES` schema, but pooled across every attack type instead of split
by family. Wired the trained model (`models/rl_verdict_classifier/`) into
live serving as a 10th scored model: `detection/experimental_models.py`
(`_predict_rl_verdict`), `app/main.py` (`/history`, `/history/{flow_id}`,
`/experimental`), and `simulate_attacks.py` (`RL_KEYS`, `MODEL_KEYS`,
`MODEL_LABELS`), then live-tested with 3 trials of all 6 scenarios (337
real flows) via `simulate_attacks.py rl_v2_live_test 3`.

**Why:** First training pass (`tafm.per_day_split`, one 70th-percentile
cutoff per day across every attack label combined) left `DDOS
attack-LOIC-UDP` and `DoS attacks-Slowloris` with **zero training rows** -
both attack types' entire time window inside their source day
(02-21-2018, 02-15-2018) fell after that day's overall cutoff, because a
much larger co-occurring attack (HOIC, GoldenEye) dominated the quantile.
Fixed with `per_day_label_split()`: the 70th-percentile cutoff is now
computed PER (day, Label) instead of once per day, so every label with
enough rows lands in both train and test. Also tried reward-shaping
(bigger miss-penalty + oversampling) for 3 weak/rare types with real
training data (Infilteration, Brute Force -Web, SQL Injection) - a -6
miss-penalty was too aggressive and collapsed the whole policy to
near-always-predict-attack (0.999 recall / 0.067 specificity, the same
degenerate pattern this project has hit before); not carried into the
saved model.

**Result (held-out, fixed split):** asymmetric-reward net (saved artifact) -
accuracy=86.4%, recall=88.6%, specificity=85.0%, F1=83.8%, train=2,675,388 /
test=1,146,596 rows. `DDOS attack-LOIC-UDP` and `Slowloris` recovered to
99.8%/69.0% recall respectively (previously untrained/coincidental).

**Live test (3 trials, 337 real flows, pooled):** accuracy=74.8%,
recall=88.5%, specificity=34.2%, F1=84.0% - the highest F1 of all 10 scored
models (deployed hybrid: 83.8%), and far better specificity than the
deployed hybrid (2.5%) or Family: Connection (11.4%), though still weak in
absolute terms. Per-attack recall: ICMP flood 72.7%, SYN flood 81.4%, UDP
flood 85.7%, HTTP flood 100.0%, port scan 100.0% - at or near the best of
any model on HTTP flood/port scan, behind deployed hybrid/Family: Raw Flood
specifically on ICMP (72.7% vs 97.7%). Benign-baseline specificity was
**highly inconsistent across trials** (75%, 0%, 0% - flagged
high-variance): the pooled 34.2% is driven almost entirely by trial 1;
trials 2-3 flagged essentially all benign traffic as attack. Not yet
reliable enough to trust for specificity in isolation - offline held-out
specificity (85.0%) did not transfer to live traffic, the same
held-out/live gap this project has documented repeatedly for other models.

**Files:** `rl_cicids_combined_classifier.py`,
`models/rl_verdict_classifier/`, `detection/experimental_models.py`,
`app/main.py`, `simulate_attacks.py`, `rl_v2_live_test/`.

---

## 2026-09-06 (2) — Fix flow-attribution bug in simulate_attacks.py; corrected RL live-test numbers

**What:** Fixed `attribute_flows()` in `simulate_attacks.py`. It matched a
flow to the FIRST scenario (in schedule order) whose `[start-1, end+slack]`
window contained the flow's `observed_at`, where `slack` = 26s
(active_timeout + flow_timeout + 2*poll_interval). With scenarios only
~10s long and ~2s apart, that slack is large enough for a scenario's
window to swallow the scenario(s) immediately following it - and since
"Benign baseline" is always scheduled first, it systematically stole
credit for the ICMP-flood/SYN-flood flows that came right after it,
whenever those flows drained late enough to still land inside benign's
extended window. Fixed by attributing each flow to the LATEST (highest
start_time) matching scenario instead of the first - the correct read of
the same slack, since a flow lands at a later timestamp because it
drained late, not because it belongs to an earlier scenario. Re-ran the
same 3-trial live test (`rl_v2_live_test_fixed_attribution/`) after the
fix.

**Why found:** Investigating why RL verdict's benign-baseline specificity
swung 75% -> 0% -> 0% across 3 back-to-back trials of the identical
scenario. Cross-referencing each attributed flow's `observed_at` against
the scenario log showed "Benign baseline"-labeled flows in trials 2-3
timestamped well inside the immediately-following ICMP-flood/SYN-flood
windows - i.e. real attack flows mislabeled as benign ground truth, so a
model correctly flagging them as ATTACK was scored as wrong.

**Result:** The fix changes the ranking reported earlier today - RL
verdict's apparent "best F1 of all 10 models" finding was partly an
artifact of the mislabeling, not fully real. Corrected overall metrics
(309 flows, 3 trials pooled): deployed hybrid now leads (acc=83.8%
recall=96.6% specificity=6.8% F1=91.1%), Family: Connection close behind
(F1=90.1%), RL verdict third (acc=72.5% recall=82.6% specificity=11.4%
F1=83.7% - down from the pre-fix 84.0%/34.2%). RL's per-attack recall:
ICMP 76.1%, SYN 72.7%, UDP 80.0%, HTTP 83.3%, port scan 91.4% - solid but
no longer the outright leader on any type.

Separately, the fix exposed (did not cause) a second real issue: benign-
baseline specificity is STILL highly inconsistent trial-to-trial for
every model built on the 25-feature `extract_deployed_features` pipeline
(deployed hybrid 33%/0%/0%, Family: Connection 44%/0%/6%, RL verdict
56%/0%/0%), while the 8-feature experimental models (variants 1-3,
classifier_comparison candidates) stay stable and high (78-100% across
all 3 trials). This lines up with this project's own previously-
documented "14.7%-specificity deployed-model bug" (referenced in
`rl_retrain_policy.py`) - the 25-feature live pipeline's poor/volatile
benign-traffic behavior looks like a pre-existing, chronic issue the RL
model inherited by using the same feature pipeline, not something
specific to the RL model or its training. Not yet root-caused.

**Files:** `simulate_attacks.py`, `rl_v2_live_test_fixed_attribution/`.

---

## 2026-08-27 — Live-test the packet-level models; fix a silent sniffer-death bug

**What:** Added `live_test_packet_models.py` to live-test the packet-level
temporal XGBoost + CNN-LSTM (no Flow/FlowManager dependency, so they can't
use the existing app/simulate_attacks.py live-test path - this sniffs
packets directly and scores them as they arrive, reusing
`simulate_attacks.py`'s scenario generators for ground truth).

**Bug found and fixed:** the first version ran XGBoost's `predict_proba`
synchronously inside the scapy `sniff()` callback. Under a genuine flood
(hundreds of packets/sec), that fell far enough behind that Npcap's
capture buffer overflowed and the sniffer died silently in its background
thread (daemon-thread exceptions aren't surfaced) - only 2 seconds into
the very first flood scenario, leaving every later scenario with zero
captured packets, which looked at first like a timestamp/attribution bug
rather than a dead capture. Fixed by decoupling capture from inference:
`on_packet()` now only does cheap field extraction and pushes onto a
queue; a separate worker thread does the rolling-history bookkeeping and
model inference.

**Result:** recovered 4 of 5 flood scenarios (previously 1 of 5) before
the sniffer eventually died again under sustained load (~2s into the 4th
consecutive flood scenario, HTTP flood) - likely Npcap's own kernel-level
buffer limit rather than the same Python-side bottleneck, not yet fixed.
Live results for the scenarios that did complete: temporal XGB generalized
near-perfectly across every flood type (99.8-100% recall) but only 56%
specificity - consistent with the earlier `shortcut_warning` (95.6%
importance on inter-packet timing regularity): it likely fires on any
unusually regular/fast timing, not attack semantics specifically. CNN+LSTM
was far less consistent (94-99.9% on ICMP/SYN, 57.7% on HTTP, only 0.4% on
UDP flood) - a real, uneven generalization signal rather than one
dominant shortcut.

**Files:** `live_test_packet_models.py` (new)

---

## 2026-08-27 — Add LSNM2024 as an independent-tool data source; pivot to packet-level modeling

**What:** Sourced LSNM2024 (Abu Al-Haija et al., ICICS 2024, CC BY 4.0,
Mendeley Data) as an independently-generated dataset to address the
diagnosed domain-shift problem (Raw Flood/Reflection overfit to one
tool's timing signature - see the "why raw_flood/reflection can't detect
their own attacks" investigation). Built `fetch_lsnm2024_25feature.py` to
reconstruct flow-level features from LSNM2024's raw per-packet CSVs (it
is NOT flow-level CICFlowMeter output despite a third-party GitHub ADR's
claim to the contrary - verified directly, its columns are per-packet
Wireshark/tshark fields).

**Key findings during integration:**
- TCP port fields are unreliable (~50% placeholder 0/1 values), ruling
  out standard 5-tuple flow grouping - reconstructed via fixed-packet-count
  windows per IP-pair instead (conceptually similar to CICFlowMeter's own
  flow-timeout splitting).
- `ddos_udp.csv` uses a distinct, never-repeated spoofed source IP on
  ~99.97% of its packets - a genuine one-shot-per-identity flood where a
  per-flow representation cannot capture the attack signal AT ALL (almost
  every "flow" is exactly 1 packet). This directly motivated a pivot away
  from flow reconstruction for temporal/sequence modeling: the attack only
  exists as a population-level pattern (many distinct identities hitting
  one victim close together in time), which no per-flow feature vector -
  reconstructed or live - can see, regardless of algorithm.
- Two bugs fixed in the reconstruction script during validation: (1)
  `np.array_split` silently converts a DataFrame to a numpy array; (2) a
  duration<=0 window (multiple packets landing within the same timestamp
  precision) was being DROPPED as invalid - but for a spoofed-burst flood,
  near-zero duration between packets IS the attack signature, not noise.
  Fixed to floor duration to a 1-microsecond epsilon instead of discarding
  the window, preserving exactly the most attack-representative samples
  that were previously being thrown away.

**Result:** 4 of 5 LSNM2024 attack types (Syn, ICMP-Flood, DDOS-ICMP,
DDOS-RAW) reconstructed cleanly into both the 25-feature (family models)
and 8-feature (experimental variants) schemas. `DDOS-UDP` yielded only
55 usable flow-windows for the structural reason above - a new
**packet-level** notebook (`train_lsnm2024_packet_level.ipynb`) was built
instead: a temporal XGBoost (rolling history over raw packets, no flow
aggregation) and a CNN+LSTM consuming sequences of consecutive raw packets
directly, with no dependency on `feature_extraction/flow.py` or the live
serving path.

Ran end to end: both models hit ~99.9% accuracy/recall on held-out
LSNM2024 data - but the temporal XGBoost's `shortcut_warning` fired
(95.6% of feature importance on `hist_std_delta_t_us`, the rolling std of
inter-packet timing). This is a different flavor of the same
shortcut-learning pattern found earlier in the session (`Min Pkt Size`
dominance): every attack packet in this dataset comes from a flood
capture (near-perfectly regular timing) and every benign packet doesn't,
so the model may be learning "is this a flood-shaped capture file" rather
than "is this attack traffic" - a near-perfect offline score that likely
will not survive live testing against traffic the model hasn't memorized
the capture-level timing signature of. Not yet live-tested.

**Files:** `fetch_lsnm2024_25feature.py` (new), `notebooks/train_lsnm2024_packet_level.ipynb` (new),
`.gitignore` (excluded the 6 raw LSNM2024 packet CSVs - 77-535MB each,
several over GitHub's 100MB limit; the derived `*_25feature.csv`/`*_8feature.csv`
outputs are tracked normally), `data/lsnm2024/*_25feature.csv`,
`data/lsnm2024/*_8feature.csv`

---

## 2026-08-27 — Fix the benign-starvation fix's overcorrection (cap borrowed benign at a 2:1 ratio)

**What:** The benign-starvation fix below (every day/file contributes its
own benign rows to every family, unconditionally) overcorrected: a
rigorous 5-trial live re-test showed Raw Flood and Reflection flipped from
"flags everything as attack" to "flags almost nothing" (recall collapsed
to 0.4%, specificity rose to 100%) - even Reflection, which wasn't broken
before. Root cause: every family was drawing the ENTIRE pooled 2,303,571-row
benign set regardless of its own attack volume (95.4%/79.8%/72.8% benign
for Raw Flood/Reflection/Connection respectively - Raw Flood's attack
signal was diluted by more than 20x its own native benign volume).

**Fix:** `_native_frames`/`_borrowed_benign_frames`/`build_family_dataset`
in `train_attack_family_models.py` now cap "borrowed" cross-family benign
(from files that aren't a family's own attack source) so each family's
TOTAL benign:attack ratio lands near a fixed `BENIGN_ATTACK_RATIO = 2.0`,
sampled proportionally across every contributing environment - keeps the
starvation fix's cross-environment diversity benefit without the
overcorrection's volume problem.

**Result:** Validated directly against real data before retraining - all
three families landed at exactly 66.7% benign (2:1 ratio), down from
95.4%/79.8%/72.8%. Post-retrain 5-trial live test: Raw Flood and Reflection
became genuine (if modest) discriminating classifiers - 9.5% recall / 74.8%
specificity pooled, and a fairer family-specialty-aware re-scoring (each
family judged only on its own trained attack types, not penalized for
missing attacks it was never trained on) showed 10.9% recall / 98.3%
specificity - high-precision, low-recall specialists rather than either
degenerate extreme. Connection recovered its strong recall (89.1% pooled /
78.9% specialty-aware) with only a partial specificity improvement
(8.1%/26.3%) - flagged as still worth investigating, not solved.

**Files:** `train_attack_family_models.py`, `notebooks/train_attack_family_models.ipynb`,
`simulate_attacks.py` (added `family_aware_metrics`/`print_family_aware_metrics` -
scores each family only against its own trained specialty scenarios, since
pooling every model against every scenario unfairly penalizes narrow
specialists for missing attacks structurally outside their training)

---

## 2026-08-27 — Fix benign-starvation bug in attack-family models

**What:** `select_2018_frames`/`select_2019_frames` in
`train_attack_family_models.py` were skipping a day/file entirely whenever it
had zero attack rows matching a given family - discarding that day's benign
rows along with its (irrelevant) attack rows. Fixed so every day/file always
contributes its own benign rows to every family, regardless of whether its
attack labels match.

**Why:** Live testing showed `family_raw_flood` was degenerate - 100% recall
but 0% specificity, flagging all traffic as attack. Root cause: its training
set only drew benign from the 4 files containing its own attack types
(~1,760 benign rows), nowhere near enough for a 25-dimension Isolation Forest
to learn a reliable benign-only boundary. `family_reflection` had the same
bug in a more severe form - its `REFLECTION_LABELS_2018` list is empty, so
literally every 2018 day was being skipped, losing ~2 million rows of 2018
benign entirely.

**Result:** Dry-run validated against real local data before handing back for
retraining - benign share jumped from ~2.2% to 95.4% (raw_flood) and from ~5%
to 79.8% (reflection); connection_application_layer (already benign-healthy)
stayed at 72.8%. All three families now draw from the same 2,303,571-row
pooled benign set. Retraining with the fix was in progress as of this entry -
actual post-fix specificity not yet confirmed live.

**Files:** `train_attack_family_models.py`, `notebooks/train_attack_family_models.ipynb`

---

## 2026-08-26 — Make simulate_attacks.py multi-trial for statistical reliability

**What:** `simulate_attacks.py` now runs 3 trials of all 6 scenarios by
default (configurable via a 2nd CLI arg), pools them into one combined-N
report, and adds a trial-to-trial consistency report (mean +/- std per
model/scenario, flagged when std > 15 percentage points).

**Why:** Consecutive single-trial live runs on identical code showed the same
model/scenario swing by 20+ percentage points purely from small sample size
(12-40 flows per scenario) - e.g. Random Forest specificity 94.5% -> 82.2%
between two back-to-back runs with no code change. A single run's percentages
were not dependable enough to draw conclusions from.

**Result:** Not yet re-run with the new multi-trial version - pending.

**Files:** `simulate_attacks.py`

---

## 2026-08-26 — Add 3 attack-family models with full label coverage

**What:** Replaced a 2-family split (volumetric vs connection) that only
covered 7 of 31 attack labels with a 3-family split - `raw_flood`
(connectionless, near-zero payload), `reflection` (connectionless, large
payload from a spoofed reflector), `connection_application_layer` (real
session/handshake) - covering all 31 attack labels across CIC-IDS2018 and
CIC-DDoS2019. Wired all 3 into the live EXPERIMENTAL panel
(`detection/experimental_models.py`) for side-by-side live-test comparison
against the existing deployed model and experimental variants.

**Why:** An earlier 2-family draft (built by another session, verified only
against synthetic data) left ~85% of CIC-DDoS2019's attack rows and several
CIC-IDS2018 attack types unrepresented in either model. The 3-way split also
resolves an internal heterogeneity problem: mixing near-zero-payload raw
floods (Syn/TFTP) with large-payload reflection floods (DrDoS_*, etc.) under
one "volumetric" label had been driving `Min Pkt Size` to a shortcut-warning
level of feature importance (Section below).

**Result:** Live simulation (single trial, pre-multi-trial-fix) -
`family_connection` was the standout: 88.2% recall / 30.0% specificity,
the first model in this project to recognize HTTP flood and port scan while
holding better specificity than the fully generalist deployed model (2.5%).
`family_reflection`: 42.1% recall / 40.0% specificity, good on ICMP/SYN/UDP,
0% on HTTP/port-scan as expected (not in its training data).
`family_raw_flood`: degenerate, 100% recall / 0% specificity - see the fix
above.

**Files:** `train_attack_family_models.py`, `notebooks/train_attack_family_models.ipynb`,
`detection/experimental_models.py`, `app/main.py`, `simulate_attacks.py`,
`models/family_raw_flood/`, `models/family_reflection/`, `models/family_connection/`

---

## 2026-08-26 — Fix ICMP/payload feature bugs; classifier algorithm comparison

**What:** Two live-serving feature bugs fixed in `feature_extraction/flow.py`
and `detection/experimental_models.py` - see full detail in the PDF report
sent this session (or `git show 930becf`). Also added
`notebooks/classifier_comparison.ipynb`, training XGBoost/Random
Forest/HistGradientBoosting/Logistic Regression on identical data+features to
test whether a shortcut-learning problem (see below) was algorithm-specific.

**Why:** The 3 experimental dashboard models (XGBoost single-flow,
XGBoost+temporal, CNN+LSTM) showed near-zero live recall against generic
ICMP/SYN/UDP/HTTP floods and port scans despite 92-95% offline accuracy.

**Result:** Root cause was a `Min Pkt Size` shortcut - 15 of CIC-DDoS2019's 17
attack types are reflection/amplification attacks sharing one large-payload
signature, so the model had effectively become a reflection-DDoS detector.
Random Forest and HistGradientBoosting (identical data/features) generalized
measurably better than XGBoost live (16.7% vs 2.7% recall, 94.5% vs 74.5%
specificity) - confirming the shortcut was partly an artifact of how boosted
trees exploit a dominant feature, not solely an unavoidable property of the
data.

**Files:** `feature_extraction/flow.py`, `detection/experimental_models.py`,
`notebooks/classifier_comparison.ipynb`, `models/classifier_comparison/`

---

## Earlier history

Everything before the entries above (packet-capture reliability fixes, the
deployed hybrid model's threshold/training-data bug and retrain, the
3-way XGBoost/temporal/CNN+LSTM research comparison) predates this file - see
`git log --oneline` for commit-level detail, or ask for the full narrative
report to be regenerated as a PDF.
