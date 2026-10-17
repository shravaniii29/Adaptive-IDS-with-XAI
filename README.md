# Simulated Real-time Adaptive IDS with XAI

A final-year B.Tech (AI & Data Science) major project: a network intrusion detection system (IDS) prototype that captures live packets, builds network flows, classifies them with a hybrid XGBoost + Isolation Forest model, monitors changes in the alert rate with ADWIN, explains predictions with SHAP, and presents results on a React dashboard through a FastAPI backend.

> **Status:** academic research prototype. It is **not** production-ready security software and must not be relied on to protect a real network.

**Team:** Shravani Bhole, Sneha Gangwani, Mahi Raikwar, Udayan Kundu
**License:** MIT, for the team's original source code and documentation on `main` and `review-integration` (see [License](#license)).

## Which branch to use

| Branch | Contents |
|---|---|
| **`main`** (default) | The **earlier V7 version** of the system: V7 XGBoost + Isolation Forest models, four rule-based agents, FastAPI backend and React dashboard. |
| **[`review-integration`](https://github.com/shravaniii29/Adaptive-IDS-with-XAI/tree/review-integration)** | The **latest V8 implementation**: V8 models and predictor, V8 SHAP explainer, the candidate-retraining prototype, V8 tests, and the evaluation reports used in [Experimental results](#experimental-results). |

**V8 is not available on `main`.** V8 is kept separately on `review-integration` and is not to be merged into `main`. Sections marked **"Applies to: `review-integration` (V8) only"** describe code and files that exist only on that branch. To use V8:

```bash
git checkout review-integration
```

---

## Contents

1. [Problem statement and objectives](#problem-statement-and-objectives)
2. [What the system does](#what-the-system-does)
3. [Architecture and workflow](#architecture-and-workflow)
4. [Technology stack](#technology-stack)
5. [Repository structure](#repository-structure)
6. [Prerequisites](#prerequisites)
7. [Installation](#installation)
8. [Running the backend](#running-the-backend)
9. [Running the frontend](#running-the-frontend)
10. [Live packet capture requirements](#live-packet-capture-requirements)
11. [Datasets](#datasets)
12. [Model artifacts](#model-artifacts)
13. [Tests](#tests)
14. [Experimental results](#experimental-results)
15. [Limitations](#limitations)
16. [Future scope](#future-scope)
17. [Privacy and security considerations](#privacy-and-security-considerations)
18. [License](#license)
19. [Acknowledgements](#acknowledgements)

---

## Problem statement and objectives

Many machine-learning IDS models are trained once on historical data, give no explanation for their alerts, and are evaluated only offline. This project explores combining, in one pipeline:

- **Real-time style detection:** classifying network flows built from live captured packets.
- **Hybrid detection:** a supervised classifier (XGBoost) together with an unsupervised anomaly detector (Isolation Forest).
- **Change monitoring:** ADWIN applied to the stream of detection outcomes.
- **Explainability:** SHAP feature attributions for each classified flow.
- **Analyst-facing output:** rule-based agents that turn model outputs into a readable assessment, shown on a web dashboard.

## What the system does

| Component | Behaviour | Branch |
|---|---|---|
| Packet capture | Scapy `sniff()` on the LAN adapter and on Npcap's loopback device at the same time, started automatically when the backend starts (no packet limit). | Both |
| Flow building | Packets are grouped into bidirectional flows. A flow is considered complete after **5 seconds of inactivity**; expired flows are checked every second. | Both |
| Detection | XGBoost and Isolation Forest; a flow is flagged if **either** model flags it. `main` uses the V7 models in `models/`. | Both (model version differs) |
| Detection (V8 details) | 25 V8 features; XGBoost on unscaled features, Isolation Forest on RobustScaler-scaled features; flagged if `XGBoost probability ≥ 0.4949` **OR** Isolation Forest anomaly. | `review-integration` only |
| Change monitoring | ADWIN (`river`, `delta=0.002`) receives the **hybrid prediction (0/1) of each flow**, so it detects changes in the **alert rate**. It does not measure feature-distribution drift or prediction errors (no ground-truth labels exist for live traffic). | Both |
| Explainability | SHAP `TreeExplainer` on the **XGBoost** model; the top 5 features by absolute SHAP value are returned per flow. Isolation Forest decisions are not explained by SHAP. | Both |
| Agents | **Rule-based** agents (Explainability, Drift, Response, Memory) and a Coordinator that computes a consensus score and an incident summary. They use fixed if/else rules; no LLM or learning is involved. | Both |
| Retraining agent | **Prototype only.** When the Drift agent reports `MODEL DEGRADING`, the Retraining agent may train **candidate** models and save them for manual review. Candidates are compared against the **V7** models in `models/`, **not** the live V8 models, and they are **never deployed automatically**. | `review-integration` only |
| Response | Produces a threat level and a recommended action (e.g. "BLOCK SOURCE IP"). These are **text recommendations only**; no firewall rule or blocking action is executed. | Both |
| API + dashboard | FastAPI REST endpoints and a WebSocket; a React dashboard that polls the REST endpoints every 5 seconds. | Both |

## Architecture and workflow

```
Live packets (Scapy)
      │
      ▼
FlowManager ── bidirectional flows, 5 s inactivity timeout
      │
      ▼
extract_features()
      │
      ▼
Predictor ── XGBoost + Isolation Forest ── OR-fusion
      │        (main: V7 predictor; review-integration: predictor_v8)
      ├──► ADWIN on hybrid prediction stream (alert-rate change)
      ├──► SHAP TreeExplainer on XGBoost (top 5 features)
      ▼
CoordinatorAgent
  ├─ ExplainabilityAgent  (feature descriptions, hypothesis, confidence)
  ├─ DriftAgent           (drift ratio over last 50 flows → status)
  ├─ ResponseAgent        (threat level + recommended action text)
  ├─ MemoryAgent          (last 20 flows, repeated source IPs)
  └─ RetrainingAgent      (review-integration only: candidate models,
                           compared with V7, never auto-deployed)
      │
      ▼
AppState (latest result + last 20 results, in memory)
      │
      ▼
FastAPI: /status /predict /drift /shap /memory /system  +  WebSocket /ws/live
      │
      ▼
React dashboard (polls REST endpoints every 5 s)
```

Main entry points (both branches):

- Backend application: `app/main.py` (FastAPI app object `app`)
- Detection pipeline: `detection/detection_service.py`
- Frontend: `frontend/` (Vite + React)

## Technology stack

| Layer | Technologies |
|---|---|
| Capture and flows | Python, Scapy |
| Machine learning | XGBoost, scikit-learn (Isolation Forest, RobustScaler), pandas, NumPy, joblib |
| Change monitoring | River (ADWIN) |
| Explainability | SHAP |
| Backend | FastAPI, Uvicorn |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, Recharts |
| Experiments | Jupyter notebook (V7) |

## Repository structure

**On `main`:**

```
.
├── app/                    FastAPI backend (main.py, state.py)
├── agents/                 Rule-based agents and coordinator
├── detection/              V7 predictor, ADWIN wrapper, detection service
├── explainability/         SHAP explainer (V7)
├── feature_extraction/     Flow, flow manager, feature extractor
├── packet_capture/         Scapy capture wrapper
├── frontend/               React dashboard (src/, old-ui/ = earlier prototype)
├── models/                 V7 model artifacts
├── notebooks/              V7 training notebook
├── tests/                  Test scripts
├── inspect_model_files.py, print_features.py, test_models.py   Helper scripts for the V7 artifacts
├── requirements.txt        Pinned Python dependencies
├── README.md
└── LICENSE                 MIT License
```

**Additional content on `review-integration` (V8):**

```
├── detection/predictor_v8.py           V8 predictor (used by the live pipeline)
├── explainability/shap_explainer_v8.py V8 SHAP explainer
├── agents/retraining_agent.py          Candidate-retraining prototype
├── v8_training/
│   ├── models_v8/                      V8 model artifacts + training report
│   └── evaluation_results/             V7 vs V8 evaluation outputs and sanity-audit summaries
├── data/                               Data-preparation notebook (no dataset files)
└── tests/                              Additional V8 tests and a live smoke-test script
```

Some frontend source files are empty placeholders for planned components.

## Prerequisites

- **Python:** developed with Python 3.14.3 (from the development virtual environment). Other versions have not been tested.
- **Node.js and npm:** required for the frontend. The Node version used was not recorded. The installed Vite version (8.2.0) requires Node `^20.19.0` or `>=22.12.0`.
- **Packet capture support:**
  - Windows: [Npcap](https://npcap.com/) installed, and the backend run from an **Administrator** terminal.
  - Linux/macOS: root privileges (or equivalent raw-socket capability).
- **Dataset files:** needed only for retraining or reproducing experiments, not for running the live dashboard (see [Datasets](#datasets)).

## Installation

> **Unverified:** these steps follow the repository's dependency files but have not been tested from a clean checkout. `requirements.txt` is identical on `main` and `review-integration`.

```bash
git clone https://github.com/shravaniii29/Adaptive-IDS-with-XAI.git
cd Adaptive-IDS-with-XAI
# Optional: switch to the V8 implementation
git checkout review-integration

python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

Notes:

- `requirements.txt` pins exact versions from the development environment (for example `xgboost==3.3.0`, `scikit-learn==1.9.0`, `shap==0.52.0`, `scapy==2.7.0`).
- `requirements.txt` does **not** include a WebSocket library for Uvicorn. `app/requirements.txt` lists `uvicorn[standard]`, which includes one. If you need the `/ws/live` endpoint, install `uvicorn[standard]`.
- `pytest` is not listed; install it separately to run the tests.

## Running the backend

A step-by-step list of every command (setup, backend, dashboard, simulations, stopping, troubleshooting) is in [`START_COMMANDS.txt`](START_COMMANDS.txt).

> **Unverified:** the command below is the standard Uvicorn invocation for the `app` object in `app/main.py`. The exact command used during development was not documented.

From the repository root, in a terminal with packet-capture privileges:

```bash
uvicorn app.main:app
```

On startup the backend:

1. Loads the model artifacts (`main`: V7 artifacts in `models/`; `review-integration`: V8 artifacts in `v8_training/models_v8/`). Startup fails if they are missing.
2. Starts packet capture on the LAN adapter and the Npcap loopback device.
3. Starts the flow-expiry worker.

| Endpoint (both branches) | Returns |
|---|---|
| `GET /status` | Flow counters (`total_flows`, `normal_flows`, `positive_flows`) and the last error |
| `GET /predict` | Latest flow's detection result, agent outputs, consensus and incident summary |
| `GET /drift` | Latest drift status, severity, trend and recommendation |
| `GET /shap` | Latest top SHAP features and explanation text |
| `GET /memory` | Memory agent pattern, risk and repeated source IPs |
| `GET /system` | Health status and uptime |
| `WS /ws/live` | Pushes each completed flow's result |

Before any flow completes, the result endpoints return `{"message": "no flows processed yet"}`.

### Two models, one switch (top bar of the dashboard, or `/mode`)

**Every flow is scored by both models, all the time.** The Hybrid | V8 switch only chooses whose results the dashboard shows:

| View | What decides whether a flow is an attack |
|---|---|
| `confidence` (default) | The deployed hybrid with confidence-weighted fusion: `confidence = 0.7 * xgb_probability + 0.3 * isolation_anomaly`, flagged when `confidence >= threshold`. `isolation_anomaly` is Isolation Forest's own anomaly score in (0, 1]. The threshold and weight are read from `models/fusion_config.json`. |
| `v8` | The paper's V8 model (`models/v8_reference/`, its own 25 features and thresholds) with V8 SHAP explanations. It decides with a weighted sum of its two scores, `0.3 * xgb_probability + 0.7 * isolation_anomaly >= 0.4128`, read from `models/v8_reference/v8_fusion_config.json` and shown on the dashboard as *V8 (calibrated)*. Without that file, or with `V8_RULE=paper`, it uses the paper's published rule (alarm if XGBoost or the Isolation Forest fires). |

Each stored result keeps one complete set of outputs per model under `variants` (verdict, probabilities, features, SHAP explanation, agent analysis, drift flag). Each model has its own drift monitor and its own agent coordinator. `GET /mode` returns the current view and which are available; `POST /mode` with `{"mode": "v8"}` switches it. Switching is instant and applies to flows scored earlier as well as new ones, nothing is reset, and the Total / Normal / Attacks counters follow the model being shown. The view is held in memory and returns to `confidence` when the backend restarts. Scoring with both models roughly doubles the SHAP and agent work per flow.

`/predict`, `/history` and the WebSocket payload also return `isolation_anomaly`, `confidence_score` and `fusion_mode`. Full statistics for the confidence mode are in `fusion_calibration/STATS.md`. The threshold was tuned by `tune_fusion_threshold.py` on live self-targeted traffic: on the held-out trial it gave 98.3% attack recall, but it is sensitive (at 0.20 recall falls to 51%), ordinary traffic overlaps attack scores, and the blended score ranks flows slightly worse than Isolation Forest alone (ROC-AUC 0.83 against 0.91) because the deployed XGBoost probability is close to chance on live flows. Re-run `tune_fusion_threshold.py` after changing the models or the feature pipeline.

### Loopback traffic is ignored, except the simulation's own address

Loopback flows (127.x to 127.x) never leave the machine: they are programs on the same PC talking to each other. On a normal desktop they are mostly noise (the dashboard polling this backend, the backend's own event-loop connection, vendor background services), and models trained on network flows flag a large share of them: in one session 16 of 20 loopback flows were flagged against 0 of 27 real network flows, and the dashboard's own polling was 112 of 174 flows. So loopback flows are skipped and counted as `ignored_loopback_flows` in `/status`.

The attack simulation has to be aimed at loopback (Windows does not deliver a machine's traffic to its own LAN address to any capture point), so it targets a dedicated **lab address**, `127.0.0.77` by default (every 127.x.x.x address is loopback on Windows). Loopback flows to or from a lab address are always scored; all other loopback flows are ignored. There is no toggle, timer or port list, nothing to change for a demo, and attacks started by hand against the lab address are scored too.

- **Target box:** the dashboard's *Run simulation* panel has a *Target* box (empty = `127.0.0.77`). The simulation sends real floods and scans, so the backend accepts only a loopback address (`127.x.x.x`) or this machine's own address and refuses anything else with HTTP 400. The chosen target is added to the scored addresses until the backend restarts (`lab_addresses` in `/status`).
- **From a terminal:** `SIM_TARGET_IP=127.0.0.88 python simulate_attacks.py <out_dir> <trials>`. `IDS_LAB_ADDRESS` changes the default address for both the backend and the script.
- `IDS_IGNORE_LOOPBACK=0` scores all loopback traffic. While it runs, `simulate_attacks.py` pins the dashboard's Hybrid | V8 view to the hybrid and restores it afterwards.

### Calibrating V8's rule

The paper's V8 raises an alarm when either of its two detectors fires, so a single Isolation Forest vote can flag an ordinary flow on its own. `collect_v8_flows.py` runs one simulation trial and records V8's scores for every flow (lab flows labelled by scenario, other network flows treated as benign); `tune_v8_fusion.py` compares the published rule, each detector alone and weighted sums with two-fold cross-validation, and `--write` stores the best weight and threshold in `models/v8_reference/v8_fusion_config.json`. The shipped values were fitted on only 90 flows from one machine and network (7 of them benign), so they are provisional: re-run both scripts with more data (`IDS_IGNORE_DISCOVERY=0 python -m uvicorn app.main:app --port 8001`, then `set IDS_API_BASE=http://127.0.0.1:8001`).

### Paper evaluation on the dashboard

`paper_offline_evaluation/` holds the paper's offline results (V7 and V8 on the held-out CSE-CIC-IDS2018 flows: 4,987 benign flows and 14 attack types, built from `v8_training/evaluation_results/v7_vs_v8_per_attack.csv` on the `review-integration` branch). It appears in the Live Simulation page's run list with a V7 vs V8 comparison and one tab per attack type.

### LAN discovery traffic is ignored

Flows this machine sends to a multicast or broadcast address (mDNS `224.0.0.251:5353`, SSDP `239.255.255.250:1900`, NetBIOS/LLMNR, app LAN-discovery broadcasts such as `192.168.1.255:57621`) are short, repetitive announcements. Once loopback noise is skipped they are most of what an idle desktop produces, and the models (trained on unicast flows) flag a good share of them: on one network V8 flagged 8 of 11 such flows and the hybrid 3 of 11, which fills a quiet dashboard with alerts that are not attacks. They are skipped by default and counted as `ignored_discovery_flows` in `/status`. Set `IDS_IGNORE_DISCOVERY=0` to score them. How many get flagged depends on the network: the thresholds in this repo were tuned on one home Wi-Fi.

### Reading a flagged row in Live Logs

Click a row to see *Why this verdict*. V8 raises an alarm when either XGBoost or the Isolation Forest fires; the hybrid raises one when its combined confidence score reaches the alert line. The SHAP bars explain **XGBoost only**, so when the Isolation Forest raised the alarm the bars can point the other way. The AI hypothesis is rule-based text built from XGBoost's features and can disagree with the verdict. The explanation for a row is fetched when it is opened, from `/history/{flow_id}`, and the table is wrapped so a malformed explanation can no longer blank the page.

### Hybrid vs V8 after a simulation

The *Live Simulation* page opens the newest run automatically when a simulation finishes and shows a **Hybrid vs V8** card: pooled recall, specificity, precision, F1 and accuracy for both models on the same flows, and a per-attack table. `python compare_hybrid_v8.py <run_dir>` prints the same comparison and writes `COMPARISON.md` into the run folder.

## Running the frontend

> **Unverified:** these commands come from `frontend/package.json` (the same scripts on both branches) and have not been re-tested.

```bash
cd frontend
npm install
cp .env.example .env          # Windows: copy .env.example .env
npm run dev
```

`.env.example` contains:

```
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_URL=ws://127.0.0.1:8000/ws/live
```

If `VITE_API_BASE_URL` is unset, the frontend defaults to `http://127.0.0.1:8000`. Other scripts in `package.json`: `npm run build`, `npm run lint`, `npm run preview`.

## Live packet capture requirements

- Capture starts **as soon as the backend starts** and runs until it stops.
- It sniffs two interfaces at once: the adapter carrying this machine's LAN IP (real traffic) and Npcap's loopback device (the attack simulation's self-targeted traffic). No interface option is exposed. Earlier builds listened on loopback only, which left the dashboard blind to real traffic.
- It passively observes traffic on that interface. It does not generate, inject or replay attack traffic.
- Only capture on networks and devices you own or are authorised to monitor.
- Most traffic on an ordinary machine is benign, so live results are a **functional demonstration**, not an accuracy measurement.

## Datasets

**No dataset files are included in this release.** The team's local training and evaluation CSV files are not published.

The models were trained and evaluated on **CSE-CIC-IDS2018** (Canadian Institute for Cybersecurity, University of New Brunswick). To reproduce training, evaluation or retraining, obtain the dataset yourself from the official source and follow its terms of use and citation requirements:

- Dataset page: https://www.unb.ca/cic/datasets/ids-2018.html
- AWS Open Data Registry: https://registry.opendata.aws/cse-cic-ids2018/

**Applies to: `review-integration` (V8) only.** `agents/retraining_agent.py` reads daily CSVs (`02-14-2018.csv` … `02-23-2018.csv`) from `data/cicids2018/`, or from the folder in the `CIC_IDS2018_DATA_DIR` environment variable. `CIC_IDS2018_RETRAIN_ROWS_PER_FILE` sets the rows read per file (default 8000).

Some notebooks and scripts contain absolute paths from the authors' machines; update them before running.

**Other branches:** some other branches of this repository contain data files and models derived from other sources, including **LSNM2024**. Their redistribution permissions have **not been verified**. They are not part of this release and are **not covered by the MIT License**.

## Model artifacts

The model files listed below are **currently tracked in this repository and publicly accessible**, because the code needs them to run. They are provided as-is for reference and reproducibility. They are **not covered by the MIT License**, and **permission to redistribute them has not been confirmed**; this notice does not grant or establish that permission. Their continued availability is not guaranteed.

| Set | Location | Branch | Used by |
|---|---|---|---|
| **V7** | `models/`: `xgb_model.pkl`, `isolation_forest.pkl`, `scaler.pkl`, `threshold.pkl`, `top_features.pkl` | Both (**the files differ between the two branches**) | `main`: the live pipeline. `review-integration`: the retraining prototype (as the comparison baseline), V7 comparison scripts, some tests. |
| **V8** | `v8_training/models_v8/`: `xgb_model_v8.pkl`, `isolation_forest_v8.pkl`, `scaler_v8.pkl`, `threshold_v8.pkl`, `top_features_v8.pkl` | `review-integration` only | Live detection (`detection/predictor_v8.py`), SHAP (`explainability/shap_explainer_v8.py`), V8 tests |

Compatibility and safety notes:

- Use the library versions in `requirements.txt`; other versions may fail to load the artifacts or behave differently. (On `review-integration`, the V8 artifacts are loaded with `joblib.load()`.)
- **These are pickle files. Loading a pickle can execute arbitrary code.** Only load artifacts from a source you trust.
- The models were trained on CSE-CIC-IDS2018 data, whose terms may apply to them.

## Tests

> **Unverified:** the tests have **not been re-run** for this release.

- **`main`:** `tests/` contains V7-era test scripts. Some are standalone scripts rather than pytest tests.
- **Applies to: `review-integration` (V8) only:**

  ```bash
  pip install pytest
  python -m pytest tests/test_predictor_v8.py tests/test_shap_v8_validation.py
  ```

- **`tests/test_live_prediction.py` (both branches) and `tests/test_live_v8_smoke.py` (`review-integration` only) capture real live traffic** and need capture privileges. They are smoke tests, not accuracy evaluations.

## Experimental results

> **Applies to: `review-integration` (V8) only.** The reports referenced below are in `v8_training/evaluation_results/` and `v8_training/models_v8/v8_training_report.json` on that branch.

All results below are **offline evaluations on CSE-CIC-IDS2018**, produced during development and **not re-run** for this release.

**Live-system testing:** a live smoke-test script (`tests/test_live_v8_smoke.py`) checks that packet capture, flow building and the V8 pipeline run without errors. In the recorded run, capture and flow building completed without errors, but no captured flow met the script's minimum-packet threshold, so **no live flow was classified by V8 in that run**; a follow-up run has not been documented. V8 classification was tested offline (unit tests and the dataset evaluation below). **No systematic labelled live-traffic evaluation was performed.**

### Data used

| | Rows |
|---|---|
| V8 training pool | 139,718 |
| Train split | 111,774 |
| Validation split | 27,944 (stratified by attack type) |
| Separate evaluation set | 22,428 (5,000 benign + 14 attack types) |

The XGBoost decision threshold (0.4949) was chosen by an F1 sweep on the validation split.

### V8 overall metrics

| Metric | Validation | Evaluation set (22,428 rows) |
|---|---|---|
| Accuracy | 0.9158 | 0.8918 |
| Precision | 0.9437 | 0.9329 |
| Attack recall | 0.9380 | 0.9275 |
| F1 | 0.9408 | 0.9302 |
| ROC-AUC | 0.9798 | 0.9543 |
| **Benign false-positive rate** | 0.1396 | **0.2326** |

### V7 vs V8 (same 22,382 evaluation rows)

The V7 column uses the V7 artifacts on `review-integration`. **The V7 model files on `main` are different and were not evaluated in these reports.** 46 rows with zero flow duration could not be scored by V7 and are excluded.

| Metric | V7 | V8 |
|---|---|---|
| Accuracy | 0.4797 | 0.8930 |
| Precision | 0.7955 | 0.9329 |
| Attack recall | 0.4448 | 0.9292 |
| F1 | 0.5706 | 0.9310 |
| ROC-AUC | 0.5644 | 0.9549 |
| Benign false-positive rate | 0.3988 | 0.2332 |

### V8 recall per attack type (evaluation set)

| Attack type | N | V8 recall |
|---|---|---|
| Bot, DDOS-HOIC, DDOS-LOIC-UDP, DDoS-LOIC-HTTP, DoS-GoldenEye, DoS-Hulk, DoS-SlowHTTPTest, DoS-Slowloris, FTP-BruteForce, SSH-Bruteforce | 1,500 each | 1.000 |
| Brute Force-XSS | 230 | 0.687 |
| Brute Force-Web | 611 | 0.498 |
| SQL Injection | 87 | 0.483 |
| Infilteration | 1,467 | 0.449 |

(N for Infilteration is 1,467 because rows V7 could not score are excluded.)

### Evaluation caveats

- **High false-alarm rate:** about **23% of benign flows are flagged as attacks** on the evaluation set.
- **Same capture days:** the training pool and the evaluation set both come from the same CSE-CIC-IDS2018 capture days. Exact duplicate rows were removed and the remaining overlap was audited (zero exact duplicates), so the separation is at the **row level only**, not a separate-day or separate-network test.
- **Near-identical attack flows:** the sanity audit (`v8_training/evaluation_results/sanity_audit/`) found that, for most attack classes, evaluation flows have **near-identical neighbours in the training pool**. The 100% recall values largely reflect how repetitive CSE-CIC-IDS2018 attack traffic is; they are **not evidence of generalisation** to new networks or attacks.
- **Underrepresented or unseen attack classes:** Brute Force-Web, Brute Force-XSS and SQL Injection do not appear in the V8 training pool's class counts, and recall on them is about 48–69%. DDOS-LOIC-UDP had only 184 training rows, and Infilteration recall is 45%.

## Limitations

1. **Retraining and drift detection:** drift monitoring currently tracks changes in alert rates, and candidate retraining compares models against V7 rather than the live V8 model. Retrained models are not automatically deployed.
2. **Detection reliability:** the model has a relatively high false-positive rate on the evaluated dataset, and performance on unseen real-world traffic has not been fully validated.
3. **Dashboard and security:** some dashboard integrations remain incomplete, and authentication and access controls are not implemented. The application should be used locally for research and testing.

## Future scope

1. **Improved adaptive learning:** enhance drift detection, evaluate retrained candidates against the current production model, and introduce safe model updates after validation.
2. **Improved detection and explainability:** reduce false positives, validate on unseen network traffic, and expand feature-level explanations.
3. **Dashboard and deployment improvements:** complete dashboard integration and add authentication, access controls and persistent storage.

## Privacy and security considerations

- **Live capture:** the backend captures real network traffic. Source and destination IP addresses are kept in memory, and repeated source IPs are returned by `/predict`, `/memory` and the WebSocket. Run it only on networks you are authorised to monitor.
- **No authentication:** the API has no authentication, and CORS allows all origins (`allow_origins=["*"]`). Keep the backend bound to `127.0.0.1` (the Uvicorn default) and do **not** expose it to other networks (for example with `--host 0.0.0.0`).
- **No enforcement:** "BLOCK SOURCE IP" and similar actions are recommendations only.
- **Pickle files:** model artifacts must only be loaded from trusted sources.
- **Not a security product:** this prototype has a high false-positive rate and has not been systematically evaluated on real network traffic.

## License

The team licenses its **original source code and documentation** under the **MIT License**. This applies to the team's original work on both the **`main`** and **`review-integration`** branches.

The [`LICENSE`](LICENSE) file is added to the `main` branch only. **It is not added to `review-integration`.** The team's statement here is that the same MIT terms apply to its original code and documentation on that branch.

```
Copyright (c) 2026 Shravani Bhole, Sneha Gangwani, Mahi Raikwar, Udayan Kundu
```

The MIT License does **not** cover:

- **Third-party libraries** (Scapy, XGBoost, scikit-learn, SHAP, River, FastAPI, React and others), which remain under their own licenses. In particular, Scapy is licensed under GPL-2.0-only. Dependencies are installed separately and are not redistributed here.
- **Datasets:** CSE-CIC-IDS2018, LSNM2024 and any data derived from them. These are governed by their owners' terms.
- **Model artifacts** (`.pkl` files). They are currently tracked and publicly accessible in this repository, but their redistribution permissions have not been confirmed.
- **Files on other branches** of this repository (branches other than `main` and `review-integration`).

## Acknowledgements

- Canadian Institute for Cybersecurity, University of New Brunswick, for the CSE-CIC-IDS2018 dataset.
- The maintainers of the open-source libraries this project builds on, including Scapy, XGBoost, scikit-learn, SHAP, River, FastAPI and React.

This repository was prepared for the college term-work activity *"Open Source Licensing or Code/Data Release under an Open License."*
