# Running the project

This covers the live IDS app (backend + dashboard), the attack simulator,
and the demo chart generator. All commands assume you're in the
`Adaptive-IDS-with-XAI/` folder, on Windows.

## 1. Prerequisites

- Python 3.11+ (this project has been run on 3.13.14)
- Node.js (for the frontend)
- [Npcap](https://npcap.com/) installed, with **WinPcap API-compatible
  mode** enabled — required for live packet capture via scapy
- Windows only: capture over `127.0.0.1` is unreliable without a
  dedicated loopback adapter. Everything here targets the machine's real
  LAN IP instead (auto-detected), even for local/self-targeted traffic.

## 2. Install dependencies

```
pip install -r requirements.txt
pip install -r app/requirements.txt
```

Both files list `torch` — install the CPU build explicitly if it isn't
already present (no GPU is needed at serve time, only single-sample
inference is ever run live):

```
pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
```

Frontend:

```
cd frontend
npm install
cd ..
```

(A venv is optional — this session ran directly against the system
Python install. Use `python -m venv venv` + `.\venv\Scripts\activate`
first if you want isolation, per the top-level README.)

## 3. Run the live app

Start the backend (packet capture + detection API) first:

```
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Wait for `Uvicorn running on http://127.0.0.1:8000` in the log. Sanity
check:

```
curl http://127.0.0.1:8000/status
```

Then start the dashboard:

```
cd frontend
npm run dev
```

Open the printed local URL (default `http://localhost:5173`). It polls
`/predict`, `/shap`, `/drift`, `/experimental`, and connects a websocket
to `/ws/live` for real-time results, including the 3 EXPERIMENTAL model
cards.

Generate a bit of traffic (browse the web, ping the machine, etc.) and
flows should start appearing within a few seconds of completing.

## 4. Run the attack simulator

With the backend already running (step 3), in a separate terminal:

```
python simulate_attacks.py
```

This runs a fixed sequence of short (~10s), bounded, **self-targeted**
scenarios — ICMP flood, SYN flood, UDP flood, HTTP flood, port scan, plus
a benign baseline for measuring false positives — all aimed at this
machine's own LAN IP, never an external host. It then polls the
backend's `/history` endpoint, attributes completed flows back to the
scenario that generated them by timing + destination IP, and scores the
deployed model plus all 3 experimental variants against each other.

Takes a few minutes end to end (includes a drain period so the last
flows of each scenario have time to complete and get scored). Output:

- A printed per-model accuracy table (recall on attack scenarios,
  specificity on the benign one).
- `simulation_results/<scenario_name>.json` — one file per attack type,
  with every attributed flow's per-model prediction and a summary score.
- `simulation_results/summary.json` — indexes all of the above.

## 5. Generate demo charts

After the simulator has produced `simulation_results/*.json`:

```
python visualize_simulation.py
```

Writes PNGs to `simulation_results/charts/`:

- `<scenario_name>.png` — one bar chart per attack type, all 4 models +
  the voting system.
- `combined_comparison.png` — every scenario side by side.
- `summary.png` — the headline chart: average recall across attack
  scenarios vs. specificity on the benign baseline, per model.

The **voting system** shown alongside the 4 individual models is an
AND-vote between the deployed hybrid model and experimental variant 2
(temporal features) — both must independently flag a flow as ATTACK
before the vote does. This pairing was chosen because variant 2 showed
higher recall than the other variants in earlier runs but also a much
worse false-positive rate; the vote tests whether requiring agreement
with the deployed model can keep some of that recall while cutting the
false positives. It is not wired into the live app — it only exists in
this offline scoring script, computed from the simulator's saved
predictions.

## 6. Tests

Tests here are script-style (module-level asserts, no pytest), matching
the existing `tests/test_predictor.py` convention:

```
python -m tests.test_experimental_history
python -m tests.test_experimental_models
python -m tests.test_flow_manager
```
