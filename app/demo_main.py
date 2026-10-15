"""
Demo FastAPI backend for the Network IDS project.

Generates simulated IDS results so the dashboard can be
demonstrated without live packet capture or admin privileges.
"""

import time
import random
import threading
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


DEMO_IPS = [
    "192.168.1.10", "192.168.1.25", "10.0.0.5",
    "172.16.0.100", "192.168.1.50", "10.0.0.12",
    "192.168.2.30", "172.16.1.55", "10.10.0.8",
]

ATTACK_IPS = [
    "45.33.49.119", "185.220.101.35", "23.129.64.210",
    "104.248.89.77", "91.219.236.174",
]

TOP_FEATURES = [
    "pkt_rate_ratio", "Flow Duration", "Flow IAT Max",
    "Flow Pkts/s", "Fwd Pkts/s", "Flow IAT Mean",
    "Pkt Len Max", "Pkt Size Avg", "Fwd IAT Tot",
    "iat_variation", "Fwd Header Len", "Fwd IAT Max",
    "Fwd IAT Mean", "Flow IAT Std", "TotLen Fwd Pkts",
    "Subflow Fwd Byts", "Init Bwd Win Byts", "Flow IAT Min",
    "Bwd Pkt Len Max", "Subflow Bwd Byts", "TotLen Bwd Pkts",
    "Bwd Seg Size Avg", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Pkt Len Mean",
]

ATTACK_HYPOTHESES = [
    "Rapid automated port scanning detected — unusually high packet rate with minimal payload",
    "Possible SYN flood attack — high forward packet count with asymmetric response",
    "Potential data exfiltration — large outbound packet sizes with sustained connection",
    "Brute-force login attempt — repetitive connection patterns to authentication port",
    "DNS tunneling suspected — anomalous DNS query patterns with large payload",
    "Lateral movement detected — internal host scanning multiple subnets",
]

SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class DemoState:
    def __init__(self):
        self.lock = threading.Lock()
        self.last_result = None
        self.result_history = []
        self.max_history = 50
        self.last_error = None
        self.start_time = 0.0
        self.loop = None
        self._clients = set()
        self.total_flows = 0
        self.normal_flows = 0
        self.positive_flows = 0
        self.drift_window = []
        self.analysis_cache = {}

    def record_result(self, result):
        with self.lock:
            self.last_result = result
            self.result_history.append(result)
            if len(self.result_history) > self.max_history:
                self.result_history = self.result_history[-self.max_history:]
            self.total_flows += 1
            if result["hybrid_prediction"] == 1:
                self.positive_flows += 1
            else:
                self.normal_flows += 1
            self.analysis_cache[result["flow_id"]] = result

    def get_history(self):
        with self.lock:
            return list(self.result_history)

    def get_analysis(self, flow_id):
        with self.lock:
            return self.analysis_cache.get(flow_id)

    def broadcast_soon(self, payload):
        if self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(payload), self.loop)

    def add_client(self, ws):
        self._clients.add(ws)

    def remove_client(self, ws):
        self._clients.discard(ws)

    async def _broadcast(self, payload):
        dead = []
        for client in list(self._clients):
            try:
                await client.send_json(payload)
            except Exception:
                dead.append(client)
        for c in dead:
            self._clients.discard(c)


state = DemoState()


def _generate_shap_features(is_attack):
    features = random.sample(TOP_FEATURES, 5)
    result = []
    for f in features:
        impact = random.uniform(0.3, 0.9) if is_attack else random.uniform(0.01, 0.15)
        if random.random() < 0.3:
            impact = -impact
        result.append({"feature": f, "value": round(random.uniform(0, 100000), 2), "impact": round(impact, 4)})
    result.sort(key=lambda x: abs(x["impact"]), reverse=True)
    return result


def _generate_flow():
    # V8 evaluation: 92.75% attack recall, 76.74% specificity (23.26% benign FPR)
    is_attack = random.random() < 0.20
    flow_id = state.total_flows + 1

    if is_attack:
        src_ip = random.choice(ATTACK_IPS)
        dst_ip = random.choice(DEMO_IPS)
        # V8 recall ~92.75%: most attacks get high XGB probability
        if random.random() < 0.9275:
            xgb_prob = round(random.uniform(0.55, 0.99), 4)
        else:
            xgb_prob = round(random.uniform(0.10, 0.49), 4)
        iso_pred = 1 if random.random() < 0.60 else 0
    else:
        src_ip = random.choice(DEMO_IPS)
        dst_ip = random.choice(DEMO_IPS[:5])
        # V8 benign FPR ~10%: most normals stay well below threshold
        if random.random() < 0.10:
            xgb_prob = round(random.uniform(0.50, 0.65), 4)
        else:
            xgb_prob = round(random.uniform(0.01, 0.35), 4)
        iso_pred = 1 if random.random() < 0.08 else 0

    xgb_pred = 1 if xgb_prob >= 0.495 else 0
    # Confidence-weighted fusion: XGBoost probability (0.7 weight) + Isolation Forest (0.3 weight)
    # replaces the OR-fusion that crushed specificity
    iso_score = random.uniform(0.6, 0.95) if iso_pred == 1 else random.uniform(0.05, 0.4)
    confidence_score = round(0.7 * xgb_prob + 0.3 * iso_score, 4)
    hybrid = 1 if confidence_score >= 0.55 else 0
    is_attack = hybrid == 1

    shap_features = _generate_shap_features(is_attack)
    avg_impact = sum(abs(f["impact"]) for f in shap_features) / len(shap_features)
    confidence = "HIGH" if avg_impact > 0.5 else ("MEDIUM" if avg_impact > 0.2 else "LOW")

    state.drift_window.append(hybrid)
    if len(state.drift_window) > 50:
        state.drift_window = state.drift_window[-50:]
    drift_ratio = sum(state.drift_window) / len(state.drift_window)
    drift_detected = random.random() < 0.08

    if drift_ratio >= 0.40:
        drift_status, drift_severity = "MODEL DEGRADING", "HIGH"
        drift_recommendation = "Immediate model retraining recommended"
    elif drift_ratio >= 0.20:
        drift_status, drift_severity = "MODERATE DRIFT", "MEDIUM"
        drift_recommendation = "Monitor closely and schedule retraining"
    elif drift_detected:
        drift_status, drift_severity = "MINOR DRIFT", "LOW"
        drift_recommendation = "Continue monitoring"
    else:
        drift_status, drift_severity = "MODEL STABLE", "NONE"
        drift_recommendation = "No action needed"

    if is_attack:
        if xgb_prob >= 0.80:
            threat_level, action = "HIGH", "BLOCK SOURCE IP"
            reason = f"High-confidence attack from {src_ip}"
        else:
            threat_level, action = "MEDIUM", "LOG AND MONITOR"
            reason = f"Suspicious activity from {src_ip}"
        alert = True
    else:
        threat_level, action, reason, alert = "LOW", "CONTINUE MONITORING", "Normal traffic pattern", False

    hypothesis = random.choice(ATTACK_HYPOTHESES) if is_attack else "Normal network communication — no suspicious patterns detected"

    recent_attacks = state.positive_flows
    if recent_attacks >= 10:
        mem_pattern, mem_risk = "SUSTAINED ATTACK CAMPAIGN", "CRITICAL"
    elif recent_attacks >= 3:
        mem_pattern, mem_risk = "EMERGING ATTACK TREND", "MEDIUM"
    else:
        mem_pattern, mem_risk = "NORMAL NETWORK BEHAVIOUR", "LOW"

    consensus = random.randint(70, 100) if is_attack else random.randint(85, 100)
    agreement = "FULL" if consensus >= 80 else "PARTIAL"

    severity = "critical" if threat_level == "HIGH" and xgb_prob >= 0.85 else SEVERITY_MAP.get(threat_level, "medium")

    mitigation = []
    if is_attack:
        mitigation = [f"Block source IP {src_ip} at the firewall", "Inspect related flows for lateral movement", "Review affected endpoint for compromise indicators"]
    else:
        mitigation = ["Continue routine monitoring"]

    result = {
        "flow_id": flow_id,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "packet_count": random.randint(3, 500),
        "duration": round(random.uniform(0.01, 30.0), 3),
        "timestamp": time.time(),
        "xgb_probability": xgb_prob,
        "xgb_prediction": xgb_pred,
        "isolation_prediction": iso_pred,
        "hybrid_prediction": hybrid,
        "drift_detected": drift_detected,
        "agent_analysis": {
            "response": {"threat_level": threat_level, "action": action, "reason": reason, "alert": alert},
            "explanation": {
                "top_features": shap_features,
                "confidence": confidence,
                "attack_hypothesis": hypothesis,
                "summary": f"{'Malicious' if is_attack else 'Benign'} flow from {src_ip} to {dst_ip}",
                "reasoning": [f"{f['feature']}: contributes to detection with impact {f['impact']}" for f in shap_features[:3]],
                "detailed_report": [
                    f"Flow {flow_id}: {src_ip} -> {dst_ip}",
                    f"Detection: XGBoost={xgb_prob:.2%}, IsolationForest={'Anomaly' if iso_pred else 'Normal'}",
                    f"Verdict: {'ATTACK' if is_attack else 'NORMAL'} ({confidence} confidence)",
                ],
            },
            "drift": {
                "status": drift_status, "severity": drift_severity,
                "trend": f"Drift ratio: {drift_ratio:.1%} over last {len(state.drift_window)} flows",
                "recommendation": drift_recommendation,
            },
            "memory": {
                "pattern": mem_pattern, "risk": mem_risk,
                "confidence": "HIGH" if recent_attacks >= 5 else "MEDIUM",
                "flows_in_memory": min(len(state.result_history), 20),
                "recent_attacks": recent_attacks,
                "repeated_sources": [],
                "recommendation": "Escalate to SOC" if mem_risk == "CRITICAL" else "Continue automated monitoring",
            },
            "consensus": {"score": consensus, "agreement": agreement},
            "incident_report": {
                "verdict": "ATTACK DETECTED" if is_attack else "NORMAL TRAFFIC",
                "confidence": confidence,
                "summary": f"Flow {flow_id} from {src_ip}: {hypothesis}",
            },
        },
        "_analysis_detail": {
            "explanation": hypothesis if is_attack else "Routine network traffic with no anomalous indicators",
            "severity": severity,
            "recommended_mitigation": mitigation,
            "business_impact": "Potential data breach or service disruption" if is_attack else "No business impact",
            "soc_analyst_summary": f"Flow #{flow_id} from {src_ip} to {dst_ip}: {hypothesis}" if is_attack else f"Flow #{flow_id}: benign traffic, no action required",
            "incident_report": {
                "title": f"{'Suspected intrusion' if is_attack else 'Normal activity'} — Flow #{flow_id}",
                "affected_asset": dst_ip,
                "evidence": [
                    f"XGBoost probability: {xgb_prob:.2%}",
                    f"Isolation Forest: {'Anomaly' if iso_pred else 'Normal'}",
                    f"Top SHAP feature: {shap_features[0]['feature']} (impact {shap_features[0]['impact']})",
                ],
                "recommended_next_step": action,
            },
            "model_name": "V8 XGBoost + Isolation Forest Hybrid",
            "memory_agent_result": {
                "summary": f"{'Attack pattern recurring across multiple flows' if recent_attacks >= 3 else 'No recurring patterns detected'}",
                "similar_incidents": recent_attacks,
                "pattern_detected": recent_attacks >= 3,
                "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        },
    }
    return result


def _build_ws_payload(result):
    agent = result.get("agent_analysis", {})
    response = agent.get("response", {})
    explanation = agent.get("explanation", {})
    drift = agent.get("drift", {})
    memory = agent.get("memory", {})
    consensus = agent.get("consensus", {})
    incident = agent.get("incident_report", {})
    return {
        "flow_id": result.get("flow_id"),
        "source_ip": result.get("source_ip"),
        "destination_ip": result.get("destination_ip"),
        "timestamp": result.get("timestamp"),
        "xgb_probability": result.get("xgb_probability"),
        "xgb_prediction": result.get("xgb_prediction"),
        "isolation_prediction": result.get("isolation_prediction"),
        "hybrid_prediction": result.get("hybrid_prediction"),
        "drift_detected": result.get("drift_detected"),
        "drift_status": drift.get("status"),
        "drift_severity": drift.get("severity"),
        "model_recommendation": drift.get("recommendation"),
        "threat_level": response.get("threat_level"),
        "recommended_action": response.get("action"),
        "response_reason": response.get("reason"),
        "alert": response.get("alert"),
        "attack_hypothesis": explanation.get("attack_hypothesis"),
        "confidence": explanation.get("confidence"),
        "explanation_summary": explanation.get("summary"),
        "reasoning": explanation.get("reasoning", []),
        "supporting_features": explanation.get("top_features", []),
        "detailed_explanation": explanation.get("detailed_report", []),
        "memory_pattern": memory.get("pattern"),
        "memory_risk": memory.get("risk"),
        "memory_confidence": memory.get("confidence"),
        "flows_in_memory": memory.get("flows_in_memory"),
        "recent_attacks": memory.get("recent_attacks"),
        "repeated_sources": memory.get("repeated_sources"),
        "memory_recommendation": memory.get("recommendation"),
        "consensus_score": consensus.get("score"),
        "agreement_level": consensus.get("agreement"),
        "verdict": incident.get("verdict"),
        "overall_confidence": incident.get("confidence"),
        "incident_summary": incident.get("summary"),
    }


def _simulation_worker():
    while True:
        time.sleep(random.uniform(2.0, 5.0))
        result = _generate_flow()
        state.record_result(result)
        payload = _build_ws_payload(result)
        state.broadcast_soon(payload)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.loop = asyncio.get_event_loop()
    state.start_time = time.time()
    sim_thread = threading.Thread(target=_simulation_worker, daemon=True)
    sim_thread.start()
    yield


app = FastAPI(title="Network IDS API (Demo Mode)", lifespan=lifespan)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/status")
def get_status():
    return {
        "total_flows": state.total_flows,
        "normal_flows": state.normal_flows,
        "positive_flows": state.positive_flows,
        "last_error": state.last_error,
    }


@app.post("/clear")
def clear_stats():
    with state.lock:
        state.total_flows = 0
        state.normal_flows = 0
        state.positive_flows = 0
        state.last_result = None
        state.result_history.clear()
        state.drift_window.clear()
        state.analysis_cache.clear()
        state.last_error = None
    return {"status": "cleared"}


@app.get("/predict")
def get_predict():
    if state.last_result is None:
        return {"message": "no flows processed yet"}
    r = state.last_result
    return {
        "flow_id": r.get("flow_id"),
        "source_ip": r.get("source_ip"),
        "destination_ip": r.get("destination_ip"),
        "timestamp": r.get("timestamp"),
        "xgb_probability": r.get("xgb_probability"),
        "xgb_prediction": r.get("xgb_prediction"),
        "isolation_prediction": r.get("isolation_prediction"),
        "hybrid_prediction": r.get("hybrid_prediction"),
    }


@app.get("/drift")
def get_drift():
    if state.last_result is None:
        return {"message": "no flows processed yet"}
    r = state.last_result
    drift = r.get("agent_analysis", {}).get("drift", {})
    return {
        "flow_id": r.get("flow_id"),
        "drift_detected": r.get("drift_detected"),
        "status": drift.get("status"),
        "severity": drift.get("severity"),
        "trend": drift.get("trend"),
        "recommendation": drift.get("recommendation"),
    }


@app.get("/shap")
def get_shap():
    if state.last_result is None:
        return {"message": "no flows processed yet"}
    r = state.last_result
    explanation = r.get("agent_analysis", {}).get("explanation", {})
    return {
        "flow_id": r.get("flow_id"),
        "top_features": explanation.get("top_features", []),
        "confidence": explanation.get("confidence"),
        "attack_hypothesis": explanation.get("attack_hypothesis"),
        "summary": explanation.get("summary"),
        "reasoning": explanation.get("reasoning", []),
        "detailed_explanation": explanation.get("detailed_report", []),
    }


@app.get("/memory")
def get_memory():
    if state.last_result is None:
        return {"message": "no flows processed yet"}
    memory = state.last_result.get("agent_analysis", {}).get("memory", {})
    return {
        "pattern": memory.get("pattern"),
        "risk": memory.get("risk"),
        "confidence": memory.get("confidence"),
        "flows_in_memory": memory.get("flows_in_memory"),
        "recent_attacks": memory.get("recent_attacks"),
        "repeated_sources": memory.get("repeated_sources"),
        "recommendation": memory.get("recommendation"),
    }


@app.get("/system")
def get_system():
    return {
        "status": "ok" if state.last_error is None else "degraded",
        "uptime_seconds": time.time() - state.start_time,
        "last_error": state.last_error,
    }


@app.get("/history")
def get_history():
    return {"flows": [_build_ws_payload(r) for r in state.get_history()]}


@app.get("/analysis/{flow_id}")
def get_analysis(flow_id: int):
    r = state.get_analysis(flow_id)
    if r is None:
        return {"flow_id": flow_id, "analysis": None}
    detail = r.get("_analysis_detail", {})
    return {"flow_id": flow_id, "analysis": detail}


@app.get("/simulations")
def list_simulations():
    return {
        "simulations": [
            {
                "name": "demo_baseline_2026_10",
                "generated_at": time.time() - 86400,
                "trials": 5,
                "target_ip": "192.168.1.50",
                "scenario_count": 6,
            },
            {
                "name": "stress_test_2026_09",
                "generated_at": time.time() - 604800,
                "trials": 10,
                "target_ip": "10.0.0.5",
                "scenario_count": 4,
            },
        ]
    }


def _make_metrics(accuracy, precision, recall, total):
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    tp = int(total * recall * 0.5)
    fn = int(total * 0.5) - tp
    fp = int(tp / precision) - tp if precision > 0 else 0
    tn = total - tp - fn - fp
    return {
        "confusion_matrix": {"tp": max(tp, 0), "fp": max(fp, 0), "tn": max(tn, 0), "fn": max(fn, 0)},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": round(f1, 4),
        "specificity": round(tn / (tn + fp), 4) if (tn + fp) > 0 else 1.0,
        "total_flows": total,
    }


@app.get("/simulations/{name}")
def get_simulation(name: str):
    return {
        "generated_at": time.time() - 86400,
        "target_ip": "192.168.1.50",
        "trials": 5,
        "scenarios": [
            {"name": "Benign baseline", "is_attack": False, "flow_count": 44, "model_scores": {"deployed_hybrid": 0.068, "connection_family": 0.114, "v8_candidate": 0.767}, "file": "benign.csv"},
            {"name": "ICMP flood", "is_attack": True, "flow_count": 46, "model_scores": {"deployed_hybrid": 0.935, "connection_family": 0.870, "v8_candidate": 0.928}, "file": "icmp_flood.csv"},
            {"name": "SYN flood", "is_attack": True, "flow_count": 44, "model_scores": {"deployed_hybrid": 0.955, "connection_family": 0.909, "v8_candidate": 0.928}, "file": "syn_flood.csv"},
            {"name": "UDP flood", "is_attack": True, "flow_count": 40, "model_scores": {"deployed_hybrid": 0.975, "connection_family": 0.975, "v8_candidate": 0.928}, "file": "udp_flood.csv"},
            {"name": "HTTP flood", "is_attack": True, "flow_count": 42, "model_scores": {"deployed_hybrid": 0.952, "connection_family": 0.929, "v8_candidate": 0.928}, "file": "http_flood.csv"},
            {"name": "Port scan", "is_attack": True, "flow_count": 93, "model_scores": {"deployed_hybrid": 0.989, "connection_family": 0.978, "v8_candidate": 0.928}, "file": "port_scan.csv"},
        ],
        "aggregate_metrics": {
            "deployed_hybrid": {"confusion_matrix": {"tp": 256, "fp": 41, "tn": 3, "fn": 9}, "accuracy": 0.838, "precision": 0.862, "recall": 0.966, "f1": 0.911, "specificity": 0.068, "total_flows": 309},
            "connection_family": {"confusion_matrix": {"tp": 249, "fp": 39, "tn": 5, "fn": 16}, "accuracy": 0.822, "precision": 0.865, "recall": 0.940, "f1": 0.901, "specificity": 0.114, "total_flows": 309},
            "v8_candidate": {"confusion_matrix": {"tp": 16165, "fp": 1163, "tn": 3837, "fn": 1263}, "accuracy": 0.892, "precision": 0.933, "recall": 0.928, "f1": 0.930, "specificity": 0.767, "total_flows": 22428},
        },
        "family_aware_metrics": {
            "deployed_hybrid": {**{"confusion_matrix": {"tp": 256, "fp": 41, "tn": 3, "fn": 9}, "accuracy": 0.838, "precision": 0.862, "recall": 0.966, "f1": 0.911, "specificity": 0.068, "total_flows": 309}, "specialty_scenarios": ["ICMP flood", "SYN flood", "UDP flood", "HTTP flood", "Port scan"]},
            "connection_family": {**{"confusion_matrix": {"tp": 130, "fp": 39, "tn": 5, "fn": 5}, "accuracy": 0.754, "precision": 0.769, "recall": 0.963, "f1": 0.855, "specificity": 0.114, "total_flows": 179}, "specialty_scenarios": ["HTTP flood", "Port scan"]},
            "v8_candidate": {**{"confusion_matrix": {"tp": 16165, "fp": 1163, "tn": 3837, "fn": 1263}, "accuracy": 0.892, "precision": 0.933, "recall": 0.928, "f1": 0.930, "specificity": 0.767, "total_flows": 22428}, "specialty_scenarios": ["ICMP flood", "SYN flood", "UDP flood", "HTTP flood", "Port scan"]},
        },
    }


class RunRequest(BaseModel):
    trials: int = 5


class SimRunState:
    def __init__(self):
        self.running = False
        self.started_at = 0.0
        self.trials = 0
        self.out_dir = ""
        self.duration = 0.0
        self.exit_code = 0
        self.log_tail = ""
        self.finished = False

sim_run = SimRunState()

SIM_SCENARIOS = [
    {"log": "Initializing loopback capture on 127.0.0.1...", "attack": False, "flows": 0},
    {"log": "Running benign baseline (44 flows)...", "attack": False, "flows": 6},
    {"log": "Running ICMP flood scenario (46 flows)...", "attack": True, "flows": 6, "label": "ICMP flood"},
    {"log": "Running SYN flood scenario (44 flows)...", "attack": True, "flows": 5, "label": "SYN flood"},
    {"log": "Running UDP flood scenario (40 flows)...", "attack": True, "flows": 5, "label": "UDP flood"},
    {"log": "Running HTTP flood scenario (42 flows)...", "attack": True, "flows": 5, "label": "HTTP flood"},
    {"log": "Running port scan scenario (93 flows)...", "attack": True, "flows": 8, "label": "Port scan"},
    {"log": "Scoring all flows against 11 models...", "attack": False, "flows": 0},
    {"log": "Computing aggregate metrics...", "attack": False, "flows": 0},
    {"log": "Simulation completed successfully. 6 scenarios evaluated.", "attack": False, "flows": 0},
]

def _make_sim_flow(is_attack, label=None):
    flow_id = state.total_flows + 1
    if is_attack:
        src_ip = random.choice(ATTACK_IPS)
        dst_ip = "192.168.1.50"
        xgb_prob = round(random.uniform(0.70, 0.99), 4)
        iso_pred = 1 if random.random() < 0.75 else 0
    else:
        src_ip = random.choice(DEMO_IPS)
        dst_ip = "192.168.1.50"
        xgb_prob = round(random.uniform(0.01, 0.30), 4)
        iso_pred = 0
    xgb_pred = 1 if xgb_prob >= 0.495 else 0
    iso_score = random.uniform(0.6, 0.95) if iso_pred == 1 else random.uniform(0.05, 0.4)
    confidence_score = round(0.7 * xgb_prob + 0.3 * iso_score, 4)
    hybrid = 1 if confidence_score >= 0.55 else 0
    detected = hybrid == 1
    shap_features = _generate_shap_features(detected)
    avg_impact = sum(abs(f["impact"]) for f in shap_features) / len(shap_features)
    confidence = "HIGH" if avg_impact > 0.5 else ("MEDIUM" if avg_impact > 0.2 else "LOW")
    hypothesis = f"{label} detected — high-rate traffic pattern" if label and detected else "Normal network communication"
    result = {
        "flow_id": flow_id, "source_ip": src_ip, "destination_ip": dst_ip,
        "packet_count": random.randint(10, 500), "duration": round(random.uniform(0.1, 5.0), 3),
        "timestamp": time.time(), "xgb_probability": xgb_prob, "xgb_prediction": xgb_pred,
        "isolation_prediction": iso_pred, "hybrid_prediction": hybrid, "drift_detected": False,
        "agent_analysis": {
            "response": {"threat_level": "HIGH" if detected else "LOW", "action": "BLOCK SOURCE IP" if detected else "CONTINUE MONITORING", "reason": f"{label} from {src_ip}" if label and detected else "Normal traffic", "alert": detected},
            "explanation": {"top_features": shap_features, "confidence": confidence, "attack_hypothesis": hypothesis, "summary": f"{'Malicious' if detected else 'Benign'} flow from {src_ip}", "reasoning": [f"{f['feature']}: impact {f['impact']}" for f in shap_features[:3]], "detailed_report": [f"Flow {flow_id}: {src_ip} -> {dst_ip}", f"Detection: XGBoost={xgb_prob:.2%}", f"Verdict: {'ATTACK' if detected else 'NORMAL'}"]},
            "drift": {"status": "MODEL STABLE", "severity": "NONE", "trend": "Stable", "recommendation": "No action needed"},
            "memory": {"pattern": "SIMULATION RUN", "risk": "LOW", "confidence": "HIGH", "flows_in_memory": 0, "recent_attacks": 0, "repeated_sources": [], "recommendation": "Simulation in progress"},
            "consensus": {"score": random.randint(80, 100), "agreement": "FULL"},
            "incident_report": {"verdict": "ATTACK DETECTED" if detected else "NORMAL TRAFFIC", "confidence": confidence, "summary": f"Sim flow {flow_id}: {hypothesis}"},
        },
        "_analysis_detail": {
            "explanation": hypothesis, "severity": "high" if detected else "low",
            "recommended_mitigation": [f"Block {src_ip}"] if detected else ["Continue monitoring"],
            "business_impact": "Simulation test", "soc_analyst_summary": f"Sim flow #{flow_id}",
            "incident_report": {"title": f"Sim — {label or 'Benign'} flow #{flow_id}", "affected_asset": dst_ip, "evidence": [f"XGBoost: {xgb_prob:.2%}"], "recommended_next_step": "Review"},
            "model_name": "V8 XGBoost + Isolation Forest Hybrid",
            "memory_agent_result": {"summary": "Simulation run", "similar_incidents": 0, "pattern_detected": False, "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        },
    }
    return result

def _sim_worker():
    sim_run.log_tail = ""
    total = sim_run.duration
    per_step = total / len(SIM_SCENARIOS)
    for i, scenario in enumerate(SIM_SCENARIOS):
        time.sleep(per_step)
        sim_run.log_tail = "\n".join(s["log"] for s in SIM_SCENARIOS[: i + 1])
        for _ in range(scenario["flows"]):
            result = _make_sim_flow(scenario["attack"], scenario.get("label"))
            state.record_result(result)
            state.broadcast_soon(_build_ws_payload(result))
            time.sleep(0.15)
    sim_run.running = False
    sim_run.exit_code = 0
    sim_run.finished = True


@app.post("/simulations/run")
def start_simulation(req: RunRequest):
    sim_run.running = True
    sim_run.started_at = time.time()
    sim_run.trials = req.trials
    sim_run.out_dir = "simulations/demo_run"
    sim_run.duration = min(req.trials * 3, 15)
    sim_run.exit_code = 0
    sim_run.log_tail = ""
    sim_run.finished = False
    threading.Thread(target=_sim_worker, daemon=True).start()
    return {"status": "started", "out_dir": sim_run.out_dir, "trials": req.trials}


@app.get("/simulations/run/status")
def simulation_status():
    elapsed = time.time() - sim_run.started_at if sim_run.started_at else 0
    return {
        "running": sim_run.running,
        "out_dir": sim_run.out_dir or "simulations/demo_run",
        "trials": sim_run.trials or 5,
        "started_at": sim_run.started_at or time.time() - 120,
        "elapsed_seconds": round(elapsed, 1) if sim_run.running else round(sim_run.duration, 1),
        "exit_code": sim_run.exit_code,
        "log_tail": sim_run.log_tail or "Simulation completed successfully. 6 scenarios evaluated.",
    }


@app.post("/simulations/run/cancel")
def cancel_simulation():
    if sim_run.running:
        sim_run.running = False
        sim_run.exit_code = 1
        sim_run.log_tail += "\nSimulation cancelled by user."
        sim_run.finished = True
        return {"status": "cancelled"}
    return {"status": "no simulation running"}


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    state.add_client(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        state.remove_client(websocket)
