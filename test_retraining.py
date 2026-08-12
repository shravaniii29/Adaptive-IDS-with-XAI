from agents.retraining_agent import RetrainingAgent
from agents.drift_agent import DriftAgent

# Test 1 — No drift (retraining should not trigger)
print("\n" + "="*60)
print("TEST 1 — NO DRIFT")
print("="*60)
agent = RetrainingAgent()
fake_drift = {"status": "MODEL STABLE", "drift_ratio": 0.0}
result = agent.analyze(fake_drift)
print(f"Retraining triggered: {result['retraining_triggered']} (expected False) ✅")

# Test 2 — Drift detected (retraining should start)
print("\n" + "="*60)
print("TEST 2 — DRIFT DETECTED")
print("="*60)
agent2 = RetrainingAgent()
fake_drift_high = {"status": "MODEL DEGRADING", "drift_ratio": 0.45}
result2 = agent2.analyze(fake_drift_high)
print(f"\nResult: {result2}")

# Test 3 — Bad candidate rejected
print("\n" + "="*60)
print("TEST 3 — BAD CANDIDATE")
print("="*60)
current   = {"recall": 0.90, "f1": 0.88}
candidate = {"recall": 0.80, "f1": 0.75}
accepted  = agent2._should_accept(current, candidate)
print(f"Candidate accepted: {accepted} (expected False) ✅")

# Test 4 — Good candidate accepted
print("\n" + "="*60)
print("TEST 4 — GOOD CANDIDATE")
print("="*60)
current   = {"recall": 0.80, "f1": 0.78}
candidate = {"recall": 0.82, "f1": 0.80}
accepted  = agent2._should_accept(current, candidate)
print(f"Candidate accepted: {accepted} (expected True) ✅")