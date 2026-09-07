"""Guards detection/fast_isolation_forest.py against ever silently
diverging from sklearn's real IsolationForest.decision_function()/
.predict() - both the deployed hybrid model's isolation_forest.pkl and
every family model's isolation_forest.pkl are checked. If this ever
fails after a scikit-learn upgrade, fast_isolation_forest.py's internal
attribute access (model._decision_path_lengths etc.) has drifted from
that version's real implementation and needs updating to match."""

import numpy as np
import pandas as pd

from detection import fast_isolation_forest
from detection.predictor import isolation_forest as deployed_iso, scaler as deployed_scaler, top_features as deployed_features
from detection.experimental_models import family_models

RNG = np.random.RandomState(42)


def _check_model(name, model, scaler, feature_names, n_rows=200):
    max_diff = 0.0
    for _ in range(n_rows):
        scale = RNG.choice([0, 1, 100, 1e6])
        row = {f: float(RNG.uniform(-scale, scale)) if scale else 0.0 for f in feature_names}
        df = pd.DataFrame([row], columns=feature_names)
        scaled = scaler.transform(df) if scaler is not None else df.values

        real_score = model.decision_function(scaled)
        fast_score = fast_isolation_forest.decision_function(model, scaled)
        max_diff = max(max_diff, float(np.max(np.abs(real_score - fast_score))))

        real_pred = model.predict(scaled)
        fast_pred = fast_isolation_forest.predict(model, scaled)
        assert np.array_equal(real_pred, fast_pred), (
            f"{name}: predict() sign mismatch (real={real_pred}, fast={fast_pred})"
        )

    assert max_diff < 1e-9, f"{name}: decision_function diverged, max abs diff={max_diff}"
    print(f"{name}: OK (max abs diff over {n_rows} rows: {max_diff})")


_check_model("deployed_hybrid isolation_forest", deployed_iso, deployed_scaler, deployed_features)

for _fname, _fmodel in family_models.items():
    _check_model(
        f"family[{_fname}] isolation_forest",
        _fmodel["isolation"],
        _fmodel["scaler"],
        _fmodel["top_features"],
    )

# batch (multi-row) sanity check on the deployed model
_rows = [{f: float(RNG.uniform(-1000, 1000)) for f in deployed_features} for _ in range(10)]
_df = pd.DataFrame(_rows, columns=deployed_features)
_scaled = deployed_scaler.transform(_df)
_real = deployed_iso.decision_function(_scaled)
_fast = fast_isolation_forest.decision_function(deployed_iso, _scaled)
assert np.max(np.abs(_real - _fast)) < 1e-9, "batch (multi-row) decision_function diverged"
print("batch (10-row) decision_function: OK")

print("\nFAST ISOLATION FOREST TEST PASSED")
