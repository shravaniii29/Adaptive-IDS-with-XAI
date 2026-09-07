"""Drop-in replacement for sklearn IsolationForest.decision_function()/
.predict() that skips joblib's per-tree Parallel() dispatch.

Why: sklearn's own _compute_score_samples wraps one delayed() call PER
TREE (500 trees per model here) through Parallel(require="sharedmem") -
already forced to a low-overhead threading backend by sklearn itself
(IsolationForest.predict()'s own docstring: "This inherently does NOT
use the n_jobs parameter... predict may actually be faster without
parallelization for a small number of samples"), so setting n_jobs on
the model has no effect here. Profiling one live detect() call found
this dispatch overhead - not multiprocessing, not actual tree
computation - the dominant cost, at ~500ms across the multiple 500-tree
IsolationForest models (deployed hybrid + 3 family models) scored per
flow: joblib's per-task submission cost for 500 trivial tasks (each
just an .apply() leaf lookup) swamps the ~0.1ms of real work per task.

This calls the same underlying tree.apply() + precomputed path-length
lookup in a plain Python loop instead - mathematically identical to
IsolationForest._compute_score_samples (same formula, same precomputed
model._decision_path_lengths/_average_path_length_per_tree arrays), just
without paying joblib's dispatch cost for each of 500 trees. Verified
bit-exact (0.0 max abs diff) against the real decision_function()/
predict() output across 200+ random rows spanning zeros, extremes, and
both single-row and batch inputs - see tests/test_fast_isolation_forest.py.

If sklearn's internal IsolationForest layout ever changes (a version
bump touching _iforest.py's private attributes), this will raise an
AttributeError rather than silently diverging - that test module is the
guard against this having silently drifted from correct."""

import numpy as np
from sklearn.ensemble._iforest import _average_path_length


def decision_function(model, X):
    """Numerically identical to model.decision_function(X), without
    joblib's per-tree dispatch overhead."""

    X = np.asarray(X, dtype=np.float32)

    subsample_features = model._max_features != X.shape[1]

    depths = np.zeros(X.shape[0], order="f")

    for tree_idx, (tree, features) in enumerate(
        zip(model.estimators_, model.estimators_features_)
    ):
        X_subset = X[:, features] if subsample_features else X

        leaves_index = tree.tree_.apply(X_subset)

        depths += (
            model._decision_path_lengths[tree_idx][leaves_index]
            + model._average_path_length_per_tree[tree_idx][leaves_index]
            - 1.0
        )

    average_path_length_max_samples = _average_path_length([model._max_samples])

    denominator = len(model.estimators_) * average_path_length_max_samples

    scores = 2 ** (
        -np.divide(
            depths, denominator, out=np.ones_like(depths), where=denominator != 0
        )
    )

    return -scores - model.offset_


def predict(model, X):
    """Numerically identical to model.predict(X), without joblib's
    per-tree dispatch overhead."""

    scores = decision_function(model, X)

    is_inlier = np.ones_like(scores, dtype=int)

    is_inlier[scores < 0] = -1

    return is_inlier
