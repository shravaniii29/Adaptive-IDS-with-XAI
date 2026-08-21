"""
Three-way comparison of how much temporal context helps flow classification,
using only information a live attack simulation could actually produce -
no Src IP, no dataset-only identity columns.

Design (see conversation for the reasoning that led here):
  - Grouping key for "recent history" is (Dst Port, Protocol) - something
    your live FlowManager could genuinely track in real time, unlike a
    database of past attacker source IPs.
  - Train/test split is CHRONOLOGICAL, not held-out-by-identity: train on
    the earlier portion of the day, test on a later portion. This matches
    how the deployed system is actually used (classify what comes next,
    given real past history) and sidesteps a fatal confound discovered
    along the way - in this dataset, (Dst Port=80, Protocol=6) is almost
    perfectly correlated with the attack label (77.6% of all attack rows),
    so holding out *that* group entirely makes evaluation meaningless in
    either direction.
  - The attack window is only ~7 minutes wide, so the split cutoff is
    placed at the 70th percentile of ATTACK timestamps specifically (not
    all data), so both train and test contain a real, non-degenerate mix
    of benign and attack examples.
  - All three variants predict the SAME target (the anchor flow's own
    label) over the SAME set of held-out anchor rows - only the feature
    representation differs, which is what isolates whether temporal
    context helps and whether it needs a sequence architecture to exploit.

Variants:
  1. XGBoost, single-flow only (matches what's deployed today)
  2. XGBoost, single-flow + engineered rolling-history features over the
     same (Dst Port, Protocol) group (temporal info, no sequence model)
  3. CNN+LSTM, raw 10-step sequence over the same group (temporal info,
     sequence-native architecture)
"""

from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from torch.utils.data import DataLoader, TensorDataset
from xgboost import XGBClassifier

DATA_PATH = Path(__file__).resolve().parent / "data" / "cicids2018" / "02-20-2018.csv"
SEQUENCE_LENGTH = 10
BASE_FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol",
]
GROUP_KEYS = ["Dst Port", "Protocol"]
DEVICE = torch.device("cpu")


def load_and_clean():
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df["Label"] != "Label"].reset_index(drop=True)

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["Timestamp"])
    df["Binary_Label"] = df["Label"].apply(lambda x: 0 if str(x).strip().lower() == "benign" else 1)

    for col in ["TotLen Fwd Pkts", "Tot Fwd Pkts", "Fwd Pkt Len Min", "Flow Duration",
                "Flow Byts/s", "Flow Pkts/s", "Protocol", "Dst Port"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["Avg Pkt Size"] = df["TotLen Fwd Pkts"] / df["Tot Fwd Pkts"].replace(0, 1)
    df["Min Pkt Size"] = df["Fwd Pkt Len Min"]

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=BASE_FEATURES + GROUP_KEYS)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    return df


def chronological_cutoff(df):
    attack_times = df.loc[df["Binary_Label"] == 1, "Timestamp"]
    return attack_times.quantile(0.7)


def build_temporal_features(df):
    """Rolling stats over strictly PRIOR flows in the same (Dst Port, Protocol) group."""
    df = df.copy()

    for col in ["Flow Pkts/s", "Flow Byts/s", "Flow Duration", "TotLen Fwd Pkts"]:
        roll = df.groupby(GROUP_KEYS)[col].apply(lambda s: s.shift(1).rolling(SEQUENCE_LENGTH, min_periods=1).mean())
        df[f"hist_mean_{col.replace('/', '_').replace(' ', '_')}"] = roll.reset_index(level=list(range(len(GROUP_KEYS))), drop=True)
        roll_std = df.groupby(GROUP_KEYS)[col].apply(lambda s: s.shift(1).rolling(SEQUENCE_LENGTH, min_periods=1).std())
        df[f"hist_std_{col.replace('/', '_').replace(' ', '_')}"] = roll_std.reset_index(level=list(range(len(GROUP_KEYS))), drop=True)

    df["hist_flow_count"] = df.groupby(GROUP_KEYS).cumcount()
    df["time_since_last"] = (
        df["Timestamp"] - df.groupby(GROUP_KEYS)["Timestamp"].shift(1)
    ).dt.total_seconds()

    hist_cols = [c for c in df.columns if c.startswith("hist_") or c == "time_since_last"]
    df[hist_cols] = df[hist_cols].fillna(0)
    df["hist_flow_count"] = df["hist_flow_count"].clip(upper=SEQUENCE_LENGTH)

    return df, hist_cols


def build_raw_sequences(df):
    """For every row, the raw feature vectors of up to the last 10 flows
    in the same group (itself included, as the last step), zero-padded
    at the front if fewer than 10 are available."""
    sequences = np.zeros((len(df), SEQUENCE_LENGTH, len(BASE_FEATURES)), dtype=np.float32)
    feat_matrix = df[BASE_FEATURES].values.astype(np.float32)

    for _, group_idx in df.groupby(GROUP_KEYS).groups.items():
        group_idx = list(group_idx)
        for pos, row_idx in enumerate(group_idx):
            local_positions = df.index.get_indexer(group_idx[max(0, pos - SEQUENCE_LENGTH + 1):pos + 1])
            window = feat_matrix[local_positions]
            sequences[df.index.get_loc(row_idx), -len(window):] = window

    return sequences


class CNN_LSTM(nn.Module):
    def __init__(self, n_features, seq_len=SEQUENCE_LENGTH):
        super().__init__()
        self.conv1 = nn.Conv1d(in_channels=n_features, out_channels=32, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.lstm = nn.LSTM(input_size=32, hidden_size=64, batch_first=True)
        self.fc = nn.Linear(64, 1)

    def forward(self, x):
        x = x.permute(0, 2, 1)
        x = self.relu(self.conv1(x))
        x = x.permute(0, 2, 1)
        _, (h, _) = self.lstm(x)
        return self.fc(h.squeeze(0))


def train_cnn_lstm(X_train, y_train):
    idx = np.arange(len(X_train))
    rng = np.random.default_rng(0)
    rng.shuffle(idx)
    split = int(len(idx) * 0.8)
    tr_idx, val_idx = idx[:split], idx[split:]

    X_tr_t = torch.FloatTensor(X_train[tr_idx])
    y_tr_t = torch.FloatTensor(y_train[tr_idx]).unsqueeze(1)
    X_val_t = torch.FloatTensor(X_train[val_idx])
    y_val_t = torch.FloatTensor(y_train[val_idx]).unsqueeze(1)

    train_loader = DataLoader(TensorDataset(X_tr_t, y_tr_t), batch_size=256, shuffle=True)
    val_loader = DataLoader(TensorDataset(X_val_t, y_val_t), batch_size=256, shuffle=False)

    model = CNN_LSTM(n_features=X_train.shape[2])
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    pos = y_train[tr_idx].sum()
    neg = len(tr_idx) - pos
    pos_weight = torch.tensor([neg / max(pos, 1)])
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss, patience, counter, best_state = float("inf"), 3, 0, None
    for epoch in range(1, 31):
        model.train()
        for xb, yb in train_loader:
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            val_loss = float(np.mean([criterion(model(xb), yb).item() for xb, yb in val_loader]))
        print(f"    epoch {epoch}: val_loss={val_loss:.4f}")
        if val_loss < best_val_loss:
            best_val_loss, best_state, counter = val_loss, {k: v.clone() for k, v in model.state_dict().items()}, 0
        else:
            counter += 1
            if counter >= patience:
                print("    early stopping")
                break
    model.load_state_dict(best_state)
    return model


def eval_metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def main():
    print("loading + cleaning ...")
    df = load_and_clean()
    print(f"rows: {len(df)}  label balance: {df['Binary_Label'].value_counts().to_dict()}")

    cutoff = chronological_cutoff(df)
    print(f"chronological cutoff (70th pct of attack timestamps): {cutoff}")
    train_mask = (df["Timestamp"] < cutoff).values
    test_mask = ~train_mask
    print(f"train: {train_mask.sum()} rows ({df.loc[train_mask,'Binary_Label'].mean():.3f} attack ratio)")
    print(f"test:  {test_mask.sum()} rows ({df.loc[test_mask,'Binary_Label'].mean():.3f} attack ratio)")

    y = df["Binary_Label"].values

    # ---------- Variant 1: XGBoost, single-flow only ----------
    print("\n--- Variant 1: XGBoost, single-flow only ---")
    X1 = df[BASE_FEATURES]
    xgb1 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb1.fit(X1[train_mask], y[train_mask])
    pred1 = xgb1.predict(X1[test_mask])
    m1 = eval_metrics(y[test_mask], pred1)
    print("metrics:", m1)

    # ---------- Variant 2: XGBoost, single-flow + engineered temporal features ----------
    print("\n--- Variant 2: XGBoost, single-flow + engineered temporal (Dst Port, Protocol) history ---")
    df2, hist_cols = build_temporal_features(df)
    X2 = df2[BASE_FEATURES + hist_cols]
    xgb2 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb2.fit(X2[train_mask], y[train_mask])
    pred2 = xgb2.predict(X2[test_mask])
    m2 = eval_metrics(y[test_mask], pred2)
    print("engineered feature columns:", hist_cols)
    print("metrics:", m2)

    # ---------- Variant 3: CNN+LSTM, raw sequence ----------
    print("\n--- Variant 3: CNN+LSTM, raw 10-step (Dst Port, Protocol) sequence ---")
    X3_seq = build_raw_sequences(df)
    from sklearn.preprocessing import StandardScaler
    n, seq_len, n_feat = X3_seq.shape
    scaler = StandardScaler().fit(X3_seq[train_mask].reshape(-1, n_feat))
    X3_scaled = scaler.transform(X3_seq.reshape(-1, n_feat)).reshape(n, seq_len, n_feat)

    print("  training ...")
    model3 = train_cnn_lstm(X3_scaled[train_mask], y[train_mask])
    model3.eval()
    with torch.no_grad():
        logits = model3(torch.FloatTensor(X3_scaled[test_mask]))
        probs = torch.sigmoid(logits).numpy().ravel()
    pred3 = (probs >= 0.5).astype(int)
    m3 = eval_metrics(y[test_mask], pred3)
    print("metrics:", m3)

    print("\n=== SUMMARY (identical chronological split, identical anchor rows/targets) ===")
    rows = [
        ("1. XGBoost, single-flow only", m1),
        ("2. XGBoost, single-flow + temporal features", m2),
        ("3. CNN+LSTM, raw sequence", m3),
    ]
    print(f"{'Variant':<45}{'Accuracy':<10}{'Precision':<10}{'Recall':<10}{'F1':<10}")
    for name, m in rows:
        print(f"{name:<45}{m['accuracy']:<10.4f}{m['precision']:<10.4f}{m['recall']:<10.4f}{m['f1']:<10.4f}")


if __name__ == "__main__":
    main()
