"""
Multi-day version of train_three_way_comparison.py.

The single-day version (02-20-2018, DDoS-LOIC-HTTP only) turned out to
have a degenerate shortcut: every attack row had TotLen Fwd Pkts == 20.0
exactly (LOIC-HTTP's fixed request payload), so XGBoost keyed off that
one feature (importance 0.9999) and hit a perfect but meaningless
ceiling. Combining multiple days with different attack tools closes
that shortcut - no single fixed-payload trick works across FTP brute
force, GoldenEye, Slowloris, SlowHTTPTest, Hulk, LOIC-HTTP, HOIC,
LOIC-UDP, Web/XSS brute force, and SQL injection simultaneously.

All 7 downloaded CIC-IDS2018 day samples have Dst Port + Protocol
(only one day - 02-20 - additionally has Src IP, which is why the
earlier per-source-IP version was limited to that single day). Since
sequencing/grouping now uses (day, Dst Port, Protocol) instead of
source identity, all 7 days can be used.

Per-day chronological split: each day gets its own 70/30 split at the
70th percentile of THAT day's attack timestamps (mirrors the single-day
version), so every attack type is represented in both train and test -
this tests "recognize more of an ongoing campaign", not zero-shot
detection of a completely unseen attack type. Splits are then
concatenated across days into one combined train/test set.

Reports feature importances for variant 1 as a built-in diagnostic -
a single feature above ~0.5 importance is the same red flag found
before and should be investigated before trusting the result.
"""

from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
from xgboost import XGBClassifier

DATA_DIR = Path(__file__).resolve().parent / "data" / "cicids2018"
DAY_FILES = [
    "02-14-2018.csv", "02-15-2018.csv", "02-16-2018.csv", "02-20-2018.csv",
    "02-21-2018.csv", "02-22-2018.csv", "02-23-2018.csv",
]
SEQUENCE_LENGTH = 10
BASE_FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol",
]
GROUP_KEYS = ["day", "Dst Port", "Protocol"]
DEVICE = torch.device("cpu")


def load_one_day(path):
    df = pd.read_csv(path, low_memory=False)
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

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=BASE_FEATURES + ["Dst Port"])
    df["day"] = path.stem
    return df.sort_values("Timestamp").reset_index(drop=True)


def load_all_days():
    frames = [load_one_day(DATA_DIR / f) for f in DAY_FILES]
    return frames


def per_day_split(day_df):
    """70th percentile of THAT day's attack timestamps as the cutoff.
    Falls back to an 80/20 row split if a day has too few/no attacks
    for a meaningful attack-based cutoff."""
    attacks = day_df.loc[day_df["Binary_Label"] == 1, "Timestamp"]
    if len(attacks) < 20:
        cutoff = day_df["Timestamp"].quantile(0.8)
    else:
        cutoff = attacks.quantile(0.7)
    train_mask = (day_df["Timestamp"] < cutoff).values
    return train_mask, ~train_mask


def build_dataset():
    frames = load_all_days()
    train_parts, test_parts = [], []
    for day_df in frames:
        tr, te = per_day_split(day_df)
        day_df = day_df.assign(is_test=te)
        train_parts.append(day_df[tr])
        test_parts.append(day_df[te])
        atk = day_df["Binary_Label"]
        print(f"  {day_df['day'].iloc[0]}: {len(day_df)} rows, "
              f"train={tr.sum()} (attack={atk[tr].sum()}), test={te.sum()} (attack={atk[te].sum()})")

    df = pd.concat(train_parts + test_parts, ignore_index=True)
    train_mask = np.concatenate([np.ones(len(p), dtype=bool) for p in train_parts] +
                                 [np.zeros(len(p), dtype=bool) for p in test_parts])
    return df, train_mask, ~train_mask


def build_temporal_features(df):
    """Rolling stats over strictly PRIOR flows in the same (day, Dst Port, Protocol) group.
    Vectorized: shift(1) then a Cython-level groupby().rolling(), no per-group Python callback."""
    df = df.sort_values(["day", "Dst Port", "Protocol", "Timestamp"]).reset_index(drop=True)
    grp = df.groupby(GROUP_KEYS, sort=False)

    hist_cols = []
    for col in ["Flow Pkts/s", "Flow Byts/s", "Flow Duration", "TotLen Fwd Pkts"]:
        shifted = grp[col].shift(1)
        df["_shifted"] = shifted
        roll = df.groupby(GROUP_KEYS)["_shifted"]
        mean_col = f"hist_mean_{col.replace('/', '_').replace(' ', '_')}"
        std_col = f"hist_std_{col.replace('/', '_').replace(' ', '_')}"
        df[mean_col] = roll.rolling(window=SEQUENCE_LENGTH, min_periods=1).mean().reset_index(level=list(range(len(GROUP_KEYS))), drop=True)
        df[std_col] = roll.rolling(window=SEQUENCE_LENGTH, min_periods=1).std().reset_index(level=list(range(len(GROUP_KEYS))), drop=True)
        hist_cols += [mean_col, std_col]
    df.drop(columns=["_shifted"], inplace=True)

    df["hist_flow_count"] = grp.cumcount().clip(upper=SEQUENCE_LENGTH)
    df["time_since_last"] = (df["Timestamp"] - grp["Timestamp"].shift(1)).dt.total_seconds()
    hist_cols += ["hist_flow_count", "time_since_last"]

    df[hist_cols] = df[hist_cols].fillna(0)
    return df, hist_cols


def build_raw_sequences(df):
    """Vectorized sliding window built from SEQUENCE_LENGTH-1 per-group
    shifts (groupby().shift(k), Cython-level) rather than a Python loop
    over every group. The original per-group-loop version scaled with
    the number of distinct (day, Dst Port, Protocol) groups, not just
    row count, and became the dominant cost once the dataset grew to
    include more/bigger days (tens of thousands of groups) - this
    approach does a fixed SEQUENCE_LENGTH-1 vectorized passes regardless
    of group count."""
    df = df.sort_values(["day", "Dst Port", "Protocol", "Timestamp"]).reset_index(drop=True)
    grp = df.groupby(GROUP_KEYS, sort=False)

    n = len(df)
    n_feat = len(BASE_FEATURES)
    sequences = np.zeros((n, SEQUENCE_LENGTH, n_feat), dtype=np.float32)

    # Step SEQUENCE_LENGTH - 1 (the last timestep) is the row's own
    # features - no shift needed.
    sequences[:, SEQUENCE_LENGTH - 1, :] = df[BASE_FEATURES].values.astype(np.float32)

    # Earlier timesteps are lag-k shifts within each group, k = 1..SEQUENCE_LENGTH-1.
    # A shift with no prior row (start of group / not enough history)
    # produces NaN, which correctly stays as the zero-padding.
    for lag in range(1, SEQUENCE_LENGTH):
        step = SEQUENCE_LENGTH - 1 - lag
        shifted = grp[BASE_FEATURES].shift(lag)
        sequences[:, step, :] = shifted.fillna(0.0).values.astype(np.float32)

    return sequences, df


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

    train_loader = DataLoader(TensorDataset(X_tr_t, y_tr_t), batch_size=512, shuffle=True)
    val_loader = DataLoader(TensorDataset(X_val_t, y_val_t), batch_size=512, shuffle=False)

    model = CNN_LSTM(n_features=X_train.shape[2])
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    pos = y_train[tr_idx].sum()
    neg = len(tr_idx) - pos
    pos_weight = torch.tensor([neg / max(pos, 1)])
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss, patience, counter, best_state = float("inf"), 3, 0, None
    for epoch in range(1, 21):
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
    print("loading + splitting each day ...")
    df, train_mask, test_mask = build_dataset()
    print(f"\ncombined: {len(df)} rows  train={train_mask.sum()}  test={test_mask.sum()}")
    print(f"train attack ratio: {df.loc[train_mask,'Binary_Label'].mean():.3f}")
    print(f"test attack ratio:  {df.loc[test_mask,'Binary_Label'].mean():.3f}")
    print(f"attack types present: {sorted(df.loc[df.Binary_Label==1,'Label'].unique())}")

    y = df["Binary_Label"].values

    # ---------- Variant 1: XGBoost, single-flow only ----------
    print("\n--- Variant 1: XGBoost, single-flow only ---")
    X1 = df[BASE_FEATURES]
    xgb1 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb1.fit(X1[train_mask], y[train_mask])
    pred1 = xgb1.predict(X1[test_mask])
    m1 = eval_metrics(y[test_mask], pred1)
    print("metrics:", m1)
    print("feature importances:")
    for name, imp in sorted(zip(BASE_FEATURES, xgb1.feature_importances_), key=lambda x: -x[1]):
        flag = "  <-- SHORTCUT WARNING" if imp > 0.5 else ""
        print(f"  {name}: {imp:.4f}{flag}")

    # ---------- Variant 2: XGBoost, single-flow + engineered temporal features ----------
    print("\n--- Variant 2: XGBoost, single-flow + engineered temporal (day, Dst Port, Protocol) history ---")
    df2, hist_cols = build_temporal_features(df)
    # re-derive masks in df2's (re-sorted) row order
    train_mask2 = df2["is_test"].values == False
    test_mask2 = ~train_mask2
    y2 = df2["Binary_Label"].values
    X2 = df2[BASE_FEATURES + hist_cols]
    xgb2 = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb2.fit(X2[train_mask2], y2[train_mask2])
    pred2 = xgb2.predict(X2[test_mask2])
    m2 = eval_metrics(y2[test_mask2], pred2)
    print("metrics:", m2)
    print("feature importances:")
    for name, imp in sorted(zip(BASE_FEATURES + hist_cols, xgb2.feature_importances_), key=lambda x: -x[1]):
        flag = "  <-- SHORTCUT WARNING" if imp > 0.5 else ""
        print(f"  {name}: {imp:.4f}{flag}")

    # ---------- Variant 3: CNN+LSTM, raw sequence ----------
    print("\n--- Variant 3: CNN+LSTM, raw 10-step (day, Dst Port, Protocol) sequence ---")
    X3_seq, df3 = build_raw_sequences(df)
    train_mask3 = df3["is_test"].values == False
    test_mask3 = ~train_mask3
    y3 = df3["Binary_Label"].values

    n, seq_len, n_feat = X3_seq.shape
    scaler = StandardScaler().fit(X3_seq[train_mask3].reshape(-1, n_feat))
    X3_scaled = scaler.transform(X3_seq.reshape(-1, n_feat)).reshape(n, seq_len, n_feat)

    print("  training ...")
    model3 = train_cnn_lstm(X3_scaled[train_mask3], y3[train_mask3])
    model3.eval()
    with torch.no_grad():
        logits = model3(torch.FloatTensor(X3_scaled[test_mask3]))
        probs = torch.sigmoid(logits).numpy().ravel()
    pred3 = (probs >= 0.5).astype(int)
    m3 = eval_metrics(y3[test_mask3], pred3)
    print("metrics:", m3)

    print("\n=== SUMMARY (multi-day, multi-attack-type, identical per-day chronological splits) ===")
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
