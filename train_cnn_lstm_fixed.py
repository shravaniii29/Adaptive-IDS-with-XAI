"""
Re-run of the CNN+LSTM experiment from Major Project/CNN+LSTM.ipynb with
the sequencing bug fixed.

What was wrong: the notebook's cell 4 correctly built sliding-window
sequences grouped by flow_key = Src IP + "_" + Protocol (one attacker's
own flow history over time), with the sequence label taken as the
majority label within the window. But a later, unrelated cell (cell 6)
silently re-built X_seq/y_seq from the flat, globally-timestamp-sorted
table with NO grouping - each "sequence" was just 10 consecutive rows
from whichever hosts happened to be interleaved in the capture at that
moment, unrelated to each other. That overwritten, ungrouped version is
what actually got trained on.

This script revives the original grouped design (verbatim: same flow_key,
same window length, same majority-label rule) and, just as important,
splits train/test by flow_key rather than by row so no sequence's own
history leaks across the split - a coherent "one attacker's behavior over
time" comparison.

Data availability note: CIC-IDS2018's official release only keeps Src IP
on ONE of the seven days used in the original notebook (Tuesday
02-20-2018 - the rest have Src IP/Dst IP/Flow ID stripped). Per-source
sequencing is only meaningful where source identity exists, so this
re-run uses only that day, sampled from four spread-out byte offsets
across the ~3.8GB file (not just the first chunk, which turned out to
land entirely inside one DDoS burst - 99.9% attack, 32 source IPs).

Reports two numbers on an identical, source-IP-held-out split:
  1. CNN+LSTM on properly-grouped 10-step sequences (the fixed version)
  2. XGBoost on the same 8 features, single-flow-at-a-time, no sequence
This isolates whether the sequence/temporal modeling itself adds value,
holding data, features, and the train/test split constant.
"""

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix,
)
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
from xgboost import XGBClassifier

from pathlib import Path

DATA_PATH = Path(__file__).resolve().parent / "data" / "cicids2018" / "02-20-2018.csv"
SEQUENCE_LENGTH = 10
FEATURE_ORDER = [
    "Flow Duration", "Tot Fwd Pkts", "TotLen Fwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "Avg Pkt Size", "Min Pkt Size", "Protocol",
]

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class CNN_LSTM(nn.Module):
    def __init__(self, n_features=8, seq_len=SEQUENCE_LENGTH):
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


def load_and_clean():
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df[df["Label"] != "Label"].reset_index(drop=True)

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    df["Binary_Label"] = df["Label"].apply(lambda x: 0 if str(x).strip().lower() == "benign" else 1)

    for col in ["TotLen Fwd Pkts", "Tot Fwd Pkts", "Fwd Pkt Len Min", "Flow Duration",
                "Flow Byts/s", "Flow Pkts/s", "Protocol"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df["Avg Pkt Size"] = df["TotLen Fwd Pkts"] / df["Tot Fwd Pkts"].replace(0, 1)
    df["Min Pkt Size"] = df["Fwd Pkt Len Min"]

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_ORDER + ["Src IP"])
    return df


def build_grouped_sequences(df):
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df["flow_key"] = df["Src IP"].astype(str) + "_" + df["Protocol"].astype(str)

    sequences, labels, keys = [], [], []
    for key, group in df.groupby("flow_key"):
        group = group.reset_index(drop=True)
        X = group[FEATURE_ORDER].values
        y = group["Binary_Label"].values
        for i in range(len(X) - SEQUENCE_LENGTH + 1):
            sequences.append(X[i:i + SEQUENCE_LENGTH])
            labels.append(1 if y[i:i + SEQUENCE_LENGTH].mean() > 0.5 else 0)
            keys.append(key)

    return np.array(sequences), np.array(labels), np.array(keys)


def split_by_key(keys, test_frac=0.2, seed=42):
    unique_keys = np.unique(keys)
    rng = np.random.default_rng(seed)
    rng.shuffle(unique_keys)
    n_test = max(1, int(len(unique_keys) * test_frac))
    test_keys = set(unique_keys[:n_test])
    is_test = np.array([k in test_keys for k in keys])
    return ~is_test, is_test


def train_cnn_lstm(X_train, y_train):
    n_val_keys_frac = 0.2
    idx = np.arange(len(X_train))
    rng = np.random.default_rng(0)
    rng.shuffle(idx)
    split = int(len(idx) * (1 - n_val_keys_frac))
    tr_idx, val_idx = idx[:split], idx[split:]

    X_tr_t = torch.FloatTensor(X_train[tr_idx]).to(DEVICE)
    y_tr_t = torch.FloatTensor(y_train[tr_idx]).unsqueeze(1).to(DEVICE)
    X_val_t = torch.FloatTensor(X_train[val_idx]).to(DEVICE)
    y_val_t = torch.FloatTensor(y_train[val_idx]).unsqueeze(1).to(DEVICE)

    train_loader = DataLoader(TensorDataset(X_tr_t, y_tr_t), batch_size=256, shuffle=True)
    val_loader = DataLoader(TensorDataset(X_val_t, y_val_t), batch_size=256, shuffle=False)

    model = CNN_LSTM().to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    pos = y_train[tr_idx].sum()
    neg = len(tr_idx) - pos
    pos_weight = torch.tensor([neg / max(pos, 1)]).to(DEVICE)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss = float("inf")
    patience, counter = 3, 0
    best_state = None

    for epoch in range(1, 31):
        model.train()
        for xb, yb in train_loader:
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()

        model.eval()
        val_losses = []
        with torch.no_grad():
            for xb, yb in val_loader:
                val_losses.append(criterion(model(xb), yb).item())
        val_loss = float(np.mean(val_losses))
        print(f"  epoch {epoch}: val_loss={val_loss:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            counter = 0
        else:
            counter += 1
            if counter >= patience:
                print("  early stopping")
                break

    model.load_state_dict(best_state)
    return model


def evaluate_cnn_lstm(model, X_test, y_test):
    model.eval()
    with torch.no_grad():
        logits = model(torch.FloatTensor(X_test).to(DEVICE))
        probs = torch.sigmoid(logits).cpu().numpy().ravel()
    preds = (probs >= 0.5).astype(int)
    return preds, {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, zero_division=0),
        "recall": recall_score(y_test, preds, zero_division=0),
        "f1": f1_score(y_test, preds, zero_division=0),
    }


def main():
    print(f"device: {DEVICE}")
    print("loading + cleaning ...")
    df = load_and_clean()
    print(f"rows: {len(df)}  label balance: {df['Binary_Label'].value_counts().to_dict()}")
    print(f"unique Src IP: {df['Src IP'].nunique()}")

    print("\nbuilding per-source-IP grouped sequences (the fix) ...")
    X_seq, y_seq, keys = build_grouped_sequences(df)
    print(f"sequences: {X_seq.shape}  attack ratio: {y_seq.mean():.3f}  unique flow_keys: {len(np.unique(keys))}")

    train_mask, test_mask = split_by_key(keys)
    X_train, X_test = X_seq[train_mask], X_seq[test_mask]
    y_train, y_test = y_seq[train_mask], y_seq[test_mask]
    print(f"train sequences: {len(X_train)}  test sequences: {len(X_test)} (held-out flow_keys, zero overlap)")

    n_samples, seq_len, n_features = X_train.shape
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train.reshape(-1, n_features)).reshape(n_samples, seq_len, n_features)
    X_test_scaled = scaler.transform(X_test.reshape(-1, n_features)).reshape(X_test.shape[0], seq_len, n_features)

    print("\ntraining CNN+LSTM on properly-grouped sequences ...")
    model = train_cnn_lstm(X_train_scaled, y_train)
    _, cnn_lstm_metrics = evaluate_cnn_lstm(model, X_test_scaled, y_test)
    print("CNN+LSTM (fixed sequencing) test metrics:", cnn_lstm_metrics)

    print("\n--- baseline: XGBoost, same features, same train/test flow_key split, no sequence ---")
    df_idx = df.reset_index(drop=True)
    df_idx["flow_key"] = df_idx["Src IP"].astype(str) + "_" + df_idx["Protocol"].astype(str)
    row_train_mask = df_idx["flow_key"].isin(set(keys[train_mask]) & set(df_idx["flow_key"]))
    train_keys_set = set(np.unique(keys[train_mask]))
    test_keys_set = set(np.unique(keys[test_mask]))
    row_train = df_idx[df_idx["flow_key"].isin(train_keys_set)]
    row_test = df_idx[df_idx["flow_key"].isin(test_keys_set)]

    Xr_train, yr_train = row_train[FEATURE_ORDER], row_train["Binary_Label"]
    Xr_test, yr_test = row_test[FEATURE_ORDER], row_test["Binary_Label"]

    xgb = XGBClassifier(n_estimators=200, max_depth=5, eval_metric="logloss", random_state=42)
    xgb.fit(Xr_train, yr_train)
    yr_pred = xgb.predict(Xr_test)
    xgb_metrics = {
        "accuracy": accuracy_score(yr_test, yr_pred),
        "precision": precision_score(yr_test, yr_pred, zero_division=0),
        "recall": recall_score(yr_test, yr_pred, zero_division=0),
        "f1": f1_score(yr_test, yr_pred, zero_division=0),
    }
    print("XGBoost (no sequence, same split) test metrics:", xgb_metrics)

    print("\n=== SUMMARY (identical source-IP-held-out split, same 8 features) ===")
    print(f"{'Model':<30}{'Accuracy':<10}{'Precision':<10}{'Recall':<10}{'F1':<10}")
    print(f"{'CNN+LSTM (fixed sequencing)':<30}{cnn_lstm_metrics['accuracy']:<10.4f}{cnn_lstm_metrics['precision']:<10.4f}{cnn_lstm_metrics['recall']:<10.4f}{cnn_lstm_metrics['f1']:<10.4f}")
    print(f"{'XGBoost (no sequence)':<30}{xgb_metrics['accuracy']:<10.4f}{xgb_metrics['precision']:<10.4f}{xgb_metrics['recall']:<10.4f}{xgb_metrics['f1']:<10.4f}")


if __name__ == "__main__":
    main()
