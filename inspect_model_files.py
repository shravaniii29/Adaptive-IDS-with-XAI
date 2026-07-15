from pathlib import Path

MODELS_DIR = Path("models")

model_files = [
    "xgb_model.pkl",
    "isolation_forest.pkl",
    "scaler.pkl",
    "threshold.pkl",
    "top_features.pkl",
]

for model_file in model_files:

    path = MODELS_DIR / model_file

    print("=" * 60)
    print("FILE:", model_file)
    print("SIZE:", path.stat().st_size, "bytes")

    with open(path, "rb") as file:
        first_bytes = file.read(20)

    print("FIRST BYTES:", first_bytes)