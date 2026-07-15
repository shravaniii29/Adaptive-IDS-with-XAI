import pandas as pd


CSV_PATH = r"C:\Shravani Data\Study\ENGINEERING\TE\SEM 6\Major Project\archive\02-14-2018.csv"


TIMING_FEATURES = [
    "Flow Duration",
    "Flow IAT Max",
    "Flow IAT Mean",
    "Flow IAT Min",
    "Flow IAT Std",
    "Fwd IAT Tot",
    "Fwd IAT Max",
    "Fwd IAT Mean",
]


print("Loading training data sample...\n")

df = pd.read_csv(
    CSV_PATH,
    nrows=10000
)

# Remove accidental spaces from CICIDS column names
df.columns = df.columns.str.strip()


print("=" * 70)
print("TRAINING FEATURE UNIT INSPECTION")
print("=" * 70)

for feature in TIMING_FEATURES:

    print(f"\nFEATURE: {feature}")

    if feature not in df.columns:

        print("NOT FOUND IN CSV")
        continue

    values = pd.to_numeric(
        df[feature],
        errors="coerce"
    ).dropna()

    print(f"Count   : {len(values)}")
    print(f"Min     : {values.min()}")
    print(f"Median  : {values.median()}")
    print(f"Mean    : {values.mean()}")
    print(f"Max     : {values.max()}")

    print("Samples :")
    print(values.head(10).tolist())


print("\n" + "=" * 70)
print("INSPECTION COMPLETE")
print("=" * 70)