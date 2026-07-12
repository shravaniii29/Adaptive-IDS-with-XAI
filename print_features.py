import joblib

features = joblib.load("models/top_features.pkl")

print(type(features))
print()

for i, feature in enumerate(features, start=1):
    print(f"{i}. {feature}")