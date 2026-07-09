import joblib

xgb = joblib.load("models/xgb_model.pkl")
iso = joblib.load("models/isolation_forest.pkl")
scaler = joblib.load("models/scaler.pkl")
top_features = joblib.load("models/top_features.pkl")
threshold = joblib.load("models/threshold.pkl")

print("XGBoost:", type(xgb))
print("Isolation Forest:", type(iso))
print("Scaler:", type(scaler))
print("Number of Features:", len(top_features))
print("Threshold:", threshold)

print("\n✅ All deployment files loaded successfully!")