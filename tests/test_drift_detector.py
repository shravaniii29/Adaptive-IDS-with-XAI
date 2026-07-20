from detection.drift_detector import DriftDetector


detector = DriftDetector()

print("Testing ADWIN...\n")

# Stable stream
for _ in range(100):

    drift = detector.update(0)

assert drift is False

print("Stable stream: No drift detected")


# Sudden change
drift_found = False

for i in range(100):

    drift = detector.update(1)

    if drift:
        drift_found = True
        print(f"Drift detected at sample {i + 1}")
        break


assert drift_found

print("\nADWIN TEST PASSED")