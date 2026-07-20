from river.drift import ADWIN


class DriftDetector:

    def __init__(self, delta=0.002):

        self.adwin = ADWIN(delta=delta)

    def update(self, value):

        self.adwin.update(value)

        return self.adwin.drift_detected

    def reset(self):

        self.adwin = ADWIN(delta=0.002)