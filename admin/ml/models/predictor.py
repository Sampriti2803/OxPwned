import joblib
import numpy as np

def predict_anomaly(features):
    """Predicts whether the given features are anomalous."""
    model = joblib.load("models/trained_model/anomaly_detector.pkl")
    prediction = model.predict(np.array(features).reshape(1, -1))
    return prediction