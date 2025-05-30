# eval.py

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Define the expected features
feature_columns = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'logged_in', 'wrong_fragment',
    'same_srv_count', 'same_srv_rate'
]

# Load encoders and model
try:
    le_protocol = joblib.load('model/le_protocol.pkl')
    le_service = joblib.load('model/le_service.pkl')
    le_flag = joblib.load('model/le_flag.pkl')
    model = joblib.load('model/ids_model.pkl')
except Exception as e:
    print(f"❌ Error loading model or encoders: {e}")
    exit(1)

# 1. Evaluate from CSV
def evaluate_from_csv(csv_path='KDDTest.csv'):
    try:
        df = pd.read_csv(csv_path)
        X_test = df[feature_columns].copy()
        y_test = df['label']

        # Encode categorical features
        X_test['protocol_type'] = le_protocol.transform(X_test['protocol_type'])
        X_test['service'] = le_service.transform(X_test['service'])
        X_test['flag'] = le_flag.transform(X_test['flag'])

        # Predict and evaluate
        y_pred = model.predict(X_test)

        print("✅ Accuracy:", accuracy_score(y_test, y_pred))
        print("✅ Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
        print("✅ Classification Report:\n", classification_report(y_test, y_pred))

    except Exception as e:
        print(f"❌ Error during evaluation: {e}")

# 2. Preprocess input features
def preprocess(features):
    try:
        if isinstance(features, str):
            features = features.strip().split(',')

        if not isinstance(features, list):
            raise ValueError("Input must be a list or a comma-separated string.")

        if len(features) != 10:
            raise ValueError(f"Expected 10 features, got {len(features)}.")

        # Encode categorical fields
        features[1] = le_protocol.transform([features[1].strip()])[0]
        features[2] = le_service.transform([features[2].strip()])[0]
        features[3] = le_flag.transform([features[3].strip()])[0]

        # Convert numeric fields
        for i in [0, 4, 5, 6, 7, 8, 9]:
            features[i] = float(features[i])

        return np.array(features).reshape(1, -1)

    except Exception as e:
        return f"❌ Preprocessing Error: {e}"

# 3. Predict attack type
def predict_attack(features):
    processed = preprocess(features)
    if isinstance(processed, str):
        return processed
    try:
        prediction = model.predict(processed)[0]
        return prediction
    except Exception as e:
        return f"❌ Prediction Error: {e}"

# Run evaluation when executed directly
if __name__ == "__main__":
    evaluate_from_csv()
