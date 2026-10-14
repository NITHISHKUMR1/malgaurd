import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

model = tf.keras.models.load_model('models/malware_model.keras')
scaler = joblib.load('models/scaler.pkl')
label_encoders = joblib.load('models/label_encoders.pkl')
target_encoder = joblib.load('models/target_encoder.pkl')
feature_columns = joblib.load('models/feature_columns.pkl')
is_multiclass = joblib.load('models/is_multiclass.pkl')

df = pd.read_csv('malware_dataset_multitype.csv')
if 'malware_family' in df.columns:
    y = df['malware_family']
    X = df.drop(columns=['malware_family', 'file_id', 'file_name', 'detection_date', 'severity'], errors='ignore')
else:
    y = df['malware'] if 'malware' in df.columns else (df['detection_score'] > 0.5)
    X = df.drop(columns=['malware', 'detection_score', 'file_id', 'file_name', 'detection_date'], errors='ignore')

for col in X.select_dtypes(include=['object']).columns:
    if col in label_encoders:
        X[col] = label_encoders[col].transform(X[col].astype(str))
    else:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))

for col in feature_columns:
    if col not in X.columns:
        X[col] = 0
X = X[feature_columns]
X_scaled = scaler.transform(X)

if is_multiclass:
    y_enc = target_encoder.transform(y)
    preds = model.predict(X_scaled)
    y_pred = np.argmax(preds, axis=1)
else:
    y_enc = y if np.issubdtype(y.dtype, np.integer) else y.astype(int)
    y_pred = (model.predict(X_scaled) > 0.5).astype(int).reshape(-1)

acc = accuracy_score(y_enc, y_pred)
print(f'accuracy={acc:.6f}')
