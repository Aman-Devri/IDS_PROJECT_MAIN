import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

df = pd.read_csv('KDDTrain.csv')
features = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'logged_in', 'wrong_fragment',
    'same_srv_count', 'same_srv_rate'
]
X = df[features]
y = df['label']

le_protocol = LabelEncoder()
le_service = LabelEncoder()
le_flag = LabelEncoder()

X.loc[:, 'protocol_type'] = le_protocol.fit_transform(X['protocol_type'])
X.loc[:, 'service'] = le_service.fit_transform(X['service'])
X.loc[:, 'flag'] = le_flag.fit_transform(X['flag'])

clf = RandomForestClassifier()
clf.fit(X, y)

os.makedirs('model', exist_ok=True)
joblib.dump(clf, 'model/ids_model.pkl')
joblib.dump(le_protocol, 'model/le_protocol.pkl')
joblib.dump(le_service, 'model/le_service.pkl')
joblib.dump(le_flag, 'model/le_flag.pkl')

print("Model and encoders saved in /model.")