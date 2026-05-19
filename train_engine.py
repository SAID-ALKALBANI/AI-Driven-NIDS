import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# 1. Loading the dataset
print("[*] Loading NSL-KDD dataset...")
# Make sure the file name matches exactly what appeared in your 'ls' command
data = pd.read_csv('KDDTrain+_20Percent.txt', header=None)

# 2. Data Preparation
print("[*] Preparing features and labels...")
X = data.select_dtypes(include=['number']).iloc[:, :-1]
y = data.iloc[:, -1]

# 3. Splitting Data (80% for training, 20% for testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Training the AI Model
print("[*] Training started... please wait.")
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# 5. Accuracy Result
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"[+] Training Complete! Accuracy: {acc * 100:.2%}")

# 6. Saving the Model
joblib.dump(model, 'ids_model_v2.pkl')
print("[+] Model saved successfully as 'ids_model_v2.pkl'")
