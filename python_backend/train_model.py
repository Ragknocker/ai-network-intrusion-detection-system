import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

def train_rf_model():
    print("Loading dataset...")
    # Mocking dataset loading since we use generate_dataset.py
    try:
        df = pd.read_csv("synthetic_network_traffic.csv")
    except FileNotFoundError:
        print("Dataset not found. Run generate_dataset.py first.")
        return

    # Features: size, protocol (encoded), port, entropy, etc.
    # For this mock, we just use random numeric columns as features
    X = df.drop(columns=['label', 'id', 'timestamp', 'src_ip', 'dest_ip', 'classification'])
    
    # Encode categorical 'protocol'
    X = pd.get_dummies(X, columns=['protocol'])
    
    y = df['classification']

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    print("Evaluating Model...")
    y_pred = clf.predict(X_test)
    
    print("\n--- Model Performance ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nSaving model to disk...")
    joblib.dump(clf, "rf_nids_model.pkl")
    print("Model saved as rf_nids_model.pkl")

if __name__ == "__main__":
    train_rf_model()
