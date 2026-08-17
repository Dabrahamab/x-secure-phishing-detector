import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os


def train_phishing_model(csv_path="phishing_dataset.csv"):
    if not os.path.exists(csv_path):
        print(f"Error: Could not find '{csv_path}'.")
        return

    print(f"Loading dataset from '{csv_path}'...")
    df = pd.read_csv(csv_path)

    # Clean up column names (removes trailing spaces)
    df.columns = [col.strip() for col in df.columns]
    print(f"Dataset loaded successfully! Shape: {df.shape}")

    # Separate Features (X) and Target (y)
    # The 'index' column is already deleted, so we just drop 'Result'
    X = df.drop(columns=['Result'])
    y = df['Result']

    # Standardize the Target Labels
    # Convert -1 (Phishing) to 1, and 1 (Safe) to 0
    y = y.replace({-1: 1, 1: 0})
    print("Labels mapped successfully: 1 (Phishing), 0 (Safe)")

    # Train/Test Split (80% training, 20% testing)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Initialize and Train Random Forest Classifier
    print("\nTraining Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Evaluate Model Performance
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "="*50)
    print(f"MODEL ACCURACY: {accuracy * 100:.2f}%")
    print("="*50)
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # Save Model and Feature List Artifacts
    joblib.dump(rf_model, "phishing_rf_model.pkl")
    joblib.dump(X.columns.tolist(), "model_features.pkl")

    print("\nModel artifacts saved successfully:")
    print(" - phishing_rf_model.pkl")
    print(" - model_features.pkl")


if __name__ == "__main__":
    train_phishing_model()
