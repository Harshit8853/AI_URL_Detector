import os
import pickle

import pandas as pd
from scipy.io import arff
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier

# ---------------- PATHS ----------------

# BASE_DIR = AI_Financial_Fraud_Detector/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_ARFF_PATH = os.path.join(BASE_DIR, "data", "training.arff")
CLEAN_CSV_PATH = os.path.join(BASE_DIR, "data", "phishing_data_clean.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "models", "minmax_scaler.pkl")

# make sure models folder exists
os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)


def load_arff_to_dataframe(arff_path: str) -> pd.DataFrame:
    """
    1) Load the training.arff file
    2) Convert to pandas DataFrame
    3) Clean label column 'Result'
    """
    print(f"[INFO] Loading ARFF file from: {arff_path}")
    data, meta = arff.loadarff(arff_path)
    df = pd.DataFrame(data)

    # ARFF often stores strings as bytes -> decode them
    byte_cols = df.select_dtypes(include=["object"]).columns
    for col in byte_cols:
        if isinstance(df[col].iloc[0], (bytes, bytearray)):
            df[col] = df[col].str.decode("utf-8")

    # ---- handle the target/label column ----
    if "Result" not in df.columns:
        # if for some reason it's named differently, you can print columns to debug
        print("[ERROR] 'Result' column not found. Columns are:")
        print(df.columns)
        raise ValueError("Expected a 'Result' column in the ARFF file.")

    # If Result is string, map to numeric (1, -1)
    if df["Result"].dtype == "object":
        mapping = {
            "legitimate": 1,
            "phishing": -1,
            "Legitimate": 1,
            "Phishing": -1,
            "1": 1,
            "-1": -1,
        }
        df["Result"] = df["Result"].map(mapping)

    # Convert to numeric in case it's still string-like
    if not pd.api.types.is_numeric_dtype(df["Result"]):
        df["Result"] = pd.to_numeric(df["Result"], errors="coerce")

    # Drop rows where label is missing
    df = df.dropna(subset=["Result"])

    print(f"[INFO] ARFF loaded successfully. Shape: {df.shape}")
    return df


def save_clean_csv(df: pd.DataFrame, csv_path: str):
    """
    Save cleaned dataframe to CSV.
    This matches what you mentioned in your mid-term report (phishing_data_clean.csv).
    """
    df.to_csv(csv_path, index=False)
    print(f"[INFO] Clean CSV saved at: {csv_path}")


def train_and_save_model(df: pd.DataFrame):
    """
    Train RandomForest on the dataset and save model + scaler as .pkl files.
    """
    if "Result" not in df.columns:
        raise ValueError("DataFrame must contain 'Result' as target label.")

    # Split features and label
    X = df.drop("Result", axis=1)
    y = df["Result"]

    # Convert any non-numeric feature columns
    for col in X.columns:
        if X[col].dtype == "object":
            X[col] = pd.to_numeric(X[col], errors="coerce")

    # Drop rows with NaNs in features
    before_rows = X.shape[0]
    X = X.dropna()
    y = y.loc[X.index]
    dropped = before_rows - X.shape[0]
    if dropped > 0:
        print(f"[INFO] Dropped {dropped} rows with NaN feature values.")

    # Scale features between 0 and 1
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42
    )

    # Random Forest Classifier
    model = RandomForestClassifier(n_estimators=300, random_state=42)
    model.fit(X_train, y_train)

    # Accuracy
    accuracy = model.score(X_test, y_test)
    print(f"[INFO] Model accuracy on test set: {accuracy * 100:.2f}%")

    # Save model and scaler
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    print(f"[INFO] Model saved to: {MODEL_PATH}")
    print(f"[INFO] Scaler saved to: {SCALER_PATH}")


if __name__ == "__main__":
    print("[INFO] Starting training pipeline...")

    # 1. Load ARFF → DataFrame
    df = load_arff_to_dataframe(DATA_ARFF_PATH)

    # 2. Save clean CSV
    save_clean_csv(df, CLEAN_CSV_PATH)

    # 3. Train model + save artifacts
    train_and_save_model(df)

    print("[INFO] Training pipeline finished successfully ✅")
