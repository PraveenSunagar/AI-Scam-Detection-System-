"""
Model Training and Evaluation Pipeline for AI Scam Detection System.
Trains TF-IDF vectorizer + calibrated ML classifier on scam and legitimate text data.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# Ensure utf-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from src.preprocessor import preprocessor
from src.utils import ensure_dataset_exists


MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "scam_detector_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def train_scam_detector():
    print("=" * 60, flush=True)
    print("[*] AI Scam Detection System - Model Training Pipeline", flush=True)
    print("=" * 60, flush=True)

    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs("data", exist_ok=True)

    # 1. Load or generate dataset
    print("\n[1/5] Loading training dataset...", flush=True)
    df = ensure_dataset_exists("data/scam_dataset.csv")
    print(f"Loaded {len(df)} total samples.", flush=True)
    print(f"Scam samples: {int((df['label'] == 1).sum())} | Legitimate samples: {int((df['label'] == 0).sum())}", flush=True)
    print(f"Categories present: {df['category'].nunique()}", flush=True)

    # 2. Text Preprocessing
    print("\n[2/5] Cleaning and normalizing text features...", flush=True)
    df["cleaned_text"] = df["text"].apply(lambda t: preprocessor.clean_text(str(t), remove_stopwords=False))

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["cleaned_text"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"]
    )

    # 3. TF-IDF Feature Extraction
    print("\n[3/5] Extracting TF-IDF features (unigrams + bigrams)...", flush=True)
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
        min_df=2
    )

    X_train_vec = vectorizer.fit_transform(X_train_raw)
    X_test_vec = vectorizer.transform(X_test_raw)
    print(f"TF-IDF Vocabulary size: {len(vectorizer.vocabulary_)} features", flush=True)

    # 4. Fast Model Training
    print("\n[4/5] Training Classifiers...", flush=True)
    
    # Train Logistic Regression
    lr = LogisticRegression(C=2.0, max_iter=500, random_state=42, solver="lbfgs")
    lr.fit(X_train_vec, y_train)

    # Train Naive Bayes
    nb = MultinomialNB(alpha=0.1)
    nb.fit(X_train_vec, y_train)

    # Soft Voting Ensemble (LR + NB)
    ensemble = VotingClassifier(
        estimators=[
            ("lr", lr),
            ("nb", nb)
        ],
        voting="soft",
        weights=[2.0, 1.0]
    )
    ensemble.fit(X_train_vec, y_train)

    # 5. Model Evaluation
    print("\n[5/5] Evaluating Best Model (Ensemble)...", flush=True)
    y_pred = ensemble.predict(X_test_vec)
    y_pred_proba = ensemble.predict_proba(X_test_vec)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n[*] Evaluation Results:", flush=True)
    print(f"  - Accuracy:  {acc * 100:.2f}%", flush=True)
    print(f"  - Precision: {prec * 100:.2f}%", flush=True)
    print(f"  - Recall:    {rec * 100:.2f}%", flush=True)
    print(f"  - F1-Score:  {f1 * 100:.2f}%", flush=True)
    print(f"  - Confusion Matrix (TN, FP / FN, TP):", flush=True)
    print(f"    {cm[0]}", flush=True)
    print(f"    {cm[1]}", flush=True)

    # Top TF-IDF keywords for Scam class
    feature_names = np.array(vectorizer.get_feature_names_out())
    top_scam_indices = np.argsort(lr.coef_[0])[-25:][::-1]
    top_scam_keywords = feature_names[top_scam_indices].tolist()

    # Save artifacts
    print(f"\n[*] Saving model artifacts to '{MODEL_DIR}'...", flush=True)
    joblib.dump(ensemble, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    metadata = {
        "model_type": "TF-IDF + Soft Voting Ensemble (Logistic Regression + Multinomial Naive Bayes)",
        "trained_at": datetime.now().isoformat(),
        "total_samples": int(len(df)),
        "train_samples": int(len(X_train_raw)),
        "test_samples": int(len(X_test_raw)),
        "vocabulary_size": int(len(vectorizer.vocabulary_)),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4)
        },
        "confusion_matrix": cm,
        "top_scam_keywords": top_scam_keywords,
        "classes": ["Legitimate", "Scam"]
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("[SUCCESS] Model, Vectorizer, and Metadata successfully saved!", flush=True)
    print("=" * 60, flush=True)
    return metadata


if __name__ == "__main__":
    train_scam_detector()
