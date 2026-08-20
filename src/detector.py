"""
Inference Engine and Risk Scoring System for AI Scam Detection.
Combines TF-IDF Machine Learning Ensemble with rule-based heuristics,
trigger highlighting, category classification, and actionable safety advice.
"""

import os
import json
import joblib
import numpy as np
from typing import Dict, List, Any, Optional

from src.preprocessor import preprocessor, TRIGGER_PATTERNS


MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "scam_detector_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


class ScamDetector:
    """Core Scam Detection inference engine."""

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata = {}
        self.load_model()

    def load_model(self):
        """Load trained model artifacts; fallback if needed."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                if os.path.exists(METADATA_PATH):
                    with open(METADATA_PATH, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                print("[+] Loaded trained ML model and TF-IDF vectorizer successfully.")
            else:
                print("[!] Model files not found. Run 'python train.py' to generate.")
        except Exception as e:
            print(f"[-] Error loading model: {e}")
            self.model = None
            self.vectorizer = None

    def determine_category(self, text: str, triggers: List[Dict[str, Any]], is_scam: bool) -> str:
        """Classify the specific fraud vertical or legitimate category."""
        if not is_scam:
            return "Legitimate Message"

        lower = text.lower()
        trigger_cats = [t["category"] for t in triggers]

        if any(k in lower for k in ["sbi", "hdfc", "wells fargo", "chase", "bank", "kyc", "pan card", "netbanking", "debit card", "cvv", "pin"]):
            return "Banking / KYC Fraud"
        if any(k in lower for k in ["bitcoin", "btc", "eth", "crypto", "usdt", "binance", "roi", "invest"]):
            return "Crypto & Investment Scam"
        if any(k in lower for k in ["usps", "fedex", "dhl", "ups", "parcel", "package", "customs", "delivery"]):
            return "Delivery & Package Scam"
        if any(k in lower for k in ["lottery", "won", "winner", "prize", "jackpot", "gift card", "reward points", "megawin"]):
            return "Lottery & Prize Scam"
        if any(k in lower for k in ["warrant", "arrest", "irs", "police", "lawsuit", "court", "fbi", "blackmail", "webcam"]):
            return "Threat & Impersonation Scam"
        if any(k in lower for k in ["hiring", "part-time", "earn $", "rating products", "data entry", "telegram @", "work from home"]):
            return "Job & Task Scam"
        if any(k in lower for k in ["gmail", "google", "apple id", "icloud", "netflix", "paypal", "password", "unauthorized login", "suspended"]):
            return "Phishing & Account Security"

        if "financial" in trigger_cats:
            return "Financial / Advance Fee Scam"
        if "threat" in trigger_cats:
            return "Extortion / Threat Scam"
        if "phishing_action" in trigger_cats or "suspicious_link" in trigger_cats:
            return "Phishing / Malicious Link"

        return "Suspicious Unsolicited Message"

    def generate_explanation(self, text: str, risk_score: float, triggers: List[Dict[str, Any]], indicators: Dict[str, float], category: str) -> str:
        """Create a human-readable, context-aware explanation for the verdict."""
        if risk_score <= 30.0:
            return (
                "This message appears legitimate and safe. It follows typical conversational or standard transactional patterns "
                "with no detected deceptive links, coercive urgency, or credential theft attempts."
            )

        reasons = []
        if indicators.get("urgency_score", 0) > 0.3:
            reasons.append("high-pressure urgency designed to cause panic or prompt hasty action")
        if indicators.get("financial_score", 0) > 0.3:
            reasons.append("requests for sensitive financial information, banking credentials, or fake prize promises")
        if indicators.get("threat_score", 0) > 0.3:
            reasons.append("intimidation tactics, impersonation of authority (police/IRS), or legal threats")
        if indicators.get("link_score", 0) > 0.3:
            reasons.append("suspicious third-party links or shortened redirect URLs attempting credential phishing")
        if len(triggers) > 0:
            top_triggers = ", ".join([f"'{t['text']}'" for t in triggers[:3]])
            reasons.append(f"specific trigger phrases such as {top_triggers}")

        if not reasons:
            reasons.append("patterns consistent with known fraudulent message templates")

        joined_reasons = "; ".join(reasons)
        return (
            f"Flagged as {category} with a {risk_score}% risk score. "
            f"The system detected multiple threat indicators: {joined_reasons}."
        )

    def generate_action_advice(self, is_scam: bool, risk_level: str, category: str, entities: Dict[str, List[str]]) -> List[str]:
        """Generate defensive action recommendations."""
        if not is_scam:
            return [
                "Message appears safe to read and respond to.",
                "Always ensure 2-factor authentication is enabled on your accounts."
            ]

        advice = []
        if "Banking" in category:
            advice.append("DO NOT click any link or provide your OTP, PIN, CVV, or NetBanking password.")
            advice.append("Banks never ask for sensitive credentials or KYC updates via unverified SMS/Email links.")
            advice.append("Contact your bank directly using the official phone number on the back of your card.")
        elif "Phishing" in category:
            advice.append("DO NOT enter login credentials on third-party links.")
            advice.append("Navigate to the service (Google, Apple, Netflix, etc.) directly by typing its official URL in your browser.")
            advice.append("If you entered credentials, change your password immediately and revoke active sessions.")
        elif "Lottery" in category or "Crypto" in category:
            advice.append("Ignore and block this sender. Legitimate lotteries never require an upfront fee or tax payment to claim winnings.")
            advice.append("Guaranteed double crypto returns are mathematical impossibilities and 100% Ponzi/fraud schemes.")
        elif "Delivery" in category:
            advice.append("Postal carriers (USPS, FedEx, UPS) do not ask for redelivery fees via random text messages.")
            advice.append("Track your package exclusively using the official carrier website or app.")
        elif "Threat" in category:
            advice.append("Do not be intimidated. Government agencies and law enforcement NEVER demand gift cards or crypto payments to avoid arrest.")
            advice.append("Report extortion attempts to local cybercrime authorities.")
        else:
            advice.append("Do not click any embedded links or download attachments.")
            advice.append("Block the sender and report as spam/phishing.")

        if entities.get("urls"):
            advice.append("Do not visit the detected URL(s): " + ", ".join(entities["urls"][:2]))

        return advice

    def detect(self, text: str) -> Dict[str, Any]:
        """
        Analyze a message and return comprehensive classification,
        confidence score, risk level, triggers, entities, and advice.
        """
        if not text or not text.strip():
            return {
                "text": "",
                "is_scam": False,
                "label": "Legitimate",
                "risk_score": 0.0,
                "confidence": 100.0,
                "risk_level": "Safe",
                "category": "Legitimate Message",
                "triggers": [],
                "extracted_entities": {"urls": [], "phones": [], "emails": [], "currencies": []},
                "indicators": {"urgency_score": 0.0, "financial_score": 0.0, "threat_score": 0.0, "link_score": 0.0, "caps_ratio": 0.0},
                "explanation": "No text provided for analysis.",
                "action_advice": ["Please enter text to analyze."]
            }

        # 1. Feature extraction & heuristics
        entities = preprocessor.extract_entities(text)
        triggers = preprocessor.find_triggers(text)
        indicators = preprocessor.compute_heuristic_indicators(text)
        cleaned_text = preprocessor.clean_text(text, remove_stopwords=False)

        # 2. ML Model inference
        ml_prob_scam = 0.0
        if self.model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([cleaned_text])
                proba = self.model.predict_proba(vec)[0]
                # Class 1 is Scam
                ml_prob_scam = float(proba[1])
            except Exception as e:
                print(f"[-] Inference error: {e}")
                ml_prob_scam = 0.5
        else:
            # Fallback heuristic probability if model not loaded
            heuristic_sum = (
                indicators["urgency_score"] * 0.35 +
                indicators["financial_score"] * 0.35 +
                indicators["threat_score"] * 0.4 +
                indicators["link_score"] * 0.4 +
                (0.3 if len(triggers) > 0 else 0.0)
            )
            ml_prob_scam = min(1.0, heuristic_sum)

        # 3. Hybrid Calibrated Risk Score (0 - 100%)
        # Combine ML probability with strong real-world trigger heuristics
        heuristic_boost = 0.0
        if len(triggers) >= 2:
            heuristic_boost += 0.15
        if indicators["threat_score"] >= 0.5:
            heuristic_boost += 0.25
        if indicators["link_score"] >= 0.5 and (indicators["urgency_score"] >= 0.3 or indicators["financial_score"] >= 0.3):
            heuristic_boost += 0.20

        combined_risk = min(1.0, max(0.0, (ml_prob_scam * 0.75) + (heuristic_boost * 0.25)))

        # If high triggers are present, ensure risk floor
        if len(triggers) >= 1 and (indicators["financial_score"] >= 0.4 or indicators["threat_score"] >= 0.4 or indicators["urgency_score"] >= 0.4):
            combined_risk = max(combined_risk, 0.75)

        # If zero triggers, zero entities, zero indicators, and clean text, ensure safe floor
        if len(triggers) == 0 and indicators["urgency_score"] == 0 and indicators["financial_score"] == 0 and indicators["threat_score"] == 0 and indicators["link_score"] == 0:
            if ml_prob_scam < 0.3:
                combined_risk = min(combined_risk, 0.15)

        risk_score_pct = round(combined_risk * 100.0, 1)
        is_scam = risk_score_pct >= 45.0

        # Risk level string
        if risk_score_pct < 30.0:
            risk_level = "Safe"
            label = "Legitimate"
        elif risk_score_pct < 65.0:
            risk_level = "Suspicious"
            label = "Suspicious"
        else:
            risk_level = "High Risk Scam"
            label = "Scam"

        confidence_pct = round(max(risk_score_pct, 100.0 - risk_score_pct), 1)
        category = self.determine_category(text, triggers, is_scam)
        explanation = self.generate_explanation(text, risk_score_pct, triggers, indicators, category)
        action_advice = self.generate_action_advice(is_scam, risk_level, category, entities)

        return {
            "text": text,
            "is_scam": is_scam,
            "label": label,
            "risk_score": risk_score_pct,
            "confidence": confidence_pct,
            "risk_level": risk_level,
            "category": category,
            "triggers": triggers,
            "extracted_entities": entities,
            "indicators": indicators,
            "explanation": explanation,
            "action_advice": action_advice
        }


# Global detector instance
detector = ScamDetector()
