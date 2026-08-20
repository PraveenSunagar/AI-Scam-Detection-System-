"""
Automated unit and integration test suite for AI Scam Detection System.
Tests model inference, preprocessing, heuristic triggers, and API endpoints.
"""

import sys
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app import app
from src.detector import detector
from src.preprocessor import preprocessor


class TestScamDetectionSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_model_loaded(self):
        """Verify model and vectorizer are loaded."""
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.vectorizer)

    def test_banking_scam_detection(self):
        """Verify high risk score on Banking KYC phishing."""
        msg = "Dear customer, your SBI bank account has been blocked due to incomplete KYC. Update KYC immediately at http://sbi-kyc-verify.xyz/login to avoid permanent deactivation."
        result = detector.detect(msg)
        self.assertTrue(result["is_scam"])
        self.assertIn("Banking", result["category"])
        self.assertGreaterEqual(result["risk_score"], 65.0)
        self.assertEqual(result["risk_level"], "High Risk Scam")
        self.assertGreater(len(result["triggers"]), 0)
        self.assertIn("http://sbi-kyc-verify.xyz/login", result["extracted_entities"]["urls"])

    def test_legitimate_message_detection(self):
        """Verify low risk score on legitimate messages."""
        msg = "Hey! Are we still meeting for lunch at 12:30 PM at the Italian bistro near downtown?"
        result = detector.detect(msg)
        self.assertFalse(result["is_scam"])
        self.assertLessEqual(result["risk_score"], 30.0)
        self.assertEqual(result["risk_level"], "Safe")
        self.assertEqual(result["category"], "Legitimate Message")

    def test_crypto_giveaway_scam(self):
        """Verify crypto giveaway scam detection."""
        msg = "Elon Musk Giveaway: Send 0.1 BTC to receive 0.5 BTC back immediately! Guaranteed 500% profit. Join official event at http://elon-crypto-event.xyz"
        result = detector.detect(msg)
        self.assertTrue(result["is_scam"])
        self.assertIn("Crypto", result["category"])
        self.assertGreaterEqual(result["risk_score"], 65.0)

    def test_api_health_endpoint(self):
        """Verify /api/health endpoint response."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_api_detect_endpoint(self):
        """Verify /api/detect endpoint response."""
        payload = {
            "text": "USPS Alert: Your parcel could not be delivered. Pay $1.99 fee at http://usps-redelivery.info",
            "sender": "USPS",
            "channel": "SMS"
        }
        response = self.client.post("/api/detect", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["is_scam"])
        self.assertIn("Delivery", data["category"])
        self.assertEqual(data["sender"], "USPS")

    def test_api_batch_detect_endpoint(self):
        """Verify /api/batch-detect endpoint."""
        payload = {
            "messages": [
                "Your account is locked. Verify at http://scam.xyz",
                "Hi Mom, I am on my way home from work.",
                "CONGRATULATIONS! You won $1,000,000 lottery!"
            ]
        }
        response = self.client.post("/api/batch-detect", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_analyzed"], 3)
        self.assertEqual(data["scam_count"], 2)
        self.assertEqual(data["legitimate_count"], 1)

    def test_api_stats_endpoint(self):
        """Verify /api/stats endpoint."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("metrics", data)
        self.assertGreater(data["total_samples"], 1000)

    def test_api_sample_scams_endpoint(self):
        """Verify /api/sample-scams endpoint."""
        response = self.client.get("/api/sample-scams")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["samples"]), 5)


if __name__ == "__main__":
    unittest.main()
