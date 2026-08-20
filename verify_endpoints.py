"""
Endpoint verification script.
Tests all web assets and REST APIs over live HTTP server.
"""

import sys
import time
import subprocess
import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_URL = "http://127.0.0.1:8000"

def ensure_server_running():
    try:
        r = httpx.get(f"{BASE_URL}/api/health", timeout=1.0)
        if r.status_code == 200:
            return None  # Server is already running
    except Exception:
        pass
    
    print("[*] Server is not running. Automatically starting background server on http://127.0.0.1:8000...")
    proc = subprocess.Popen([sys.executable, "app.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)  # Allow FastAPI server to start
    return proc

def verify_all():
    server_proc = ensure_server_running()
    try:
        print("=" * 60)
        print("[*] Verifying Live AI Scam Detection System Endpoints")
        print("=" * 60)

        client = httpx.Client(base_url=BASE_URL, timeout=10.0)

        # 1. Root / UI Page
        r_root = client.get("/")
        print(f"[+] GET / -> Status: {r_root.status_code} | Size: {len(r_root.text)} bytes")
        assert r_root.status_code == 200
        assert "<title>AI Scam Detection System" in r_root.text

        # 2. CSS Stylesheet
        r_css = client.get("/static/css/styles.css")
        print(f"[+] GET /static/css/styles.css -> Status: {r_css.status_code} | Size: {len(r_css.text)} bytes")
        assert r_css.status_code == 200

        # 3. JavaScript App
        r_js = client.get("/static/js/app.js")
        print(f"[+] GET /static/js/app.js -> Status: {r_js.status_code} | Size: {len(r_js.text)} bytes")
        assert r_js.status_code == 200

        # 4. API Health
        r_health = client.get("/api/health")
        print(f"[+] GET /api/health -> Status: {r_health.status_code} | Response: {r_health.json()}")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "healthy"

        # 5. API Detect (Scam)
        payload_scam = {
            "text": "Dear customer, your SBI bank account has been blocked due to incomplete KYC. Update KYC immediately at http://sbi-kyc-verify.xyz/login",
            "sender": "+1 (800) 555-0199",
            "channel": "SMS"
        }
        r_detect_scam = client.post("/api/detect", json=payload_scam)
        scam_data = r_detect_scam.json()
        print(f"[+] POST /api/detect (Scam) -> Status: {r_detect_scam.status_code} | Category: {scam_data['category']} | Risk: {scam_data['risk_score']}% | Level: {scam_data['risk_level']}")
        assert r_detect_scam.status_code == 200
        assert scam_data["is_scam"] is True
        assert scam_data["risk_level"] == "High Risk Scam"

        # 6. API Detect (Legitimate)
        payload_ham = {
            "text": "Hey Alex! Are we still meeting for lunch at 12:30 PM at the Italian bistro near downtown?",
            "sender": "Alex",
            "channel": "SMS"
        }
        r_detect_ham = client.post("/api/detect", json=payload_ham)
        ham_data = r_detect_ham.json()
        print(f"[+] POST /api/detect (Clean) -> Status: {r_detect_ham.status_code} | Category: {ham_data['category']} | Risk: {ham_data['risk_score']}% | Level: {ham_data['risk_level']}")
        assert r_detect_ham.status_code == 200
        assert ham_data["is_scam"] is False
        assert ham_data["risk_level"] == "Safe"

        # 7. API Batch Detect
        batch_payload = {
            "messages": [
                "Your Wells Fargo debit card is locked. Call +1-800-555-0199",
                "Your Uber driver is arriving in 3 minutes.",
                "Elon Musk Crypto Giveaway: Double your BTC at http://elon.xyz"
            ]
        }
        r_batch = client.post("/api/batch-detect", json=batch_payload)
        batch_data = r_batch.json()
        print(f"[+] POST /api/batch-detect -> Status: {r_batch.status_code} | Total: {batch_data['total_analyzed']} | Scams: {batch_data['scam_count']} | Ratio: {batch_data['scam_percentage']}%")
        assert r_batch.status_code == 200
        assert batch_data["scam_count"] == 2

        # 8. API Sample Scams
        r_samples = client.get("/api/sample-scams")
        samples_data = r_samples.json()
        print(f"[+] GET /api/sample-scams -> Status: {r_samples.status_code} | Samples Count: {len(samples_data.get('samples', []))}")
        assert r_samples.status_code == 200
        assert len(samples_data["samples"]) >= 8

        # 9. API Stats
        r_stats = client.get("/api/stats")
        stats_data = r_stats.json()
        print(f"[+] GET /api/stats -> Status: {r_stats.status_code} | Accuracy: {stats_data['metrics']['accuracy'] * 100}% | Samples: {stats_data['total_samples']}")
        assert r_stats.status_code == 200

        # 10. Swagger Docs
        r_docs = client.get("/docs")
        print(f"[+] GET /docs -> Status: {r_docs.status_code} (Interactive OpenAPI UI)")
        assert r_docs.status_code == 200

        print("=" * 60)
        print("[SUCCESS] All 10 live endpoint tests passed with flying colors!")
        print("=" * 60)
    finally:
        if server_proc is not None:
            server_proc.terminate()


if __name__ == "__main__":
    verify_all()
