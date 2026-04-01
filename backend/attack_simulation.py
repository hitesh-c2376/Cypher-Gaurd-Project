import requests
import hmac
import hashlib
import time

BASE_URL = "http://127.0.0.1:5000"

# ----------------------------------------
# Helper Function
# ----------------------------------------

def safe_post(url, json=None, headers=None):
    try:
        res = requests.post(url, json=json, headers=headers)
        return res
    except Exception as e:
        print("Request failed:", e)
        exit()


# ----------------------------------------
# Admin Setup
# ----------------------------------------

def register_admin():
    print("\n[+] Registering admin (if not exists)...")

    safe_post(f"{BASE_URL}/register", {
        "username": "admin",
        "password": "admin123",
        "role": "admin"
    })


def login_admin():
    print("[+] Logging in admin...")

    res = safe_post(f"{BASE_URL}/login", {
        "username": "admin",
        "password": "admin123"
    })

    if res.status_code != 200:
        print("Login failed:", res.text)
        exit()

    return res.json()["access_token"]


# ----------------------------------------
# Device Setup
# ----------------------------------------

def register_device(token):
    print("[+] Registering device (if not exists)...")

    headers = {"Authorization": f"Bearer {token}"}

    safe_post(f"{BASE_URL}/register-device", {
        "device_id": "esp32_01",
        "secret_key": "my_secret_key_123"
    }, headers=headers)


# ----------------------------------------
# Normal Authentication
# ----------------------------------------

def normal_auth():
    print("\n[+] Performing normal authentication...")

    res = safe_post(f"{BASE_URL}/generate-challenge", {
        "device_id": "esp32_01"
    })

    if res.status_code != 200:
        print("Challenge failed:", res.text)
        return

    nonce = res.json()["nonce"]

    correct_hmac = hmac.new(
        b"my_secret_key_123",
        nonce.encode(),
        hashlib.sha256
    ).hexdigest()

    res = safe_post(f"{BASE_URL}/verify-response", {
        "device_id": "esp32_01",
        "hmac": correct_hmac
    })

    print("   Auth response:", res.json())


# ----------------------------------------
# Attack Simulations
# ----------------------------------------

def brute_force_attack():
    print("\n[!] Simulating brute force attack...")
    for _ in range(6):
        safe_post(f"{BASE_URL}/login", {
            "username": "admin",
            "password": "wrong_password"
        })


def enumeration_attack():
    print("\n[!] Simulating device enumeration attack...")
    for i in range(12):
        safe_post(f"{BASE_URL}/verify-response", {
            "device_id": f"fake_device_{i}",
            "hmac": "0" * 64
        })


def hmac_attack():
    print("\n[!] Simulating HMAC attack...")

    for _ in range(6):
        res = safe_post(f"{BASE_URL}/generate-challenge", {
            "device_id": "esp32_01"
        })

        if res.status_code != 200:
            continue

        safe_post(f"{BASE_URL}/verify-response", {
            "device_id": "esp32_01",
            "hmac": "0" * 64
        })


# ----------------------------------------
# Run SIEM + Show Alerts
# ----------------------------------------

def run_siem(token):
    print("\n[+] Running SIEM detection...")

    headers = {"Authorization": f"Bearer {token}"}

    res = safe_post(f"{BASE_URL}/run-detections", headers=headers)
    print("   Detection result:", res.json())

    print("\n[+] Fetching alerts...")
    res = requests.get(f"{BASE_URL}/alerts", headers=headers)
    
    # FIXED: response is now paginated, alerts are inside "alerts" key
    data = res.json()
    alerts = data.get("alerts", data) if isinstance(data, dict) else data

    for alert in alerts:
        print(f"   - {alert['alert_type']} | Severity: {alert['severity']}")


# ----------------------------------------
# MAIN EXECUTION
# ----------------------------------------

if __name__ == "__main__":

    print("\n========= Secure IoT Automated Security Test =========")

    register_admin()
    token = login_admin()
    register_device(token)

    normal_auth()

    brute_force_attack()
    enumeration_attack()
    hmac_attack()

    time.sleep(1)

    run_siem(token)

    print("\n[✓] Automated security testing completed.")