import requests
import json

BASE_URL = "http://localhost:5000/api/admin"

def seed_and_test_admin():
    email = "admin@gmail.com"
    username = "admin"  # Required for admin login
    password = "admin"
    
    print("1. Creating Main Admin...")
    try:
        resp = requests.post(f"{BASE_URL}/create-main-admin", json={
            "email": email,
            "username": username,
            "password": password
        })
        print(f"Create Response [{resp.status_code}]: {resp.text}")
    except Exception as e:
        print(f"Create failed: {e}")

    print("\n2. Testing Admin Login...")
    try:
        # Note: Admin login requires username, email AND password
        resp = requests.post(f"{BASE_URL}/login", json={
            "email": email,
            "username": username,
            "password": password
        })
        print(f"Login Response [{resp.status_code}]: {resp.text}")
        
        if resp.status_code == 200:
            print("✅ Admin Login Successful!")
            token = resp.json().get("token")
            print(f"Token received: {token[:20]}...")
    except Exception as e:
        print(f"Login failed: {e}")

if __name__ == "__main__":
    seed_and_test_admin()
