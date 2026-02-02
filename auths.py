# auth.py

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app as app
from models.admins import Admin

SECRET_KEY = "secret"  # Make sure this matches your app config

def admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing !!"}), 401

        # Remove Bearer prefix if present
        if token.startswith("Bearer "):
            token = token[7:]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            admin_id = int(payload["sub"])
            admin = Admin.query.get(admin_id)
            if not admin:
                return jsonify({"message": "Admin not found !!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired !!"}), 401
        except Exception as e:
            print(e)
            return jsonify({"message": "Token is invalid !!"}), 401

        return f(admin, *args, **kwargs)

    return decorated

def encode_admin_auth_token(admin_id):
    """
    Generates JWT Auth Token for admin
    """
    try:
        payload = {
            "exp": datetime.utcnow() + timedelta(days=1),
            "iat": datetime.utcnow(),
            "sub": str(admin_id)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return token if isinstance(token, str) else token.decode("utf-8")
    except Exception as e:
        return str(e)
