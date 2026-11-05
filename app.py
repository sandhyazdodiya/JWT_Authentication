
from flask import Flask, request, jsonify
import json
import base64
import hmac
import hashlib
import time
import os

app = Flask(__name__)

SECRET_KEY = os.getenv("JWT_SECRET", "my-secret-key")


# 1. Base64 URL Encoding
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# 2. Base64 URL Decoding
def base64url_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# 3. Generate JWT Token
def generate_token(payload):

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    encoded_header = base64url_encode(
        json.dumps(header, separators=(",", ":")).encode()
    )

    encoded_payload = base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    message = f"{encoded_header}.{encoded_payload}"

    signature = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()

    encoded_signature = base64url_encode(signature)

    return f"{message}.{encoded_signature}"


# 4. Verify JWT Token
def verify_token(token):

    try:
        header, payload, signature = token.split(".")

        decoded_header = json.loads(base64url_decode(header))

        # Only allow HS256
        if decoded_header.get("alg") != "HS256":
            return None

        message = f"{header}.{payload}"

        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        actual_signature = base64url_decode(signature)

        if not hmac.compare_digest(
            expected_signature, actual_signature
        ):
            return None

        decoded_payload = json.loads(
            base64url_decode(payload)
        )

        if "exp" not in decoded_payload:
            return None

        if time.time() >= decoded_payload["exp"]:
            return None

        return decoded_payload

    except (ValueError, TypeError, json.JSONDecodeError):
        return None


# 5. Login API
@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    # Demo credentials
    if username == "sandhya" and password == "12345":

        payload = {
            "user_id": 101,
            "username": username,
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }

        token = generate_token(payload)

        return jsonify({
            "success": True,
            "access_token": token,
            "token_type": "Bearer"
        })

    return jsonify({
        "success": False,
        "message": "Invalid credentials"
    }), 401


# 6. Protected Profile API
@app.route("/profile", methods=["GET"])
def profile():

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return jsonify({
            "message": "Token missing"
        }), 401

    token = auth_header.split(" ", 1)[1]

    user = verify_token(token)

    if user is None:
        return jsonify({
            "message": "Invalid or expired token"
        }), 401

    return jsonify({
        "message": "Access granted",
        "user": user
    })


if __name__ == "__main__":
    app.run(debug=True)
