import jwt
import time
import sys

# Replace with actual values
SECRET_KEY = sys.argv[1]
API_KEY_ID = "b888f4f2-2372-46de-b3a0-a47a8370cccd"
LOGIN = "admin"

payload = {
    "login": LOGIN,
    "api_key_id": API_KEY_ID,
    "iat": int(time.time()),
    "aud": "http://127.0.0.1",
    "scope": "api_key",
    "sub": LOGIN
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS512")
print(token)
