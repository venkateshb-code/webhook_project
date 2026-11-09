
import hmac
import hashlib
import requests


URL = "http://127.0.0.1:8000/webhooks/customer-events"

SECRET = "my_super_secret_webhook_key_123"


# Original webhook payload
payload = b'{"event":"customer.created","customer_id":101,"name":"Arun"}'


# Generate HMAC-SHA256 signature
signature = hmac.new(
    SECRET.encode("utf-8"),
    payload,
    hashlib.sha256
).hexdigest()


# ---------------------------------
# TEST 1: Valid signature
# ---------------------------------

print("\nTEST 1: Valid signature")

response = requests.post(
    URL,
    data=payload,
    headers={"X-Signature": signature}
)

print("Status:", response.status_code)
print("Response:", response.json())


# ---------------------------------
# TEST 2: Tampered payload
# ---------------------------------

print("\nTEST 2: Tampered payload")

tampered_payload = b'{"event":"customer.deleted","customer_id":101}'

response = requests.post(
    URL,
    data=tampered_payload,
    headers={"X-Signature": signature}
)

print("Status:", response.status_code)
print("Response:", response.json())


# ---------------------------------
# TEST 3: Missing signature
# ---------------------------------

print("\nTEST 3: Missing signature")

response = requests.post(
    URL,
    data=payload
)

print("Status:", response.status_code)
print("Response:", response.json())
