import hashlib
import hmac

def generate_hmac(message: bytes, key: bytes):
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(message: bytes, received_hmac: bytes, key: bytes):
    expected_hmac = generate_hmac(message, key)
    return hmac.compare_digest(expected_hmac, received_hmac)