import bcrypt
import hmac
import hashlib


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def generate_hmac(secret_key, nonce):
    return hmac.new(
        secret_key.encode(),
        nonce.encode(),
        hashlib.sha256
    ).hexdigest()
