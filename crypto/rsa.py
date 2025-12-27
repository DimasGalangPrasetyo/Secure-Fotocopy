from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

KEY_DIR = "crypto/keys"
os.makedirs(KEY_DIR, exist_ok=True)

PRIVATE_KEY_PATH = f"{KEY_DIR}/private.pem"
PUBLIC_KEY_PATH = f"{KEY_DIR}/public.pem"

def generate_keys():
    if not os.path.exists(PRIVATE_KEY_PATH):
        key = RSA.generate(2048)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.export_key())
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(key.publickey().export_key())

def encrypt_key(aes_key: bytes):
    with open(PUBLIC_KEY_PATH, "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(aes_key)

def decrypt_key(encrypted_key: bytes):
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_key)
