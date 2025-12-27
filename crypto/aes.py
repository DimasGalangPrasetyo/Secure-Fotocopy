from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_file(data: bytes):
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    encrypted_data = cipher.encrypt(data)
    return encrypted_data, key, iv

def decrypt_file(encrypted_data: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(encrypted_data)
    pad_len = data[-1]
    return data[:-pad_len]
