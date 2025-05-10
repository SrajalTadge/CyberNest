# modules/cryptography/aes_tool.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(plaintext, key):
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes[:32].ljust(32, b'\0')  # Pad/trim to 32 bytes for AES-256
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def aes_decrypt(ciphertext_b64, nonce_b64, tag_b64, key):
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes[:32].ljust(32, b'\0')

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8')
