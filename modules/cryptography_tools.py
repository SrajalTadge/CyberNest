from Crypto.Cipher import AES
import base64
import hashlib

def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(message, key):
    try:
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(message)
        encrypted = cipher.encrypt(padded.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        return f"Encryption error: {str(e)}"

def aes_decrypt(message, key):
    try:
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        decoded = base64.b64decode(message)
        decrypted = cipher.decrypt(decoded)
        return unpad(decrypted.decode())
    except Exception as e:
        return f"Decryption error: {str(e)}"
