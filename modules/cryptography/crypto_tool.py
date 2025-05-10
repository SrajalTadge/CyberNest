
import base64

def custom_encrypt(text, key):
    try:
        key = int(key)
        encrypted = ''.join(chr((ord(char) + key) % 256) for char in text)
        encrypted_bytes = encrypted.encode('utf-8')
        return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
    except:
        return "Encryption failed. Invalid key."

def custom_decrypt(encrypted_text, key):
    try:
        key = int(key)
        decoded_bytes = base64.urlsafe_b64decode(encrypted_text)
        decoded_str = decoded_bytes.decode('utf-8')
        decrypted = ''.join(chr((ord(char) - key) % 256) for char in decoded_str)
        return decrypted
    except Exception as e:
        return f"Decryption failed: {e}"
