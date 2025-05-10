
import base64

def decode_text(text, encoding):
    try:
        if encoding == 'base64':
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        elif encoding == 'base32':
            return base64.b32decode(text).decode('utf-8', errors='ignore')
        elif encoding == 'base16':
            return base64.b16decode(text).decode('utf-8', errors='ignore')
        elif encoding == 'hex':
            return bytes.fromhex(text).decode('utf-8', errors='ignore')
        elif encoding == 'binary':
            return ''.join([chr(int(text[i:i+8], 2)) for i in range(0, len(text), 8)])
        else:
            return "Unsupported encoding"
    except Exception as e:
        return f"Decoding error: {e}"
