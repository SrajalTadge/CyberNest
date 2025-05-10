import base64
import re

def detect_base(text):
    results = []
    text = text.strip()
    reasons = {}
    confidences = {}

    if re.fullmatch(r'[01]+', text) and len(text) % 8 == 0:
        results.append("Binary")
        reasons["Binary"] = "Only contains 0 and 1, and length is multiple of 8."
        confidences["Binary"] = 90

    try:
        if len(text) % 2 == 0:
            bytes.fromhex(text)
            results.append("Hex")
            reasons["Hex"] = "Valid hexadecimal string (0-9, A-F), even-length, decodable."
            confidences["Hex"] = 85
    except:
        pass

    try:
        decoded = base64.b32decode(text, casefold=True)
        if decoded:
            results.append("Base32")
            reasons["Base32"] = "Valid base32 decoding using RFC 4648 standard."
            confidences["Base32"] = 80
    except:
        pass

    base64_regex = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
    if base64_regex.match(text) and len(text) >= 8 and not re.fullmatch(r'[01]+', text):
        try:
            decoded = base64.b64decode(text, validate=True)
            if decoded:
                results.append("Base64")
                reasons["Base64"] = "Valid base64 decoding with proper padding and format."
                confidences["Base64"] = 95
        except:
            pass

    if not results:
        results = ["Unknown or custom encoding"]
        reasons["Unknown or custom encoding"] = "No known base matched the input."
        confidences["Unknown or custom encoding"] = 50

    return [{"base": b, "reason": reasons[b], "confidence": confidences[b]} for b in results]
