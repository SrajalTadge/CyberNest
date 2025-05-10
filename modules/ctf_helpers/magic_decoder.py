# modules/ctf_helpers/magic_decoder.py
import base64, urllib.parse, codecs
def magic_auto_decode(input_text):
    results = []
    def try_decode(label, decode_func):
        try:
            decoded = decode_func(input_text)
            if decoded:
                results.append({"encoding": label, "output": decoded.strip()})
        except: pass

    try_decode("Base64", lambda x: base64.b64decode(x).decode("utf-8", errors="ignore"))
    try_decode("Base32", lambda x: base64.b32decode(x).decode("utf-8", errors="ignore"))
    try_decode("Base16", lambda x: base64.b16decode(x).decode("utf-8", errors="ignore"))
    try_decode("ROT13", lambda x: codecs.decode(x, 'rot_13'))

    if all(c in "01" for c in input_text) and len(input_text) % 8 == 0:
        try:
            binary_decoded = ''.join([chr(int(input_text[i:i+8], 2)) for i in range(0, len(input_text), 8)])
            results.append({"encoding": "Binary", "output": binary_decoded.strip()})
        except: pass

    try_decode("Hex", lambda x: bytes.fromhex(x).decode("utf-8", errors="ignore"))
    try_decode("URL Encoding", lambda x: urllib.parse.unquote(x))
    try_decode("Unicode Escape", lambda x: bytes(x, "utf-8").decode("unicode_escape"))

    try:
        import base58
        base58_decoded = base58.b58decode(input_text).decode("utf-8", errors="ignore")
        results.append({"encoding": "Base58", "output": base58_decoded.strip()})
    except: pass

    try:
        base85_decoded = base64.b85decode(input_text).decode("utf-8", errors="ignore")
        results.append({"encoding": "Base85", "output": base85_decoded.strip()})
    except: pass

    return results if results else [{"encoding": "Unknown", "output": "Could not decode the input."}]
