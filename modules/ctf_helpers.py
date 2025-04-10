import base64

def convert_base(text, base):
    try:
        if base == "base64":
            return base64.b64decode(text).decode()
        elif base == "base32":
            return base64.b32decode(text).decode()
        elif base == "base85":
            return base64.b85decode(text).decode()
        else:
            return "Unsupported base!"
    except Exception as e:
        return f"Error: {str(e)}"
