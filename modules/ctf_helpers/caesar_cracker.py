import string

ENGLISH_WORDS = set("""
hello world this is test secret message decode password key encryption security tool flag capture the hidden welcome you are using a simple caesar brute force dictionary attack try all possibilities openai python cybernest example brute force decoder encoding
""".lower().split())

def score_english(text):
    words = text.lower().split()
    matches = sum(1 for word in words if word in ENGLISH_WORDS)
    return matches

def caesar_brute_force(text):
    results = []
    for key in range(1, 26):
        decrypted = ''
        for char in text:
            if char.isalpha():
                offset = 65 if char.isupper() else 97
                decrypted += chr((ord(char) - offset - key) % 26 + offset)
            else:
                decrypted += char
        score = score_english(decrypted)
        results.append({"key": key, "output": decrypted, "score": score})
    results.sort(key=lambda x: -x["score"])
    return results
