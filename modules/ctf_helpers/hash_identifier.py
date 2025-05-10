def identify_hash(hash_str):
    hash_str = hash_str.strip().lower()
    length = len(hash_str)
    
    candidates = []

    if length == 32 and all(c in '0123456789abcdef' for c in hash_str):
        candidates.append("MD5")

    if length == 40 and all(c in '0123456789abcdef' for c in hash_str):
        candidates.append("SHA1")

    if length == 64 and all(c in '0123456789abcdef' for c in hash_str):
        candidates.append("SHA256")

    if length == 96 and all(c in '0123456789abcdef' for c in hash_str):
        candidates.append("SHA384")

    if length == 128 and all(c in '0123456789abcdef' for c in hash_str):
        candidates.append("SHA512")

    if not candidates:
        candidates.append("Unknown or unsupported hash format.")

    return candidates
