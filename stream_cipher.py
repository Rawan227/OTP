def stream_encrypt(plaintext: bytes, keystream: bytes):
    return bytes([p ^ k for p, k in zip(plaintext, keystream)])