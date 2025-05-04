from Crypto.Random import get_random_bytes
import hashlib

class DiffieHellman:
    def __init__(self, g=5, p=0xFFFFFFFB):
        self.g = g
        self.p = p
        self.private_key = int.from_bytes(get_random_bytes(16), 'big')
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_key(self, other_public):
        shared = pow(other_public, self.private_key, self.p)
        return hashlib.sha256(str(shared).encode()).digest()[:16]