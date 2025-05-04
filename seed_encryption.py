from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class SeedEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, seed):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(seed.to_bytes(16, 'big'), AES.block_size))
        return cipher.iv + ct_bytes

    def decrypt(self, enc_data):
        iv = enc_data[:16]
        ct = enc_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return int.from_bytes(pt, 'big')