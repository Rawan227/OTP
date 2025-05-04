import os
import socket
import pickle
from lcg import LCG
from stream_cipher import stream_encrypt
from seed_encryption import SeedEncryptor
from hmac_auth import generate_hmac
from key_exchange import DiffieHellman
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
CHUNK_SIZE = int(config['DEFAULT']['CHUNK_SIZE'])
HOST = config['DEFAULT']['HOST']
PORT = int(config['DEFAULT']['PORT'])

class Sender:
    def __init__(self):
        print("Initializing Sender...")
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Sender DH public key: {self.dh.public_key}")

    def connect_to_receiver(self):
        self.sock.connect((HOST, PORT))
        print(f"Connection established with {HOST}:{PORT}")

    def send_in_chunks(self, data, chunk_size):
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def send(self):
        self.sock.sendall(str(self.dh.public_key).encode())
        
        receiver_pub_key = int(self.sock.recv(1024).decode())
        print(f"Received receiver public key: {receiver_pub_key}")

        shared_key = self.dh.compute_shared_key(receiver_pub_key)
        print(f"Shared Key established: {shared_key.hex()}")

        seed = int.from_bytes(os.urandom(8), 'big')
        print(f"Generated seed: {seed}")
        lcg = LCG(seed)

        with open('input.txt', 'r') as f:
            plaintext = f.read().encode()
        print(f"Plaintext length: {len(plaintext)} bytes")

        keystream = lcg.generate_keystream(len(plaintext))
        ciphertext = stream_encrypt(plaintext, keystream)
        print(f"Ciphertext generated: {len(ciphertext)} bytes")

        encryptor = SeedEncryptor(shared_key)
        enc_seed = encryptor.encrypt(seed)
        print(f"Encrypted seed: {enc_seed.hex()}")

        seed_bytes = seed.to_bytes(8, 'big')  # Convert seed to bytes for HMAC
        hmac_tag = generate_hmac(seed_bytes, shared_key)  # HMAC of the seed
        print(f"Generated HMAC (for seed): {hmac_tag.hex()}")

        metadata = {
            'enc_seed': enc_seed,
            'hmac_tag': hmac_tag,
            'total_length': len(ciphertext)
        }
        print("Sending metadata...")
        self.sock.sendall(pickle.dumps(metadata))

        print("Starting chunked transmission...")
        chunk_count = 0
        for chunk in self.send_in_chunks(ciphertext, CHUNK_SIZE):
            self.sock.sendall(chunk)
            print(f"Sent chunk {chunk_count}: {len(chunk)} bytes")
            ack = self.sock.recv(3)
            if ack != b'ACK':
                print("ERROR: Missing ACK")
                raise ConnectionError("ACK not received")
            chunk_count += 1

        print(f"Transmission complete. Sent {chunk_count} chunks.")
        self.sock.close()