import socket
import pickle
from lcg import LCG
from stream_cipher import stream_encrypt
from seed_encryption import SeedEncryptor
from hmac_auth import verify_hmac
from key_exchange import DiffieHellman
import configparser

config = configparser.ConfigParser()
config.read('config.txt')
HOST = config['DEFAULT']['HOST']
PORT = int(config['DEFAULT']['PORT'])
CHUNK_SIZE = int(config['DEFAULT']['CHUNK_SIZE'])

class Receiver:
    def __init__(self):
        print("Initializing Receiver...")
        self.dh = DiffieHellman()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((HOST, PORT))
        self.sock.listen()
        print(f"Receiver listening on {HOST}:{PORT}")
        print(f"Receiver DH public key: {self.dh.public_key}")

    def receive_chunks(self, conn, total_length):
        received_data = bytearray()
        chunk_count = 0
        while len(received_data) < total_length:
            remaining = total_length - len(received_data)
            chunk_size = min(CHUNK_SIZE, remaining)
            chunk = conn.recv(chunk_size)
            if not chunk:
                print("ERROR: Connection closed prematurely")
                break
            received_data.extend(chunk)
            conn.sendall(b'ACK')
            print(f"Received chunk {chunk_count}: {len(chunk)} bytes")
            print(chunk.decode())
            chunk_count += 1
        print(f"Received all {chunk_count} chunks")
        return bytes(received_data)

    def receive(self):
        conn, addr = self.sock.accept()
        print(f"Connection established with {addr}")

        print("Waiting for sender's public key...")
        sender_pub_key = int(conn.recv(1024).decode())
        print(f"Received sender public key: {sender_pub_key}")

        conn.sendall(str(self.dh.public_key).encode())
        
        shared_key = self.dh.compute_shared_key(sender_pub_key)
        print(f"Shared Key established: {shared_key.hex()}")

        metadata = pickle.loads(conn.recv(1024))
        enc_seed = metadata['enc_seed']
        hmac_tag = metadata['hmac_tag']
        total_length = metadata['total_length']

        print("Starting chunked reception...")
        ciphertext = self.receive_chunks(conn, total_length)
        print(f"Full ciphertext received: {len(ciphertext)} bytes")

        decryptor = SeedEncryptor(shared_key)
        seed = decryptor.decrypt(enc_seed)
        seed_bytes = seed.to_bytes(8, 'big')  # Convert seed to bytes for verification
        if verify_hmac(seed_bytes, hmac_tag, shared_key):
            print("HMAC verification successful (seed is authentic)")

            lcg = LCG(seed)
            keystream = lcg.generate_keystream(len(ciphertext))
            plaintext = stream_encrypt(ciphertext, keystream)
            print(f"Plaintext decrypted: {len(plaintext)} bytes")

            with open('output.txt', 'w') as f:
                f.write(plaintext.decode())
            print("Received plaintext:", plaintext[:].decode())
        else:
            print("ERROR: HMAC verification failed (seed tampered!)")
            conn.close()
            return  # Exit if verification fails

        conn.close()