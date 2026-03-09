import oqs
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PostQuantumCrypto:

    def __init__(self, mechanism="Kyber512"):
        self.mechanism = mechanism
        self.private_kem = None
        self.shared_key = None
        # metrics
        self.keygen_time = None
        self.encap_time = None
        self.decap_time = None
        self.encrypt_time = None
        self.decrypt_time = None
        self.ciphertext_size = None

    def generate_keypair(self):
        start = time.perf_counter() # to generate both the public and the private key

        self.private_kem = oqs.KeyEncapsulation(self.mechanism)
        public_key = self.private_kem.generate_keypair()
        stop = time.perf_counter()
        self.keygen_time = stop - start
        
        return public_key

    def encapsulate(self, peer_public_key):
        start = time.perf_counter()
        with oqs.KeyEncapsulation(self.mechanism) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        stop = time.perf_counter()
        self.encap_time = stop - start

        self.shared_key = shared_secret
        return ciphertext

    def decapsulate(self, ciphertext):
        start = time.perf_counter()
        shared_secret = self.private_kem.decap_secret(ciphertext)
        stop = time.perf_counter()
        self.decap_time = stop - start

        self.shared_key = shared_secret

    def encrypt(self, plaintext):
        start = time.perf_counter()
        aesgcm = AESGCM(self.shared_key[:32])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        self.ciphertext_size = len(ciphertext)
        stop = time.perf_counter()
        self.encrypt_time = stop - start
        
        return nonce + ciphertext

    def decrypt(self, data):
        start = time.perf_counter()
        aesgcm = AESGCM(self.shared_key[:32])
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        stop = time.perf_counter()
        self.decrypt_time = stop - start
        return plaintext.decode()

    def get_metrics(self):
        return {
            "keygen_time": self.keygen_time,
            "encapsulation_time": self.encap_time,
            "decapsulation_time": self.decap_time,
            "encrypt_time": self.encrypt_time,
            "decrypt_time": self.decrypt_time,
            "ciphertext_size": self.ciphertext_size
        }