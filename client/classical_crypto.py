# ECDH key generation
# shared key derivation
# AES-GCM encryption and decryption

import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ClassicalCrypto:
    def __init__(self):
        # metrics
        self.keygen_time = None
        self.key_derivation_time = None
        self.key_exchange_time = None
        self.encrypt_time = None
        self.decrypt_time = None
        self.ciphertext_size = None

        # Generate ECDH key pair
        start = time.perf_counter()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        stop = time.perf_counter()
        self.keygen_time = stop - start
        self.shared_key = None
    
    def get_public_bytes(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo  
        )
    def derive_shared_key(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        start_exchange = time.perf_counter()
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        stop_exchange = time.perf_counter()
        self.key_exchange_time = stop_exchange - start_exchange

        start_kdf = time.perf_counter()
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None, 
            info=b'handshake data',
        ).derive(shared_secret)
        stop_kdf = time.perf_counter()
        self.key_derivation_time = stop_kdf - start_kdf

        self.shared_key = derived_key
    
    def encrypt(self, plaintext):
        start = time.perf_counter()
        aesgcm = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        self.ciphertext_size = len(ciphertext)
        stop = time.perf_counter()

        self.encrypt_time = stop - start
        return nonce + ciphertext
    def decrypt(self, data):
        start = time.perf_counter()
        aesgcm = AESGCM(self.shared_key)
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        stop = time.perf_counter()

        self.decrypt_time = stop - start
        return plaintext.decode()

    def get_metrics(self):

        return {
            "keygen_time": self.keygen_time,
            "key_exchange_time": self.key_exchange_time,
            "key_derivation_time": self.key_derivation_time,
            "encrypt_time": self.encrypt_time,
            "decrypt_time": self.decrypt_time,
            "ciphertext_size": self.ciphertext_size
        }
