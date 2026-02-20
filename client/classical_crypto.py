# ECDH key generation
# shared key derivation
# AES-GCM encryption and decryption

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ClassicalCrypto:
    def __init__(self):
        # Generate ECDH key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.shared_key = None
    
    def get_public_bytes(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo  
        )
    def derive_shared_key(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None, 
            info=b'handshake data',
        ).derive(shared_secret)

        self.shared_key = derived_key
    
    def encrypt(self, plaintext):
        aesgcm = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext
    def decrypt(self, data):
        aesgcm = AESGCM(self.shared_key)
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
