import oqs
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PostQuantumCrypto:

    def __init__(self, mechanism="Kyber512"):
        self.mechanism = mechanism
        self.private_kem = None
        self.shared_key = None

    def generate_keypair(self):
        self.private_kem = oqs.KeyEncapsulation(self.mechanism)
        public_key = self.private_kem.generate_keypair()
        return public_key

    def encapsulate(self, peer_public_key):
        with oqs.KeyEncapsulation(self.mechanism) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        self.shared_key = shared_secret
        return ciphertext

    def decapsulate(self, ciphertext):
        shared_secret = self.private_kem.decap_secret(ciphertext)
        self.shared_key = shared_secret

    def encrypt(self, plaintext):
        aesgcm = AESGCM(self.shared_key[:32])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext

    def decrypt(self, data):
        aesgcm = AESGCM(self.shared_key[:32])
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()