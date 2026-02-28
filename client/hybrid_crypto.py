import os
from classical_crypto import ClassicalCrypto
from post_quantum_crypto import PostQuantumCrypto
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class HybridCrypto:

    def __init__(self):
        self.classical = ClassicalCrypto()
        self.pqc = PostQuantumCrypto()

        self.ecdh_secret = None
        self.kyber_secret = None
        self.shared_key = None

    # -------- Key Generation --------

    def generate_ecdh_public(self):
        return self.classical.get_public_bytes()

    def generate_kyber_public(self):
        return self.pqc.generate_keypair()

    # -------- Classical Secret --------

    def derive_ecdh_secret(self, peer_public):
        self.classical.derive_shared_key(peer_public)
        self.ecdh_secret = self.classical.shared_key

    # -------- Kyber Secret --------

    def encapsulate_kyber(self, peer_public):
        ciphertext = self.pqc.encapsulate(peer_public)
        self.kyber_secret = self.pqc.shared_key
        return ciphertext

    def decapsulate_kyber(self, ciphertext):
        self.pqc.decapsulate(ciphertext)
        self.kyber_secret = self.pqc.shared_key

    # -------- Final Key Derivation --------

    def derive_final_key(self):
        if self.ecdh_secret is None or self.kyber_secret is None:
            return False

        combined = self.ecdh_secret + self.kyber_secret

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid key derivation'
        )

        self.shared_key = hkdf.derive(combined)
        return True

    # -------- Encryption --------

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