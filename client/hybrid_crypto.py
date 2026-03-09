import os
import time
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
        # metrics
        self.ecdh_time = None
        self.kyber_encap_time = None
        self.kyber_decap_time = None
        self.encrypt_time = None
        self.decrypt_time = None
        self.ciphertext_size = None
        self.key_derivation_time = None

    # -------- Key Generation --------

    def generate_ecdh_public(self):
        return self.classical.get_public_bytes()

    def generate_kyber_public(self):
        return self.pqc.generate_keypair()

    # -------- Classical Secret --------

    def derive_ecdh_secret(self, peer_public):
        start = time.perf_counter()
        self.classical.derive_shared_key(peer_public)
        stop = time.perf_counter()
        self.ecdh_time = stop - start
        self.ecdh_secret = self.classical.shared_key

    # -------- Kyber Secret --------

    def encapsulate_kyber(self, peer_public):
        start = time.perf_counter()
        ciphertext = self.pqc.encapsulate(peer_public)
        self.kyber_secret = self.pqc.shared_key

        stop = time.perf_counter()
        self.kyber_encap_time = stop - start
        return ciphertext

    def decapsulate_kyber(self, ciphertext):
        start = time.perf_counter()
        self.pqc.decapsulate(ciphertext)
        self.kyber_secret = self.pqc.shared_key

        stop = time.perf_counter()
        self.kyber_decap_time = stop - start

    # -------- Final Key Derivation --------

    def derive_final_key(self):
        if self.ecdh_secret is None or self.kyber_secret is None:
            return False

        start = time.perf_counter()

        combined = self.ecdh_secret + self.kyber_secret

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid key derivation'
        )

        self.shared_key = hkdf.derive(combined)
        stop = time.perf_counter()
        self.key_derivation_time = stop - start

        return True

    # -------- Encryption --------

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

        classical_metrics = self.classical.get_metrics()
        pqc_metrics = self.pqc.get_metrics()

        hybrid_keygen = None

        if classical_metrics.get("keygen_time") and pqc_metrics.get("keygen_time"):
            hybrid_keygen = (
                classical_metrics["keygen_time"] +
                pqc_metrics["keygen_time"]
            )

        return {
            "keygen_time": hybrid_keygen,
            "key_exchange_time": self.ecdh_time,
            "key_derivation_time": self.key_derivation_time,
            "encrypt_time": self.encrypt_time,
            "decrypt_time": self.decrypt_time,
            "ciphertext_size": self.ciphertext_size
        }
