import oqs

print("Enabled KEMs:", oqs.get_enabled_kem_mechanisms())

with oqs.KeyEncapsulation("Kyber512") as server:
    public_key = server.generate_keypair()

    with oqs.KeyEncapsulation("Kyber512") as client:
        ciphertext, shared_client = client.encap_secret(public_key)

    shared_server = server.decap_secret(ciphertext)

print("Client secret (first 10 bytes):", shared_client[:10])
print("Server secret (first 10 bytes):", shared_server[:10])
print("Secrets match:", shared_client == shared_server)