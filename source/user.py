from cryptography.hazmat.primitives.asymmetric import rsa

class User:
    def __init__(self, name):
        self.name = name

        self.identity_private_key = None
        self.identity_public_key = None
        self.peer_identity_public_key = None

    def generate_key_pair(self):
        # Generating private key with RSA
        self.identity_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identity_public_key = self.identity_private_key.public_key()

    def set_peer_identity_public_key(self, key):
        # Setting peer public key
        self.peer_identity_public_key = key

    def print_info(self):
        print("Name:", self.name)
        print("Private key type:", type(self.identity_private_key).__name__)
        print("Public key type:", type(self.identity_public_key).__name__)
        print("Peer public key type:", type(self.peer_identity_public_key).__name__)

    
