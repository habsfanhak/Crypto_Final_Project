from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

class User:
    def __init__(self, name):
        self.name = name

        # Long term identity keys
        self.identity_private_key = None
        self.identity_public_key = None
        self.peer_identity_public_key = None

        # Temporary key-exchange keys
        self.dh_private_key = None
        self.dh_public_key = None
        self.peer_dh_public_key = None

    # -----
    # IDENTITY KEY PAIRS
    # -----
    def generate_key_pair(self):
        # Generating private key with RSA
        self.identity_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identity_public_key = self.identity_private_key.public_key()
        print("Generated identity key pair for", self.name)


    def set_peer_identity_public_key(self, key):
        # Setting peer public key
        self.peer_identity_public_key = key
        print("Set peer identity key pair for", self.name)


    # -----
    # EPHEMERAL DH KEY 
    # -----
    def generate_dh_key_pair(self):
        # Generating DH key pairs
        self.dh_private_key = x25519.X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()
        print("Generated emphemeral DH key pair for", self.name)

    def sign_dh_with_identity_private_key(self):
        # Signing the DH public key with our private key
        dh_public_key_bytes = self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = self.identity_private_key.sign(
            dh_public_key_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return dh_public_key_bytes, signature
    # -----
    # VERIFY DIGITAL SIGNATURE
    # -----    
    def verify_signature(self, content, signature):
        # Verifying the content of something with our public key and a provided signature
        try:
            self.peer_identity_public_key.verify(
                signature,
                content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            print("Signature and Content Match")
            return True
        except InvalidSignature:
            return False

    def set_peer_dh_public_key(self, key):
        public_key = serialization.load_pem_public_key(key)

        print("DH public key set for", self.name)
        self.peer_dh_public_key = public_key


    
