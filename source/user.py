from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class User:
    def __init__(self, name):
        self.name = name
        self.peer_name = None

        # Long term identity keys
        self.identity_private_key = None
        self.identity_public_key = None
        self.peer_identity_public_key = None

        # Temporary key-exchange keys
        self.dh_private_key = None
        self.dh_public_key = None
        self.peer_dh_public_key = None

        # Shared session secret to be computed
        self.shared_session_secret = None

        # Session sending and receiving keys
        self.session_sending_key = None
        self.session_receiving_key = None

        # Send and receive counter for AAD
        self.send_counter = 0
        self.receive_counter = 0

        # Received messages list for this session
        self.received_session_messages = []

        # Session ID
        self.session_id = None

    def start_session(self, session_id, peer_name):
        # Starting a new session
        self.session_id = session_id
        self.peer_name = peer_name

        self.send_counter = 0
        self.receive_counter = 0

    def delete_session(self):
        # Clean up current session
        self.session_id = None
        self.peer_name = None


        self.dh_private_key = None
        self.dh_public_key = None
        self.peer_dh_public_key = None

        self.shared_session_secret = None

        self.send_counter = 0
        self.receive_counter = 0
        self.session_sending_key = None
        self.session_receiving_key = None

        self.received_session_messages = []


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

        content = (
            b"secure-dh-exchange" +
            self.session_id +
            self.name.encode("utf-8") +
            self.peer_name.encode("utf-8") +
            dh_public_key_bytes
        )

        signature = self.identity_private_key.sign(
            content,
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
    def verify_signature(self, dh_public_key_bytes, signature):
        # Verifying the content of dh_public_key_bytes with our public key and a provided signature
        content = (
            b"secure-dh-exchange"
            + self.session_id
            + self.peer_name.encode("utf-8")
            + self.name.encode("utf-8")
            + dh_public_key_bytes
        )

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
        # Accepting and storing the peer's DH public key 
        
        public_key = serialization.load_pem_public_key(key)

        if not isinstance(public_key, x25519.X25519PublicKey):
            raise TypeError("Received key is not an X25519 public key.")

        print("DH public key set for", self.name)
        self.peer_dh_public_key = public_key

    # -----
    # SET SHARED SESSION KEY
    # -----  
    def set_shared_session_secret(self):
        # Setting shared session secret using our DH private key and the peer's DH public key
        self.shared_session_secret = self.dh_private_key.exchange(self.peer_dh_public_key)
        print("Shared session secret set for", self.name)

    def set_session_sending_receiving_key(self, sending_info, receiving_info):
        # Setting session sending and receiving key using the shared session secret
        
        self.session_sending_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=sending_info
        ).derive(self.shared_session_secret)

        self.session_receiving_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=receiving_info
        ).derive(self.shared_session_secret)

        # No longer need the shared session secret and other DH keys
        self.shared_session_secret = None

        self.dh_private_key = None
        self.dh_public_key = None
        self.peer_dh_public_key = None

        print("Session sending and receiving keys set for", self.name)

    # -----
    # ENCRYPT AND DECRYPT MESSAGE
    # -----  
    def encrypt_message(self, message):
        # Encrypting a message using our sending counter, a random nonce, and AES GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_sending_key)

        sequence = self.send_counter
        sequence_bytes = sequence.to_bytes(8, byteorder="big")

        ciphertext = aesgcm.encrypt(
            nonce,
            message.encode("utf-8"),
            sequence_bytes,
        )

        # For the next message
        self.send_counter += 1

        return {
            "nonce": nonce,
            "ciphertext": ciphertext,
            "sequence": sequence
        }

    def decrypt_message(self, packet):
        # Decrypting a message, taking the packet header, ciphertext, and ensuring packet integrity
        sequence = packet["sequence"]
        sequence_bytes = sequence.to_bytes(8, byteorder="big")

        aesgcm = AESGCM(self.session_receiving_key)

        try:
            message = aesgcm.decrypt(
                packet["nonce"],
                packet["ciphertext"],
                sequence_bytes,
            )
        except InvalidTag:
            raise ValueError(
                "Message authentication failed: packet was modified."
            )

        if sequence != self.receive_counter:
            raise ValueError(
                f"Sent sequence and receive counter not matching, counter is {self.receive_counter}, actually received {sequence}"
            )

        # For the next message
        self.receive_counter += 1

        # Appending the message to our list
        self.received_session_messages.append(message.decode("utf-8"))

        return message.decode("utf-8")