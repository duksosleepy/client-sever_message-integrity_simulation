from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import gmpy2, os, binascii
from cryptography.hazmat.primitives import hashes

ISSUER_NAME = "fake_cert_authority1"
SUBJECT_KEY = "subject"
ISSUER_KEY = "issuer"
PUBLICKEY_KEY = "public_key"
challenge_bytes = os.urandom(32)
with open(public_key_bob, "rb") as public_key_file_object:
        public_key_bob = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend())

with open(private_key_bob, "rb") as private_key_file_object:
	private_key_bob = serialization.load_pem_private_key(
    		private_key_file_object.read(),
    		backend=default_backend(),
    		password=None)

with open(public_key_alice, "rb") as public_key_file_object:
        public_key_alice = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend())

with open(issuer_public_key, "rb") as public_key_file_object:
    issuer_public_key = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend())
    public_bytes = public_key_file_object.read()

public_key.verify(
    signature,
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)

with open(issuer_public_key, "rb") as public_key_file_object:
    issuer_public_key = serialization.load_pem_public_key(
           public_key_file_object.read(),
           backend=default_backend())
    public_bytes = public_key_file_object.read()

def validate_certificate(certificate_bytes, issuer_public_key):
    raw_cert_bytes, signature = certificate_bytes[:-256], certificate_bytes [-256:]
    issuer_public_key.verify(
            signature,
            raw_cert_bytes,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())
    cert_data = json.loads(raw_cert_bytes.decode('utf-8'))
    cert_data[PUBLICKEY_KEY] = cert_data[PUBLICKEY_KEY].encode('utf-8')
    return cert_data

def verify_identity(identity, certificate_data):
    if certificate_data[ISSUER_KEY] != ISSUER_NAME:
        raise Exception("Invalid (untrusted) Issuer!")
    if certificate_data[SUBJECT_KEY] != identity.decode('utf-8'):
        raise Exception("Claimed identity does not match")
    certificate_public_key = serialization.load_pem_public_key(
        certificate_data[PUBLICKEY_KEY],
        backend=default_backend())


HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    print(f"Connected by {addr}")
    data = conn.recv(1024)
    cert_data = validate_certificate(data, issuer_public_key)
    data = conn.recv(1024)
    verify_identity(data,cert_data)
    print("Verify the identity !!!, so you can send the message to Alice.")
    conn.sendall("Hello".encode('utf-8'))
    with conn:
        while True:
	    data = conn.recv(1024)
	    plaintext = private_key_bob.decrypt(
    				data,
    				padding.OAEP(
        			mgf=padding.MGF1(algorithm=hashes.SHA256()),
        			algorithm=hashes.SHA256(),
        label=None
    )
)
	    raw_bytes, signature_alice = plaintext[:-256], plaintext[-256:]
	    try:	
	    		public_key_alice.verify(signature_alice,
    					raw_bytes,
    					padding.PSS(
        				mgf=padding.MGF1(hashes.SHA256()),
        				salt_length=padding.PSS.MAX_LENGTH
    		),
    			hashes.SHA256()
)
			print("Satify!!")
	    except:
			print("Message had been changed !!")
	    reply = input("Enter the reply message: ").encode('utf-8')
	    signature_bob = private_key_bob.sign(reply,
    				padding.PSS(
    				mgf=padding.MGF1(hashes.SHA256()),
    				salt_length=padding.PSS.MAX_LENGTH
    			),
    			hashes.SHA256()
)
		
	    ciphertext = public_key_alice.encrypt(
    				reply+signature_bob,
    				padding.OAEP(
        			mgf=padding.MGF1(algorithm=hashes.SHA256()),
        			algorithm=hashes.SHA256(),
        label=None
    )
)
	    
	    conn.sendall(ciphertext)
