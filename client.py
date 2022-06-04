import socket
import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

with open(cert_file, "rb") as cert_file_object:
        certificate_bytes = cert_file_object.read()

with open(public_key_alice, "rb") as public_key_file_object:
        public_key_alice = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend())

with open(private_key_alice, "rb") as private_key_file_object:
	private_key_alice = serialization.load_pem_private_key(
    		private_key_file_object.read(),
    		backend=default_backend(),
    		password=None)

with open(public_key_bob, "rb") as public_key_file_object:
        public_key_bob = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend())

signature = private_key.sign(message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

message_as_int = bytes_to_int(message+signature)
cipher_as_int = simple_rsa_encrypt(message_as_int,public_key)
cipher = int_to_bytes(cipher_as_int)
print("\nCiphertext (hexlified): {}\n".format(binascii.hexlify(cipher)))


cipher_hex = input("\nCiphertext (hexlified): ").encode()
cipher = binascii.unhexlify(cipher_hex)
cipher_as_int = bytes_to_int(cipher)
message_as_int = simple_rsa_decrypt(cipher_as_int,private_key)
message = int_to_bytes(message_as_int)
print("\nPlaintext: {}\n".format(message))


raw_bytes, signature = message[:-256], message[-256:]

public_key.verify(
    signature,
    message,
    padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
),
    hashes.SHA256()
)


with open(cert_alice, "rb") as cert_file_object:
    data = cert_file_object.read()

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Sending the certificate...")
    s.sendall(certificate_bytes)
    while True:
    	iden = input("Enter the identity: ").encode('utf-8')
    	s.sendall(iden)
    	data = s.recv(1024)
    	if data == b"Hello":
    		while True:
    			message = input("Enter the message: ").encode('utf-8')
    			signature_alice = private_key_alice.sign(message,
        						padding.PSS(
        						mgf=padding.MGF1(hashes.SHA256()),
        						salt_length=padding.PSS.MAX_LENGTH
        			),
        			hashes.SHA256()
    )
    			ciphertext = public_key_bob.encrypt(
        					message+signature_alice,
        					padding.OAEP(
            				mgf=padding.MGF1(algorithm=hashes.SHA256()),
            				algorithm=hashes.SHA256(),
            		label=None
        )
    )
    			s.sendall(ciphertext)
    		    print("Receiving message...")
    			data = s.recv(1024)
    			plaintext = private_key_alice.decrypt(
        					data,
        					padding.OAEP(
            				mgf=padding.MGF1(algorithm=hashes.SHA256()),
            				algorithm=hashes.SHA256(),
            		label=None
        )
    )	
    			raw_bytes, signature_bob = plaintext[:-256], plaintext[-256:]
    	    	try:	
    	    			public_key_bob.verify(signature_bob,
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





