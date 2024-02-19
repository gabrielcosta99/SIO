import os, sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import AES

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt (cipher, plaintext):
	padder = padding.PKCS7(128).padder()
	encryptor = cipher.encryptor()

	b_plaintext = padder.update(bytes(plaintext, "utf-8"))+padder.finalize()
	encrypted_data = encryptor.update(b_plaintext)+encryptor.finalize()

	# Return number encrypted
	return encrypted_data


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary strings coded in base64

def decrypt (cipher, data):
	unpadder = padding.PKCS7(128).unpadder()
	decryptor = cipher.decryptor()

	decrypted_text = decryptor.update(data)+decryptor.finalize()
	return decrypted_text.strip().decode('utf-8')
	



if len(sys.argv) != 2:
	print("Usage: python3 ex1.py <mode>")
	exit(1)
salt = os.urandom(16)

# derive

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

key = kdf.derive(b"my great password")

# verify

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)

kdf.verify(b"my great password", key)
	
iv = os.urandom(16)

mode = sys.argv[1]
if mode == "ecb":
	cipher = Cipher(algorithms.AES(key), modes.ECB())
elif mode == "cbc":
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
	

ciphered=encrypt(cipher,"12345")
print("encrypted: ", ciphered)
deciphered=decrypt(cipher, ciphered)
print("deciphered: ",deciphered)