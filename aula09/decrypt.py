import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# rsa1024 = 128 bytes
# rsa2048 = 256 bytes
# rsa3072 = 384 bytes
# rsa4096 = 512 bytes
def decryptFile(encryptedfile,private_key,fileDecrypted):
    
    plaintext=b''
    with open(encryptedfile, "rb") as f:
        while True:
            ciphertext = f.read(int(private_key.key_size/8))    # 128-11 = 117 bytes (RSA 1024)
            if not ciphertext:
                break
            
            plaintext += private_key.decrypt(
            ciphertext,
            padding.PKCS1v15(),
        )
    with open(fileDecrypted, "wb") as f:
        f.write(plaintext)
    pass

def main():
    private_key_file = sys.argv[1]
    encryptedfile = sys.argv[2]
    fileDecrypted = sys.argv[3]

    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    decryptFile(encryptedfile,private_key,fileDecrypted)
    pass


if __name__=="__main__":
    main()