import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# rsa1024 = 128 bytes
# rsa2048 = 256 bytes
# rsa3072 = 384 bytes
# rsa4096 = 512 bytes

def encryptFile(filetobecrypted,public_key,encryptedfile):
    fsrc = open(filetobecrypted,"rb")
    fdst = open(encryptedfile,"wb")    
    
    while True:
        message = fsrc.read(int(public_key.key_size/8)-11)    # 128-11 = 117 bytes (RSA 1024)
        if not message:
            break
        ciphertext = public_key.encrypt(

            message,
            padding.PKCS1v15(),
        )
        fdst.write(ciphertext)

    fsrc.close()
    fdst.close
    pass

def main():
    filetobecrypted = sys.argv[1]
    public_key_file = sys.argv[2]
    encryptedfile = sys.argv[3]

    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    encryptFile(filetobecrypted,public_key,encryptedfile)
    pass


if __name__=="__main__":
    main()