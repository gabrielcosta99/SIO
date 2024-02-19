import sys,os
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# rsa1024 = 128 bytes
# rsa2048 = 256 bytes
# rsa3072 = 384 bytes
# rsa4096 = 512 bytes

def encryptFile(filetobecrypted,public_key,encryptedfile):
    aes_key= os.urandom(16)     # generate AES key
    with open(filetobecrypted, 'rb') as file:
        plaintext = file.read()     # read the data from the file (all of it)

    iv = b'\x00' * 16  # Initialization Vector for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))  
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # RSA encryption of AES key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.PKCS1v15()
    )

    with open(encryptedfile, 'wb') as file:
        file.write(encrypted_aes_key)
        file.write(iv)
        file.write(ciphertext)
        

    pass

def decryptFile(encryptedfile,private_key,fileDecrypted):
    
    with open(encryptedfile, 'rb') as file:
        encrypted_aes_key = file.read(private_key.key_size // 8)
        iv = file.read(16)
        ciphertext = file.read()

    # RSA decryption of AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.PKCS1v15()
    )

    # AES decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(fileDecrypted, 'wb') as file:
        file.write(plaintext)



def main():
    op = sys.argv[1]        # encrypt/decrypt
    file = sys.argv[2]      # file to encrypt/decrypt
    key_file = sys.argv[3]       # pode ser a privada ou a publica
    if op.lower() == "encrypt":
            with open(key_file, "rb") as pub_key_file:
                pub_key = serialization.load_pem_public_key(
                    pub_key_file.read()
                )
            print("public")
            encryptFile(file,pub_key,"ciphered_file.txt")
            print("ciphered")
    elif op.lower() == "decrypt":
    # Attempt to load the key
        with open(key_file, "rb") as priv_key_file:
            priv_key = serialization.load_pem_private_key(
                priv_key_file.read(),
                password=None,
            )
        print("private key")
        decryptFile(file,priv_key,"deciphered_file.txt")
        print("deciphered")
    else:
        print("first argument should be: encrypt/decrypt")


    #encryptFile(filetobecrypted,key,encryptedfile)
    pass


if __name__=="__main__":
    main()