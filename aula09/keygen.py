from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys




def private_keygen(size,private_key_file):
    accepted_sizes = [1024, 2048, 3072, 4096]
    if size not in accepted_sizes:
        print("Key size not accepted. Accepted sizes: 1024, 2048, 3072, 4096")
        exit(1)
    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=size,
        
    )
    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(

        encoding=serialization.Encoding.PEM,

        format=serialization.PrivateFormat.TraditionalOpenSSL,

        encryption_algorithm=serialization.NoEncryption(),

    ))
    return private_key

    
def public_keygen(private_key,public_key_file):


    public_key = private_key.public_key()

    with open(public_key_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def main():
    public_key_file=sys.argv[1]
    private_key_file=sys.argv[2]
    size = int(sys.argv[3])
    private_key = private_keygen(size,private_key_file)
    public_keygen(private_key,public_key_file)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 keygen.py <public_key> <private_key> <key_size>")
        exit(1)
    main()
