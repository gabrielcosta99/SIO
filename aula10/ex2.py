import datetime
from cryptography import x509

CERT_FILE = "ua-pt.pem"

def validate_expiry(cert): 
    now = datetime.datetime.now()
    return now < cert.not_valid_after

def main():
    with open(CERT_FILE, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())


    print(validate_expiry(cert))

if __name__ == "__main__":
    main()