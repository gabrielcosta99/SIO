import os
import datetime
from cryptography import x509

"""
Usually, trust anchor certificates are provided by the operating system or the application in use (e.g., Firefox,
Chrome, etc.). Sometimes, the user may also provide new trust anchors, depending on the application
and the security model. The trust anchor certificates must be protected in a keystore or a restricted
location (/etc/ssl/certs) to prevent unwanted additions or removals, be these intentional (e.g., adversarial) or
unintentional (i.e., accidents). You can use the certificates in your Linux system as individual files containing
certificates in the PEM format.
Task: Implement a small program that reads all system-trusted certificates into a dictionary of trusted
certificates, with the subject as the key.
Do not load certificates that have already expired (use the previously developed function).
HINT: Use the os.scandir object to scan for all certificates in /etc/ssl/certs
"""

def validate_expiry(cert): 
    now = datetime.datetime.now()
    return now < cert.not_valid_after


def my_certs():
    certs = {}
    i=0
    for entry in os.scandir("/etc/ssl/certs"):
        i+=1
        with open(entry, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            if validate_expiry(cert):
                certs[cert.subject] = cert
    print("total certificates: ",i)
    
    return certs

def main():
    certs = my_certs()
    print("valid certificates: ",len(certs))

if __name__ == "__main__":
    main()
