import os
import datetime
from cryptography import x509

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
            #print(cert.subject)
            if validate_expiry(cert):
                certs[cert.subject] = cert
    #print("total certificates: ",i)    
    return certs


# Function to recreate validation chain
def recreate_validation_chain(user_cert, certificates):
    validation_chain = []
    current_cert = user_cert

    while current_cert.issuer != current_cert.subject:  # Continue until reaching self-signed root certificate
        issuer_name = current_cert.issuer.rfc4514_string()

        # Check if the issuer is present in certificates
        #if issuer_name in certificates:
        issuer_cert = certificates[issuer_name]
        validation_chain.append((current_cert, issuer_cert))
        current_cert = issuer_cert
        """else:
            # Issuer not found in the provided certificates
            validation_chain.append((current_cert, None))
            break"""

    return validation_chain
    
    


def main():
    certs = my_certs()
    certificate = "ua-pt.pem"
    with open(certificate, "rb") as f:
        user_cert = x509.load_pem_x509_certificate(f.read())
    
    # Recreate validation chain for the user certificate
    validation_chain = recreate_validation_chain(user_cert, certs)
    print(validation_chain)
    # Display validation chain
    for index, link in enumerate(validation_chain, start=1):
        user_cert, issuer_cert = link
        if issuer_cert:
            print(f"Link {index}: User Certificate (Subject: {user_cert.subject}) is issued by {issuer_cert.subject}")
        else:
            print(f"Link {index}: User Certificate (Subject: {user_cert.subject}) is untrusted or a root certificate")
    """if certificate.subject in certs:
        user_cert = certs[certificate.subject]

        # Recreate validation chain for the user certificate
        validation_chain = recreate_validation_chain(user_cert, certs)

        # Display validation chain
        for index, link in enumerate(validation_chain, start=1):
            user_cert, issuer_cert = link
            if issuer_cert:
                print(f"Link {index}: User Certificate (Subject: {user_cert.subject}) is issued by {issuer_cert.subject}")
            else:
                print(f"Link {index}: User Certificate (Subject: {user_cert.subject}) is untrusted or a root certificate")
    else:
        print(f"Certificate '{certificate}' not found.")"""
    

if __name__ == "__main__":
    main()
