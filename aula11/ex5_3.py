import PyKCS11
import binascii
import hashlib

lib = 'libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load( lib )
slots = pkcs11.getSlotList()
for slot in slots:
    pkcs11.getTokenInfo( slot )     

# Attributes are key-value pairs, get all the possible keys
all_attr = list( PyKCS11.CKA.keys() )
#Filter attributes
all_attr = [e for e in all_attr if isinstance( e, int )]
session = pkcs11.openSession( slot )
for obj in session.findObjects():
    # Get object attributes
    attr = session.getAttributeValue( obj, all_attr )
    # Create dictionary with attributes
    attr = dict( zip( map( PyKCS11.CKA.get, all_attr ), attr ) )
    # Print the object label
    print( 'Label: %s, Class: %d' % (attr['CKA_LABEL'], attr['CKA_CLASS']) )

print( 'Class: %d means private key, %d means public key, %d means certificate'
    % (PyKCS11.CKO_PRIVATE_KEY, PyKCS11.CKO_PUBLIC_KEY, PyKCS11.CKO_CERTIFICATE) )


method = 1
private_key = session.findObjects( [ (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_LABEL, 'CITIZEN SIGNATURE KEY') ] )[0]
if method == 0:

    # The function returns a list, that's why we need the [0] at the end
    mechanism = PyKCS11.Mechanism( PyKCS11.CKM_SHA1_RSA_PKCS, None )
    text = b'text to sign'
    signature = bytes( session.sign( private_key, text, mechanism) )
else:
    
    mechanism = PyKCS11.Mechanism( PyKCS11.CKM_RSA_PKCS, None )
    h = hashlib.sha1()
    text = 'text to sign'
    h.update( text.encode( 'UTF-8') )
    signature = bytes( session.sign( private_key, h.digest(), mechanism) )
