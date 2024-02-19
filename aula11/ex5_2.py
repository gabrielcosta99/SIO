import PyKCS11
import binascii

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