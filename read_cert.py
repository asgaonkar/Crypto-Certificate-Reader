'''
CSE 539 Project 5
Jaswant Pakki 1208755310
Atit Gaonkar 1217031322

# Readme

> (Linux Based) use Python3

### Usage and Execution

Usage:
```
python3 read_cert.py Certificates/cert_bckup.p12 Certificates/root.crt Certificates/subject.crt CSE539_Rocks!
```

> Mandatory Inputs: All above mentioned files are Mandatory (Total Arguments: 4)

## Authors

* **Atit S Gaonkar** - *1217031322*
* **Jaswant  Pakki** - *1208755310*


## I/O

#Input:
```
.p12 - Backup file containing the private key of Subjects Public Key
subject.crt - Subject's Certificate
CA.crt - CA's Certificate
passphrase - Key to open .p12 File
```

#Output:

Sub-task 1
```
Verify the Subject’s certificate (print True if valid, False otherwise)
```
Sub-task 2 - Subject's Information
```
a.       *Subject name
b.       Issuer
c.       Serial Number
d.       Encryption Algorithm
e.       Not Valid Before
f.       Not Valid After
```
Sub-task 3 - Subject's Key Information
```
a.       Public Key Modulus (n)
b.       Public Key Exponent (e)
c.       Private Key Exponent (d)
```
Sub-task 4 - CA's Key Information
```
a.       Root Public Key Modulus (n)
b.       Root Public Key Exponent (e)
```
Sub-task 5 - Subject's Signature on Certificate
```
Print the hex signature on the Subject’s certificate
```
Sub-task 6 - Encryption
```
Encrypt b’Hello World’ using RSA (OEAP Padding, MGF Function as MGF1 and SHA256 hash function). Encryption using Subject's public key
```

'''
import sys
import base64
import OpenSSL.crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey, TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1, load_pkcs12)

#Load Certificate
#OpenSSL.crypto.X509
cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,open(sys.argv[3]).read())

ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,open(sys.argv[2]).read())


#print("=========================== 1 (Complete) ===========================")
store = OpenSSL.crypto.X509Store()
store.add_cert(ca_cert)
store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
try:
    store_ctx.verify_certificate()
    print (True)
except OpenSSL.crypto.X509StoreContextError as e:
    print (False)

#print("=========================== 2 (Complete) ===========================")

#Load Subject Name
subject = cert.get_subject()
issued_to = subject.CN
print (issued_to)

#Load Issuer Name
issuer = cert.get_issuer()
issued_by = issuer.CN
print (issued_by)

#Serial Number
serial_no = cert.get_serial_number()
print (serial_no)

#Sign algorithm
sign_algo = cert.get_signature_algorithm()
print (sign_algo.decode())

#Not Before
not_before = cert.get_notBefore()
print (not_before.decode())

#Not After
not_after = cert.get_notAfter()
print (not_after.decode())

#print("=========================== 3 (********) ===========================")

#Public Key Subject
subject_key_obj = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8")
subject_key_obj_keys = cert.get_pubkey().to_cryptography_key().public_numbers()

print("{}".format(subject_key_obj_keys.n))
print("{}".format(subject_key_obj_keys.e))


#Private Key Subject
with open(sys.argv[1], 'rb') as f:
  c = f.read()
p = load_pkcs12(c, str.encode(sys.argv[4]))
private_key = p.get_privatekey()

print("{}".format(private_key.to_cryptography_key().private_numbers().d))
#print("=========================== 4 (Complete) ===========================")

ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,open(sys.argv[2]).read())
ca_key_obj = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, ca_cert.get_pubkey()).decode("utf-8")

ca_key_obj_keys = ca_cert.get_pubkey().to_cryptography_key().public_numbers()

print("{}".format(ca_key_obj_keys.n))
print("{}".format(ca_key_obj_keys.e))

#print("=========================== 5 (Incomplete) ===========================")

cert_txt = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert)

cert_txt = cert_txt.split(b'Signature Algorithm:')
cert_txt = cert_txt[len(cert_txt)-1]
cert_txt = cert_txt.split(b'\n')[1:]
# print(cert_txt)

test_text = ""

for i in range(0,len(cert_txt)):
    test_text += str(cert_txt[i].decode('utf-8'))

test_text = test_text.replace(" ","")
test_text = test_text.replace(":","")

print("========================================================================")
print("{}".format(test_text))
print("========================================================================")

# cert_sign = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,open(sys.argv[3]).read())
# print(cert_sign)


#print("=========================== 6 (Complete) ===========================")

message = b'Hello World'

subject_key_obj_key_enc = cert.get_pubkey().to_cryptography_key()

ciphertext = subject_key_obj_key_enc.encrypt(message,padding.OAEP(mgf= padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None ))

print("{}".format(ciphertext.hex()))

# print(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert))
