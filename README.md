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

### Packages Imported

- OpenSSL.Crypto

```
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey, TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1, load_pkcs12)
```

- cryptography.hazmat.primitives.asymmetric
```
from cryptography.hazmat.primitives.asymmetric import padding
```


- cryptography.hazmat.backends
```
from cryptography.hazmat.backends import default_backend
```

- Crypto.Util.asn1
```
from Crypto.Util.asn1 import (DerSequence, DerObject)
```

- cryptography.hazmat.primitives
```
from cryptography.hazmat.primitives import hashes
```

- Crypto.PublicKey
```
from Crypto.PublicKey import RSA
```

- import OpenSSL.crypto

- import sys
