# CryptographyFun

Before these scripts will run, you need to do the following:

- Download and Install latest Python: https://www.python.org/downloads/
- install PyCryptoDome

* - pip install pycryptodome

Then:

- Create your keys
- - python .\create_keys.py sprout
- - Give someone your public key.
- - Get someone elses public key
- Encrypt something using someone elses public key
- Send encrypted message to recipient.
- Recipient uses their private key to decrypt message

Examples:

- Generate your keys. Share the public key, and keep the private key safe and sound.

```
PS D:\cryptography0> python .\create_keys.py MyName
Generating RSA Keys...
    ".\private_MyName.pem"    <--- keep this safe, and secret.
    ".\public_MyName.pem"     <--- share this
```

- Get the public key from the person you'd like to send a message to...

- Encrypt a message, using the public key of the recipient.

```
  PS D:\Pythons\cryptography0> python .\rsa_encrypt.py bob "Let's revolt tomorrow at noon"
  Encrypting with public_bob.pem:

  GkR1BOXVBXQDNZcAc/KiAbXp5V+DnMdw4Iw9aKGyoQcnnxzNweni2GgHtQ21yXTLna/ kUMwGwDbUXovxwrCpxGaX+NPkEwP0U3Q+xkv/pfck0bKeJ0qoC0umrL/ Ny53iX4gWyJELqUNBgvrP5XMifTBjxP868jvLB9vMKY54Szx +oEaKdZUOuzWqSx9XId4IeDUWhPb5qdnubMhyu3acCWhAv8tc +wwaNJ5eeL1aVA6byCVYGCqhjuxnC+0OsCXenTkV0fu/ 6Wy8gzyeUlDpbLIuNbRAcxX97acjGz5dTllYZFQhzIJXPN1IgTpvY2UJZkh1mEQoQE +UZPebWJoLjnIVlevDuzcp3frD5rY7Xi3GL8Y+4q4Nie1btrljYA4p4Eyqx/ TgqlCULTpDEqehtiXMm53i/bZMExqVaQ3apM1hNSacyxOI6Vc +ZZbBwJIWBDocgwpj6QyyeSuLYgnkQ6NLZwcYgefmaW6CHyckTc3nULeBgTNMZDnOIGq9gOM2yRzp t2fJePXzXOVC0e+W4yNO1r2cPqQ8vSnF0rOeAh+ksCsoe+MhWYLw75V +4UPpgiy3nU7n4z4zWZdfTXZTaZu6cE/t2crx0K7E1DfnCcsJy1LrpbCRg +bRhR6qhHtEPx4PDH0TDTjv+bjo5q67xOOD3CKIeDex1UalDFET5FY=
```

- Send the encrypted message to bob
- Bob decrypts the message, using his private key:

```
  PS D:\Pythons\cryptography0> python .\rsa_decrypt.py bob GkR1BOXVBXQDNZcAc/ KiAbXp5V+DnMdw4Iw9aKGyoQcnnxzNweni2GgHtQ21yXTLna/kUMwGwDbUXovxwrCpxGaX +NPkEwP0U3Q+xkv/pfck0bKeJ0qoC0umrL/ Ny53iX4gWyJELqUNBgvrP5XMifTBjxP868jvLB9vMKY54Szx +oEaKdZUOuzWqSx9XId4IeDUWhPb5qdnubMhyu3acCWhAv8tc +wwaNJ5eeL1aVA6byCVYGCqhjuxnC+0OsCXenTkV0fu/ 6Wy8gzyeUlDpbLIuNbRAcxX97acjGz5dTllYZFQhzIJXPN1IgTpvY2UJZkh1mEQoQE +UZPebWJoLjnIVlevDuzcp3frD5rY7Xi3GL8Y+4q4Nie1btrljYA4p4Eyqx/ TgqlCULTpDEqehtiXMm53i/bZMExqVaQ3apM1hNSacyxOI6Vc +ZZbBwJIWBDocgwpj6QyyeSuLYgnkQ6NLZwcYgefmaW6CHyckTc3nULeBgTNMZDnOIGq9gOM2yRzp t2fJePXzXOVC0e+W4yNO1r2cPqQ8vSnF0rOeAh+ksCsoe+MhWYLw75V +4UPpgiy3nU7n4z4zWZdfTXZTaZu6cE/t2crx0K7E1DfnCcsJy1LrpbCRg +bRhR6qhHtEPx4PDH0TDTjv+bjo5q67xOOD3CKIeDex1UalDFET5FY=
  Decrypting with private_bob.pem

  Let's revolt tomorrow at noon
```

- To use AES symmetric encryption (using a shared password):

```
  PS D:\Pythons\cryptography0> python .\aes_encrypt.py bingbong "secret sauce"
  ZjlnnvIxqkZMqLITs5kOSQ== QaNvD7XUqDq2S/b5FFgNYQ== wR9xRkr/Pcmayzir

  PS D:\Pythons\cryptography0> python .\aes_decrypt.py bingbong ZjlnnvIxqkZMqLITs5kOSQ== QaNvD7XUqDq2S/b5FFgNYQ== wR9xRkr/Pcmayzir
  secret sauce
```

- To find the SHA256 hash of a file:

```
  PS D:\Pythons\cryptography0> python .\sha256_hash.py "C:\Users\Daniel\Downloads\Sparrow-1.7.9.exe"
  22457f2c6882663194a39f8d705195dcc2599f8cca2273b2db95057db0fcfc51
```
