from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import sys
import os

import common

if __name__ == "__main__":
    them = sys.argv[1]
    message = sys.argv[2]

    print("Encrypting using recipients public key ...")
    recipientKeyFile = common.find_public_key(them)
    if recipientKeyFile:
        recipientKey = common.import_key(recipientKeyFile)
        common.rsa_encrypt(message, recipientKey)
    else:
        print("Can't find public key for recipient")
