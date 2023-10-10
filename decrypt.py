from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import sys
import os

import common

if __name__ == "__main__":
    me = sys.argv[1]
    message = sys.argv[2] #bytes(sys.argv[2], "utf-8")

    print(f"Decrypting using recipients private key ...")
    myKeyFile = common.find_private_key(me)
    if myKeyFile:
        senderKey = common.import_key(myKeyFile)
        common.rsa_decrypt(message, senderKey)
    else:
        print(f"Can't find recipients private key")

