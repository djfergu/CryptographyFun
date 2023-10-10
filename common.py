from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import os
import base64

def find_public_key(who):
    f = f"public_{who}.pem"
    if os.path.isfile(f):
        return f
    return None

def find_private_key(who):
    f = f"private_{who}.pem"
    if os.path.isfile(f):
        return f
    return None

def import_key(public_key_file):
    f = open(public_key_file, "r")
    key = RSA.import_key(f.read())
    return key

def rsa_encrypt(clear_text, receiever_key):
    cipher_rsa = PKCS1_OAEP.new(receiever_key)
    cipher_text = cipher_rsa.encrypt(bytes(clear_text, "utf-8"))
    b64_cipher_text = base64.b64encode(cipher_text).decode()

    print(f"{clear_text} ---> {b64_cipher_text}\n")
    return b64_cipher_text

def rsa_decrypt(b64_cipher_text, receiever_key):
    cipher_text = base64.b64decode(b64_cipher_text)
    cipher_rsa = PKCS1_OAEP.new(receiever_key)
    clear_text = cipher_rsa.decrypt(cipher_text)

    print(f"{b64_cipher_text} ---> {clear_text.decode()}\n")
    return clear_text