from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256

import os
import base64

def generate_keys(who):
    key = RSA.generate(4096)
    private_key = key.export_key()
    file_out = open(f"private_{who}.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open(f"public_{who}.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    return key

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

    return cipher_text

def rsa_decrypt(cipher_text, receiever_key):
    cipher_rsa = PKCS1_OAEP.new(receiever_key)
    clear_text = cipher_rsa.decrypt(cipher_text).decode()
    return clear_text

def aes_encrypt(clear_text, secret_key):
    secret_key_hash = sha26_hash(bytes(secret_key, "utf-8")).hexdigest()[:16]

    cipher_aes = AES.new(bytes(secret_key_hash, "utf-8"), AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(clear_text)
    return (cipher_text, tag, cipher_aes.nonce)

def aes_decrypt(cipher_text, secret_key, nonce, tag):
    secret_key_hash = sha26_hash(bytes(secret_key, "utf-8")).hexdigest()[:16]
    cipher_aes = AES.new(bytes(secret_key_hash, "utf-8"), AES.MODE_EAX, nonce)
    clear_text = cipher_aes.decrypt_and_verify(cipher_text, tag)
    return clear_text.decode("utf-8")

def sha26_hash(data):
    hash = SHA256.new()
    hash.update(data)
    return hash


def base64_encode(data):
    return base64.b64encode(data).decode()

def base64_decode(data):
    return base64.b64decode(data)