#
# 1)  Install python
# 2)  pip install pycryptodome
#

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import base64

secret_message      = b"Once upon a time, there was a strong nation."
secret_message_copy = b"Once upon a time, there was a strong nation."

def generate_keys(who):
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(f"private_{who}.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open(f"public_{who}.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    return key

def generate_hash(data):
    hash = SHA256.new()
    hash.update(data)
    digest = hash.hexdigest()
    print(f"Hash: {digest}")
    return hash

def sign_hash(hash, key):
    signer = pkcs1_15.new(key)
    signature = signer.sign(hash)
    return signature

def verify_hash(hash, key, signature):
    verifier = pkcs1_15.new(key)
    return verifier.verify(hash, signature)

def rsa_encrypt(clear_text, receiever_key):
    cipher_rsa = PKCS1_OAEP.new(receiever_key)
    cipher_text = cipher_rsa.encrypt(clear_text)
    print(f"{clear_text} ---> {binascii.b2a_hex(cipher_text)}\n")
    return cipher_text

def rsa_decrypt(cipher_text, receiever_key):
    cipher_rsa = PKCS1_OAEP.new(receiever_key)
    clear_text = cipher_rsa.decrypt(cipher_text)
    print(f"{binascii.b2a_hex(cipher_text)} ---> {clear_text}\n")
    return clear_text

def aes_encrypt(clear_text, secret_key):
    cipher_aes = AES.new(secret_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(clear_text)
    print(f"{clear_text} ---> {binascii.b2a_hex(cipher_text)}\n")
    return (cipher_text, tag, cipher_aes.nonce)

def aes_decrypt(cipher_text, secret_key, nonce, tag):
    cipher_aes = AES.new(secret_key, AES.MODE_EAX, nonce)
    clear_text = cipher_aes.decrypt_and_verify(cipher_text, tag)
    print(f"{binascii.b2a_hex(cipher_text)} ---> {clear_text.decode('utf-8')}\n")
    return clear_text

def test0():
    keys = generate_keys()
    hash = generate_hash(secret_message)
    signature = sign_hash(hash, keys)

    hash_2 = generate_hash(secret_message_copy)
    try:
        verify_hash(hash_2, keys, signature)
        print("Signature Verified!")
    except ValueError:
        print("Signature is invalid")
    

def test1():
    alice_keys = generate_keys()
    bob_keys = generate_keys()
    cipher_text = rsa_encrypt(b"dogs are cute", bob_keys)
    clear_text = rsa_decrypt(cipher_text, bob_keys)


# def SendTo(fromUser, toUser, toKeys, message, secret):

#     # print(f"{toUser} GENERATED HIS KEYS (RSA), AND HE PUBLISHED HIS PUBLIC KEY TO A PUBLIC KEYRING.\n")
#     # bob_keys = generate_keys()

#     # Generate random secret shared key.
#     #secret_key = get_random_bytes(16)
#     secret_password = b"secret pass word"
#     print(f"{fromUser} HAS SOMETHING EXTRAORDINARILY IMPORTANT TO SAY TO {toUser}.")
#     print(f"IF ANYONE KNEW WHAT {fromUser} HAD TO SAY TO {toUser}, {fromUser} WOULD SURELY BE")
#     print(f"ARRESTED, SILENCED, AND NEVER TO BE SEEN EVER AGAIN.")
#     print(f"THIS IS WHAT SHE NEEDED TO SAY:\n{message}\n")
#     print(f"TO PROTECT HER IDEA, {fromUser} CAME UP WITH A SECRET PASSWORD THAT NO ONE IN THE ENTIRE UNIVERSE COULD KNOW")
#     print(secret)
#     print("")

#     print(f"{fromUser} ENCRYPTS HER MESSAGE USING THE SECRET PASSWORD (AES)")
#     (cipher_text, tag, nonce) = aes_encrypt(message, secret)

#     print(f"{fromUser} ENCRYPTS THE SECRET PASSWORD USING {toUser}S PUBLIC KEY FROM THE PUBLIC KEYRING (RSA)")
#     # Encrypt secret key using public key of receiver
#     enc_secret_password = rsa_encrypt(secret, toKeys)
#     return (cipher_text, tag, nonce, enc_secret_password)



# def ReceiveFrom(fromUser, toUser, toKeys, original_secret_message, encrypted_message, encrypted_password, nonce, tag):
#     print(f"{toUser} DECRYPTS THE SECRET PASSWORD USING HIS PRIVATE KEY (RSA)")
#     secret_password_2 = rsa_decrypt(encrypted_password, toKeys)


#     print(f"{toUser} DECRYPTS MESSAGE USING THE SECRET PASSWORD (AES)")
#     secret_message_copy = aes_decrypt(encrypted_message, secret_password_2, nonce, tag)

    
#     if secret_message == secret_message_copy:
#         print(f"MESSAGE FROM {fromUser} IS VERIFIABLY PRIVATE AND AUTHENTIC")
#     else:
#         print(f"MESSAGE FROM {fromUser} IS TAINTED")
#     return (secret_message, secret_password_2)

def test2():
    print("ALICE GENERATED HER KEYS (RSA), AND SHE PUBLISHED HER PUBLIC KEY TO A PUBLIC KEYRING.")
    alice_keys = generate_keys("ALICE")

    print("BOB GENERATED HIS KEYS (RSA), AND HE PUBLISHED HIS PUBLIC KEY TO A PUBLIC KEYRING.\n")
    bob_keys = generate_keys("BOB")

    # Generate random secret shared key.
    #secret_key = get_random_bytes(16)
    secret_password = b"secret pass word"
    print("ALICE HAS SOMETHING EXTRAORDINARILY IMPORTANT TO SAY TO BOB.")
    print("IF ANYONE KNEW WHAT ALICE HAD TO SAY TO BOB, ALICE WOULD SURELY BE")
    print("ARRESTED, SILENCED, AND NEVER TO BE SEEN EVER AGAIN.")
    print(f"THIS IS WHAT SHE NEEDED TO SAY:\n{secret_message}\n")
    print("TO PROTECT HER IDEA, ALICE CAME UP WITH A SECRET PASSWORD THAT NO ONE IN THE ENTIRE UNIVERSE COULD KNOW")
    print(secret_password)
    print("")

    print("ALICE ENCRYPTS HER MESSAGE USING THE SECRET PASSWORD (AES)")
    (cipher_text, tag, nonce) = aes_encrypt(secret_message, secret_password)

    print("ALICE ENCRYPTS THE SECRET PASSWORD USING BOBS PUBLIC KEY FROM THE PUBLIC KEYRING (RSA)")
    # Encrypt secret key using public key of receiver
    enc_secret_password = rsa_encrypt(secret_password, bob_keys)


    print("ALICE SENDS ENCRYPTED SECRET PASSWORD AND ENCRYPTED MESSAGE TO BOB....")
    print("....BOB RECEIVES ENCRYPTED SECRET PASSWORD AND ENCRYPTED MESSAGE FROM ALICE.\n")
    # document is encrypted with secret key, then secret key is encrypted with reciever public key.
    # both encrypted document, and encrypted secret key are sent to reciever

    print("BOB DECRYPTS THE SECRET PASSWORD USING HIS PRIVATE KEY (RSA)")
    secret_password_2 = rsa_decrypt(enc_secret_password, bob_keys)


    print("BOB DECRYPTS MESSAGE USING THE SECRET PASSWORD (AES)")
    secret_message_copy = aes_decrypt(cipher_text, secret_password_2, nonce, tag)

    if secret_message == secret_message_copy:
        print("MESSAGE FROM ALICE IS VERIFIABLY PRIVATE AND AUTHENTIC")
    else:
        print("MESSAGE FROM ALICE IS TAINTED")

if __name__ == "__main__":
    #test0()
    #test1()
    test2()
    # bobs_keys = generate_keys("BOB")
    # (cipher_text, tag, nonce, enc_secret_password) = SendTo("ALICE", "BOB", bobs_keys, b"God, Guns, and Money.", b"secret pass word")
    # print("ALICE SENDS ENCRYPTED SECRET PASSWORD AND ENCRYPTED MESSAGE TO BOB....")
    # print("....BOB RECEIVES ENCRYPTED SECRET PASSWORD AND ENCRYPTED MESSAGE FROM ALICE.\n")
    # (secret_message, secret_password) = ReceiveFrom("ALICE", "BOB", bobs_keys, cipher_text, enc_secret_password , nonce, tag );
