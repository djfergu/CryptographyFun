import sys
import common

def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <Recipient name> <cipher text>")
        return

    me = sys.argv[1]
    b64_cipher_text = sys.argv[2] #bytes(sys.argv[2], "utf-8")

    #print(f"Decrypting using recipients private key ...")
    print(f"Decrypting with private_{me}.pem\n")
    myKeyFile = common.find_private_key(me)
    if myKeyFile:
        senderKey = common.import_key(myKeyFile)
        cipher_text = common.base64_decode(b64_cipher_text)
        clear_text = common.rsa_decrypt(cipher_text, senderKey)
        print(f"{clear_text}")
    else:
        print(f"Can't find recipients private key")
    print("\n")

if __name__ == "__main__":
    main()

