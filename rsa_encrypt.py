import sys
import common

def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <Recipient name> <clear text>")
        return

    them = sys.argv[1]
    message = sys.argv[2]

    print(f"Encrypting with public_{them}.pem:\n")
    recipientKeyFile = common.find_public_key(them)
    if recipientKeyFile:
        recipientKey = common.import_key(recipientKeyFile)
        cipher_text = common.rsa_encrypt(message, recipientKey)
        b64_cipher_text = common.base64_encode(cipher_text)
        print(f"{b64_cipher_text}")
    else:
        print("Can't find public key for recipient")
    print("\n")

if __name__ == "__main__":
    main()    
