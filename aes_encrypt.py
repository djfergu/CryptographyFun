import sys
import common
def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <password> <clear text>")
        return
    password = sys.argv[1]
    message = sys.argv[2]

    message = bytes(message, "utf-8")
    (cipher_text, tag, nonce) = common.aes_encrypt(message, password)

    b64_cipher_text = common.base64_encode(cipher_text)
    b64_tag = common.base64_encode(tag)
    b64_nonce = common.base64_encode(nonce)

    print(f"{b64_tag}  {b64_nonce}  {b64_cipher_text}")

if __name__ == "__main__":
    main()




