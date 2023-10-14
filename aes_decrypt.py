import sys
import common
def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <password> <tag> <nonce> <cipher text>")
        return
    password = sys.argv[1]
    b64_tag = sys.argv[2]
    b64_nonce = sys.argv[3]
    b64_message = sys.argv[4]

    nonce = common.base64_decode(b64_nonce)
    tag = common.base64_decode(b64_tag)
    message = common.base64_decode(b64_message)

    cipher_text= common.aes_decrypt(message, password, nonce, tag)

    print(f"{cipher_text}")

if __name__ == "__main__":
    main()




