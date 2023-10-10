#
# 1)  Install python
# 2)  pip install pycryptodome
#
import sys
from Crypto.PublicKey import RSA

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

if __name__ == "__main__":
    forWhom = sys.argv[1]
    print("Generating RSA Keys...")
    generate_keys(forWhom)
    print("Done")