#
# 1)  Install python
# 2)  pip install pycryptodome
#
import sys
import common


if __name__ == "__main__":
    forWhom = sys.argv[1]
    print("Generating RSA Keys...")
    common.generate_keys(forWhom)
    print(f"    \".\private_{forWhom}.pem\"    <--- keep this safe, and secret.")
    print(f"    \".\public_{forWhom}.pem\"     <--- share this")
