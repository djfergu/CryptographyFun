import common
import sys
import os

def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <signer name> <FileName Or Text>")
        return
    who = sys.argv[1]

    data = sys.argv[2]
    if os.path.isfile(data):
        data = open(data, "rb").read();
    else:
        data = bytes(data, "utf-8")

    hash = common.sha26_hash(data)

    myKeyFile = common.find_private_key(who)
    myKey = common.import_key(myKeyFile)

    signature = common.sign_data(hash, myKey)
    #print(f"{signature}")
    print(f"{common.base64_encode(signature)}")

if __name__ == "__main__":
    main()