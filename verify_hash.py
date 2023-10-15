import common
import sys
import os

def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <signer name> <FileName Or Text> <signature> ")
        return
    who = sys.argv[1]
    signature = common.base64_decode(sys.argv[3])
    data = sys.argv[2]
    if os.path.isfile(data):
        data = open(data, "rb").read();
    else:
        data = bytes(data, "utf-8")

    my_hash = common.sha26_hash(data)

    theirKeyFile = common.find_public_key(who)
    theirKey = common.import_key(theirKeyFile)
    try:
        verified = common.verify_data(my_hash, theirKey, signature)
        print(f"Signature is Good.")
    except:
        print("Signature is Bad.")
    #signature = common.sign_data(hash, myKey)
    #print(f"{signature}")
    #print(f"{common.base64_encode(signature)}")

if __name__ == "__main__":
    main()