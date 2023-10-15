import sys
import os
import common

def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <file_name>")
        print(" OR ")
        print(f"{sys.argv[0]} <clear text>")
        return
    
    file_name = sys.argv[1]
    data = ""
    if os.path.isfile(file_name):
        data = open(file_name, "rb").read();
    else:
        data = bytes(file_name, "utf-8")


    hash = common.sha26_hash(data)

    #print(f"{common.base64_encode(hash.digest())}")
    print(f"{hash.hexdigest()}")

if __name__ == "__main__":
    main()




