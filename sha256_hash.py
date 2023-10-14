import sys
import common
def main():
    if len(sys.argv) == 1:
        print(f"{sys.argv[0]} <file_name>")
        return
    file_name = sys.argv[1]
    d = open(file_name, "rb").read();


    hash = common.sha26_hash(d)

    print(f"{hash.hexdigest()}")

if __name__ == "__main__":
    main()




