from pwn import *
import time
import sys
import difflib

def read_file(filename):
    """Read a file and return its contents as a list of lines."""
    with open(filename, "r") as f:
        return f.readlines()

def normalize_line(line):
    """Normalize a line by stripping leading/trailing whitespace and reducing internal whitespace to a single space."""
    return ' '.join(line.split())

def compare_files(file1, file2):
    """Compare two files and print the differences or 'accept' if they are the same."""
    content1 = read_file(file1)
    content2 = read_file(file2)
    
    # Normalize lines to ignore whitespace differences
    normalized1 = [normalize_line(line) for line in content1]
    normalized2 = [normalize_line(line) for line in content2]
    
    diff = difflib.unified_diff(normalized1, normalized2, fromfile=file1, tofile=file2)

    
    # Convert the generator to a list to check if there are any differences
    diff_list = list(diff)
    
    if not diff_list:
        print("accept")
    else:
        for line in diff_list:
            print(line)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./run.py <test case id>")
        sys.exit(1)

    filename = "./in/" + sys.argv[1] + ".in"
    f = open(filename)
    input_lines = f.read().splitlines()

    # start process
    p_run = input_lines[0].split(" ")
    if len(p_run) == 1:
        p = process([p_run[0]])
    else:
        p = process([p_run[0]] + [p_run[1]])

    for i in range(1, len(input_lines)):
        # info(input_lines[i])
        p.sendline(input_lines[i].encode())
        time.sleep(0.2)

    # wait
    time.sleep(1) 

    # \x00, (sdb)... 
    with open("output.txt", "w", encoding="utf-8") as f:
        output = p.recvall(timeout=1).decode("utf-8")
        output = output.replace("\x00", "")  # \x00 terminate
        output = output.replace("(sdb) ", "")
        output = output.replace("guess a number > ", "guess a number > \n")
        f.write(output)
    p.close()
    
    ans_file = "./out/" + sys.argv[1] + ".ans"
    info(ans_file)
    compare_files("output.txt", ans_file)
