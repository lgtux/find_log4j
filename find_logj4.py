import os
import sys
import hashlib
from signal import signal, SIGINT
from os import path

# sha256 cksum lookup
cksumlookup = {}

# sha256 filename lookup
log4jdict = {}


def load_sums(filename):
    with open(filename, "r") as f:
        for line in f:
            (cksum, fname) = line.split()
            log4jdict[fname] = cksum
            cksumlookup[cksum] = fname


def get_sha256sum(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while True:
            block = file.read(h.block_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def handler(signal_received, frame):
    # Handle any cleanup here
    exit(0)


def matchfilenames(thisdir):
    # r=root, d=directories, f = files
    for r, d, f in os.walk(thisdir):
        for file in f:
            if file in log4jdict:
                fullfilename = os.path.join(r, file)
                cksum = get_sha256sum(fullfilename)
                if cksum == log4jdict[file]:
                    print(fullfilename, "    MATCH, vulnerable file detected")
            if file == "log4j-core.jar" or file == "log4j-api.jar":
                fullfilename = os.path.join(r, file)
                cksum = get_sha256sum(fullfilename)
                if cksum in cksumlookup:
                    print(fullfilename, " matches vulnerable ", cksumlookup[cksum])


if __name__ == "__main__":
    signal(SIGINT, handler)

    if len(sys.argv) > 1:
        load_sums(sys.argv[1])
    else:
        load_sums("log4j_sha256sums.txt")

    # Getting the current work directory (cwd)
    curdir = input("Enter full path you want to scan here:  ")
    matchfilenames(curdir)
