import os
import sys
import hashlib
import argparse
from signal import signal, SIGINT


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

    parser = argparse.ArgumentParser(
        description='scan the directory looking for potential vunerable log4j jar files')

    # -d directory -c configfile
    parser.add_argument("-d", "--directory",
        help="directory to scan, defaults to current directory")
    parser.add_argument("-c", "--config",
        help="file containing the SHA256 sums of log4j jar files")

    args = parser.parse_args()

    # handle some defaults
    scandir = args.directory
    configfile = args.config
    if args.directory is None:
        scandir = os.getcwd()
    if args.config is None:
        configfile = "logj4_sha256sums.txt"

    # load the SHA256 sums to compare against
    load_sums(configfile)

    # match filenames and try to match SHA256 sums
    matchfilenames(scandir)
