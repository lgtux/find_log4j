#!/usr/bin/env python3
"""find_log4j.py

   A simple script to find log4j jar files and try to determine
   if they are the vunerable versions.
   If the jar filename matches then it compares SHA256 hash against
   known vunerable versions.
   It will display a message for each vunerable version found.

"""

import os
import sys
import hashlib
import argparse
from signal import signal, SIGINT
from zipfile import ZipFile

# sha256 cksum lookup
cksumlookup = {}

# sha256 filename lookup
log4jdict = {}

exit_status = 0


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
    sys.exit(0)


def check_for_jndi(filename):
    with ZipFile(filename, 'r') as zip_file:
        zip_list = zip_file.namelist()

    for elem in zip_list:
        if elem.endswith("JndiLookup.class"):
            print("Warning ", filename, " contains JndiLookup.class, it is recommended to remove this")


def matchfilenames(thisdir):
    global exit_status
    # r=root, d=directories, f = files
    for r, _, f in os.walk(thisdir):
        for file in f:
            if file in log4jdict:
                fullfilename = os.path.join(r, file)
                cksum = get_sha256sum(fullfilename)
                if cksum == log4jdict[file]:
                    exit_status = 1
                    print("Matched ", fullfilename, "   vulnerable file detected")
                    check_for_jndi(fullfilename)
            if file in ('log4j-core.jar', 'log4j-api.jar'):
                fullfilename = os.path.join(r, file)
                cksum = get_sha256sum(fullfilename)
                if cksum in cksumlookup:
                    exit_status = 1
                    print(fullfilename, " matches vulnerable ", cksumlookup[cksum])
                    check_for_jndi(fullfilename)


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

    sys.exit(exit_status)
