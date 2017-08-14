#!/usr/bin/env python2
import coloredlogs
coloredlogs.install()

import argparse
from binary_load import load_array

def parse():
    parser = argparse.ArgumentParser(description="convert binary to \
                                     understandable graph format")
    parser.add_argument('-b',
                        '--binary',
                        dest="binaries",
                        nargs='+',
                        action='append',
                        help="list of binaries to convert")
    parser.add_argument('-s',
                        '--shared',
                        dest='shared',
                        action='store_true',
                        help='switch on/off loading of shared objects',
                        default=False)
    return parser.parse_args()


def main():
    args = parse()
    _ = load_array(args)


if __name__ == '__main__':
    main()
