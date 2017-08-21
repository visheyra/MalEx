#!/usr/bin/env python2
import coloredlogs
import argparse
import logging as log

from binary_load import load_array
from binary_match import Match

coloredlogs.install()


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
                        help='switch for loading of shared objects',
                        default=False)
    parser.add_argument('-m',
                        '--match',
                        dest='match',
                        action='store_true',
                        help="switch for naive isomorphism detection between \
                            samples based on VF2")
    return parser.parse_args()


def main():
    args = parse()
    loaded_bins = load_array(args)
    if args.match:
        m = Match()
        m.feed(*loaded_bins)
        for i in m.compare():
            log.info("[{}] <{}> match [{}] <{}>".format(*i))


if __name__ == '__main__':
    main()
