#!/usr/bin/env python2
import coloredlogs
import argparse
import logging as log

from output import output_binary
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
    parser.add_argument('-o',
                        '--output',
                        dest="output",
                        help="relative path of the output folder",
                        default="malex_output")
    parser.add_argument('-c',
                        '--create',
                        dest="create",
                        help="create the output folder if it don't exists",
                        default=True)
    parser.add_argument('-e',
                        '--erase',
                        dest="erase",
                        help="erase already existing resources if conflict",
                        default=True)
    return parser.parse_args()


def main():
    args = parse()
    o = output_binary(args.output, erase=args.erase, create=args.create)
    loaded_bins = load_array(args)
    for b in loaded_bins:
        o.feed(b)
    if args.match:
        m = Match()
        m.feed(*loaded_bins)
        m.compare()
        m.output()
    o.output()


if __name__ == '__main__':
    main()
