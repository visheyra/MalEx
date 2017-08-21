#!/usr/bin/env python2

import networkx as nx
import logging as log


class Match:

    def __init__(self):
        self.binaries = []

    def feed(self, *args):
        """
        Feed binaries for matching
        """
        for b in args:
            self.binaries.append(b)
            log.info("loaded binary {} for matching".format(b.proj.filename))

    def compare(self):
        """
        Compare
        """
        match = []
        if len(self.binaries) <= 1:
            log.error("Can't perform matching, too few binaries feeded")
            return []
        for i in range(len(self.binaries)):
            mb = self.binaries.pop()
            log.debug("matching binary {}".format(mb.proj.filename))
            log.info("found {} symbols in {}".format(
                len(mb.infos["vfg"]),
                mb.proj.filename))
            for tb in self.binaries:
                log.info("match against {} symbols in {}".format(
                    len(tb.infos["vfg"]),
                    mb.proj.filename))
                for mb_name, mb_symbol in mb.infos["vfg"].items():
                    for tb_name, tb_symbol in tb.infos["vfg"].items():
                        if nx.is_isomorphic(mb_symbol.graph, tb_symbol.graph):
                            log.debug("[{}] from <{}> match [{}] \
                                     from <{}>".format(
                                         mb_name,
                                         mb.proj.filename,
                                         tb_name,
                                         tb.proj.filename))
                            fg = (mb_name, mb.proj.filename, tb_name,
                                  tb.proj.filename)
                            gf = (mb_name, mb.proj.filename, tb_name,
                                  tb.proj.filename)
                            if fg in match or gf in match:
                                continue
                            else:
                                match.append(fg)
            self.binaries.append(mb)
            return match
