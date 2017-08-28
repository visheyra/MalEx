#!/usr/bin/env python2

import networkx as nx
from networkx import isomorphism as ism
import logging as log


class Match:

    def __init__(self):
        self.binaries = []
        self.results = {
            "bins": [],
            # {"first": smth, "second": smth,
            # "isomorphism": True/False, "possible_isomorphism": True/False}
            "funcs": []
            # {"first": {"binary": smth, "func": smth},
            # second: {"binary": smth, "func": smth},
            # isomorphism: True/False, possible_isomorphism: True/False}}
        }

    def feed(self, *args):
        """
        Feed binaries for matching
        """
        for b in args:
            self.binaries.append(b)
            log.info("loaded binary {} for matching".format(b.proj.filename))

    @staticmethod
    def batch_compare_graph(g_one, g_two):
        m = ism.GraphMatcher(g_one, g_two)
        return (m.is_isomorphic(), m.subgraph_is_isomorphic())

    def compare(self):
        bins = self.init()
        while len(bins) is not 0:
            b_key, b_graph = bins.popitem()
            log.info("Now commparing {} against targets".format(b_key))

            # Program Level Comparison
            for k_target, v_target in bins.items():

                # Compare overall CFG
                iso, psb_iso = Match.batch_compare_graph(
                    b_graph["cfg"],
                    v_target["cfg"])
                self.results["bins"].append({
                    "first": b_key,
                    "second": k_target,
                    "isomorphism": iso,
                    "possible_isomorphism": psb_iso
                })

                # Compare per func CFG
                for bk_func, bv_func in b_graph["functions"].items():
                    for tk_func, tv_func in v_target["functions"].items():
                        iso, psb_iso = Match.batch_compare_graph(
                            bv_func,
                            tv_func
                        )
                        self.results["funcs"].append({
                            "first": {
                                "binary": b_key,
                                "func": bk_func,
                            },
                            "second": {
                                "binary": k_target,
                                "func": tk_func,
                            },
                            "isomorphism": iso,
                            "possible_isomorphism": psb_iso,
                        })

    def output(self):
        print " ==== Comparison output === "
        print " ========================== "
        print "\n"
        print " Program level comparison "
        for entry in self.results["bins"]:
            print(" = [{}] and [{}] isomorphism:\
                  {} possible_isomorphism: {} = ".format(
                entry["first"],
                entry["second"],
                entry["isomorphism"],
                entry["possible_isomorphism"]
            ))
        print " ========================== "
        for entry in self.results["funcs"]:
            print(" = [{}] from [{}] and [{}] from [{}] \
                  isomorphism: {} possible_isomorphism: {} = ".format(
                entry["first"]["binary"],
                entry["first"]["func"],
                entry["second"]["binary"],
                entry["second"]["func"],
                entry["isomorphism"],
                entry["possible_isomorphism"]
            ))

    def init(self):
        bins = {}
        for b in self.binaries:
            bins[b.filename] = b.__graph__()
        return bins
